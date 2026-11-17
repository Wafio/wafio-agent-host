// SPDX-License-Identifier: GPL-2.0
// wafio_lsm.c — Proactive Linux Security Module (BPF-LSM) for pre-event blocking.
//
// Hooks:
//   - lsm/bprm_check_security: block unauthorized binary executions (-EPERM)
//   - lsm/socket_connect:      block outbound connects to blocklisted IPv4
//                              addresses (-EPERM), including an AF_INET6
//                              connect to the IPv4-mapped form
//   - lsm/socket_sendmsg:      block addressed sends (sendto/sendmsg with a
//                              destination: unconnected UDP, MSG_FASTOPEN)
//                              to the same blocklist when the rule carries
//                              LSM_RULE_SEND
//
// Synchronous in-kernel denial: the harmful operation never takes
// effect, unlike the async userspace kill path. Requires kernel >= 5.7 with
// BPF-LSM enabled.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define LSM_PATH_LEN 256
#define TRACE_COMM_LEN 16

#define TRACE_ACTION_MONITOR  0
#define TRACE_ACTION_ALERT    1
#define TRACE_ACTION_KILL     2
#define TRACE_ACTION_SIMULATE 3
#define TRACE_ACTION_BLOCK    4

#define LSM_HOOK_EXEC   0
#define LSM_HOOK_CONNECT 2
#define LSM_HOOK_SENDMSG 3

#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 10
/* SIN6_LEN_RFC2133: the shortest sockaddr_in6 inet6 connect accepts. */
#define LSM_SIN6_LEN_RFC2133 24
#define EPERM 1

/* LSM blocklist rule (executable path or IP keyed) */
struct lsm_rule {
    __u32 action;       /* TRACE_ACTION_* */
    __u32 policy_id;
    __u32 enabled;
    __u32 flags;        /* LSM_RULE_*; was padding, 0 from older agents */
    __u64 hit_count;
};

/* wafio_lsm_ip_blocklist: also deny an addressed send to this IP (the
 * enforcing policy selects sendto, not only connect). */
#define LSM_RULE_SEND (1U << 0)

/* Global LSM Configuration (single-entry array, key=0) */
struct lsm_config {
    __u32 enabled;        /* 1 = LSM enabled */
    __u32 block_exec;     /* 1 = -EPERM on exec match, 0 = alert only */
    __u32 block_connect;  /* 1 = -EPERM on socket_connect match, 0 = alert only */
    __u32 agent_pid;      /* never block Wafio control plane or agent */
    __u32 pad;
};

/* LSM enforcement event emitted to ring buffer */
struct wafio_lsm_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 action;
    __u32 policy_id;
    __s32 ret_code;
    __u32 hook;           /* LSM_HOOK_* */
    char  comm[TRACE_COMM_LEN];
    char  path[LSM_PATH_LEN];   /* exec path; empty for connect */
    __u8  addr[16];             /* connect destination (IPv4 in [0..3]) */
    __u16 port;                 /* connect destination port (host order) */
    __u16 family;               /* connect: socket address family; 0 otherwise */
    __u64 pad;
};

/* Config map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct lsm_config);
    __uint(max_entries, 1);
} wafio_lsm_config SEC(".maps");

/* Blocklist map: executable path (e.g. "/bin/nc") -> rule */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[LSM_PATH_LEN]);
    __type(value, struct lsm_rule);
    __uint(max_entries, 1024);
} wafio_lsm_blocklist SEC(".maps");

/* Outbound connect blocklist: destination IPv4 (big-endian) -> rule */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct lsm_rule);
    __uint(max_entries, 4096);
} wafio_lsm_ip_blocklist SEC(".maps");

/* ABI marker: present in objects whose socket_connect hook checks an
 * AF_INET6 destination carrying an IPv4-mapped address (::ffff:a.b.c.d)
 * against wafio_lsm_ip_blocklist. The agent skips its userspace action on
 * such a connect only when it finds this map; with an older object the
 * connect is still enforced from userspace. Never read or written. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} wafio_lsm_connect_v4mapped SEC(".maps");

/* Ringbuf for streaming LSM events to userspace (1 MB) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} wafio_lsm_events SEC(".maps");

/* Network deny reports (connect, sendmsg) are rate-limited per CPU: a
 * process looping sendto() at a blocklisted IP must not flood the ring and
 * crowd out exec reports. The denial itself and the
 * rule's hit_count are never limited. LSM_NET_REPORTS_PER_SEC reports per
 * CPU per second pass; the rest are counted in wafio_lsm_reports_suppressed
 * (per CPU, read by the agent). Per-CPU values need no atomics; a program
 * preempted on the same CPU may miscount by one. */
#define LSM_NET_REPORTS_PER_SEC 32
#define LSM_REPORT_WINDOW_NS    1000000000ULL

struct lsm_report_window {
    __u64 start_ns;
    __u64 sent;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct lsm_report_window);
    __uint(max_entries, 1);
} wafio_lsm_report_window SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} wafio_lsm_reports_suppressed SEC(".maps");

/* lsm_net_report_allowed: 1 when this CPU may still report a network deny in
 * the current one-second window; otherwise counts the suppressed report. */
static __always_inline int
lsm_net_report_allowed(__u64 now_ns)
{
    __u32 zero = 0;
    struct lsm_report_window *w = bpf_map_lookup_elem(&wafio_lsm_report_window, &zero);
    if (!w)
        return 1;
    if (now_ns < w->start_ns || now_ns - w->start_ns >= LSM_REPORT_WINDOW_NS) {
        w->start_ns = now_ns;
        w->sent = 0;
    }
    if (w->sent >= LSM_NET_REPORTS_PER_SEC) {
        __u64 *suppressed = bpf_map_lookup_elem(&wafio_lsm_reports_suppressed, &zero);
        if (suppressed)
            *suppressed += 1;
        return 0;
    }
    w->sent += 1;
    return 1;
}

/* Shared guard: LSM off or the agent/PID 1 itself → skip. Returns config. */
static __always_inline struct lsm_config *
lsm_gate(void) {
    __u32 zero = 0;
    struct lsm_config *cfg = bpf_map_lookup_elem(&wafio_lsm_config, &zero);
    if (!cfg || !cfg->enabled)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid <= 1 || (cfg->agent_pid > 0 && pid == cfg->agent_pid))
        return 0;
    return cfg;
}

/* Submit a rule-hit event; returns the rule's action. */
static __always_inline __u32
lsm_report(struct lsm_config *cfg, struct lsm_rule *rule, __u32 hook,
           const char path[LSM_PATH_LEN], __be32 addr, __u16 port, __u16 family) {
    __sync_fetch_and_add(&rule->hit_count, 1);

    if ((hook == LSM_HOOK_CONNECT || hook == LSM_HOOK_SENDMSG) &&
        !lsm_net_report_allowed(bpf_ktime_get_ns()))
        return rule->action;

    struct wafio_lsm_event *evt = bpf_ringbuf_reserve(&wafio_lsm_events, sizeof(*evt), 0);
    if (evt) {
        __u64 uid_gid = bpf_get_current_uid_gid();
        evt->timestamp_ns = bpf_ktime_get_ns();
        evt->cgroup_id = bpf_get_current_cgroup_id();
        evt->pid = bpf_get_current_pid_tgid() >> 32;
        evt->uid = (__u32)uid_gid;
        evt->gid = uid_gid >> 32;
        evt->action = rule->action;
        evt->policy_id = rule->policy_id;
        evt->hook = hook;
        switch (hook) {
        case LSM_HOOK_CONNECT:
        case LSM_HOOK_SENDMSG:
            evt->ret_code = cfg->block_connect ? -EPERM : 0;
            break;
        default:
            evt->ret_code = cfg->block_exec ? -EPERM : 0;
        }
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        if (path)
            __builtin_memcpy(evt->path, path, LSM_PATH_LEN);
        if (addr)
            *(__be32 *)evt->addr = addr;
        evt->port = port;
        evt->family = family;
        bpf_ringbuf_submit(evt, 0);
    }
    return rule->action;
}

/* Verdict helpers: noinline so the caller cannot fold the literal error
 * returns into arithmetic over a map-derived scalar (clang does exactly that,
 * producing an R0 exit the verifier cannot prove lies in [-4095, 0]). Each
 * subprogram returns a constant, verified independently. */
static __noinline int deny_perm(void)   { return -EPERM; }
static __noinline int lsm_allow(void)   { return 0; }

SEC("lsm/bprm_check_security")
int BPF_PROG(wafio_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    /* If prior LSM module already denied, honor denial. The verifier needs a
     * provable [-4095, 0] range for LSM program returns — an unchecked
     * scalar arg makes R0 "unknown" at exit and the whole collection
     * rejects. */
    if (ret != 0) {
        if (ret < -4095 || ret > 0)
            return 0;
        return ret;
    }

    struct lsm_config *cfg = lsm_gate();
    if (!cfg)
        return 0;

    char path[LSM_PATH_LEN] = {};
    const char *fn = BPF_CORE_READ(bprm, filename);
    if (!fn)
        return 0;

    bpf_core_read_str(path, sizeof(path), fn);

    /* Lookup path in blocklist */
    struct lsm_rule *rule = bpf_map_lookup_elem(&wafio_lsm_blocklist, path);
    if (!rule || !rule->enabled)
        return 0;

    __u32 action = lsm_report(cfg, rule, LSM_HOOK_EXEC, path, 0, 0, 0);

    if (cfg->block_exec && action == TRACE_ACTION_BLOCK)
        return deny_perm();
    return lsm_allow();
}

/* The IPv4 peer a connect reaches. An AF_INET destination, or an
 * AF_INET6 one carrying an IPv4-mapped address (::ffff:a.b.c.d), which a
 * dual-stack socket connects over IPv4 (tcp_v6_connect / ip6_datagram_connect
 * hand it to the IPv4 path). IPv4-compatible (::a.b.c.d) and every other IPv6
 * address stay IPv6. Returns 1 and fills *addr and *port (network order) and
 * *family, or 0 when the destination names no IPv4 peer or is shorter than
 * its family needs (the connect then fails with -EINVAL after this hook, and
 * the bytes past addrlen are stale). */
static __always_inline int
lsm_connect_ipv4(struct sockaddr *address, int addrlen, __be32 *addr, __be16 *port, __u16 *family)
{
    __u16 fam = BPF_CORE_READ(address, sa_family);
    if (fam == AF_INET) {
        struct sockaddr_in sin = {};
        if (addrlen < (int)sizeof(sin))
            return 0;
        bpf_core_read(&sin, sizeof(sin), address);
        *addr = sin.sin_addr.s_addr;
        *port = sin.sin_port;
    } else if (fam == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        if (addrlen < LSM_SIN6_LEN_RFC2133)
            return 0;
        bpf_core_read(&sin6, sizeof(sin6), address);
        const __u8 *b = sin6.sin6_addr.in6_u.u6_addr8;
        if (sin6.sin6_addr.in6_u.u6_addr32[0] || sin6.sin6_addr.in6_u.u6_addr32[1] ||
            b[8] || b[9] || b[10] != 0xff || b[11] != 0xff)
            return 0;
        *addr = sin6.sin6_addr.in6_u.u6_addr32[3];
        *port = sin6.sin6_port;
    } else {
        return 0;
    }
    *family = fam;
    return 1;
}

SEC("lsm/socket_connect")
int BPF_PROG(wafio_socket_connect, struct socket *sock, struct sockaddr *address,
             int addrlen, int ret)
{
    if (ret != 0) {
        if (ret < -4095 || ret > 0)
            return 0;
        return ret;
    }

    struct lsm_config *cfg = lsm_gate();
    if (!cfg)
        return 0;

    __be32 daddr = 0;
    __be16 dport = 0;
    __u16 family = 0;
    if (!lsm_connect_ipv4(address, addrlen, &daddr, &dport, &family))
        return 0;

    struct lsm_rule *rule = bpf_map_lookup_elem(&wafio_lsm_ip_blocklist, &daddr);
    if (!rule || !rule->enabled)
        return 0;

    __u32 action = lsm_report(cfg, rule, LSM_HOOK_CONNECT, 0, daddr,
                              __builtin_bswap16(dport), family);

    if (cfg->block_connect && action == TRACE_ACTION_BLOCK)
        return deny_perm();
    return lsm_allow();
}

/* lsm_sock_family: address family of the sending socket. */
static __always_inline __u16
lsm_sock_family(struct socket *sock)
{
    return BPF_CORE_READ(sock, sk, __sk_common.skc_family);
}

/* The IPv4 peer of an addressed send (sendto/sendmsg with
 * msg_name), read like a connect destination (lsm_connect_ipv4) — plus
 * AF_UNSPEC on an AF_INET socket, which udp_sendmsg and raw_sendmsg accept
 * as AF_INET (an AF_INET6 socket ignores such an address and uses its
 * connected peer). */
static __always_inline int
lsm_send_ipv4(struct socket *sock, struct sockaddr *address, int addrlen,
              __be32 *addr, __be16 *port, __u16 *family)
{
    __u16 fam = BPF_CORE_READ(address, sa_family);
    if (fam != AF_UNSPEC)
        return lsm_connect_ipv4(address, addrlen, addr, port, family);
    if (lsm_sock_family(sock) != AF_INET)
        return 0;
    struct sockaddr_in sin = {};
    if (addrlen < (int)sizeof(sin))
        return 0;
    bpf_core_read(&sin, sizeof(sin), address);
    *addr = sin.sin_addr.s_addr;
    *port = sin.sin_port;
    *family = AF_INET;
    return 1;
}

/* An unconnected UDP sendto, a sendmsg with a destination and a TCP Fast
 * Open send (MSG_FASTOPEN connects inside tcp_sendmsg without
 * security_socket_connect) never pass socket_connect. The same blocklist
 * applies here to rules marked LSM_RULE_SEND. The agent attaches this
 * program only when it knows the flag; with an older object addressed sends
 * stay enforced from userspace. */
SEC("lsm/socket_sendmsg")
int BPF_PROG(wafio_socket_sendmsg, struct socket *sock, struct msghdr *msg,
             int size, int ret)
{
    if (ret != 0) {
        if (ret < -4095 || ret > 0)
            return 0;
        return ret;
    }

    /* Every socket write passes here: leave at once when the send names no
     * destination (a connected socket, checked at connect). */
    void *name = BPF_CORE_READ(msg, msg_name);
    if (!name)
        return 0;

    struct lsm_config *cfg = lsm_gate();
    if (!cfg)
        return 0;

    __be32 daddr = 0;
    __be16 dport = 0;
    __u16 family = 0;
    if (!lsm_send_ipv4(sock, name, BPF_CORE_READ(msg, msg_namelen), &daddr, &dport, &family))
        return 0;

    struct lsm_rule *rule = bpf_map_lookup_elem(&wafio_lsm_ip_blocklist, &daddr);
    if (!rule || !rule->enabled || !(rule->flags & LSM_RULE_SEND))
        return 0;

    __u32 action = lsm_report(cfg, rule, LSM_HOOK_SENDMSG, 0, daddr,
                              __builtin_bswap16(dport), family);

    if (cfg->block_connect && action == TRACE_ACTION_BLOCK)
        return deny_perm();
    return lsm_allow();
}
