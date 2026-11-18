// SPDX-License-Identifier: GPL-2.0
// wafio_common.h — Shared definitions between all Wafio eBPF programs.
// Enterprise WAF kernel dataplane: IP firewall, SYN-flood, rate-limit, metrics.
//
// CO-RE (Compile Once, Run Everywhere): uses vmlinux.h for all kernel types.
// A single .o works on any kernel ≥ 5.10 that has BTF enabled.

#ifndef __WAFIO_COMMON_H__
#define __WAFIO_COMMON_H__

#include "vmlinux.h"          /* all kernel types from BTF — CO-RE portable  */
#include "wafio_compat.h"     /* UAPI constants not in BTF (ETH_P_IP, etc.)  */
#include <bpf/bpf_helpers.h>  /* SEC(), __uint/__type, bpf_map_lookup_elem() */
#include <bpf/bpf_endian.h>   /* bpf_htons / bpf_ntohs                       */
#include <bpf/bpf_core_read.h>/* BPF_CORE_READ / BPF_CORE_READ_STR           */

/* ── Action codes (shared between XDP and TC) ────────────────────────────── */

#define ACTION_ALLOW   0
#define ACTION_DROP    1
#define ACTION_LOG     2   /* allow but log to perf ring */
#define ACTION_WOULD_DROP 4 /* policy matched in monitor mode; packet passed */
#define ACTION_RATELIMIT 3 /* delayed / shaped */

/* ── Firewall rule types ─────────────────────────────────────────────────── */

#define RULE_BLOCKLIST  1  /* IP is in block list → drop */
#define RULE_ALLOWLIST  2  /* IP is in allow list → always pass */
#define RULE_RATELIMIT  3  /* IP is being rate-limited */

/* ── Maximum sizes ───────────────────────────────────────────────────────── */

#define MAX_BLOCKLIST_SIZE    100000   /* up to 100k IPs in blocklist */
#define MAX_ALLOWLIST_SIZE    10000    /* up to 10k IPs in allowlist */
#define MAX_RATELIMIT_SIZE    100000   /* per-IP rate counters */
#define MAX_CONNTRACK_SIZE    500000   /* connection tracking entries */
#define MAX_METRICS_SIZE      1024     /* per-interface/per-port metrics */
#define MAX_CONFIG_ENTRIES    64       /* runtime config key-value pairs */
#define MAX_GEO_ENTRIES       100000   /* IP→country mappings for geo-block */
#define MAX_PERF_EVENTS       4096     /* perf ring buffer depth */
#define MAX_HTTP_PATTERN_LEN  128
#define MAX_HTTP_PATTERNS     256      /* HTTP URI pattern blocklist */
#define MAX_PORTS             64       /* monitored ports */
#define MAX_SYNFLOOD_SIZE     200000   /* SYN tracking entries */

/* ── IPv4/IPv6 union key ─────────────────────────────────────────────────── */

struct ip_key {
    __u8  family;       /* AF_INET=2, AF_INET6=10 */
    __u8  pad[3];
    union {
        __be32  v4;
        struct in6_addr v6;
    } addr;
} __attribute__((packed));

/* ── CIDR entry for prefix matching ──────────────────────────────────────── */

struct cidr_entry {
    struct ip_key ip;
    __u8  prefix_len;   /* /8 .. /32 for v4, /8 .. /128 for v6 */
    __u8  pad[3];
};

/* ── Blocklist / Allowlist value (timestamp + metadata) ──────────────────── */

struct ip_list_val {
    __u64 added_ns;     /* bpf_ktime_get_ns() when added */
    __u64 expires_ns;   /* 0 = permanent; else auto-expiry */
    __u32 rule_type;    /* RULE_BLOCKLIST or RULE_ALLOWLIST */
    __u32 hit_count;    /* number of packets matched */
};

/* ── LPM Trie keys and values for CIDR subnet blocklist/allowlist ───────── */

struct subnet_v4_key {
    __u32 prefixlen;    /* CIDR prefix length (0..32) */
    __be32 addr;        /* IPv4 network address in big-endian */
};

struct subnet_v6_key {
    __u32 prefixlen;    /* CIDR prefix length (0..128) */
    __u8  addr[16];     /* IPv6 network address */
};

struct subnet_val {
    __u64 added_ns;     /* bpf_ktime_get_ns() when added */
    __u64 expires_ns;   /* 0 = permanent; else auto-expiry */
    __u32 rule_type;    /* RULE_BLOCKLIST or RULE_ALLOWLIST */
    __u32 hit_count;    /* number of packets matched */
};

/* ── Ingress IP lists: one LPM trie per list and family ──────────────────── */
/*
 * wafio_allow4/6 and wafio_block4/6 hold prefixes natively (an IPv6 /64 is
 * one entry), keyed by subnet_v4_key / subnet_v6_key. Allow and block live in
 * separate tries, so an allow and a block of one prefix never overwrite each
 * other. "0.0.0.0/0" / "::/0" are the /0 entries (the old 0xFD/0xFE wildcard
 * sentinels). LPM tries never evict: a full trie refuses the insert.
 *
 * A lookup returns only the longest matching prefix; the value repeats its
 * prefixlen, so when that entry does not decide (expired, or, for a
 * port-scoped allowlist entry, out of scope) the program looks again with
 * prefixlen - 1, at most LIST_WALK_MAX levels. An expired longest prefix no
 * longer hides a live shorter one, and a /32 scoped to 22/tcp does not hide a
 * /24 that allows every port.
 */
#define MAX_ALLOW_PREFIXES 10000    /* per family */
#define MAX_BLOCK_PREFIXES 100000   /* per family */
#define LIST_WALK_MAX      4
#define ALLOW_MAX_SCOPES   8
#define ALLOW_F_ALL        (1U << 0) /* every port and protocol (entries without ports) */

/* Port scope of an allowlist entry (host order; proto 0 = TCP and UDP,
 * else IPPROTO_TCP or IPPROTO_UDP). An entry without ALLOW_F_ALL decides
 * only for a TCP or UDP packet whose destination port lies in one of its
 * first nscopes scopes (lo..hi inclusive, lo >= 1); every other packet of
 * the source — ICMP, other protocols, ports outside the scopes — walks on
 * to a shorter prefix and then the normal path. */
struct allow_scope {
    __u16 lo;
    __u16 hi;
    __u8  proto;
    __u8  pad;
};

/* list_val: the head allow_val and block_val share (the walk reads it). */
struct list_val {
    __u64 added_ns;     /* bpf_ktime_get_ns() when added */
    __u64 expires_ns;   /* 0 = permanent */
    __u64 hit_count;
    __u32 flags;        /* ALLOW_F_* (allowlist), 0 (blocklist) */
    __u32 nscopes;      /* allowlist: scopes in use, 0..ALLOW_MAX_SCOPES */
    __u32 prefixlen;    /* the key's prefix length */
};

struct allow_val {      /* 88 bytes (ebpf.AllowVal) */
    __u64 added_ns;
    __u64 expires_ns;
    __u64 hit_count;
    __u32 flags;
    __u32 nscopes;
    __u32 prefixlen;
    struct allow_scope scopes[ALLOW_MAX_SCOPES];
    __u32 pad;
};

/* Jail: single addresses the WAF agent jails after repeated L7 blocks,
 * kept apart from the operator lists in wafio_jail
 * (ip_key -> ip_list_val, expiry always set). A control-plane push never
 * touches it, so a jail keeps its TTL. It is a HASH table: a full jail
 * refuses a new entry (the agent reports it) and never evicts one, so a jailed
 * address stays jailed until its TTL ends. */
#define MAX_JAIL_SIZE 65536

struct block_val {      /* 40 bytes (ebpf.BlockVal) */
    __u64 added_ns;
    __u64 expires_ns;
    __u64 hit_count;
    __u32 flags;
    __u32 nscopes;
    __u32 prefixlen;
    __u32 pad;
};

/* ── Rate limit state (per IP) ───────────────────────────────────────────── */

struct rate_state {
    __u64 window_start_ns;  /* start of current window */
    __u64 pkt_count;        /* packets in current window */
    __u64 byte_count;       /* bytes in current window */
    __u32 syn_count;        /* SYN packets in current window */
    __u32 action;           /* current action: allow/drop/log */
    struct bpf_spin_lock lock;
    __u32 _pad;
};

/* ── Rate limit config (global, set from userspace) ──────────────────────── */

struct rate_config {
    __u64 window_ns;       /* window size in nanoseconds (e.g. 1s = 1000000000) */
    __u32 max_pps;         /* max packets per second per IP; 0 = unlimited */
    __u32 max_bps;         /* max bytes per second per IP; 0 = unlimited */
    __u32 max_syn_pps;     /* max SYN packets per second per IP (SYN flood) */
    __u32 burst_pps;       /* burst allowance above max_pps */
    __u32 burst_syn;       /* burst allowance for SYN */
    __u32 action;          /* what to do when limit exceeded: ACTION_DROP or ACTION_LOG */
    __u32 syn_pressure_pps; /* GLOBAL SYN rate triggering pressure mode; 0 = off.
                             * Under pressure: no new state allocation (protects
                             * LRU tables), SYNs only pass for flows already
                             * established in conntrack. */
};

/* ── Connection tracking entry ───────────────────────────────────────────── */

struct conn_key {
    struct ip_key src;
    struct ip_key dst;
    __be16 sport;
    __be16 dport;
    __u8   proto;         /* IPPROTO_TCP or IPPROTO_UDP */
    __u8   pad[3];
} __attribute__((packed));

/* flags_seen marks (bits above the 8 TCP flag bits):
 *   CONN_OUTBOUND — TC egress entry of a flow this host opened; its replies
 *                   pass the ingress default deny and wildcard blocklists.
 *   CONN_REPLY    — XDP ingress entry created by such a reply. It is the
 *                   reply side of a host-opened flow, NOT a tracked inbound
 *                   connection, so TC must not exempt the flow's outbound
 *                   packets from the egress port filter. TC
 *                   also sets it on an XDP entry it finds to be the remote
 *                   side of a flow this host opened (tc_verify_inbound).
 *   CONN_VERIFIED — XDP ingress entry TC confirmed as an inbound connection:
 *                   the host answered its SYN with a SYN-ACK, or the kernel
 *                   holds a connection for exactly the tuple and a TCP
 *                   listener owns its local port; entries TC
 *                   adopts start with it. Set once; TC exempts the replies
 *                   of an inbound TCP entry only with it. */
#define CONN_OUTBOUND (1U << 31)
#define CONN_REPLY    (1U << 30)
#define CONN_VERIFIED (1U << 29)
/* CONN_HOST_ACKED — XDP ingress entry of an inbound TCP connection on which
 * TC saw the host send a segment without SYN or RST after the handshake (an
 * ACK or data). Together with CONN_VERIFIED and tcp_state 1 it exempts the
 * connection from the per-IP rate limit; a blind spoofed handshake
 * gets a reset from the host instead (TC then sets tcp_state 3). */
#define CONN_HOST_ACKED (1U << 28)
#define CONN_TCP_TTL_NS 300000000000ULL
/* Established inbound TCP connections (tcp_state 1) keep their egress reply
 * exemption this long without traffic — the netfilter default for
 * established flows — so an idle SSH session is not stalled when the server
 * speaks first after five quiet minutes. */
#define CONN_TCP_EST_TTL_NS 432000000000000ULL
#define CONN_UDP_TTL_NS 30000000000ULL

/* ct_fresh: a conntrack entry last seen at `last` is fresh at `now` when it is
 * younger than ttl. A timestamp up to 1 s in the future also counts as fresh:
 * another CPU may stamp an entry after this run read its clock, and treating
 * that as stale deleted or refused live flows. */
static __always_inline int
ct_fresh(__u64 now, __u64 last, __u64 ttl) {
    return last > now ? last - now < 1000000000ULL : now - last < ttl;
}

struct conn_val {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 packets;
    __u64 bytes;
    __u32 tcp_state;      /* simplified: 0=new, 1=established, 2=fin, 3=rst */
    __u32 flags_seen;     /* OR of all TCP flags seen */
};

/* ── SYN flood tracking (lightweight, per source IP) ─────────────────────── */

struct syn_state {
    __u64 window_start_ns;
    __u64 syn_count;
    __u64 synack_count;
    __u64 ack_count;
    __u64 drop_count;
    struct bpf_spin_lock lock;
    __u32 _pad;
};

/* ── Global SYN pressure (per-CPU, stateless-adjacent mitigation) ────────── */
/* PERCPU map: each CPU owns its copy — no spin_lock (unsupported on per-CPU
 * maps, and unnecessary since there is no cross-CPU sharing). */

struct syn_pressure_state {
    __u64 window_start_ns;
    __u64 count;              /* SYNs seen this second on this CPU */
};

/* ── Perf event (sent to userspace ring buffer) ──────────────────────────── */

struct perf_event_data {
    __u64 timestamp_ns;
    struct ip_key src_ip;
    struct ip_key dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   proto;
    __u8   action;          /* ACTION_ALLOW/DROP/LOG */
    __u8   reason;          /* see EVENT_REASON_* below */
    __u8   tcp_flags;
    __u32  pkt_len;
    __u32  rule_id;         /* which rule triggered (for audit) */
} __attribute__((packed));

/* ── Event reasons ───────────────────────────────────────────────────────── */

#define EVENT_REASON_BLOCKLIST       1
#define EVENT_REASON_RATELIMIT_PPS   2
#define EVENT_REASON_RATELIMIT_BPS   3
#define EVENT_REASON_SYNFLOOD        4
#define EVENT_REASON_CONNTRACK       5
#define EVENT_REASON_GEOBLOCK        6
#define EVENT_REASON_PORT_SCAN       7
#define EVENT_REASON_ALLOWLIST       8
#define EVENT_REASON_HTTP_PATTERN    9
#define EVENT_REASON_PAYLOAD_SIZE    10
#define EVENT_REASON_PORT_POLICY     11   /* port policy ingress/egress */
#define EVENT_REASON_PACKET_PARSE 13
#define EVENT_REASON_EGRESS_IP       12   /* egress IP blocklist */

/* ── Global config (set from userspace, key=0) ───────────────────────────── */

struct global_config {
    __u32 enabled;             /* master kill switch: 0=disabled, 1=enabled */
    __u32 mode;                /* 0=enforce, 1=monitor-only (log but don't drop) */
    __u32 log_allowed;         /* log allowed packets too (verbose) */
    __u32 log_blocked;         /* log blocked packets (default on) */
    __u32 enable_conntrack;    /* enable connection tracking */
    __u32 enable_synflood;     /* enable SYN flood protection */
    __u32 enable_ratelimit;    /* enable per-IP rate limiting */
    __u32 enable_geoblock;     /* enable IP→country geo blocking */
    __u32 max_payload_bytes;   /* max L4 payload → drop if exceeded; 0=unlimited */
};

/* ── Per-interface/port metrics (atomically updated by eBPF) ─────────────── */

struct metrics_val {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 dropped_packets;
    __u64 dropped_bytes;
    __u64 ratelimited_packets;
    __u64 synflood_drops;
    __u64 blocklist_drops;
    __u64 allowlist_passes;
    __u64 geoblock_drops;
    __u64 conntrack_entries;      /* conntrack entries created (XDP + TC,
                                   * both families; cumulative, not the live
                                   * table size) */
    __u64 port_scan_drops;
    __u64 port_policy_drops;      /* port policy drops (ingress + egress) */
    __u64 egress_ip_drops;        /* egress IP blocklist drops */
    __u64 would_drop_packets;
    __u64 would_drop_bytes;
    __u64 state_table_full;
    __u64 packet_parse_failures;
    __u64 syn_pressure_drops;     /* SYNs dropped by global pressure mode */
};

static __always_inline void
record_firewall_drop(struct metrics_val *m, __u32 pkt_len, __u32 mode) {
    if (!m) return;
    if (mode == 1) {
        __sync_fetch_and_add(&m->would_drop_packets, 1);
        __sync_fetch_and_add(&m->would_drop_bytes, pkt_len);
    } else {
        __sync_fetch_and_add(&m->dropped_packets, 1);
        __sync_fetch_and_add(&m->dropped_bytes, pkt_len);
    }
}

/* ── Geo-IP map value (country code as 2 bytes) ──────────────────────────── */

struct geo_val {
    __u16 country_code;       /* packed 2-char ISO code: 'U'<<8|'S' = US */
    __u8  action;             /* ACTION_DROP or ACTION_ALLOW */
    __u8  pad;
};

/* ── Geo blocked countries set ───────────────────────────────────────────── */

struct geo_country_val {
    __u8 blocked;             /* 1 = blocked, 0 = allowed */
    __u8 pad[3];
};

/* ── Port monitoring entry ───────────────────────────────────────────────── */

struct port_config {
    __u16 port;
    __u8  proto;             /* IPPROTO_TCP or IPPROTO_UDP */
    __u8  enabled;
};

/* ── Port policy (enterprise ingress/egress port firewall) ───────────────── */
/*
 * Direction constants for port_policy_key.direction:
 *   0 = ingress only (XDP)
 *   1 = egress only (TC)
 *   2 = both ingress and egress
 */
#define PORT_DIR_INGRESS 0
#define PORT_DIR_EGRESS  1
#define PORT_DIR_BOTH    2

/* Key for port policy hash map */
struct port_policy_key {
    __u16 port;              /* port number (host byte order) */
    __u8  proto;             /* IPPROTO_TCP=6, IPPROTO_UDP=17, 0=any */
    __u8  direction;         /* PORT_DIR_INGRESS/EGRESS/BOTH */
} __attribute__((packed));

/* Value for port policy hash map */
struct port_policy_val {
    __u32 action;            /* ACTION_DROP or ACTION_LOG */
    __u64 hit_count;         /* packets matched */
    __u64 added_ns;          /* when the rule was created */
    __u64 expires_ns;        /* 0 = permanent; else auto-expiry */
};

/* Port policy global config (key=0 in port_policy_config map) */
struct port_policy_config {
    __u32 enabled;           /* master enable for port policies */
    __u32 default_ingress;   /* 0=allow-all, 1=deny-all (allowlist mode) */
    __u32 default_egress;    /* 0=allow-all, 1=deny-all (allowlist mode) */
    __u32 pad;
};

/* Maximum entries for port policy maps */
#define MAX_PORT_POLICIES     4096
#define MAX_EGRESS_BLOCKLIST  100000

/* ── Control-plane endpoints ─────────────────────────────────────────────── */
/*
 * The agent writes the resolved address(es) and port of its control plane
 * into wafio_cp_endpoints (shared by XDP and TC). TC egress always passes
 * packets to these endpoints; XDP passes their replies only when they belong
 * to a fresh outbound flow of this host, so a spoofed control-plane source
 * address cannot reach any other port. The map's presence in both objects is
 * the ABI marker the agent checks before accepting egress Deny All or
 * wildcard blocklist entries.
 */
#define MAX_CP_ENDPOINTS 16

/* ── DHCPv4 client state ──────────────────────────────────────────────────── */
/*
 * Kept out of wafio_conntrack (inbound packets of other hosts' DHCP traffic
 * share its keys). Both maps are shared by XDP and TC.
 *   wafio_dhcp_pending — broadcast BOOTREQUESTs this host sent, keyed by xid
 *     (wire order): TC records xid + chaddr; XDP accepts a BOOTREPLY only
 *     with that xid and chaddr, addressed to broadcast or to that hardware
 *     address, within DHCP_PENDING_TTL_NS. Inbound packets never write it.
 *   wafio_dhcp_servers — sources of such replies (learned by XDP); TC passes
 *     the unicast RENEW/RELEASE to them for DHCP_SERVER_TTL_NS, after which
 *     the client falls back to a broadcast REBIND.
 */
#define DHCP_PENDING_TTL_NS 30000000000ULL      /* 30 s */
#define DHCP_SERVER_TTL_NS  86400000000000ULL   /* 1 day */
#define DHCP_BOOTP_MIN      34                  /* op..chaddr[6] */

struct dhcp_pending_val {
    __u64 sent_ns;
    __u8  chaddr[6];
    __u8  pad[2];
};

/* Not in the vmlinux.h IPPROTO enum (UAPI #define). */
#define WAFIO_IPPROTO_ICMPV6 58

struct cp_endpoint_key {
    struct ip_key ip;        /* control-plane address */
    __be16 port;             /* network byte order */
    __u8   proto;            /* IPPROTO_TCP */
    __u8   pad;
} __attribute__((packed));

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static __always_inline void
ip_key_from_v4(struct ip_key *key, __be32 addr) {
    key->family = 2; /* AF_INET */
    key->pad[0] = key->pad[1] = key->pad[2] = 0;
    __builtin_memset(&key->addr.v6, 0, sizeof(struct in6_addr));
    key->addr.v4 = addr;
}

static __always_inline void
ip_key_from_v6(struct ip_key *key, struct in6_addr *addr) {
    key->family = 10; /* AF_INET6 */
    key->pad[0] = key->pad[1] = key->pad[2] = 0;
    __builtin_memcpy(&key->addr.v6, addr, sizeof(struct in6_addr));
}

/* Pack a 2-char country code into __u16 */
static __always_inline __u16
pack_country(__u8 c0, __u8 c1) {
    return ((__u16)c0 << 8) | (__u16)c1;
}

/* Fill perf event IPv4 source/dest from raw addresses */
static __always_inline void
fill_event_ips_v4(struct perf_event_data *evt, __be32 saddr, __be32 daddr) {
    ip_key_from_v4(&evt->src_ip, saddr);
    ip_key_from_v4(&evt->dst_ip, daddr);
}

#endif /* __WAFIO_COMMON_H__ */
