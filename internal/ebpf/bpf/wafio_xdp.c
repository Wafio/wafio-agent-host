// SPDX-License-Identifier: GPL-2.0
// wafio_xdp.c — Wafio enterprise XDP firewall program.
//
// Runs at XDP hook (driver level) for wire-speed packet filtering:
//   1. IP blocklist / allowlist (O(1) hash lookup)
//   2. SYN flood protection (per-source-IP SYN rate tracking)
//   3. Per-IP rate limiting (packets/sec + bytes/sec with burst)
//   4. Geo-IP blocking (IP → country code → blocked countries set)
//   5. Connection tracking (lightweight stateful inspection)
//   6. Port scan detection (track unique dst ports per source)
//   7. Payload size enforcement
//   8. Per-event audit trail via perf ring buffer
//   9. Atomic metrics counters
//
// All configuration is done at runtime via BPF maps — no recompilation needed.
// Master kill-switch: global_config.enabled = 0 → XDP_PASS everything.

#include "wafio_common.h"
#include "wafio_packet.h"

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAP DEFINITIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Global configuration (key=0) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_config);
} wafio_config SEC(".maps");

/* Ingress IP lists (wafio_common.h): prefixes in LPM tries, one per
 * list and family; LPM tries never evict. They need BPF_F_NO_PREALLOC,
 * and only the firewall programs use them. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct subnet_v4_key);
    __type(value, struct allow_val);
    __uint(max_entries, MAX_ALLOW_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_allow4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct subnet_v6_key);
    __type(value, struct allow_val);
    __uint(max_entries, MAX_ALLOW_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_allow6 SEC(".maps");

/* Presence tells the agent that this object's allowlist walk matches port
 * scopes (allow_scope_hit), so it may write entries without ALLOW_F_ALL and
 * reports firewall_features "allowlist_ports". An object with wafio_allow4
 * but without this map treats such an entry as never deciding. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} wafio_allow_scopes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct subnet_v4_key);
    __type(value, struct block_val);
    __uint(max_entries, MAX_BLOCK_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_block4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct subnet_v6_key);
    __type(value, struct block_val);
    __uint(max_entries, MAX_BLOCK_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_block6 SEC(".maps");

/* Jail (wafio_common.h): addresses jailed by the WAF agent. A HASH map, so a
 * full jail refuses the next entry (the agent sees E2BIG and counts it) instead
 * of evicting a jailed address. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_JAIL_SIZE);
    __type(key, struct ip_key);
    __type(value, struct ip_list_val);
} wafio_jail SEC(".maps");

/* Rate limit configuration (key=0) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_config);
} wafio_rate_config SEC(".maps");

/* Per-IP rate state */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RATELIMIT_SIZE);
    __type(key, struct ip_key);
    __type(value, struct rate_state);
} wafio_rate_state SEC(".maps");

/* SYN flood tracking (per source IP) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SYNFLOOD_SIZE);
    __type(key, struct ip_key);
    __type(value, struct syn_state);
} wafio_syn_state SEC(".maps");

/* Inserts the three per-source state maps above refused because they were
 * full, per CPU: slot 0 rate limit, 1 SYN flood, 2 port scan (the port scan
 * map is declared further down). The packet passes unchecked when its source
 * cannot be tracked; sources already tracked stay limited. Optional: an agent
 * tolerates an object without it. */
#define STATE_FULL_RATE     0
#define STATE_FULL_SYN      1
#define STATE_FULL_PORTSCAN 2
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} wafio_state_full SEC(".maps");

/* Global SYN pressure (per-CPU window) — stateless-ish flood detector that
 * costs no shared memory and cannot be exhausted by spoofed sources. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syn_pressure_state);
} wafio_syn_pressure SEC(".maps");

/* Connection tracking */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNTRACK_SIZE);
    __type(key, struct conn_key);
    __type(value, struct conn_val);
} wafio_conntrack SEC(".maps");

/* Geo-IP lookup: ip_key → geo_val (must be populated by userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_GEO_ENTRIES);
    __type(key, struct ip_key);
    __type(value, struct geo_val);
} wafio_geoip SEC(".maps");

/* Blocked countries set: country_code (__u16) → geo_country_val */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u16);
    __type(value, struct geo_country_val);
} wafio_geo_blocked SEC(".maps");

/* Geo CIDR ranges for IPv4 — pre-populated from the GeoIP country database
 * at config time. LPM lookup: {prefixlen=32, addr=src_ip} finds the longest
 * matching CIDR. The value says which list the range belongs to
 * (GEO_CIDR_BLOCKED in block mode, GEO_CIDR_ALLOWED in allow mode), so the
 * agent can load a new list before it switches the mode (no window in which
 * an allowed source is unlisted). Capacity 262144 per family: in
 * the DB-IP country lite data (2026-05) the largest single countries hold
 * 154,703 IPv4 (US) and 139,730 IPv6 (AU) ranges, the 27 EU countries
 * together 147,772 IPv4 and 252,507 IPv6. The agent merges duplicate and
 * sibling ranges and refuses a list that does not fit instead of loading
 * part of it. Entries are allocated on insert (BPF_F_NO_PREALLOC). */
#define GEO_CIDR_MAX_ENTRIES 262144
struct geo_cidr_v4_key {
    __u32 prefixlen;
    __be32 addr;
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct geo_cidr_v4_key);
    __type(value, __u8);
    __uint(max_entries, GEO_CIDR_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_geo_cidr4 SEC(".maps");

/* Geo CIDR ranges for IPv6 */
struct geo_cidr_v6_key {
    __u32 prefixlen;
    __u8  addr[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct geo_cidr_v6_key);
    __type(value, __u8);
    __uint(max_entries, GEO_CIDR_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_geo_cidr6 SEC(".maps");

/* Geo CIDR values (wafio_geo_cidr4/6). */
#define GEO_CIDR_BLOCKED 1
#define GEO_CIDR_ALLOWED 2

/* Geo mode (key 0): GEO_MODE_BLOCK drops the blocked countries' ranges,
 * GEO_MODE_ALLOW drops every public source outside the allowed countries'
 * ranges. The map also marks an object that can enforce allow mode: the
 * agent refuses allow mode on an object without it, which would read the
 * allowed ranges as blocked ones. */
#define GEO_MODE_BLOCK 0
#define GEO_MODE_ALLOW 1
struct geo_config {
    __u32 mode;
    __u32 _pad;
    /* allow_since_ns: bpf_ktime_get_ns() when allow mode went live in this
     * dataplane. Only inbound connections tracked before it keep running
     * (geo_tracked_inbound). */
    __u64 allow_since_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct geo_config);
} wafio_geo_config SEC(".maps");

/* The subnets of the interface this program is attached to (agent-filled,
 * key as wafio_geo_cidr4/6; other interfaces' subnets — docker0, bridges,
 * VPN tunnels, a second NIC — are never on-link for packets seen here).
 * Allow mode exempts private and special sources only for TCP (no
 * handshake for a spoofed source) and ICMP; any other protocol's private
 * source must lie in one of these subnets (geo_exempt_source_v4/v6). */
#define GEO_LOCAL_MAX_ENTRIES 1024
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct geo_cidr_v4_key);
    __type(value, __u8);
    __uint(max_entries, GEO_LOCAL_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_geo_local4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct geo_cidr_v6_key);
    __type(value, __u8);
    __uint(max_entries, GEO_LOCAL_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_geo_local6 SEC(".maps");

/* rule_id of a geo drop event: the mode that dropped the packet. */
#define GEO_EVENT_BLOCK_MODE 1
#define GEO_EVENT_ALLOW_MODE 2

/* Per-CPU metrics (key=0) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct metrics_val);
} wafio_metrics SEC(".maps");

/* Perf event output ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} wafio_events SEC(".maps");

/* Exact bounded distinct-port tracking. The configured threshold is at most
 * MAX_SCAN_PORTS (ebpf.MaxPortScanUniquePorts, validated by the control plane,
 * the agent and the local API): a higher one is never reached, so
 * check_port_scan refuses to decide and only logs. */
#define MAX_SCAN_PORTS 32 /* bounded loop × spinlock = verifier state explosion
                           * on kernel 5.15; 32 covers real scan thresholds
                           * (default configs use 10-30 unique ports) */
struct port_scan_state {
    __u64 window_start_ns;
    __u32 unique_ports;     /* count of unique ports in window */
    __u32 drop_count;
    struct bpf_spin_lock lock;
    __u16 ports[MAX_SCAN_PORTS];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RATELIMIT_SIZE);
    __type(key, struct ip_key);
    __type(value, struct port_scan_state);
} wafio_portscan SEC(".maps");

/* Untyped scratch avoids placing a 280-byte initializer on the BPF stack.
 * The scratch map has no spin-lock field; only the destination HASH does. */
struct scan_scratch { __u8 bytes[sizeof(struct port_scan_state)]; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scan_scratch);
} wafio_scan_scratch SEC(".maps");

/* Port scan config (key=0) */
struct portscan_config {
    __u64 window_ns;         /* detection window (e.g. 10s) */
    __u32 max_unique_ports;  /* max unique dest ports per source before flagging */
    __u32 action;            /* ACTION_DROP or ACTION_LOG */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct portscan_config);
} wafio_portscan_config SEC(".maps");

/* ── Port Policy maps (enterprise ingress/egress port firewall) ──────────── */

/* Port policy rules: port_policy_key → port_policy_val */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORT_POLICIES);
    __type(key, struct port_policy_key);
    __type(value, struct port_policy_val);
} wafio_port_policy SEC(".maps");

/* Port policy global config (key=0) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct port_policy_config);
} wafio_port_policy_config SEC(".maps");

/* Egress IP blocklist: blocks outbound connections to specific IPs. Entries
 * are allocated on insert (BPF_F_NO_PREALLOC), so the map costs memory only
 * for its content. The programs read and delete; the agent writes. Shared with
 * TC: both declarations carry the same flags. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH); /* never evicts an operator entry */
    __uint(max_entries, MAX_EGRESS_BLOCKLIST);
    __type(key, struct ip_key);
    __type(value, struct ip_list_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_egress_blocklist SEC(".maps");

/* Control-plane endpoints — shared with TC; see wafio_common.h. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CP_ENDPOINTS);
    __type(key, struct cp_endpoint_key);
    __type(value, __u32);
} wafio_cp_endpoints SEC(".maps");

/* DHCPv4 client state — shared by XDP and TC; see
 * wafio_common.h. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);                    /* xid, wire order */
    __type(value, struct dhcp_pending_val);
} wafio_dhcp_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16);
    __type(key, __be32);                   /* server address */
    __type(value, __u64);                  /* learned at, ktime ns */
} wafio_dhcp_servers SEC(".maps");

/* Tail-call dispatch: entry program jumps to per-family sub-programs.
 * Each gets its own independent verifier budget and a fresh stack. */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} wafio_xdp_progs SEC(".maps");

/* ═══════════════════════════════════════════════════════════════════════════
 *  HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

static __always_inline void
emit_event(void *ctx, struct perf_event_data *evt) {
    bpf_perf_event_output(ctx, &wafio_events, BPF_F_CURRENT_CPU,
                          evt, sizeof(*evt));
}

/* The packet programs build their event in a per-CPU scratch value, not on
 * the stack: wafio_xdp_v4 / wafio_xdp_v6 plus their deepest helper sat at the
 * 480-byte budget of TestXDPStackHeadroom, and the event alone is 64 bytes
 * (same pattern as wafio_tc_evt_buf). Each program clears and refills it
 * first; XDP does not nest on a CPU. A failed lookup (never for a per-CPU
 * array) only loses telemetry, never a verdict. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct perf_event_data);
} wafio_xdp_evt_buf SEC(".maps");

/* Conntrack key and new entry of the out-of-line conntrack helpers, in a
 * per-CPU scratch value rather than on a BPF stack (TestXDPStackHeadroom).
 * Used one helper at a time within a packet; XDP does not nest on a CPU. */
struct xdp_ct_scratch {
    struct conn_key ck;
    struct conn_val cv;
    struct bpf_sock_tuple t; /* socket lookup tuple (conntrack_socket_proof) */
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_ct_scratch);
} wafio_xdp_ct_buf SEC(".maps");

static __always_inline struct perf_event_data *
xdp_event_buf(__u64 now_ns, __u32 pkt_len) {
    __u32 zero = 0;
    struct perf_event_data *evt = bpf_map_lookup_elem(&wafio_xdp_evt_buf, &zero);
    if (evt) {
        __builtin_memset(evt, 0, sizeof(*evt));
        evt->timestamp_ns = now_ns;
        evt->pkt_len = pkt_len;
    }
    return evt;
}

/* xdp_event_rule / xdp_event: emit the packet's event (filled by
 * xdp_event_buf when the family program started) with this action, reason
 * and rule. The buffer is looked up here and the counters (get_metrics)
 * where they are counted: a pointer that may be NULL, kept live through
 * every check of the packet program, doubled the states the verifier
 * explores at each later branch (Ubuntu 22.04 kernel 5.15: wafio_xdp_v4
 * 573k → 425k processed instructions). */
static __always_inline void
xdp_event_rule(void *ctx, __u8 action, __u8 reason, __u32 rule_id) {
    __u32 zero = 0;
    struct perf_event_data *evt = bpf_map_lookup_elem(&wafio_xdp_evt_buf, &zero);
    if (!evt)
        return;
    evt->action = action;
    evt->reason = reason;
    evt->rule_id = rule_id;
    emit_event(ctx, evt);
}

static __always_inline void
xdp_event(void *ctx, __u8 action, __u8 reason) {
    xdp_event_rule(ctx, action, reason, 0);
}

static __always_inline void
update_metrics_rx(struct metrics_val *m, __u32 pkt_len) {
    __sync_fetch_and_add(&m->rx_packets, 1);
    __sync_fetch_and_add(&m->rx_bytes, pkt_len);
}

static __always_inline struct global_config *
get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&wafio_config, &key);
}

static __always_inline struct rate_config *
get_rate_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&wafio_rate_config, &key);
}

static __always_inline struct metrics_val *
get_metrics(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&wafio_metrics, &key);
}

/* state_full: a per-source state map refused a new source. Counted in
 * state_table_full and in the map's own slot of wafio_state_full. */
static __always_inline void
state_full(__u32 slot) {
    struct metrics_val *metrics = get_metrics();
    if (metrics) __sync_fetch_and_add(&metrics->state_table_full, 1);
    __u64 *cnt = bpf_map_lookup_elem(&wafio_state_full, &slot);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK: IP BLOCKLIST / ALLOWLIST
 * ═══════════════════════════════════════════════════════════════════════════ */

/* LISTS_SKIP_WILDCARD: the packet is a reply to a fresh outbound flow of
 * this host; a family-wide block does not apply to it.
 * LISTS_L4(proto, dport): the packet's protocol (bits 8-15) and destination
 * port in host order (bits 16-31), which port-scoped allowlist entries match;
 * dport 0 = no readable port. Packed into the one flags argument the
 * global list functions have room for (five scalar arguments at most). */
#define LISTS_SKIP_WILDCARD 1
#define LISTS_L4(proto, dport) ((((__u32)(proto)) & 0xff) << 8 | ((__u32)(dport)) << 16)

/* allow_scope_hit: a port-scoped allowlist entry covers the packet — TCP or
 * UDP with a readable destination port inside one of its first nscopes
 * scopes (proto 0 = TCP and UDP). ICMP, other protocols and frames whose
 * port could not be read never match a scope. */
static __always_inline int
allow_scope_hit(const struct allow_val *v, __u32 flags) {
    __u32 proto = (flags >> 8) & 0xff;
    __u32 dport = flags >> 16;
    if (dport == 0 || (proto != IPPROTO_TCP && proto != IPPROTO_UDP))
        return 0;
    __u32 n = v->nscopes;
    for (__u32 i = 0; i < ALLOW_MAX_SCOPES; i++) {
        if (i >= n)
            return 0;
        const struct allow_scope *s = &v->scopes[i];
        if ((s->proto == 0 || s->proto == proto) && s->lo != 0 &&
            dport >= s->lo && dport <= s->hi)
            return 1;
    }
    return 0;
}

/* allow_decides: a live allowlist entry decides for the packet when it
 * allows every port and protocol (ALLOW_F_ALL) or one of its scopes covers
 * the packet. */
static __always_inline int
allow_decides(const struct allow_val *v, __u64 now_ns, __u32 flags) {
    if (v->expires_ns != 0 && v->expires_ns <= now_ns)
        return 0;
    return (v->flags & ALLOW_F_ALL) || allow_scope_hit(v, flags);
}

/* allow_walk_v4 / allow_walk_v6: the first allowlist entry that decides for
 * the packet (allow_decides), longest prefix first (wafio_common.h); an
 * entry that does not decide — lapsed, or scoped to other ports — sends the
 * walk one bit shorter than its prefix, at most LIST_WALK_MAX levels.
 * Returns the deciding prefix length, or -1. */
static __always_inline int
allow_walk_v4(__be32 addr, __u64 now_ns, __u32 flags) {
    struct subnet_v4_key k = { .prefixlen = 32, .addr = addr };
    for (int i = 0; i < LIST_WALK_MAX; i++) {
        struct allow_val *v = bpf_map_lookup_elem(&wafio_allow4, &k);
        if (!v)
            return -1;
        __u32 plen = v->prefixlen;
        if (plen > 32 || plen >= k.prefixlen + 1)
            return -1; /* inconsistent value: never loop on it */
        if (allow_decides(v, now_ns, flags)) {
            __sync_fetch_and_add(&v->hit_count, 1);
            return plen;
        }
        if (plen == 0)
            return -1;
        k.prefixlen = plen - 1;
    }
    return -1;
}

static __always_inline int
allow_walk_v6(const struct subnet_v6_key *addr, __u64 now_ns, __u32 flags) {
    struct subnet_v6_key k = *addr;
    k.prefixlen = 128;
    for (int i = 0; i < LIST_WALK_MAX; i++) {
        struct allow_val *v = bpf_map_lookup_elem(&wafio_allow6, &k);
        if (!v)
            return -1;
        __u32 plen = v->prefixlen;
        if (plen > 128 || plen >= k.prefixlen + 1)
            return -1;
        if (allow_decides(v, now_ns, flags)) {
            __sync_fetch_and_add(&v->hit_count, 1);
            return plen;
        }
        if (plen == 0)
            return -1;
        k.prefixlen = plen - 1;
    }
    return -1;
}

/* block_walk_v4 / block_walk_v6: the first live blocklist entry for addr,
 * longest prefix first, as the allow walk. skip_root: a /0 entry does not
 * decide. Returns the deciding prefix length, or -1. */
static __always_inline int
block_walk_v4(__be32 addr, __u64 now_ns, int skip_root) {
    struct subnet_v4_key k = { .prefixlen = 32, .addr = addr };
    for (int i = 0; i < LIST_WALK_MAX; i++) {
        struct block_val *v = bpf_map_lookup_elem(&wafio_block4, &k);
        if (!v)
            return -1;
        __u32 plen = v->prefixlen;
        if (plen > 32 || plen >= k.prefixlen + 1)
            return -1;
        if (plen == 0 && skip_root)
            return -1;
        if (v->expires_ns == 0 || v->expires_ns > now_ns) {
            __sync_fetch_and_add(&v->hit_count, 1);
            return plen;
        }
        if (plen == 0)
            return -1;
        k.prefixlen = plen - 1;
    }
    return -1;
}

static __always_inline int
block_walk_v6(const struct subnet_v6_key *addr, __u64 now_ns, int skip_root) {
    struct subnet_v6_key k = *addr;
    k.prefixlen = 128;
    for (int i = 0; i < LIST_WALK_MAX; i++) {
        struct block_val *v = bpf_map_lookup_elem(&wafio_block6, &k);
        if (!v)
            return -1;
        __u32 plen = v->prefixlen;
        if (plen > 128 || plen >= k.prefixlen + 1)
            return -1;
        if (plen == 0 && skip_root)
            return -1;
        if (v->expires_ns == 0 || v->expires_ns > now_ns) {
            __sync_fetch_and_add(&v->hit_count, 1);
            return plen;
        }
        if (plen == 0)
            return -1;
        k.prefixlen = plen - 1;
    }
    return -1;
}

/* jail_hit: a live wafio_jail entry for ip; a lapsed one is removed. */
static __always_inline int
jail_hit(struct ip_key *ip, __u64 now_ns) {
    struct ip_list_val *jailed = bpf_map_lookup_elem(&wafio_jail, ip);
    if (!jailed)
        return 0;
    if (jailed->expires_ns == 0 || jailed->expires_ns > now_ns) {
        __sync_fetch_and_add(&jailed->hit_count, 1);
        return 1;
    }
    bpf_map_delete_elem(&wafio_jail, ip);
    return 0;
}

/* list_decision: ACTION_ALLOW, ACTION_DROP, or -1 when no list decides.
 * Order, as the hash + sentinel lookup before it:
 *   1. an allowlist prefix other than /0 that decides for the packet (every
 *      port, or a scope covering it)  → ALLOW
 *   2. a blocklist prefix other than /0       → DROP
 *   3. a live jail entry                 → DROP
 *   4. the family-wide allow (0.0.0.0/0, ::/0) → ALLOW
 *   5. the family-wide block, unless skip_wildcard → DROP
 * so a specific block still beats a family-wide allow. allow / block: the
 * deciding prefix lengths of the two walks (the block walk ran with its /0
 * skipped when allow == 0 or skip_wildcard). */
static __always_inline int
list_decision(int allow, int block, int jailed) {
    if (allow > 0)
        return ACTION_ALLOW;
    if (block > 0 || jailed)
        return ACTION_DROP;
    if (allow == 0)
        return ACTION_ALLOW;
    if (block == 0)
        return ACTION_DROP;
    return -1; /* no match */
}

/* ip_lists_v4 / ip_lists_v6: the IP list decision as global functions (BTF
 * linkage global, scalar arguments only as Linux 5.10 requires). The verifier
 * checks each once, on its own, instead of once per path of the packet
 * program that reaches it (TestBPFFirewallVerifierBudget: the inline lists
 * and jail had taken wafio_xdp_v6 from 317k to 581k processed instructions).
 * The clock is read here. */
__noinline int
ip_lists_v4(__u32 addr, __u32 flags) {
    __u64 now_ns = bpf_ktime_get_ns();
    int allow = allow_walk_v4(addr, now_ns, flags);
    if (allow > 0)
        return ACTION_ALLOW;
    int block = block_walk_v4(addr, now_ns, (flags & LISTS_SKIP_WILDCARD) || allow == 0);
    int jailed = 0;
    if (block <= 0) {
        struct ip_key ip = {};
        ip.family = AF_INET;
        ip.addr.v4 = addr;
        jailed = jail_hit(&ip, now_ns);
    }
    return list_decision(allow, block, jailed);
}

__noinline int
ip_lists_v6(__u32 w0, __u32 w1, __u32 w2, __u32 w3, __u32 flags) {
    __u64 now_ns = bpf_ktime_get_ns();
    struct subnet_v6_key a = { .prefixlen = 128 };
    __builtin_memcpy(&a.addr[0], &w0, 4);
    __builtin_memcpy(&a.addr[4], &w1, 4);
    __builtin_memcpy(&a.addr[8], &w2, 4);
    __builtin_memcpy(&a.addr[12], &w3, 4);
    int allow = allow_walk_v6(&a, now_ns, flags);
    if (allow > 0)
        return ACTION_ALLOW;
    int block = block_walk_v6(&a, now_ns, (flags & LISTS_SKIP_WILDCARD) || allow == 0);
    int jailed = 0;
    if (block <= 0) {
        struct ip_key ip = {};
        ip.family = AF_INET6;
        __builtin_memcpy(&ip.addr.v6, a.addr, 16);
        jailed = jail_hit(&ip, now_ns);
    }
    return list_decision(allow, block, jailed);
}

/* check_ip_lists: the list decision for a source address (ip_lists_v4/v6).
 * proto / dport (wire order, 0 when unreadable) feed the allowlist scopes. */
static __always_inline int
check_ip_lists(struct ip_key *src_ip, __u64 now_ns, int skip_wildcard,
               __u8 proto, __be16 dport) {
    (void)now_ns;
    __u32 flags = (skip_wildcard ? LISTS_SKIP_WILDCARD : 0) |
                  LISTS_L4(proto, bpf_ntohs(dport));
    if (src_ip->family == AF_INET)
        return ip_lists_v4(src_ip->addr.v4, flags);
    __u32 w[4];
    __builtin_memcpy(w, &src_ip->addr.v6, 16);
    return ip_lists_v6(w[0], w[1], w[2], w[3], flags);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK: RATE LIMITING (packets/sec, bytes/sec with burst)
 * ═══════════════════════════════════════════════════════════════════════════ */

static __noinline int
check_rate_limit(struct ip_key *src_ip, __u32 pkt_len, __u64 now_ns) {
    struct rate_config *rcfg = get_rate_config();
    if (!rcfg || (rcfg->max_pps == 0 && rcfg->max_bps == 0))
        return ACTION_ALLOW;

    __u64 window_ns = rcfg->window_ns ? rcfg->window_ns : 1000000000ULL;
    if (window_ns < 10000000ULL || window_ns > 60000000000ULL)
        return ACTION_LOG;
    __u64 max_packets = (__u64)rcfg->max_pps * (window_ns / 1000000ULL) / 1000ULL + rcfg->burst_pps;
    __u64 max_bytes = (__u64)rcfg->max_bps * (window_ns / 1000000ULL) / 1000ULL;
    int limit_packets = rcfg->max_pps != 0;
    int limit_bytes = rcfg->max_bps != 0;
    __u32 configured_action = rcfg->action;
    struct rate_state *state = bpf_map_lookup_elem(&wafio_rate_state, src_ip);
    if (!state) {
        struct rate_state initial = {};
        initial.window_start_ns = now_ns;
        bpf_map_update_elem(&wafio_rate_state, src_ip, &initial, BPF_NOEXIST);
        state = bpf_map_lookup_elem(&wafio_rate_state, src_ip);
        if (!state) {
            /* Full: this source is not tracked, so the packet passes. A
             * logged "detection" here would flood the event ring during the
             * very attack that filled the table. */
            state_full(STATE_FULL_RATE);
            return ACTION_ALLOW;
        }
    }
    int result = ACTION_ALLOW;
    bpf_spin_lock(&state->lock);
    if (now_ns - state->window_start_ns >= window_ns) {
        state->window_start_ns = now_ns;
        state->pkt_count = 0;
        state->byte_count = 0;
    }
    state->pkt_count++;
    state->byte_count += pkt_len;
    if ((limit_packets && state->pkt_count > max_packets) ||
        (limit_bytes && state->byte_count > max_bytes))
        result = configured_action;
    state->action = result;
    bpf_spin_unlock(&state->lock);
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK: SYN FLOOD PROTECTION
 * ═══════════════════════════════════════════════════════════════════════════ */

/* syn_pressure_over bumps the per-CPU global SYN window and reports whether
 * the configured global threshold is exceeded (pressure mode active).
 * Per-CPU state needs no lock: each CPU mutates only its own copy. */
static __always_inline int
syn_pressure_over(struct rate_config *rcfg, __u64 now_ns) {
    if (!rcfg || rcfg->syn_pressure_pps == 0)
        return 0;
    __u32 zero = 0;
    struct syn_pressure_state *ps = bpf_map_lookup_elem(&wafio_syn_pressure, &zero);
    if (!ps)
        return 0;
    if (now_ns - ps->window_start_ns >= 1000000000ULL) {
        ps->window_start_ns = now_ns;
        ps->count = 0;
    }
    ps->count++;
    return ps->count > (__u64)rcfg->syn_pressure_pps;
}

/* syn_pressure_active: read-only variant (no bump) for conntrack gating. */
static __always_inline int
syn_pressure_active(struct rate_config *rcfg, __u64 now_ns) {
    if (!rcfg || rcfg->syn_pressure_pps == 0)
        return 0;
    __u32 zero = 0;
    struct syn_pressure_state *ps = bpf_map_lookup_elem(&wafio_syn_pressure, &zero);
    if (!ps)
        return 0;
    if (now_ns - ps->window_start_ns >= 1000000000ULL)
        return 0;
    return ps->count > (__u64)rcfg->syn_pressure_pps;
}

/* conntrack_established: does this exact flow have an established entry? */
static __always_inline int
conntrack_established(struct conn_key *ck) {
    struct conn_val *cv = bpf_map_lookup_elem(&wafio_conntrack, ck);
    return cv && cv->tcp_state == 1;
}

/* tcp_flow_accepted: the packet belongs to an inbound TCP connection
 * this host accepted — the conntrack entry for exactly this tuple is
 * established (tcp_state 1), TC verified it (CONN_VERIFIED: the host
 * answered the SYN with a SYN-ACK, or the kernel holds the connection and a
 * listener owns the port) and the host has since sent a segment
 * without SYN or RST on it (CONN_HOST_ACKED). A spoofer cannot complete the
 * handshake blind: the host resets the bad ACK and TC closes the entry. Out of line: the 48-byte key lives in
 * its own frame, not in the packet program's (TestXDPStackHeadroom). */
static __noinline int
tcp_flow_accepted(struct ip_key *src, struct ip_key *dst, __be16 sport, __be16 dport) {
    struct conn_key ck = {};
    __builtin_memcpy(&ck.src, src, sizeof(*src));
    __builtin_memcpy(&ck.dst, dst, sizeof(*dst));
    ck.sport = sport;
    ck.dport = dport;
    ck.proto = IPPROTO_TCP;
    struct conn_val *cv = bpf_map_lookup_elem(&wafio_conntrack, &ck);
    return cv && cv->tcp_state == 1 &&
           (cv->flags_seen & (CONN_VERIFIED | CONN_HOST_ACKED)) == (CONN_VERIFIED | CONN_HOST_ACKED);
}

/* rate_limited_flow: the per-IP packet/byte limit applies to new
 * inbound flows only, as a --ctstate NEW limit does. Exempt: replies to a
 * flow this host opened (is_reply: a large download from one CDN address no
 * longer loses packets under drop_on_limit) and packets of an inbound TCP
 * connection the host accepted. Counted: SYNs and every other TCP packet
 * without such an entry, UDP that is not a reply (one-way floods included),
 * ICMP and other protocols. SYN-flood protection runs before this and is
 * unchanged. */
static __always_inline int
rate_limited_flow(struct ip_key *src, struct ip_key *dst, __be16 sport, __be16 dport,
                  __u8 proto, int is_reply) {
    if (is_reply)
        return 0;
    if (proto == IPPROTO_TCP && sport != 0 && dport != 0 &&
        tcp_flow_accepted(src, dst, sport, dport))
        return 0;
    return 1;
}

static __noinline int
check_syn_flood(struct ip_key *src_ip, struct ip_key *dst_ip, __u32 ports,
                __u8 tcp_flags, __u64 now_ns) {
    struct rate_config *rcfg = get_rate_config();
    if (!rcfg || rcfg->max_syn_pps == 0)
        return ACTION_ALLOW;

    __u8 syn_only = (tcp_flags & 0x12) == 0x02;
    if (!syn_only)
        return ACTION_ALLOW;

    __u32 configured_action = rcfg->action;

    /* Global pressure mode: under a distributed spoofed SYN
     * flood the per-IP LRU table would be exhausted within seconds, evicting
     * legitimate flows. While global SYN pressure exceeds the threshold:
     *   1. allocate NO new per-IP state (spoofed sources cannot evict),
     *   2. drop SYNs from sources without an established conntrack entry.
     * Established flows keep flowing; brand-new legitimate connections are
     * shed for the duration of the flood (full stateless SYN cookies are
     * tracked separately — kernel 5.17+ helpers). */
    if (syn_pressure_over(rcfg, now_ns)) {
        /* The flow key is built here, in this helper's frame, not the
         * packet program's (TestXDPStackHeadroom). ports: sport << 16 |
         * dport, both as on the wire. */
        struct conn_key ck = {};
        __builtin_memcpy(&ck.src, src_ip, sizeof(*src_ip));
        __builtin_memcpy(&ck.dst, dst_ip, sizeof(*dst_ip));
        ck.sport = (__be16)(ports >> 16);
        ck.dport = (__be16)ports;
        ck.proto = IPPROTO_TCP;
        if (!conntrack_established(&ck)) {
            struct metrics_val *m = get_metrics();
            if (m) __sync_fetch_and_add(&m->syn_pressure_drops, 1);
            return configured_action;
        }
        return ACTION_ALLOW;
    }

    __u64 window_ns = rcfg->window_ns ? rcfg->window_ns : 1000000000ULL;
    if (window_ns < 10000000ULL || window_ns > 60000000000ULL)
        return ACTION_LOG;
    __u64 max_syn = (__u64)rcfg->max_syn_pps * (window_ns / 1000000ULL) / 1000ULL + rcfg->burst_syn;
    struct syn_state *state = bpf_map_lookup_elem(&wafio_syn_state, src_ip);
    if (!state) {
        struct syn_state initial = {};
        initial.window_start_ns = now_ns;
        bpf_map_update_elem(&wafio_syn_state, src_ip, &initial, BPF_NOEXIST);
        state = bpf_map_lookup_elem(&wafio_syn_state, src_ip);
        if (!state) {
            state_full(STATE_FULL_SYN); /* as in check_rate_limit */
            return ACTION_ALLOW;
        }
    }
    int result = ACTION_ALLOW;
    bpf_spin_lock(&state->lock);
    if (now_ns - state->window_start_ns >= window_ns) {
        state->window_start_ns = now_ns;
        state->syn_count = 0;
        state->drop_count = 0;
    }
    state->syn_count++;
    if (state->syn_count > max_syn) {
        state->drop_count++;
        result = configured_action;
    }
    bpf_spin_unlock(&state->lock);
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK: GEO-IP BLOCKING
 * ═══════════════════════════════════════════════════════════════════════════ */

/* check_geoblock_v4: LPM trie first (covers all pre-loaded CIDRs from MaxMind),
 * then fallback to the reactive hash map for IPs enriched by userspace.
 * This ensures the very first packet from a geo-blocked country is dropped. */
static __always_inline int
check_geoblock_v4(struct ip_key *src_ip, __be32 raw_saddr) {
    /* LPM lookup — covers all pre-loaded CIDRs for blocked countries. An
     * allowed range (left over while the agent switches modes) is not a
     * blocked one. */
    struct geo_cidr_v4_key lk = { .prefixlen = 32, .addr = raw_saddr };
    __u8 *cidr_blocked = bpf_map_lookup_elem(&wafio_geo_cidr4, &lk);
    if (cidr_blocked && *cidr_blocked == GEO_CIDR_BLOCKED)
        return ACTION_DROP;

    /* Reactive hash map fallback — for IPs enriched via conntrack */
    struct geo_val *geo = bpf_map_lookup_elem(&wafio_geoip, src_ip);
    if (!geo) return ACTION_ALLOW;
    struct geo_country_val *blocked = bpf_map_lookup_elem(&wafio_geo_blocked, &geo->country_code);
    if (blocked && blocked->blocked)
        return ACTION_DROP;

    return ACTION_ALLOW;
}

/* check_geoblock_v6: same strategy for IPv6. */
static __always_inline int
check_geoblock_v6(struct ip_key *src_ip, const __u8 raw_saddr[16]) {
    struct geo_cidr_v6_key lk = { .prefixlen = 128 };
    __builtin_memcpy(lk.addr, raw_saddr, 16);
    __u8 *cidr_blocked = bpf_map_lookup_elem(&wafio_geo_cidr6, &lk);
    if (cidr_blocked && *cidr_blocked == GEO_CIDR_BLOCKED)
        return ACTION_DROP;

    struct geo_val *geo = bpf_map_lookup_elem(&wafio_geoip, src_ip);
    if (!geo) return ACTION_ALLOW;
    struct geo_country_val *blocked = bpf_map_lookup_elem(&wafio_geo_blocked, &geo->country_code);
    if (blocked && blocked->blocked)
        return ACTION_DROP;

    return ACTION_ALLOW;
}

/* Legacy: kept for backwards compatibility with any callers that don't have raw addr */
static __always_inline int
check_geoblock(struct ip_key *src_ip) {
    struct geo_val *geo = bpf_map_lookup_elem(&wafio_geoip, src_ip);
    if (!geo) return ACTION_ALLOW;
    struct geo_country_val *blocked = bpf_map_lookup_elem(&wafio_geo_blocked, &geo->country_code);
    if (blocked && blocked->blocked)
        return ACTION_DROP;
    return ACTION_ALLOW;
}

/* ── Geo allow mode ("only these countries") ─────────────────────────────
 * Allow mode drops an inbound packet whose source lies outside every
 * allowed country's ranges — addresses missing from the GeoIP data
 * included. The caller exempts, before any lookup: the IP allowlist (it
 * runs first), replies to flows this host opened (is_reply), the
 * control plane (passes before the lists), request-bound DHCP replies,
 * IPv6 neighbour discovery (passes first) and the sources and ICMP types
 * below. Inbound TCP connections established before allow mode went live
 * keep running (geo_tracked_inbound). */

/* geo_config_get: the geo mode record, NULL on an object load that failed
 * to provide it. A fresh map (all zero) is block mode, the behaviour of
 * every earlier object. */
static __always_inline struct geo_config *
geo_config_get(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&wafio_geo_config, &key);
}

/* geo_exempt_v4: IPv4 sources that are not in the GeoIP data — "this
 * network" (0.0.0.0/8, DHCP clients), private (RFC 1918), CGNAT
 * (100.64.0.0/10), loopback, link-local and multicast. Dropping them would
 * cut the LAN, container and VPN networks; geo_exempt_source_v4 decides
 * per protocol whether the exemption applies. */
static __always_inline int
geo_exempt_v4(__be32 saddr) {
    __u32 a = bpf_ntohl(saddr);
    __u32 o1 = a >> 24;
    return o1 == 0 || o1 == 10 || o1 == 127 ||
           (a & 0xffc00000) == 0x64400000 ||    /* 100.64.0.0/10  */
           (a & 0xffff0000) == 0xa9fe0000 ||    /* 169.254.0.0/16 */
           (a & 0xfff00000) == 0xac100000 ||    /* 172.16.0.0/12  */
           (a & 0xffff0000) == 0xc0a80000 ||    /* 192.168.0.0/16 */
           (o1 & 0xf0) == 0xe0;                 /* 224.0.0.0/4    */
}

/* geo_exempt_v6: the IPv6 counterpart — unspecified (::, duplicate address
 * detection), loopback, link-local (fe80::/10), unique local (fc00::/7)
 * and multicast (ff00::/8). */
static __always_inline int
geo_exempt_v6(const struct in6_addr *a) {
    __u8 b0 = a->in6_u.u6_addr8[0];
    __u8 b1 = a->in6_u.u6_addr8[1];
    if (b0 == 0xff || (b0 & 0xfe) == 0xfc || (b0 == 0xfe && (b1 & 0xc0) == 0x80))
        return 1;
    return a->in6_u.u6_addr32[0] == 0 && a->in6_u.u6_addr32[1] == 0 &&
           a->in6_u.u6_addr32[2] == 0 && bpf_ntohl(a->in6_u.u6_addr32[3]) <= 1;
}

/* geo_exempt_source_v4 / _v6: allow mode passes a private or special
 * source unconditionally only for TCP (a spoofed source never completes
 * the handshake) and ICMP. For UDP and every other protocol a single
 * spoofed packet reaches a service (DNS, NTP, SNMP, syslog) and can reflect
 * at internal hosts, so the source must lie in one of the host's connected
 * subnets (wafio_geo_local4/6, agent-filled). A DHCP client's 0.0.0.0
 * passes to the server port 67/udp. */
static __always_inline int
geo_exempt_source_v4(__be32 saddr, __u8 proto, __be16 dport) {
    if (!geo_exempt_v4(saddr))
        return 0;
    if (proto == IPPROTO_TCP || proto == IPPROTO_ICMP)
        return 1;
    if (saddr == 0)
        return proto == IPPROTO_UDP && dport == bpf_htons(67);
    struct geo_cidr_v4_key k = { .prefixlen = 32, .addr = saddr };
    return bpf_map_lookup_elem(&wafio_geo_local4, &k) != NULL;
}

/* key: the source as a /128 LPM key, shared with the caller's country
 * lookup — a second 20-byte key on the IPv6 program's stack pushed its
 * frame past the 32-byte-rounded budget older kernels apply. */
static __always_inline int
geo_exempt_source_v6(const struct in6_addr *saddr, __u8 proto,
                     struct geo_cidr_v6_key *key) {
    if (!geo_exempt_v6(saddr))
        return 0;
    if (proto == IPPROTO_TCP || proto == WAFIO_IPPROTO_ICMPV6)
        return 1;
    return bpf_map_lookup_elem(&wafio_geo_local6, key) != NULL;
}

/* geo_icmp4_exempt / geo_icmp6_exempt: ICMP messages allow mode passes —
 * echo replies and errors (destination unreachable incl. fragmentation
 * needed, time exceeded, parameter problem; ICMPv6 also packet too big),
 * so path-MTU discovery and diagnostics of connections this host opens to
 * peers abroad keep working. Echo requests to the host are filtered. */
static __always_inline int
geo_icmp4_exempt(__u8 type) {
    return type == 0 || type == 3 || type == 11 || type == 12;
}

static __always_inline int
geo_icmp6_exempt(__u8 type) {
    return (type >= 1 && type <= 4) || type == 129;
}

/* geo_tracked_inbound: the packet continues an inbound TCP connection that
 * was established, and verified by TC (the host answered it), before allow
 * mode went live — the session an operator had open at the switch (a
 * policy change never cuts an open connection). Never a SYN: an entry left
 * by an earlier connection on the same ports must not admit a new one.
 * Only entries first seen before allow_since_ns count, so no connection
 * made through an exempt path afterwards (an allowlist entry later removed,
 * a country later dropped) keeps the pinhole. An established entry stays
 * fresh as long as TC's reply exemption does (CONN_TCP_EST_TTL_NS); a
 * closing one (FIN seen) only for CONN_TCP_TTL_NS, enough to finish the
 * close. */
static __always_inline int
geo_tracked_inbound(struct ip_key *src, struct ip_key *dst, __be16 sport,
                    __be16 dport, __u8 tcp_flags, __u64 allow_since_ns,
                    __u64 now_ns) {
    if (tcp_flags & 0x02)
        return 0;
    /* The key lives in the per-CPU conntrack scratch value, not on the
     * packet program's stack (TestXDPStackHeadroom: wafio_xdp_v6 sat at the
     * 480-byte budget with it once the list walks, the flow lookup and the
     * truncated-frame handling were added). No other user of the
     * scratch value is active here. */
    __u32 zero = 0;
    struct xdp_ct_scratch *b = bpf_map_lookup_elem(&wafio_xdp_ct_buf, &zero);
    if (!b)
        return 0;
    struct conn_key *ck = &b->ck;
    __builtin_memset(ck, 0, sizeof(*ck));
    __builtin_memcpy(&ck->src, src, sizeof(*src));
    __builtin_memcpy(&ck->dst, dst, sizeof(*dst));
    ck->sport = sport;
    ck->dport = dport;
    ck->proto = IPPROTO_TCP;
    struct conn_val *cv = bpf_map_lookup_elem(&wafio_conntrack, ck);
    if (!cv)
        return 0;
    if ((cv->flags_seen & (CONN_OUTBOUND | CONN_REPLY | CONN_VERIFIED)) != CONN_VERIFIED)
        return 0;
    if (cv->first_seen_ns >= allow_since_ns)
        return 0;
    if (cv->tcp_state == 1)
        return ct_fresh(now_ns, cv->last_seen_ns, CONN_TCP_EST_TTL_NS);
    if (cv->tcp_state == 2)
        return ct_fresh(now_ns, cv->last_seen_ns, CONN_TCP_TTL_NS);
    return 0;
}

/* geo_allow_verdict: ACTION_ALLOW when the LPM value of the source's range
 * (cidr, NULL when no range matched) is an allowed country's, or the packet
 * continues an inbound TCP connection from before allow mode
 * (geo_tracked_inbound); else ACTION_DROP. */
static __always_inline int
geo_allow_verdict(__u8 *cidr, struct ip_key *src, struct ip_key *dst,
                  __be16 sport, __be16 dport, __u8 proto, __u8 tcp_flags,
                  __u64 allow_since_ns, __u64 now_ns) {
    if (cidr && *cidr == GEO_CIDR_ALLOWED)
        return ACTION_ALLOW;
    if (proto == IPPROTO_TCP && sport != 0 && dport != 0 &&
        geo_tracked_inbound(src, dst, sport, dport, tcp_flags, allow_since_ns, now_ns))
        return ACTION_ALLOW;
    return ACTION_DROP;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK: CONNECTION TRACKING
 * ═══════════════════════════════════════════════════════════════════════════ */

/* mark: CONN_REPLY when the packet was a reply to a host-opened flow, so TC
 * never mistakes this inbound-direction entry for a tracked inbound
 * connection (which would exempt the flow from the egress port filter).
 *
 * DHCP server replies (UDP 67 → 68, DHCPv6 547 → 546) are never tracked:
 * as an inbound connection they made TC pass the client's
 * next request to that server as a reply — past egress Deny All, family-wide
 * blocks and the expiry of the learned server. DHCP rides only on the
 * request-bound exemptions (xdp_dhcp4_reply / tc_dhcp_client). */

/* Out of line (TestXDPStackHeadroom): the key and the new entry live in
 * wafio_xdp_ct_buf, not in wafio_xdp_v4/v6's frame. Arguments are
 * packed to fit the five registers: ports = sport << 16 | dport (wire order),
 * meta = proto | tcp_flags << 8 | CONN_REPLY mark << 16 | trusted << 17. The
 * clock is read here (nanoseconds after the packet program's). */
static __noinline int
update_conntrack_ool(struct ip_key *src, struct ip_key *dst, __u32 ports, __u32 meta,
                     __u32 pkt_len) {
    __be16 sport = (__be16)(ports >> 16);
    __be16 dport = (__be16)ports;
    __u8 proto = meta & 0xff;
    __u8 tcp_flags = (meta >> 8) & 0xff;
    __u32 mark = (meta & (1U << 16)) ? CONN_REPLY : 0;
    int trusted = (meta >> 17) & 1;
    __u64 now_ns = bpf_ktime_get_ns();
    if (proto == IPPROTO_UDP &&
        ((sport == bpf_htons(67) && dport == bpf_htons(68)) ||
         (sport == bpf_htons(547) && dport == bpf_htons(546))))
        return 0;
    __u32 zero = 0;
    struct xdp_ct_scratch *b = bpf_map_lookup_elem(&wafio_xdp_ct_buf, &zero);
    if (!b)
        return 0;
    __builtin_memset(&b->ck, 0, sizeof(b->ck));
    __builtin_memcpy(&b->ck.src, src, sizeof(*src));
    __builtin_memcpy(&b->ck.dst, dst, sizeof(*dst));
    b->ck.sport = sport;
    b->ck.dport = dport;
    b->ck.proto = proto;

    struct conn_val *cv = bpf_map_lookup_elem(&wafio_conntrack, &b->ck);
    if (cv) {
        cv->last_seen_ns = now_ns;
        __sync_fetch_and_add(&cv->packets, 1);
        __sync_fetch_and_add(&cv->bytes, pkt_len);
        /* Plain read-modify-write, not an atomic OR (the fetch/OR atomics
         * need Linux 5.12; 5.8–5.11 reject the object). TC egress sets
         * CONN_VERIFIED / CONN_REPLY on this entry the same way
         * (tc_verify_inbound), so a concurrent update can drop its mark: a
         * lost CONN_REPLY means a re-check with the same result, a lost
         * CONN_VERIFIED a re-check that can fail for a DNAT'd connection. */
        cv->flags_seen |= tcp_flags | mark;

        /* Update TCP state machine */
        if (tcp_flags & 0x04) cv->tcp_state = 3; /* RST */
        else if (tcp_flags & 0x01) cv->tcp_state = 2; /* FIN */
        else if ((tcp_flags & 0x12) == 0x10 && cv->tcp_state == 0)
            cv->tcp_state = 1; /* ACK after SYN → established */
    } else {
        /* Pressure mode: do not allocate new conntrack entries — a spoofed
         * SYN flood must not evict legitimate flows from this LRU table.
         * A pure ACK (a completed handshake) still allocates, and so does
         * an allowlisted (trusted) source: TC exempts a
         * connection's replies — its SYN-ACK included — only with the entry. */
        struct rate_config *prcfg = get_rate_config();
        if (!trusted && syn_pressure_active(prcfg, now_ns) && (tcp_flags & 0x17) != 0x10)
            return 0;
        __builtin_memset(&b->cv, 0, sizeof(b->cv));
        b->cv.first_seen_ns = now_ns;
        b->cv.last_seen_ns = now_ns;
        b->cv.packets = 1;
        b->cv.bytes = pkt_len;
        b->cv.flags_seen = tcp_flags | mark;
        /* A whole-value write: it replaces an entry TC adopted (already
         * CONN_VERIFIED) between the lookup above and here — the same lost
         * mark as the read-modify-write above. */
        if (bpf_map_update_elem(&wafio_conntrack, &b->ck, &b->cv, BPF_ANY) == 0) {
            /* conntrack_entries counts entries created (both families, XDP
             * and TC), not packets. */
            struct metrics_val *cm = get_metrics();
            if (cm) __sync_fetch_and_add(&cm->conntrack_entries, 1);
        }
    }
    return 0;
}

static __always_inline void
update_conntrack(struct ip_key *src, struct ip_key *dst,
                 __be16 sport, __be16 dport, __u8 proto,
                 __u8 tcp_flags, __u32 pkt_len, __u64 now_ns, __u32 mark,
                 int trusted) {
    (void)now_ns;
    update_conntrack_ool(src, dst, (__u32)sport << 16 | (__u32)dport,
                         (__u32)proto | (__u32)tcp_flags << 8 |
                         (mark ? 1U << 16 : 0) | (trusted ? 1U << 17 : 0),
                         pkt_len);
}

/* xdp_socket_state: the state of the socket the kernel holds for a TCP tuple
 * as the receiving side sees it (saddr = the packet's source), or -1 for none.
 * remote_port 0 matches the listener only. The tuple lives in the per-CPU
 * conntrack scratch value (TestXDPStackHeadroom). */
static __always_inline int
xdp_socket_state(struct xdp_md *ctx, struct xdp_ct_scratch *b, struct ip_key *src,
                 struct ip_key *dst, __be16 remote_port, __be16 local_port) {
    struct bpf_sock *sk;
    __builtin_memset(&b->t, 0, sizeof(b->t));
    if (src->family == AF_INET) {
        b->t.ipv4.saddr = src->addr.v4;
        b->t.ipv4.daddr = dst->addr.v4;
        b->t.ipv4.sport = remote_port;
        b->t.ipv4.dport = local_port;
        sk = bpf_sk_lookup_tcp(ctx, &b->t, sizeof(b->t.ipv4), BPF_F_CURRENT_NETNS, 0);
    } else {
        __builtin_memcpy(b->t.ipv6.saddr, &src->addr.v6, 16);
        __builtin_memcpy(b->t.ipv6.daddr, &dst->addr.v6, 16);
        b->t.ipv6.sport = remote_port;
        b->t.ipv6.dport = local_port;
        sk = bpf_sk_lookup_tcp(ctx, &b->t, sizeof(b->t.ipv6), BPF_F_CURRENT_NETNS, 0);
    }
    if (!sk)
        return -1;
    int state = sk->state;
    bpf_sk_release(sk);
    return state;
}

/* conntrack_socket_proof: an ACK (no SYN, no RST) for which conntrack holds no
 * usable outbound entry answers a flow this host opened when the kernel holds
 * a connection for exactly its tuple in an established-side state (the set
 * tc_inbound_socket uses) and no listener owns the local port (a listener
 * would make it an inbound connection). A restart or an evicted entry lost the
 * state; the kernel still knows the connection. The outbound entry is written
 * again, as TC egress writes it; a FIN writes none (the flow ends). A forged
 * ACK finds no such socket and keeps the verdict it had. */
static __always_inline int
conntrack_socket_proof(struct xdp_md *ctx, struct xdp_ct_scratch *b, struct ip_key *src,
                       struct ip_key *dst, __be16 sport, __be16 dport, __u8 proto,
                       __u8 tcp_flags, __u64 now_ns, __u32 pkt_len) {
    if (proto != IPPROTO_TCP || !(tcp_flags & 0x10) || (tcp_flags & 0x06))
        return 0;
    int state = xdp_socket_state(ctx, b, src, dst, sport, dport);
    if (state != BPF_TCP_ESTABLISHED && state != BPF_TCP_CLOSE_WAIT &&
        state != BPF_TCP_FIN_WAIT1 && state != BPF_TCP_FIN_WAIT2 &&
        state != BPF_TCP_CLOSING && state != BPF_TCP_LAST_ACK)
        return 0;
    if (xdp_socket_state(ctx, b, src, dst, 0, dport) == BPF_TCP_LISTEN)
        return 0;
    if (tcp_flags & 0x01)
        return 1;
    __builtin_memset(&b->cv, 0, sizeof(b->cv));
    b->cv.first_seen_ns = now_ns;
    b->cv.last_seen_ns = now_ns;
    b->cv.packets = 1;
    b->cv.bytes = pkt_len;
    b->cv.tcp_state = 1;
    b->cv.flags_seen = CONN_OUTBOUND;
    if (bpf_map_update_elem(&wafio_conntrack, &b->ck, &b->cv, BPF_ANY) == 0) {
        struct metrics_val *cm = get_metrics();
        if (cm) __sync_fetch_and_add(&cm->conntrack_entries, 1);
    }
    return 1;
}

/* conntrack_reply: 1 when an inbound packet answers a fresh outbound flow
 * this host opened (CONN_OUTBOUND entry at the reverse key, written by TC
 * egress, or by conntrack_socket_proof when that entry is missing or stale).
 * Stale or foreign entries are removed. Inbound packets never renew
 * the authorization; only outbound packets do. */
/* Out of line, key in wafio_xdp_ct_buf (TestXDPStackHeadroom); arguments
 * packed as for update_conntrack_ool: ports = sport << 16 | dport (wire
 * order), meta = proto | tcp_flags << 8. The packet length comes from ctx,
 * which keeps the call within five arguments. */
static __noinline int
conntrack_reply_ool(struct xdp_md *ctx, struct ip_key *src_key, struct ip_key *dst_key,
                    __u32 ports, __u32 meta) {
    __be16 sport = (__be16)(ports >> 16);
    __be16 dport = (__be16)ports;
    __u8 proto = meta & 0xff;
    __u8 tcp_flags = (meta >> 8) & 0xff;
    __u32 pkt_len = (__u32)((long)ctx->data_end - (long)ctx->data);
    __u64 now_ns = bpf_ktime_get_ns();
    __u32 zero = 0;
    struct xdp_ct_scratch *b = bpf_map_lookup_elem(&wafio_xdp_ct_buf, &zero);
    if (!b)
        return 0;
    struct conn_key *reply_ck = &b->ck;
    __builtin_memset(reply_ck, 0, sizeof(*reply_ck));
    __builtin_memcpy(&reply_ck->src, dst_key, sizeof(*dst_key)); /* our IP */
    __builtin_memcpy(&reply_ck->dst, src_key, sizeof(*src_key)); /* remote IP */
    reply_ck->sport = dport;  /* our port = dport of the incoming reply */
    reply_ck->dport = sport;  /* remote port = sport of the incoming reply */
    reply_ck->proto = proto;

    struct conn_val *reply_cv = bpf_map_lookup_elem(&wafio_conntrack, reply_ck);
    if (!reply_cv)
        return conntrack_socket_proof(ctx, b, src_key, dst_key, sport, dport, proto,
                                      tcp_flags, now_ns, pkt_len);
    __u64 ttl = proto == IPPROTO_TCP ? CONN_TCP_TTL_NS : CONN_UDP_TTL_NS;
    if (!(reply_cv->flags_seen & CONN_OUTBOUND) || !ct_fresh(now_ns, reply_cv->last_seen_ns, ttl)) {
        bpf_map_delete_elem(&wafio_conntrack, reply_ck);
        return conntrack_socket_proof(ctx, b, src_key, dst_key, sport, dport, proto,
                                      tcp_flags, now_ns, pkt_len);
    }
    if (proto == IPPROTO_UDP ||
        ((tcp_flags & 0x12) == 0x12 && reply_cv->tcp_state == 0) ||
        ((tcp_flags & 0x10) && reply_cv->tcp_state == 1)) {
        if (proto == IPPROTO_TCP)
            reply_cv->tcp_state = 1; /* idempotent established transition */
        __sync_fetch_and_add(&reply_cv->packets, 1);
        __sync_fetch_and_add(&reply_cv->bytes, pkt_len);
        if (tcp_flags & 0x05)
            bpf_map_delete_elem(&wafio_conntrack, reply_ck);
        return 1;
    }
    return 0;
}

static __always_inline int
conntrack_reply(struct xdp_md *ctx, struct ip_key *src_key, struct ip_key *dst_key,
                __be16 sport, __be16 dport, __u8 proto, __u8 tcp_flags) {
    return conntrack_reply_ool(ctx, src_key, dst_key, (__u32)sport << 16 | (__u32)dport,
                               (__u32)proto | (__u32)tcp_flags << 8);
}

/* xdp_dhcp4_reply: a DHCPv4 BOOTREPLY (67→68) passes the ingress default
 * deny only when it answers a broadcast BOOTREQUEST this host sent within
 * DHCP_PENDING_TTL_NS — same xid and chaddr — and is addressed to broadcast
 * or to that hardware address; covers the unicast
 * OFFER/ACK of a first lease or a rebind. The answering server is learned
 * (wafio_dhcp_servers) so TC passes the later unicast RENEW to it. */
static __always_inline int
xdp_dhcp4_reply(void *data, void *data_end, struct iphdr *iph, __u64 now_ns) {
    __u8 *bootp = (void *)iph + (iph->ihl * 4) + sizeof(struct udphdr);
    if ((void *)(bootp + DHCP_BOOTP_MIN) > data_end || bootp[0] != 2) /* BOOTREPLY */
        return 0;
    __u32 xid;
    __builtin_memcpy(&xid, bootp + 4, 4);
    struct dhcp_pending_val *p = bpf_map_lookup_elem(&wafio_dhcp_pending, &xid);
    if (!p || now_ns < p->sent_ns || now_ns - p->sent_ns >= DHCP_PENDING_TTL_NS)
        return 0;
    __u8 *eth = data;
    if ((void *)(eth + 6) > data_end)
        return 0;
    int to_broadcast = iph->daddr == 0xFFFFFFFF;
    for (int i = 0; i < 6; i++) {
        if (bootp[28 + i] != p->chaddr[i])
            return 0;
        if (!to_broadcast && eth[i] != p->chaddr[i])
            return 0;
    }
    __be32 server = iph->saddr;
    if (server != 0 && server != 0xFFFFFFFF) {
        __u64 learned = now_ns;
        bpf_map_update_elem(&wafio_dhcp_servers, &server, &learned, BPF_ANY);
    }
    return 1;
}

/* control_plane_peer: the remote address:port is the agent's configured
 * control plane. Only meaningful together with conntrack_reply. */
static __always_inline int
control_plane_peer(struct ip_key *peer, __be16 port, __u8 proto) {
    if (proto != IPPROTO_TCP || port == 0)
        return 0;
    struct cp_endpoint_key k = {};
    __builtin_memcpy(&k.ip, peer, sizeof(*peer));
    k.port = port;
    k.proto = proto;
    return bpf_map_lookup_elem(&wafio_cp_endpoints, &k) != NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK: PORT SCAN DETECTION
 * ═══════════════════════════════════════════════════════════════════════════ */

static __noinline int
check_port_scan(struct ip_key *src_ip, __be16 dport, __u64 now_ns) {
    __u32 cfg_key = 0;
    struct portscan_config *pscfg = bpf_map_lookup_elem(&wafio_portscan_config, &cfg_key);
    if (!pscfg || pscfg->max_unique_ports == 0)
        return ACTION_ALLOW;

    if (pscfg->max_unique_ports > MAX_SCAN_PORTS)
        return ACTION_LOG; /* invalid direct map writes cannot trigger a broad drop */
    __u64 window_ns = pscfg->window_ns ? pscfg->window_ns : 10000000000ULL;
    __u32 threshold = pscfg->max_unique_ports;
    __u32 configured_action = pscfg->action;
    struct port_scan_state *ps = bpf_map_lookup_elem(&wafio_portscan, src_ip);
    if (!ps) {
        __u32 zero = 0;
        struct port_scan_state *initial = bpf_map_lookup_elem(&wafio_scan_scratch, &zero);
        if (!initial)
            return ACTION_LOG;
        __builtin_memset(initial, 0, sizeof(*initial));
        initial->window_start_ns = now_ns;
        initial->unique_ports = 1;
        initial->ports[0] = dport;
        if (bpf_map_update_elem(&wafio_portscan, src_ip, initial, BPF_NOEXIST) == 0)
            return ACTION_ALLOW;
        ps = bpf_map_lookup_elem(&wafio_portscan, src_ip);
        if (!ps) {
            state_full(STATE_FULL_PORTSCAN); /* as in check_rate_limit */
            return ACTION_ALLOW;
        }
    }
    int result = ACTION_ALLOW;
    bpf_spin_lock(&ps->lock);
    if (now_ns - ps->window_start_ns >= window_ns) {
        ps->window_start_ns = now_ns;
        ps->unique_ports = 0;
        ps->drop_count = 0;
    }
    __u32 count = ps->unique_ports;
    int seen = 0;
    for (__u32 i = 0; i < MAX_SCAN_PORTS; i++) {
        if (i >= count)
            break;
        if (ps->ports[i] == dport) {
            seen = 1;
            break;
        }
    }
    if (!seen && count <= MAX_SCAN_PORTS) {
        if (count < MAX_SCAN_PORTS)
            ps->ports[count] = dport;
        ps->unique_ports = count + 1;
    }
    if (ps->unique_ports > threshold) {
        ps->drop_count++;
        result = configured_action;
    }
    bpf_spin_unlock(&ps->lock);
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK: PORT POLICY (ingress port allow/deny)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* live_port_rule: the rule at k, or NULL when absent or expired. An expired
 * rule never decides: the next key in lookup order does (an
 * expiring 22/tcp allow used to hide a permanent 22/any allow). */
static __always_inline struct port_policy_val *
live_port_rule(struct port_policy_key *k, __u64 now_ns) {
    struct port_policy_val *pv = bpf_map_lookup_elem(&wafio_port_policy, k);
    if (pv && pv->expires_ns != 0 && pv->expires_ns <= now_ns)
        return NULL;
    return pv;
}

/* match_port_rule: first live rule in lookup order — exact protocol before
 * any protocol, the packet's direction before "both". The Go lockout guard
 * (firewall_validation.go, matchPortRule) evaluates this same order. */
static __always_inline struct port_policy_val *
match_port_rule(__u16 port, __u8 proto, __u8 direction, __u64 now_ns) {
    struct port_policy_key k = { .port = port, .proto = proto, .direction = direction };
    struct port_policy_val *pv = live_port_rule(&k, now_ns);
    if (pv)
        return pv;
    k.direction = PORT_DIR_BOTH;
    pv = live_port_rule(&k, now_ns);
    if (pv)
        return pv;
    k.proto = 0;
    k.direction = direction;
    pv = live_port_rule(&k, now_ns);
    if (pv)
        return pv;
    k.direction = PORT_DIR_BOTH;
    return live_port_rule(&k, now_ns);
}

static __always_inline int
check_port_policy_ingress(__u16 dport_host, __u8 proto, __u64 now_ns, int is_reply) {
    __u32 cfg_key = 0;
    struct port_policy_config *pcfg = bpf_map_lookup_elem(&wafio_port_policy_config, &cfg_key);
    if (!pcfg || !pcfg->enabled)
        return ACTION_ALLOW;

    struct port_policy_val *pv = match_port_rule(dport_host, proto, PORT_DIR_INGRESS, now_ns);
    if (pv) {
        __sync_fetch_and_add(&pv->hit_count, 1);
        return pv->action;
    }

    /* No live rule → default policy. Replies (and on-link DHCP replies)
     * are exempt from the default deny only. */
    if (!is_reply && pcfg->default_ingress == 1)
        return ACTION_DROP;
    return ACTION_ALLOW;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  HELPER: explicit Port Policy ALLOW check (port-scan exemption only)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Returns 1 ONLY when Port Policies is ENABLED and the rule that decides the
 * given destination port + protocol (match_port_rule) is a live ALLOW.
 * Its only use is to keep explicitly allowed ports out of the port-scan tally
 * (section 4). It bypasses nothing else: the IP lists and geo-blocking run
 * before it, SYN-flood and rate limits after it (an older comment said
 * an explicit ALLOW overrides geo-blocking; it never did). To let a source in
 * past geo-blocking, allowlist the source (every port, or the port as a
 * port-scoped entry).
 */
static __always_inline int
port_policy_has_explicit_allow(__u16 dport_host, __u8 proto, __u64 now_ns) {
    __u32 cfg_key = 0;
    struct port_policy_config *pcfg = bpf_map_lookup_elem(&wafio_port_policy_config, &cfg_key);
    if (!pcfg || !pcfg->enabled)
        return 0; /* Port Policies disabled — no explicit allow */
    struct port_policy_val *pv = match_port_rule(dport_host, proto, PORT_DIR_INGRESS, now_ns);
    return pv && pv->action == ACTION_ALLOW;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  L4 STAGE (both families)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The checks after the IP lists, geo and the payload limit — SYN flood, port
 * scan, port policy, per-IP rate limit, conntrack update — are the same for
 * IPv4 and IPv6 and read no packet bytes: the family programs extract the
 * ports and TCP flags first and hand them over in a per-CPU value (XDP does
 * not nest on a CPU). xdp_l4_stage is a global function (BTF linkage global,
 * ctx as its only argument, as Linux 5.10 requires), so the verifier checks
 * it once, on its own, instead of once for every state the family program
 * reaches it with. Inline, these checks took wafio_xdp_v6 past the 1M
 * processed-instruction limit on Linux 5.15 (v1.7.0–v1.9.0: no firewall
 * there) and wafio_xdp_v4 to 905k. */
struct xdp_l4_args {
    struct ip_key src;
    struct ip_key dst;
    __u64 now_ns;
    __u32 pkt_len;
    __be16 sport;       /* wire order, 0 when unread */
    __be16 dport;
    __u8 proto;
    __u8 tcp_flags;
    __u8 is_reply;      /* reply to a flow this host opened (conntrack_reply) */
    __u8 dhcp_reply;    /* request-bound DHCP reply: skips the default deny only */
    __u8 l4_ok;         /* the TCP/UDP header was read */
    __u8 pad[7];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_l4_args);
} wafio_xdp_l4_args SEC(".maps");

__noinline int
xdp_l4_stage(struct xdp_md *ctx) {
    __u32 zero = 0;
    struct xdp_l4_args *a = bpf_map_lookup_elem(&wafio_xdp_l4_args, &zero);
    struct global_config *cfg = get_config();
    if (!a || !cfg)
        return XDP_PASS;
    /* Fields are read from a where used: copies held across the helper
     * calls are spilled to this frame (TestXDPStackHeadroom). */
    int action;

    if (a->proto == IPPROTO_TCP || a->proto == IPPROTO_UDP) {
        /* parse_packet already checked the header; the old in-line re-read
         * passed a frame without one. */
        if (!a->l4_ok)
            return XDP_PASS;
        /* The family program filled the event (addresses, protocol). */
        struct perf_event_data *evt = bpf_map_lookup_elem(&wafio_xdp_evt_buf, &zero);
        if (evt) {
            evt->src_port = a->sport;
            evt->dst_port = a->dport;
            if (a->proto == IPPROTO_TCP)
                evt->tcp_flags = a->tcp_flags;
        }
    }

    /* ── TCP: SYN flood, port scan ────────────────────────────────────── */
    if (a->proto == IPPROTO_TCP) {
        if (cfg->enable_synflood) {
            action = check_syn_flood(&a->src, &a->dst,
                                     (__u32)a->sport << 16 | (__u32)a->dport, a->tcp_flags, a->now_ns);
            if (action == ACTION_DROP) {
                struct metrics_val *metrics = get_metrics();
                if (metrics) {
                    record_firewall_drop(metrics, a->pkt_len, cfg->mode);
                    if (cfg->mode != 1) __sync_fetch_and_add(&metrics->synflood_drops, 1);
                }
                if (cfg->log_blocked) {
                    xdp_event(ctx, cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP, EVENT_REASON_SYNFLOOD);
                }
                if (cfg->mode == 1) return XDP_PASS;
                return XDP_DROP;
            } else if (action == ACTION_LOG) {
                /* drop_on_limit=false: detected but not dropped, log only */
                if (cfg->log_blocked) {
                    xdp_event(ctx, ACTION_LOG, EVENT_REASON_SYNFLOOD);
                }
            }
        }

        /* Port scan detection.
         * Ports carrying an explicit ingress ALLOW rule are exempt from the
         * unique-dst-port tally: an administrator legitimately touches SSH +
         * dashboard + app ports from one address, and counting those ports
         * flagged the operator instead of the attacker — with the port
         * policy allow rules never consulted because this check drops
         * first. Scanners hitting non-allowed ports still trip it. */
        if (!port_policy_has_explicit_allow(bpf_ntohs(a->dport), IPPROTO_TCP, a->now_ns)) {
            action = check_port_scan(&a->src, a->dport, a->now_ns);
            if (action == ACTION_DROP) {
                struct metrics_val *metrics = get_metrics();
                if (metrics) {
                    record_firewall_drop(metrics, a->pkt_len, cfg->mode);
                    if (cfg->mode != 1) __sync_fetch_and_add(&metrics->port_scan_drops, 1);
                }
                if (cfg->log_blocked) {
                    xdp_event(ctx, cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP, EVENT_REASON_PORT_SCAN);
                }
                if (cfg->mode == 1) return XDP_PASS;
                return XDP_DROP;
            } else if (action == ACTION_LOG && cfg->log_blocked) {
                xdp_event(ctx, ACTION_LOG, EVENT_REASON_PORT_SCAN);
            }
        }
    }

    /* ── Port policy enforcement (ingress) ────────────────────────────── */
    if (a->dport != 0) {
        __u16 dport_host = bpf_ntohs(a->dport);
        action = check_port_policy_ingress(dport_host, a->proto, a->now_ns, a->is_reply || a->dhcp_reply);
        if (action == ACTION_DROP) {
            struct metrics_val *metrics = get_metrics();
            if (metrics) {
                record_firewall_drop(metrics, a->pkt_len, cfg->mode);
                if (cfg->mode != 1) __sync_fetch_and_add(&metrics->port_policy_drops, 1);
            }
            if (cfg->log_blocked) {
                xdp_event(ctx, cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP, EVENT_REASON_PORT_POLICY);
            }
            if (cfg->mode == 1) return XDP_PASS;
            return XDP_DROP;
        }
    }

    /* ── Per-IP rate limiting (new inbound flows only) ───────────────── */
    if (cfg->enable_ratelimit &&
        rate_limited_flow(&a->src, &a->dst, a->sport, a->dport, a->proto, a->is_reply)) {
        action = check_rate_limit(&a->src, a->pkt_len, a->now_ns);
        if (action == ACTION_DROP) {
            struct metrics_val *metrics = get_metrics();
            if (metrics) {
                record_firewall_drop(metrics, a->pkt_len, cfg->mode);
                if (cfg->mode != 1) __sync_fetch_and_add(&metrics->ratelimited_packets, 1);
            }
            if (cfg->log_blocked) {
                xdp_event(ctx, cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP, EVENT_REASON_RATELIMIT_PPS);
            }
            if (cfg->mode == 1) return XDP_PASS;
            return XDP_DROP;
        } else if (action == ACTION_LOG) {
            /* drop_on_limit=false: detected but not dropped, log only */
            if (cfg->log_blocked) {
                xdp_event(ctx, ACTION_LOG, EVENT_REASON_RATELIMIT_PPS);
            }
        }
    }

    /* ── Connection tracking ──────────────────────────────────────────── */
    if (cfg->enable_conntrack && (a->proto == IPPROTO_TCP || a->proto == IPPROTO_UDP)) {
        update_conntrack(&a->src, &a->dst, a->sport, a->dport, a->proto, a->tcp_flags, a->pkt_len,
                         a->now_ns, a->is_reply ? CONN_REPLY : 0, 0);
    }

    return XDP_PASS;
}

/* xdp_l4_handoff: hand the packet to xdp_l4_stage. */
static __always_inline int
xdp_l4_handoff(struct xdp_md *ctx, struct ip_key *src, struct ip_key *dst,
               __u64 now_ns, __u32 pkt_len, __be16 sport, __be16 dport,
               __u8 proto, __u8 tcp_flags, int is_reply, int dhcp_reply, int l4_ok) {
    __u32 zero = 0;
    struct xdp_l4_args *a = bpf_map_lookup_elem(&wafio_xdp_l4_args, &zero);
    if (!a)
        return XDP_PASS; /* never for a per-CPU array */
    __builtin_memcpy(&a->src, src, sizeof(*src));
    __builtin_memcpy(&a->dst, dst, sizeof(*dst));
    a->now_ns = now_ns;
    a->pkt_len = pkt_len;
    a->sport = sport;
    a->dport = dport;
    a->proto = proto;
    a->tcp_flags = tcp_flags;
    a->is_reply = is_reply != 0;
    a->dhcp_reply = dhcp_reply != 0;
    a->l4_ok = l4_ok != 0;
    return xdp_l4_stage(ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAIN XDP PROGRAM — IPv4
 * ═══════════════════════════════════════════════════════════════════════════ */

static __always_inline int
process_ipv4(struct xdp_md *ctx, void *data, void *data_end,
             struct packet_headers *headers, int l4_cut) {
    if (headers->network_offset > 22 || headers->l4_offset > 16446)
        return XDP_PASS;
    struct iphdr *iph = data + headers->network_offset;
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    __u32 pkt_len = data_end - data;
    __u64 now_ns = bpf_ktime_get_ns();

    struct global_config *cfg = get_config();
    if (!cfg || !cfg->enabled) return XDP_PASS;

    struct metrics_val *rx = get_metrics();
    if (rx) update_metrics_rx(rx, pkt_len);

    /* Build source IP key */
    struct ip_key src_key = {};
    ip_key_from_v4(&src_key, iph->saddr);
    struct ip_key dst_key = {};
    ip_key_from_v4(&dst_key, iph->daddr);

    int action;
    struct perf_event_data *evt = xdp_event_buf(now_ns, pkt_len);
    if (evt) {
        fill_event_ips_v4(evt, iph->saddr, iph->daddr);
        evt->proto = iph->protocol;
    }

    /* ── 1. Early L4 extraction ───────────────────────────────────────── */
    /* Ports and TCP flags are read first: the reply bypass below must run
     * before the IP lists. Section 4 re-reads them with the full
     * bounds check. */
    __be16 sport = 0, dport = 0;
    __u8 tcp_flags = 0;
    int l4_ok = 0;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph_e = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph_e + 1) <= data_end) {
            sport = tcph_e->source;
            dport = tcph_e->dest;
            tcp_flags = ((__u8 *)tcph_e)[13];
            l4_ok = 1;
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph_e = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph_e + 1) <= data_end) {
            sport = udph_e->source;
            dport = udph_e->dest;
            l4_ok = 1;
        }
    }

    /* ── 2. Conntrack reply bypass ────────────────────────────────────── */
    /* Replies to a fresh outbound flow of this host skip the ingress default
     * deny and family-wide (0.0.0.0/0) blocklist entries. Specific IP and
     * subnet blocks, geo, explicit port rules and rate limits still apply —
     * except for the configured control-plane endpoint, whose replies always
     * pass so the agent can never be cut off from its control plane. */
    int cp_peer = control_plane_peer(&src_key, sport, iph->protocol);
    int is_reply = 0;
    if ((cfg->enable_conntrack || cp_peer) && sport != 0 && dport != 0)
        is_reply = conntrack_reply(ctx, &src_key, &dst_key, sport, dport,
                                   iph->protocol, tcp_flags);
    if (cp_peer && is_reply)
        return XDP_PASS;
    /* DHCPv4 BOOTREPLYs answering this host's pending broadcast request
     * skip only the ingress default deny, like replies (lease
     * loss is a lockout). Unicast renewals are ordinary conntrack replies. */
    int dhcp_reply = 0;
    if (iph->protocol == IPPROTO_UDP && sport == bpf_htons(67) && dport == bpf_htons(68))
        dhcp_reply = xdp_dhcp4_reply(data, data_end, iph, now_ns);

    /* ── 3. Allowlist / Blocklist ─────────────────────────────────────── */
    /* A port-scoped allowlist entry passes only TCP/UDP to its ports; the
     * rest of the source's traffic continues below. */
    action = check_ip_lists(&src_key, now_ns, is_reply, iph->protocol, dport);
    if (action == ACTION_ALLOW) {
        struct metrics_val *metrics = get_metrics();
        if (metrics) __sync_fetch_and_add(&metrics->allowlist_passes, 1);
        if (cfg->log_allowed) {
            xdp_event(ctx, ACTION_ALLOW, EVENT_REASON_ALLOWLIST);
        }
        /* Track allowlisted flows too: without the entry TC
         * cannot tell the replies of an allowlisted SSH session from new
         * outbound traffic and egress Deny All drops them. */
        if (cfg->enable_conntrack && sport != 0 && dport != 0)
            update_conntrack(&src_key, &dst_key, sport, dport, iph->protocol,
                             tcp_flags, pkt_len, now_ns, is_reply ? CONN_REPLY : 0, 1);
        return XDP_PASS;
    }
    if (action == ACTION_DROP) {
        /* IP blocklist always wins. Port Policy ALLOW does NOT bypass the
         * blocklist. To allow a blocked IP through, add it to the allowlist. */
        struct metrics_val *metrics = get_metrics();
        if (metrics) {
            record_firewall_drop(metrics, pkt_len, cfg->mode);
            if (cfg->mode != 1) __sync_fetch_and_add(&metrics->blocklist_drops, 1);
        }
        if (cfg->log_blocked) {
            xdp_event(ctx, cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP, EVENT_REASON_BLOCKLIST);
        }
        if (cfg->mode == 1) return XDP_PASS; /* monitor-only */
        return XDP_DROP;
    }

    /* ── 3.5. Geo-IP ──────────────────────────────────────────────────── */
    /* Block mode drops a blocked country's sources (replies included, as
     * before allow mode existed). Allow mode drops every source outside
     * the allowed countries, except the exemptions listed above
     * geo_config_get. A port-scoped allowlist entry exempts only its ports:
     * a reply from such a source to a flow this host opened arrives on an
     * ephemeral port, so block mode drops it when the source's country is
     * blocked (allow mode passes replies anyway). */
    if (cfg->enable_geoblock) {
        struct geo_config *gc = geo_config_get();
        int geo_allow = gc && gc->mode == GEO_MODE_ALLOW;
        if (!geo_allow) {
            action = check_geoblock_v4(&src_key, iph->saddr);
        } else if (is_reply || dhcp_reply || geo_exempt_source_v4(iph->saddr, iph->protocol, dport)) {
            action = ACTION_ALLOW;
        } else {
            action = ACTION_DROP;
            if (iph->protocol == IPPROTO_ICMP) {
                __u8 *icmp = (void *)iph + (iph->ihl * 4);
                if ((void *)(icmp + 1) <= data_end && geo_icmp4_exempt(icmp[0]))
                    action = ACTION_ALLOW;
            }
            if (action == ACTION_DROP) {
                struct geo_cidr_v4_key glk = { .prefixlen = 32, .addr = iph->saddr };
                action = geo_allow_verdict(bpf_map_lookup_elem(&wafio_geo_cidr4, &glk),
                                           &src_key, &dst_key, sport, dport,
                                           iph->protocol, tcp_flags,
                                           gc->allow_since_ns, now_ns);
            }
        }
        if (action == ACTION_DROP) {
            struct metrics_val *metrics = get_metrics();
            if (metrics) {
                record_firewall_drop(metrics, pkt_len, cfg->mode);
                if (cfg->mode != 1) __sync_fetch_and_add(&metrics->geoblock_drops, 1);
            }
            if (cfg->log_blocked) {
                xdp_event_rule(ctx, cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP, EVENT_REASON_GEOBLOCK,
                               geo_allow ? GEO_EVENT_ALLOW_MODE : GEO_EVENT_BLOCK_MODE);
            }
            if (cfg->mode == 1) return XDP_PASS;
            return XDP_DROP;
        }
    }

    /* The RX buffer cut the TCP/UDP header (parse_packet -3). The IP
     * lists and geo above have decided on the sound IP header; the checks
     * below need the L4 header, so the frame passes as it always did (TC
     * and the stack see the full packet). */
    if (l4_cut)
        return XDP_PASS;

    if (cfg->max_payload_bytes > 0) {
        __u32 ip_hdr_len = iph->ihl * 4;
        __u32 ip_total = bpf_ntohs(iph->tot_len);
        if (ip_total > ip_hdr_len) {
            __u32 payload_len = ip_total - ip_hdr_len;
            /* Subtract TCP/UDP header later — just check total L4 payload */
            if (payload_len > cfg->max_payload_bytes) {
                struct metrics_val *metrics = get_metrics();
                if (metrics) record_firewall_drop(metrics, pkt_len, cfg->mode);
                if (cfg->log_blocked) {
                    xdp_event(ctx, cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP, EVENT_REASON_PAYLOAD_SIZE);
                }
                if (cfg->mode == 1) return XDP_PASS;
                return XDP_DROP;
            }
        }
    }

    /* ── 4.–7. SYN flood, port scan, port policy, rate limit, conntrack ── */
    return xdp_l4_handoff(ctx, &src_key, &dst_key, now_ns, pkt_len, sport, dport,
                          iph->protocol, tcp_flags, is_reply, dhcp_reply, l4_ok);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAIN XDP PROGRAM — IPv6
 * ═══════════════════════════════════════════════════════════════════════════ */

static __always_inline int
process_ipv6(struct xdp_md *ctx, void *data, void *data_end,
             struct packet_headers *headers, int l4_cut) {
    if (headers->network_offset > 22 || headers->l4_offset > 16446)
        return XDP_PASS;
    struct ipv6hdr *ip6h = data + headers->network_offset;
    if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

    __u32 pkt_len = data_end - data;
    __u64 now_ns = bpf_ktime_get_ns();

    struct global_config *cfg = get_config();
    if (!cfg || !cfg->enabled) return XDP_PASS;

    struct metrics_val *rx = get_metrics();
    if (rx) update_metrics_rx(rx, pkt_len);

    struct ip_key src_key = {};
    ip_key_from_v6(&src_key, &ip6h->saddr);
    struct ip_key dst_key = {};
    ip_key_from_v6(&dst_key, &ip6h->daddr);

    int action;
    struct perf_event_data *evt = xdp_event_buf(now_ns, pkt_len);
    if (evt) {
        evt->proto = headers->proto;
        ip_key_from_v6(&evt->src_ip, &ip6h->saddr);
        ip_key_from_v6(&evt->dst_ip, &ip6h->daddr);
    }

    /* Neighbour discovery passes before every list. */
    if (ipv6_neighbour_discovery(data, data_end, headers))
        return XDP_PASS;

    /* ── 0. Early L4 extraction + conntrack reply bypass ───────────────── */
    /* Same contract as IPv4: runs before the IP lists so replies to a fresh
     * outbound flow pass a ::/0 blocklist entry and the ingress default
     * deny; control-plane replies always pass. Section 3 re-reads the
     * header with the full bounds check. */
    __be16 sport = 0, dport = 0;
    __u8 tcp_flags = 0;
    int l4_ok = 0;
    if (headers->proto == IPPROTO_TCP) {
        volatile __u32 early_offset = headers->l4_offset;
        __u32 l4e = early_offset;
        if (l4e > 16446) return XDP_PASS;
        struct tcphdr *tcph_e = data + l4e;
        if ((void *)(tcph_e + 1) <= data_end) {
            sport = tcph_e->source;
            dport = tcph_e->dest;
            tcp_flags = ((__u8 *)tcph_e)[13];
            l4_ok = 1;
        }
    } else if (headers->proto == IPPROTO_UDP) {
        volatile __u32 early_offset = headers->l4_offset;
        __u32 l4e = early_offset;
        if (l4e > 16446) return XDP_PASS;
        struct udphdr *udph_e = data + l4e;
        if ((void *)(udph_e + 1) <= data_end) {
            sport = udph_e->source;
            dport = udph_e->dest;
            l4_ok = 1;
        }
    }
    int cp_peer = control_plane_peer(&src_key, sport, headers->proto);
    int is_reply = 0;
    if ((cfg->enable_conntrack || cp_peer) && sport != 0 && dport != 0)
        is_reply = conntrack_reply(ctx, &src_key, &dst_key, sport, dport,
                                   headers->proto, tcp_flags);
    if (cp_peer && is_reply)
        return XDP_PASS;
    /* DHCPv6 replies from a link-local server (never routed, so on-link)
     * skip only the ingress default deny. */
    int dhcp_reply = headers->proto == IPPROTO_UDP && sport == bpf_htons(547) &&
                     dport == bpf_htons(546) && ip6h->saddr.in6_u.u6_addr8[0] == 0xfe &&
                     (ip6h->saddr.in6_u.u6_addr8[1] & 0xc0) == 0x80;

    /* ── 1. Allowlist / Blocklist (scoped entries: see IPv4) ─────────── */
    action = check_ip_lists(&src_key, now_ns, is_reply, headers->proto, dport);
    if (action == ACTION_ALLOW) {
        struct metrics_val *metrics = get_metrics();
        if (metrics) __sync_fetch_and_add(&metrics->allowlist_passes, 1);
        if (cfg->log_allowed) /* as IPv4 */
            xdp_event(ctx, ACTION_ALLOW, EVENT_REASON_ALLOWLIST);
        /* Track allowlisted flows too (see IPv4). */
        if (cfg->enable_conntrack && sport != 0 && dport != 0)
            update_conntrack(&src_key, &dst_key, sport, dport, headers->proto,
                             tcp_flags, pkt_len, now_ns, is_reply ? CONN_REPLY : 0, 1);
        return XDP_PASS;
    }
    if (action == ACTION_DROP) {
        /* IP blocklist always wins. Port Policy ALLOW does NOT bypass the
         * blocklist. To allow a blocked IP through, add it to the allowlist. */
        struct metrics_val *metrics = get_metrics();
        if (metrics) {
            record_firewall_drop(metrics, pkt_len, cfg->mode);
            if (cfg->mode != 1) __sync_fetch_and_add(&metrics->blocklist_drops, 1);
        }
        if (cfg->log_blocked) {
            xdp_event(ctx, cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP, EVENT_REASON_BLOCKLIST);
        }
        if (cfg->mode == 1) return XDP_PASS;
        return XDP_DROP;
    }

    /* ── 2. Geo-IP (see IPv4 step 3.5) ────────────────────────────────── */
    if (cfg->enable_geoblock) {
        struct geo_config *gc = geo_config_get();
        int geo_allow = gc && gc->mode == GEO_MODE_ALLOW;
        struct geo_cidr_v6_key glk = { .prefixlen = 128 };
        __builtin_memcpy(glk.addr, &ip6h->saddr, 16);
        if (!geo_allow) {
            action = check_geoblock_v6(&src_key, (const __u8 *)&ip6h->saddr);
        } else if (is_reply || dhcp_reply || geo_exempt_source_v6(&ip6h->saddr, headers->proto, &glk)) {
            action = ACTION_ALLOW;
        } else {
            action = ACTION_DROP;
            if (headers->proto == WAFIO_IPPROTO_ICMPV6) {
                volatile __u32 icmp_wire = headers->l4_offset;
                __u32 icmp_off = icmp_wire;
                if (icmp_off <= 16446) {
                    __u8 *icmp = data + icmp_off;
                    if ((void *)(icmp + 1) <= data_end && geo_icmp6_exempt(icmp[0]))
                        action = ACTION_ALLOW;
                }
            }
            if (action == ACTION_DROP) {
                action = geo_allow_verdict(bpf_map_lookup_elem(&wafio_geo_cidr6, &glk),
                                           &src_key, &dst_key, sport, dport,
                                           headers->proto, tcp_flags,
                                           gc->allow_since_ns, now_ns);
            }
        }
        if (action == ACTION_DROP) {
            struct metrics_val *metrics = get_metrics();
            if (metrics) {
                record_firewall_drop(metrics, pkt_len, cfg->mode);
                if (cfg->mode != 1) __sync_fetch_and_add(&metrics->geoblock_drops, 1);
            }
            if (cfg->log_blocked) {
                xdp_event_rule(ctx, cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP, EVENT_REASON_GEOBLOCK,
                               geo_allow ? GEO_EVENT_ALLOW_MODE : GEO_EVENT_BLOCK_MODE);
            }
            if (cfg->mode == 1) return XDP_PASS;
            return XDP_DROP;
        }
    }

    /* L4 header cut by the RX buffer — lists and geo decided; pass. */
    if (l4_cut)
        return XDP_PASS;

    /* ── 2.5. Payload size (as IPv4) ─────────────────────────────────── */
    /* The upper-layer length: the declared payload minus the extension
     * headers parse_packet walked. A jumbogram (payload_len 0) is skipped. */
    if (cfg->max_payload_bytes > 0) {
        __u32 declared = bpf_ntohs(ip6h->payload_len);
        __u32 ext_len = headers->l4_offset - headers->network_offset - sizeof(struct ipv6hdr);
        if (declared > ext_len && declared - ext_len > cfg->max_payload_bytes) {
            struct metrics_val *metrics = get_metrics();
            if (metrics) record_firewall_drop(metrics, pkt_len, cfg->mode);
            if (cfg->log_blocked)
                xdp_event(ctx, cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP, EVENT_REASON_PAYLOAD_SIZE);
            if (cfg->mode == 1) return XDP_PASS;
            return XDP_DROP;
        }
    }

    /* ── 3.–6. SYN flood, port scan, port policy, rate limit, conntrack ── */
    return xdp_l4_handoff(ctx, &src_key, &dst_key, now_ns, pkt_len, sport, dport,
                          headers->proto, tcp_flags, is_reply, dhcp_reply, l4_ok);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  XDP SUB-PROGRAMS (tail-call targets)
 *
 * process_ipv4/process_ipv6 stay __always_inline — each inlines into its
 * own top-level program, giving every family an independent 1M-insn
 * verifier budget and a fresh stack (kernel 5.15).
 * ═══════════════════════════════════════════════════════════════════════════ */

SEC("xdp/v4")
int wafio_xdp_v4(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct packet_headers headers;
    int parsed = parse_packet(data, data_end, &headers);
    /* The entry tail-calls on 1 and on -3 (L4 header cut). */
    if (parsed != 1 && parsed != -3) return XDP_PASS;
    return process_ipv4(ctx, data, data_end, &headers, parsed == -3);
}

SEC("xdp/v6")
int wafio_xdp_v6(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct packet_headers headers;
    int parsed = parse_packet(data, data_end, &headers);
    if (parsed != 1 && parsed != -3) return XDP_PASS;
    return process_ipv6(ctx, data, data_end, &headers, parsed == -3);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  XDP ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

SEC("xdp")
int wafio_xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct global_config *cfg = get_config();
    if (!cfg || !cfg->enabled)
        return XDP_PASS;
    struct packet_headers headers;
    int parsed = parse_packet(data, data_end, &headers);
    if (parsed < 0) {
        if (parsed != -3) {
            struct metrics_val *metrics = get_metrics();
            if (metrics) {
                __sync_fetch_and_add(&metrics->packet_parse_failures, 1);
            }
            if (cfg->log_blocked) {
                struct perf_event_data evt = {.timestamp_ns=bpf_ktime_get_ns(), .pkt_len=data_end-data,
                    .action=cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP,
                    .reason=EVENT_REASON_PACKET_PARSE};
                emit_event(ctx, &evt);
            }
            /* Malformed (-1) and unsupported-but-valid (-2: IP fragments,
             * >2 VLAN tags, long IPv6 ext chains) are rejected in enforce
             * mode — fragment reassembly is unavailable, so passing them
             * would bypass every L3/L4 check. Monitor mode stays
             * fail-open (would-drop visibility only). -3 (RX buffer
             * truncation, virtio mergeable RX) is never dropped for the
             * truncation itself — dropping it locks the host out — but the
             * IP lists and geo still apply to it (below). */
            if (parsed == -1 || parsed == -2) {
                if (metrics)
                    record_firewall_drop(metrics, data_end - data, cfg->mode);
                if (cfg->mode == 1)
                    return XDP_PASS;
                return XDP_DROP;
            }
        }
        if (parsed != -3)
            return XDP_PASS;
        /* -3: the IP header is sound but the RX buffer cut the TCP/UDP
         * header. It used to pass here, before every check — the IP lists
         * included. It now goes to the family program, which applies
         * the IP lists and geo (and the reply / control-plane exemptions
         * when the ports are readable) and passes everything else, so the
         * truncation case still never locks the host out. Fragments are -2
         * and never reach this. */
        __u32 cut_key = headers.family == 2 ? 0 : 1;
        bpf_tail_call(ctx, &wafio_xdp_progs, cut_key);
        return XDP_PASS;
    }
    if (headers.parse_flags & PH_DECLARED_EXCEEDS) {
        /* Declared IP length exceeds the linear buffer — legit on
         * scatter-gather, counted for visibility, never dropped here. */
        struct metrics_val *metrics = get_metrics();
        if (metrics)
            __sync_fetch_and_add(&metrics->packet_parse_failures, 1);
    }
    if (!parsed)
        return XDP_PASS;

    /* Tail-call dispatch: each family gets its own verifier budget + stack */
    __u32 key = headers.family == 2 ? 0 : 1;
    bpf_tail_call(ctx, &wafio_xdp_progs, key);
    /* Fall-through if the PROG_ARRAY is empty (fail-open, same as old -3 path) */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
