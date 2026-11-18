// SPDX-License-Identifier: GPL-2.0
// wafio_tc.c — Wafio enterprise TC classifier program.
//
// Runs at TC ingress/egress hook for deeper packet inspection than XDP:
//   1. HTTP method + URI pattern matching (L7 DPI — first bytes of TCP payload)
//   2. Egress connection tracking (outbound data exfiltration detection)
//   3. DNS query logging (UDP/53 → log domain being resolved)
//   4. TCP flag anomaly detection (XMAS, NULL scans)
//   5. Bandwidth accounting per source IP
//
// XDP handles the fast-path (blocklist, rate-limit, SYN flood).
// TC handles the slow-path (L7 inspection, egress tracking).

#include "wafio_common.h"
#include "wafio_packet.h"

/* ═══════════════════════════════════════════════════════════════════════════
 *  SHARED MAPS (from XDP — access same maps)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Presence identifies the bounded dual-stack packet parser ABI to userspace. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} wafio_packet_abi SEC(".maps");

/* Global configuration — shared with XDP */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_config);
} wafio_config SEC(".maps");

/* Connection tracking — shared with XDP */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNTRACK_SIZE);
    __type(key, struct conn_key);
    __type(value, struct conn_val);
} wafio_conntrack SEC(".maps");

/* Perf event output — shared with XDP */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} wafio_events SEC(".maps");

/* Per-CPU metrics — shared with XDP */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct metrics_val);
} wafio_metrics SEC(".maps");

/* ═══════════════════════════════════════════════════════════════════════════
 *  TC-SPECIFIC MAPS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Bandwidth accounting per source IP (ingress + egress bytes per window) */
struct bw_state {
    __u64 window_start_ns;
    __u64 ingress_bytes;
    __u64 egress_bytes;
    __u64 ingress_packets;
    __u64 egress_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RATELIMIT_SIZE);
    __type(key, struct ip_key);
    __type(value, struct bw_state);
} wafio_bandwidth SEC(".maps");

/* TCP flag anomaly detection config (key=0) */
struct anomaly_config {
    __u32 detect_xmas;       /* detect XMAS scans (FIN+PSH+URG) */
    __u32 detect_null;       /* detect NULL scans (no flags) */
    __u32 detect_fin_only;   /* detect FIN-only scans */
    __u32 action;            /* ACTION_DROP or ACTION_LOG */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct anomaly_config);
} wafio_anomaly_config SEC(".maps");

/* ── Port Policy maps (shared with XDP for direction=BOTH rules) ─────────── */

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
 * XDP: both declarations carry the same flags. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH); /* never evicts an operator entry */
    __uint(max_entries, MAX_EGRESS_BLOCKLIST);
    __type(key, struct ip_key);
    __type(value, struct ip_list_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_egress_blocklist SEC(".maps");

/* Egress Subnet CIDR blocklist LPM trie for IPv4 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct subnet_v4_key);
    __type(value, struct subnet_val);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_egress_subnet_v4 SEC(".maps");

/* Egress Subnet CIDR blocklist LPM trie for IPv6 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct subnet_v6_key);
    __type(value, struct subnet_val);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} wafio_egress_subnet_v6 SEC(".maps");

/* Control-plane endpoints — shared with XDP; see wafio_common.h. */
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

/* Egress IP fragments. Only a first fragment carries the L4 header,
 * so TC egress polices it like any packet and, when it passes, remembers
 * its datagram here; the later fragments of that datagram pass by this
 * entry. A later fragment without one (its first fragment was dropped,
 * never seen, or expired) cannot be checked and is failed closed while an
 * egress deny policy or a matching egress block is in force. The local
 * stack emits a datagram's fragments in order and back to back, so a few
 * seconds cover it. TC-private; the agent never reads or writes it. */
#define FRAG_PASS_TTL_NS 5000000000ULL          /* 5 s */

struct frag_key {
    struct ip_key src;
    struct ip_key dst;
    __u32 id;                              /* packet_headers.frag_id */
    __u8  proto;                           /* packet_headers.frag_proto */
    __u8  pad[3];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct frag_key);
    __type(value, __u64);                  /* first fragment passed at, ktime ns */
} wafio_frag_pass SEC(".maps");

/* ═══════════════════════════════════════════════════════════════════════════
 *  HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

static __always_inline struct global_config *
tc_get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&wafio_config, &key);
}

static __always_inline struct metrics_val *
tc_get_metrics(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&wafio_metrics, &key);
}

static __always_inline void
tc_emit_event(struct __sk_buff *skb, struct perf_event_data *evt) {
    bpf_perf_event_output(skb, &wafio_events, BPF_F_CURRENT_CPU,
                          evt, sizeof(*evt));
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK: TCP FLAG ANOMALIES
 * ═══════════════════════════════════════════════════════════════════════════ */

static __always_inline int
check_tcp_anomaly(__u8 tcp_flags) {
    __u32 key = 0;
    struct anomaly_config *acfg = bpf_map_lookup_elem(&wafio_anomaly_config, &key);
    if (!acfg) return ACTION_ALLOW;

    /* XMAS scan: FIN=1, PSH=1, URG=1 (flags=0x29) */
    if (acfg->detect_xmas && (tcp_flags & 0x29) == 0x29)
        return acfg->action;

    /* NULL scan: all flags = 0 */
    if (acfg->detect_null && tcp_flags == 0)
        return acfg->action;

    /* FIN-only scan: only FIN set */
    if (acfg->detect_fin_only && tcp_flags == 0x01)
        return acfg->action;

    return ACTION_ALLOW;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  BANDWIDTH ACCOUNTING
 * ═══════════════════════════════════════════════════════════════════════════ */

static __always_inline void
update_bandwidth(struct ip_key *ip, __u32 pkt_len, int is_egress, __u64 now_ns) {
    struct bw_state *bw = bpf_map_lookup_elem(&wafio_bandwidth, ip);
    if (!bw) {
        struct bw_state new_bw = { .window_start_ns = now_ns };
        if (is_egress) {
            new_bw.egress_bytes = pkt_len;
            new_bw.egress_packets = 1;
        } else {
            new_bw.ingress_bytes = pkt_len;
            new_bw.ingress_packets = 1;
        }
        bpf_map_update_elem(&wafio_bandwidth, ip, &new_bw, BPF_ANY);
        return;
    }

    /* 60-second window for bandwidth tracking */
    if (now_ns - bw->window_start_ns >= 60000000000ULL) {
        bw->window_start_ns = now_ns;
        bw->ingress_bytes = 0;
        bw->egress_bytes = 0;
        bw->ingress_packets = 0;
        bw->egress_packets = 0;
    }

    if (is_egress) {
        __sync_fetch_and_add(&bw->egress_bytes, pkt_len);
        __sync_fetch_and_add(&bw->egress_packets, 1);
    } else {
        __sync_fetch_and_add(&bw->ingress_bytes, pkt_len);
        __sync_fetch_and_add(&bw->ingress_packets, 1);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  TC INGRESS — deep packet inspection
 * ═══════════════════════════════════════════════════════════════════════════ */

SEC("tc")
int wafio_tc_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct global_config *cfg = tc_get_config();
    if (!cfg || !cfg->enabled) return TC_ACT_OK;
    struct packet_headers headers = {};
    int parsed = parse_packet(data, data_end, &headers);
    if (!parsed) return TC_ACT_OK;
    if (parsed < 0) {
        if (parsed != -3) {
            struct metrics_val *m = tc_get_metrics();
            if (m) __sync_fetch_and_add(&m->packet_parse_failures, 1);
        }
        return TC_ACT_OK;
    }
    if (headers.network_offset > 22 || headers.l4_offset > 16446)
        return TC_ACT_OK;
    struct ip_key src_key = {}, dst_key = {};
    if (headers.family == 2) {
        struct iphdr *ip = data + headers.network_offset;
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
        ip_key_from_v4(&src_key, ip->saddr);
        ip_key_from_v4(&dst_key, ip->daddr);
    } else {
        struct ipv6hdr *ip = data + headers.network_offset;
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
        ip_key_from_v6(&src_key, &ip->saddr);
        ip_key_from_v6(&dst_key, &ip->daddr);
    }

    __u32 pkt_len = data_end - data;
    __u64 now_ns = bpf_ktime_get_ns();


    /* Bandwidth accounting (ingress) */
    update_bandwidth(&src_key, pkt_len, 0, now_ns);

    if (headers.proto == IPPROTO_TCP) {
        volatile __u32 wire_offset = headers.l4_offset;
        __u32 l4_offset = wire_offset;
        if (l4_offset > 16446) return TC_ACT_OK;
        struct tcphdr *tcph = data + l4_offset;
        if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;

        __u8 tcp_flags = ((__u8 *)tcph)[13];

        /* TCP flag anomaly detection */
        int action = check_tcp_anomaly(tcp_flags);
        if (action != ACTION_ALLOW) {
            struct perf_event_data evt = {
                .timestamp_ns = now_ns,
                .pkt_len = pkt_len,
                .proto = IPPROTO_TCP,
                .action = action == ACTION_DROP && cfg->mode == 1 ? ACTION_WOULD_DROP : (__u8)action,
                .reason = EVENT_REASON_CONNTRACK,
                .tcp_flags = tcp_flags,
                .src_port = tcph->source,
                .dst_port = tcph->dest,
            };
            __builtin_memcpy(&evt.src_ip, &src_key, sizeof(src_key));
            __builtin_memcpy(&evt.dst_ip, &dst_key, sizeof(dst_key));
            tc_emit_event(skb, &evt);

            if (action == ACTION_DROP) {
                record_firewall_drop(tc_get_metrics(), pkt_len, cfg->mode);
                if (cfg->mode == 0) return TC_ACT_SHOT;
            }
        }
    }

    return TC_ACT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK: PORT POLICY (egress port allow/deny)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* live_port_rule / match_port_rule: same lookup order and expiry
 * fall-through as XDP (wafio_xdp.c) and the Go lockout guard. */
static __always_inline struct port_policy_val *
live_port_rule(struct port_policy_key *k, __u64 now_ns) {
    struct port_policy_val *pv = bpf_map_lookup_elem(&wafio_port_policy, k);
    if (pv && pv->expires_ns != 0 && pv->expires_ns <= now_ns)
        return NULL;
    return pv;
}

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
check_port_policy_egress(__u16 dport_host, __u8 proto, __u64 now_ns) {
    __u32 cfg_key = 0;
    struct port_policy_config *pcfg = bpf_map_lookup_elem(&wafio_port_policy_config, &cfg_key);
    if (!pcfg || !pcfg->enabled)
        return ACTION_ALLOW;

    struct port_policy_val *pv = match_port_rule(dport_host, proto, PORT_DIR_EGRESS, now_ns);
    if (pv) {
        __sync_fetch_and_add(&pv->hit_count, 1);
        return pv->action;
    }
    if (pcfg->default_egress == 1)
        return ACTION_DROP;
    return ACTION_ALLOW;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK: EGRESS IP BLOCKLIST
 * ═══════════════════════════════════════════════════════════════════════════ */

/* skip_wildcard: the packet answers a tracked inbound connection; a
 * family-wide egress block (0.0.0.0/0, ::/0) then does not apply.
 * Specific IP and subnet entries still do. */
static __always_inline int
check_egress_ip(struct ip_key *dst_ip, __u64 now_ns, int skip_wildcard) {
    struct ip_list_val *block = bpf_map_lookup_elem(&wafio_egress_blocklist, dst_ip);
    if (block) {
        if (block->expires_ns != 0 && block->expires_ns <= now_ns) {
            bpf_map_delete_elem(&wafio_egress_blocklist, dst_ip);
        } else {
            __sync_fetch_and_add(&block->hit_count, 1);
            return ACTION_DROP;
        }
    }

    /* Subnet CIDR LPM Trie check for egress */
    if (dst_ip->family == AF_INET) {
        struct subnet_v4_key lpm_k = {
            .prefixlen = 32,
            .addr = dst_ip->addr.v4,
        };
        struct subnet_val *sub = bpf_map_lookup_elem(&wafio_egress_subnet_v4, &lpm_k);
        if (sub) {
            if (sub->expires_ns == 0 || sub->expires_ns > now_ns) {
                __sync_fetch_and_add(&sub->hit_count, 1);
                return ACTION_DROP;
            }
        }
    } else if (dst_ip->family == AF_INET6) {
        struct subnet_v6_key lpm_k = {
            .prefixlen = 128,
        };
        __builtin_memcpy(lpm_k.addr, &dst_ip->addr.v6, 16);
        struct subnet_val *sub = bpf_map_lookup_elem(&wafio_egress_subnet_v6, &lpm_k);
        if (sub) {
            if (sub->expires_ns == 0 || sub->expires_ns > now_ns) {
                __sync_fetch_and_add(&sub->hit_count, 1);
                return ACTION_DROP;
            }
        }
    }

    /* Family-specific wildcard sentinel — block destinations in that family */
    if (skip_wildcard)
        return ACTION_ALLOW;
    struct ip_key wc = {};
    wc.family = dst_ip->family == 10 ? 0xFE : 0xFD;
    struct ip_list_val *wc_block = bpf_map_lookup_elem(&wafio_egress_blocklist, &wc);
    if (wc_block) {
        if (wc_block->expires_ns == 0 || wc_block->expires_ns > now_ns) {
            __sync_fetch_and_add(&wc_block->hit_count, 1);
            return ACTION_DROP;
        }
        bpf_map_delete_elem(&wafio_egress_blocklist, &wc);
    }
    return ACTION_ALLOW;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  EXEMPTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* tc_control_plane: the destination is the agent's configured control plane. */
static __always_inline int
tc_control_plane(struct ip_key *dst, __be16 dport, __u8 proto) {
    if (proto != IPPROTO_TCP || dport == 0)
        return 0;
    struct cp_endpoint_key k = {};
    __builtin_memcpy(&k.ip, dst, sizeof(*dst));
    k.port = dport;
    k.proto = proto;
    return bpf_map_lookup_elem(&wafio_cp_endpoints, &k) != NULL;
}

#define INBOUND_ABSENT  0 /* no entry in either direction */
#define INBOUND_FRESH   1
#define INBOUND_STALE   2
#define INBOUND_FOREIGN 3 /* an entry of a flow this host opened */

#define DHCP_NONE   0
#define DHCP_EXEMPT 1

/* tc_dhcp_client: DHCP client requests pass egress Deny All and family-wide
 * egress blocks only to where a client legitimately sends them:
 * a DHCPv4 BOOTREQUEST to 255.255.255.255 (its xid and chaddr
 * are recorded for XDP) or to a server that answered one within
 * DHCP_SERVER_TTL_NS; DHCPv6 from a link-local address to ff02::1:2 — and
 * only DHCP-sized. */
static __always_inline int
tc_dhcp_client(struct packet_headers *h, void *data, void *data_end,
               struct ip_key *dst_key, __be16 sport, __be16 dport,
               __u32 udp_len, __u64 now_ns) {
    if (h->proto != IPPROTO_UDP || udp_len > DHCP_MAX_UDP_LEN)
        return DHCP_NONE;
    if (h->family == 2) {
        if (sport != bpf_htons(68) || dport != bpf_htons(67) || udp_len < DHCP4_MIN_UDP_LEN)
            return DHCP_NONE;
        volatile __u32 wire_offset = h->l4_offset;
        __u32 off = wire_offset;
        if (off > 16446)
            return DHCP_NONE;
        __u8 *bootp = data + off + sizeof(struct udphdr);
        if ((void *)(bootp + DHCP_BOOTP_MIN) > data_end || bootp[0] != 1) /* BOOTREQUEST */
            return DHCP_NONE;
        if (dst_key->addr.v4 == 0xFFFFFFFF) {
            __u32 xid;
            __builtin_memcpy(&xid, bootp + 4, 4);
            struct dhcp_pending_val pending = { .sent_ns = now_ns };
            __builtin_memcpy(pending.chaddr, bootp + 28, 6);
            bpf_map_update_elem(&wafio_dhcp_pending, &xid, &pending, BPF_ANY);
            return DHCP_EXEMPT;
        }
        __be32 server = dst_key->addr.v4;
        __u64 *learned = bpf_map_lookup_elem(&wafio_dhcp_servers, &server);
        if (learned && now_ns >= *learned && now_ns - *learned < DHCP_SERVER_TTL_NS)
            return DHCP_EXEMPT;
        return DHCP_NONE;
    }
    if (h->family != 10 || sport != bpf_htons(546) || dport != bpf_htons(547) ||
        udp_len < DHCP6_MIN_UDP_LEN || h->network_offset > 22)
        return DHCP_NONE;
    struct ipv6hdr *ip6 = data + h->network_offset;
    if ((void *)(ip6 + 1) > data_end)
        return DHCP_NONE;
    if (ip6->saddr.in6_u.u6_addr8[0] != 0xfe || (ip6->saddr.in6_u.u6_addr8[1] & 0xc0) != 0x80)
        return DHCP_NONE;
    if (ip6->daddr.in6_u.u6_addr32[0] != bpf_htonl(0xff020000) || ip6->daddr.in6_u.u6_addr32[1] != 0 ||
        ip6->daddr.in6_u.u6_addr32[2] != 0 || ip6->daddr.in6_u.u6_addr32[3] != bpf_htonl(0x00010002))
        return DHCP_NONE;
    return DHCP_EXEMPT;
}

/* tc_inbound_state: is this outbound packet the reply side of an inbound
 * connection XDP accepted? XDP keys that entry by the inbound direction
 * (remote → local). Entries carrying CONN_OUTBOUND or CONN_REPLY belong to a
 * flow this host opened and never count. An established TCP connection
 * (tcp_state 1) stays fresh for CONN_TCP_EST_TTL_NS, anything else for the
 * normal TTL. *entry receives the entry so the caller can refresh it, and
 * check a TCP entry without CONN_VERIFIED (tc_verify_inbound). */
static __always_inline int
tc_inbound_state(struct ip_key *local, struct ip_key *remote,
                 __be16 lport, __be16 rport, __u8 proto, __u64 now_ns,
                 struct conn_val **entry) {
    struct conn_key ik = {};
    __builtin_memcpy(&ik.src, remote, sizeof(*remote));
    __builtin_memcpy(&ik.dst, local, sizeof(*local));
    ik.sport = rport;
    ik.dport = lport;
    ik.proto = proto;
    struct conn_val *iv = bpf_map_lookup_elem(&wafio_conntrack, &ik);
    if (!iv)
        return INBOUND_ABSENT;
    if (iv->flags_seen & (CONN_OUTBOUND | CONN_REPLY))
        return INBOUND_FOREIGN;
    *entry = iv;
    __u64 ttl = CONN_UDP_TTL_NS;
    if (proto == IPPROTO_TCP)
        ttl = iv->tcp_state == 1 ? CONN_TCP_EST_TTL_NS : CONN_TCP_TTL_NS;
    if (ct_fresh(now_ns, iv->last_seen_ns, ttl))
        return INBOUND_FRESH;
    return INBOUND_STALE;
}

/* tc_bare_rst: 1 for a reset that may pass an unverified inbound entry without
 * the check (tc_verify_inbound) — the host's answer to a SYN on a closed port,
 * or the reset of a socket already closed, which no socket lookup finds.
 * off_flags and flags are bytes 12 and 13 of the TCP header. Only RST or
 * RST|ACK with the reserved/AE bits clear, a header of at least 20 bytes, no
 * payload — nothing past the header up to skb_len, the length of the whole
 * packet from l4_offset's origin, so bytes past the IP length count too —
 * and not a fragment (the rest of its datagram would follow it). Anything else
 * with RST set goes through the check: a reset carrying data or other flags
 * passed egress Deny All. */
static __always_inline int
tc_bare_rst(__u8 off_flags, __u8 flags, __u32 l4_offset, __u32 skb_len, int fragment) {
    __u32 doff = off_flags >> 4;
    return !fragment && (off_flags & 0x0f) == 0 && (flags == 0x04 || flags == 0x14) &&
           doff >= 5 && skb_len == l4_offset + doff * 4;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PACKETS WITHOUT READABLE PORTS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* egress_default_deny: egress Deny All is in force. */
static __always_inline int
egress_default_deny(void) {
    __u32 k = 0;
    struct port_policy_config *pcfg = bpf_map_lookup_elem(&wafio_port_policy_config, &k);
    return pcfg && pcfg->enabled && pcfg->default_egress == 1;
}

/* egress_port_rules_on: the port policy is enabled, so some port may be
 * denied on egress (a port-specific DROP rule, or Deny All). */
static __always_inline int
egress_port_rules_on(void) {
    __u32 k = 0;
    struct port_policy_config *pcfg = bpf_map_lookup_elem(&wafio_port_policy_config, &k);
    return pcfg && pcfg->enabled;
}

/* tc_unverifiable_reason: a packet whose ports cannot be read. Returns 0
 * (pass) or the EVENT_REASON_* of the drop; fk carries the addresses when
 * have_ip.
 *  - A TCP fragment at offset 8 exists only to rewrite the first fragment's
 *    flags (RFC 1858): always dropped.
 *  - A later fragment (offset > 0) whose first fragment passed
 *    (wafio_frag_pass, same src, dst, protocol and id) passes. Without one it
 *    fails closed only when the destination matches an egress block (the
 *    family-wide one included: no reply exemption can be proven without
 *    ports) or egress Deny All is on: a port rule has nothing to match, and
 *    the first fragment, which carries the ports, met the rule.
 *  - Anything else has an L4 header that should be there and cannot be read
 *    — a first fragment whose L4 header is cut (tiny fragment), or a packet
 *    the parser rejects (-1; -2 for >2 VLAN tags or a long IPv6 extension
 *    chain; -3 still cut after bpf_skb_pull_data): fails closed on a
 *    matching egress block or whenever the port policy is enabled, since a
 *    port-specific DROP rule might cover its unreadable port. */
static __always_inline int
tc_unverifiable_reason(struct packet_headers *h, struct frag_key *fk,
                       int have_ip, __u64 now_ns) {
    int later = (h->parse_flags & PH_FRAGMENT) && h->frag_offset;
    if (later && h->frag_proto == IPPROTO_TCP && h->frag_offset == 1)
        return EVENT_REASON_PACKET_PARSE;
    if (have_ip && later) {
        fk->id = h->frag_id;
        fk->proto = h->frag_proto;
        __u64 *passed = bpf_map_lookup_elem(&wafio_frag_pass, fk);
        if (passed && now_ns >= *passed && now_ns - *passed < FRAG_PASS_TTL_NS) {
            if (!(h->parse_flags & PH_FRAG_MORE))
                bpf_map_delete_elem(&wafio_frag_pass, fk);
            return 0;
        }
    }
    if (have_ip && check_egress_ip(&fk->dst, now_ns, 0) == ACTION_DROP)
        return EVENT_REASON_EGRESS_IP;
    if (later ? egress_default_deny() : egress_port_rules_on())
        return EVENT_REASON_PORT_POLICY;
    return 0;
}

/* tc_egress_unverifiable: TC egress verdict for a packet without readable
 * ports. Monitor mode counts the would-drop and passes. */
static __always_inline int
tc_egress_unverifiable(struct __sk_buff *skb, struct global_config *cfg,
                       void *data, void *data_end, struct packet_headers *h) {
    __u64 now_ns = bpf_ktime_get_ns();
    __u32 pkt_len = data_end - data;
    struct metrics_val *metrics = tc_get_metrics();
    if (metrics) {
        __sync_fetch_and_add(&metrics->tx_packets, 1);
        __sync_fetch_and_add(&metrics->tx_bytes, pkt_len);
        if (!(h->parse_flags & PH_FRAGMENT))
            __sync_fetch_and_add(&metrics->packet_parse_failures, 1);
    }
    struct frag_key fk = {};
    int have_ip = 0;
    if (h->network_offset <= 22) {
        if (h->family == 2) {
            struct iphdr *ip = data + h->network_offset;
            if ((void *)(ip + 1) <= data_end) {
                ip_key_from_v4(&fk.src, ip->saddr);
                ip_key_from_v4(&fk.dst, ip->daddr);
                have_ip = 1;
            }
        } else if (h->family == 10) {
            struct ipv6hdr *ip = data + h->network_offset;
            if ((void *)(ip + 1) <= data_end) {
                ip_key_from_v6(&fk.src, &ip->saddr);
                ip_key_from_v6(&fk.dst, &ip->daddr);
                have_ip = 1;
            }
        }
    }
    int reason = tc_unverifiable_reason(h, &fk, have_ip, now_ns);
    if (!reason)
        return TC_ACT_OK;
    if (metrics) {
        record_firewall_drop(metrics, pkt_len, cfg->mode);
        if (cfg->mode != 1) {
            if (reason == EVENT_REASON_EGRESS_IP)
                __sync_fetch_and_add(&metrics->egress_ip_drops, 1);
            else if (reason == EVENT_REASON_PORT_POLICY)
                __sync_fetch_and_add(&metrics->port_policy_drops, 1);
        }
    }
    if (cfg->log_blocked) {
        struct perf_event_data evt = {
            .timestamp_ns = now_ns,
            .pkt_len = pkt_len,
            .proto = h->proto,
            .action = cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP,
            .reason = (__u8)reason,
        };
        __builtin_memcpy(&evt.src_ip, &fk.src, sizeof(fk.src));
        __builtin_memcpy(&evt.dst_ip, &fk.dst, sizeof(fk.dst));
        tc_emit_event(skb, &evt);
    }
    return cfg->mode == 1 ? TC_ACT_OK : TC_ACT_SHOT;
}

/* tc_frag_passed: a first fragment passed egress policy; admit the later
 * fragments of its datagram. */
static __always_inline void
tc_frag_passed(struct packet_headers *h, struct ip_key *src, struct ip_key *dst, __u64 now_ns) {
    struct frag_key fk = {};
    __builtin_memcpy(&fk.src, src, sizeof(*src));
    __builtin_memcpy(&fk.dst, dst, sizeof(*dst));
    fk.id = h->frag_id;
    fk.proto = h->frag_proto;
    bpf_map_update_elem(&wafio_frag_pass, &fk, &now_ns, BPF_ANY);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  TC EGRESS — enterprise outbound firewall
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Inbound flows TC finds without proof. The
 * socket tuple and the entries tc_adopt_inbound writes live in a per-CPU map
 * value: the packet program's stack has no room. */
struct adopt_buf {
    struct bpf_sock_tuple t;
    struct conn_key ik;
    struct conn_val nv;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct adopt_buf);
} wafio_adopt_buf SEC(".maps");

/* tc_adopt_lookup: bpf_sk_lookup_tcp for the packet seen from the client side
 * (saddr = the packet's destination). client_sport is the client's port, or 0
 * to match the listener only. Returns the socket state, or -1 for none. */
static __always_inline int
tc_adopt_lookup(struct __sk_buff *skb, struct adopt_buf *b, struct conn_key *ck, __be16 client_sport) {
    struct bpf_sock *sk;
    __builtin_memset(&b->t, 0, sizeof(b->t));
    if (ck->src.family == 2) {
        b->t.ipv4.saddr = ck->dst.addr.v4;
        b->t.ipv4.daddr = ck->src.addr.v4;
        b->t.ipv4.sport = client_sport;
        b->t.ipv4.dport = ck->sport;
        sk = bpf_sk_lookup_tcp(skb, &b->t, sizeof(b->t.ipv4), BPF_F_CURRENT_NETNS, 0);
    } else {
        __builtin_memcpy(b->t.ipv6.saddr, &ck->dst.addr.v6, 16);
        __builtin_memcpy(b->t.ipv6.daddr, &ck->src.addr.v6, 16);
        b->t.ipv6.sport = client_sport;
        b->t.ipv6.dport = ck->sport;
        sk = bpf_sk_lookup_tcp(skb, &b->t, sizeof(b->t.ipv6), BPF_F_CURRENT_NETNS, 0);
    }
    if (!sk)
        return -1;
    int state = sk->state;
    bpf_sk_release(sk);
    return state;
}

/* tc_inbound_socket: 1 when the kernel accepted the connection of the
 * outbound key ck — it holds a socket for exactly this 4-tuple in an
 * established-side state AND a TCP listener owns the local port.
 *
 * Both checks are needed. The 4-tuple lookup limits the exemption to tuples the
 * kernel holds a connection for: a lone ACK sourced from a listening port
 * (sshd :22) to a peer the host has no connection with — to any destination,
 * or to a remote that sent to that port first — is neither adopted nor
 * verified. A full tuple never matches a listener, but a request or time-wait
 * socket can come back: only an established-side state counts. The listener
 * lookup (sport 0, so only the listener matches; a dual-stack [::] listener
 * matches IPv4 too) separates an accepted connection from one the host opened
 * itself.
 *
 * This does not make egress Deny All a boundary for root or CAP_NET_RAW: such
 * a process can send on the tuple of a real inbound connection, and
 * tc_verify_inbound's SYN-ACK path verifies an entry without any socket lookup
 * (a forged SYN-ACK answering a remote's SYN). */
static __always_inline int
tc_inbound_socket(struct __sk_buff *skb, struct adopt_buf *b, struct conn_key *ck) {
    int state = tc_adopt_lookup(skb, b, ck, ck->dport);
    if (state != BPF_TCP_ESTABLISHED && state != BPF_TCP_CLOSE_WAIT &&
        state != BPF_TCP_FIN_WAIT1 && state != BPF_TCP_FIN_WAIT2 &&
        state != BPF_TCP_CLOSING && state != BPF_TCP_LAST_ACK)
        return 0;
    return tc_adopt_lookup(skb, b, ck, 0) == BPF_TCP_LISTEN;
}

/* tc_verify_inbound: a TCP entry XDP created (remote → local) is not proof of
 * an inbound connection. When a flow this host opened predates the attach,
 * or lost its entries, and the remote side speaks first, XDP records the
 * remote's packet like an inbound one; exempting the host's packets then let
 * the flow outlive egress Deny All and family-wide egress blocks for as long
 * as it stayed active. A remote can also send a SYN or SYN-ACK on the tuple
 * first, so a SYN in flags_seen proves nothing by itself. Checked once per
 * entry, on the host's first packet of the flow that is not a bare reset
 * (tc_bare_rst):
 *   - a SYN-ACK answering the SYN XDP saw: the host accepted the connection
 *     (also through DNAT to a listener in another namespace) → verified;
 *   - otherwise the socket check (tc_inbound_socket) → verified;
 *   - none → CONN_REPLY: the flow is host-opened, the packet meets the egress
 *     policy, and step 5 tracks the flow as CONN_OUTBOUND once it passes.
 * b may be NULL (no scratch value): only the SYN-ACK can verify then.
 * Returns the inbound state for the caller.
 *
 * The marks are set with a plain read-modify-write, not an atomic OR: the
 * fetch/OR atomics need Linux 5.12 and 5.8–5.11 reject the whole object.
 * XDP's update_conntrack writes flags_seen the same way (|= on a hit,
 * a whole value on a miss), so a concurrent XDP update can drop TC's mark. A
 * lost CONN_REPLY only means the next host packet is checked again (same
 * result); a lost CONN_VERIFIED means a re-check too, which fails for a
 * connection whose socket is not in the host namespace (DNAT) or whose
 * listener has gone — the entry then turns CONN_REPLY. */
static __always_inline int
tc_verify_inbound(struct __sk_buff *skb, struct adopt_buf *b, struct conn_key *ck,
                  struct conn_val *iv, __u32 tcp_flags) {
    int verified = (iv->flags_seen & 0x02) && (tcp_flags & 0x12) == 0x12;
    if (!verified)
        verified = b && tc_inbound_socket(skb, b, ck);
    if (verified) {
        iv->flags_seen |= CONN_VERIFIED;
        return INBOUND_FRESH;
    }
    iv->flags_seen |= CONN_REPLY;
    return INBOUND_FOREIGN;
}

/* tc_adopt_inbound: a flow first seen mid-flow at egress with no entry
 * in either direction is the reply side of an inbound connection when the
 * kernel accepted it (tc_inbound_socket) — a session that predates the attach
 * (SSH) whose first packet after the attach is one the host sends. Treating it
 * as host-opened put it under the egress port policy with the client's
 * ephemeral port as destination and stalled it under Deny All. On a hit the
 * inbound entry is created here, exactly as XDP would have written it, and
 * already verified. */
static __always_inline int
tc_adopt_inbound(struct __sk_buff *skb, struct adopt_buf *b, struct conn_key *ck,
                 __u32 tcp_flags, __u64 now_ns) {
    if (!tc_inbound_socket(skb, b, ck))
        return 0;
    __builtin_memset(&b->ik, 0, sizeof(b->ik));
    __builtin_memcpy(&b->ik.src, &ck->dst, sizeof(b->ik.src));
    __builtin_memcpy(&b->ik.dst, &ck->src, sizeof(b->ik.dst));
    b->ik.sport = ck->dport;
    b->ik.dport = ck->sport;
    b->ik.proto = IPPROTO_TCP;
    __builtin_memset(&b->nv, 0, sizeof(b->nv));
    b->nv.first_seen_ns = now_ns;
    b->nv.last_seen_ns = now_ns;
    b->nv.tcp_state = 1;
    b->nv.flags_seen = tcp_flags | CONN_VERIFIED;
    if (bpf_map_update_elem(&wafio_conntrack, &b->ik, &b->nv, BPF_NOEXIST) == 0) {
        struct metrics_val *m = tc_get_metrics();
        if (m) __sync_fetch_and_add(&m->conntrack_entries, 1);
    }
    return 1;
}

/* tc_host_segment: the host sent a TCP segment on an inbound
 * connection XDP tracks. A reset closes it (tcp_state 3); any other segment
 * but a SYN marks CONN_HOST_ACKED, which the XDP per-IP rate limit requires
 * before it spares the connection. Plain read-modify-write, as elsewhere.
 * Out of line, returning nothing the caller reads, so its branches
 * do not multiply the egress program's verifier states. */
static __noinline int
tc_host_segment(struct conn_val *iv, __u32 tcp_flags) {
    if (tcp_flags & 0x04)
        iv->tcp_state = 3;
    else if (!(tcp_flags & 0x02) && !(iv->flags_seen & CONN_HOST_ACKED))
        iv->flags_seen |= CONN_HOST_ACKED;
    return 0;
}

/* tc_confirm_inbound: tc_adopt_inbound (iv NULL: no entry in either
 * direction) or tc_verify_inbound (iv: an inbound entry not yet verified)
 * behind one out-of-line call. A single call site keeps the packet program's
 * own frame small: with parse_packet it must fit the 512-byte stack limit
 * at -mcpu=v1 (TestTCStackHeadroom). Returns the new inbound state. */
static __noinline int
tc_confirm_inbound(struct __sk_buff *skb, struct conn_key *ck, struct conn_val *iv,
                   __u32 tcp_flags, __u64 now_ns) {
    __u32 zero = 0;
    struct adopt_buf *b = bpf_map_lookup_elem(&wafio_adopt_buf, &zero);
    if (!iv)
        return b && tc_adopt_inbound(skb, b, ck, tcp_flags, now_ns) ? INBOUND_FRESH : INBOUND_ABSENT;
    return tc_verify_inbound(skb, b, ck, iv, tcp_flags);
}

/* tc_egress_drop_event: the egress drop event is built in a per-CPU scratch
 * value, not on the stack. wafio_tc_egress plus parse_packet sit near the
 * 512-byte BPF stack limit (TestTCStackHeadroom), and the event (64 bytes) is
 * only needed on the two drop paths. Every field is written each time, so a
 * stale value never leaks. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct perf_event_data);
} wafio_tc_evt_buf SEC(".maps");

static __always_inline void
tc_egress_drop_event(struct __sk_buff *skb, struct global_config *cfg,
                     struct ip_key *src, struct ip_key *dst, __be16 sport, __be16 dport,
                     __u8 proto, __u32 pkt_len, __u64 now_ns, __u8 reason) {
    __u32 zero = 0;
    struct perf_event_data *evt = bpf_map_lookup_elem(&wafio_tc_evt_buf, &zero);
    if (!evt)
        return;
    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = now_ns;
    __builtin_memcpy(&evt->src_ip, src, sizeof(*src));
    __builtin_memcpy(&evt->dst_ip, dst, sizeof(*dst));
    evt->src_port = sport;
    evt->dst_port = dport;
    evt->proto = proto;
    evt->action = cfg->mode == 1 ? ACTION_WOULD_DROP : ACTION_DROP;
    evt->reason = reason;
    evt->pkt_len = pkt_len;
    tc_emit_event(skb, evt);
}

SEC("tc")
int wafio_tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct global_config *cfg = tc_get_config();
    if (!cfg || !cfg->enabled) return TC_ACT_OK;
    struct packet_headers headers = {};
    int parsed = parse_packet(data, data_end, &headers);
    if (!parsed) return TC_ACT_OK;
    /* -3: the L4 header lies past the linear part of the skb. Pull it in (L4
     * offset + the largest TCP header) and check the L4 header again; still
     * cut, or the pull failed → no readable ports, handled below. */
    if (parsed == -3) {
        __u32 want = headers.l4_offset + 60;
        if (want > skb->len)
            want = skb->len;
        long pulled = bpf_skb_pull_data(skb, want);
        /* The helper invalidates every packet pointer even when it fails:
         * reload both before anything reads the packet again, then every
         * pointer below is derived from these and bounds-checked anew
         * (the stale pair made the verifier reject the program). */
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        if (pulled == 0)
            parsed = reparse_l4(data, data_end, &headers);
    }
    /* A first fragment with a complete L4 header is policed below like
     * any packet (and admits the rest of its datagram, step 6); any other
     * fragment and anything the parser rejects (-1, -2, -3) has no readable
     * ports. */
    int frag_head = parsed == -2 && (headers.parse_flags & PH_FRAG_L4);
    if (parsed < 0 && !frag_head)
        return tc_egress_unverifiable(skb, cfg, data, data_end, &headers);
    if (headers.network_offset > 22 || headers.l4_offset > 16446)
        return TC_ACT_OK;
    struct ip_key src_key = {}, dst_key = {};
    if (headers.family == 2) {
        struct iphdr *ip = data + headers.network_offset;
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
        ip_key_from_v4(&src_key, ip->saddr);
        ip_key_from_v4(&dst_key, ip->daddr);
    } else {
        struct ipv6hdr *ip = data + headers.network_offset;
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
        ip_key_from_v6(&src_key, &ip->saddr);
        ip_key_from_v6(&dst_key, &ip->daddr);
    }

    __u32 pkt_len = data_end - data;
    __u64 now_ns = bpf_ktime_get_ns();


    /* Bandwidth accounting (egress) */
    update_bandwidth(&dst_key, pkt_len, 1, now_ns);

    /* Counters are looked up where they are counted: a pointer that may be
     * NULL, kept live through every check, doubles the states the verifier
     * explores at each later branch (wafio_xdp.c, xdp_event_rule). */
    struct metrics_val *tx = tc_get_metrics();
    if (tx) {
        __sync_fetch_and_add(&tx->tx_packets, 1);
        __sync_fetch_and_add(&tx->tx_bytes, pkt_len);
    }

    /* ── 0. IPv6 neighbour discovery to link-local/multicast passes ────── */
    if (ipv6_nd_to_link(data, data_end, &headers))
        return TC_ACT_OK;

    /* ── 1. L4 ports (the exemptions below need them) ─────────────────── */
    /* A truncated L4 header still meets the egress IP blocklist, then
     * passes as before; it never reaches the port filter. */
    __u8 tcp_flags = 0;
    __be16 dport = 0;
    __be16 sport = 0;
    __u32 udp_len = 0;
    int l4_short = 0;
    int bare_rst = 0;
    if (headers.proto == IPPROTO_TCP) {
        volatile __u32 wire_offset = headers.l4_offset;
        __u32 l4_offset = wire_offset;
        if (l4_offset > 16446) return TC_ACT_OK;
        struct tcphdr *tcph = data + l4_offset;
        if ((void *)(tcph + 1) > data_end) {
            l4_short = 1;
        } else {
            tcp_flags = ((__u8 *)tcph)[13];
            sport = tcph->source;
            dport = tcph->dest;
            bare_rst = tc_bare_rst(((__u8 *)tcph)[12], tcp_flags, l4_offset, skb->len, frag_head);
        }
    } else if (headers.proto == IPPROTO_UDP) {
        volatile __u32 wire_offset = headers.l4_offset;
        __u32 l4_offset = wire_offset;
        if (l4_offset > 16446) return TC_ACT_OK;
        struct udphdr *udph = data + l4_offset;
        if ((void *)(udph + 1) > data_end) {
            l4_short = 1;
        } else {
            sport = udph->source;
            dport = udph->dest;
            udp_len = bpf_ntohs(udph->len);
        }
    }
    /* ── 2. Exemptions ────────────────────────────────────────────────── */
    /* cp_peer: the agent's control plane — never cut by egress policy.
     * host_flow: a flow this host opened (CONN_OUTBOUND); egress policy
     * applies to it in full, even when XDP holds an entry for its replies.
     * inbound: the reply side of an inbound connection XDP accepted (SSH
     * session, served request). Fresh → exempt from the egress port filter
     * and family-wide egress blocks: replies never need a rule. A TCP entry
     * counts only once verified (tc_verify_inbound, one check per entry; a
     * bare reset, tc_bare_rst, passes without it). Specific egress IP/subnet
     * blocks still apply to every exemption except cp_peer. */
    int cp_peer = tc_control_plane(&dst_key, dport, headers.proto);
    int track = (cfg->enable_conntrack || cp_peer) && sport != 0 && dport != 0;
    struct conn_key ck = {};
    struct conn_val *cv = NULL;
    int host_flow = 0;
    int inbound = INBOUND_ABSENT;
    struct conn_val *iv = NULL;
    if (track) {
        __builtin_memcpy(&ck.src, &src_key, sizeof(src_key));
        __builtin_memcpy(&ck.dst, &dst_key, sizeof(dst_key));
        ck.sport = sport;
        ck.dport = dport;
        ck.proto = headers.proto;
        cv = bpf_map_lookup_elem(&wafio_conntrack, &ck);
        host_flow = cv && (cv->flags_seen & CONN_OUTBOUND);
        if (!cp_peer && !host_flow && cfg->enable_conntrack)
            inbound = tc_inbound_state(&src_key, &dst_key, sport, dport,
                                       headers.proto, now_ns, &iv);
    }
    if (track && !cp_peer && cfg->enable_conntrack && headers.proto == IPPROTO_TCP &&
        ((inbound == INBOUND_ABSENT && !cv && (tcp_flags & 0x17) == 0x10) ||
         (inbound == INBOUND_FRESH && iv && !bare_rst && !(iv->flags_seen & CONN_VERIFIED))))
        inbound = tc_confirm_inbound(skb, &ck, iv, tcp_flags, now_ns);
    int inbound_reply = inbound == INBOUND_FRESH;
    /* Replies refresh an established inbound connection: the
     * exemption lasts while either side talks. */
    if (inbound_reply && iv && headers.proto == IPPROTO_TCP && iv->tcp_state == 1)
        iv->last_seen_ns = now_ns;
    if (iv && headers.proto == IPPROTO_TCP)
        tc_host_segment(iv, tcp_flags);
    /* A SYN-ACK needs the tracked inbound SYN like any reply (XDP tracks
     * allowlisted sources even under SYN pressure). DHCP client requests
     * keep the lease, within tc_dhcp_client's bounds. */
    int dhcp = l4_short ? DHCP_NONE :
               tc_dhcp_client(&headers, data, data_end, &dst_key, sport, dport, udp_len, now_ns);
    int exempt = inbound_reply || dhcp != DHCP_NONE;

    /* ── 3. Egress IP blocklist ───────────────────────────────────────── */
    if (!cp_peer) {
        int action = check_egress_ip(&dst_key, now_ns, exempt);
        if (action == ACTION_DROP) {
            struct metrics_val *metrics = tc_get_metrics();
            if (metrics) {
                record_firewall_drop(metrics, pkt_len, cfg->mode);
                if (cfg->mode != 1) __sync_fetch_and_add(&metrics->egress_ip_drops, 1);
            }
            if (cfg->log_blocked) {
                tc_egress_drop_event(skb, cfg, &src_key, &dst_key, sport, dport,
                                     headers.proto, pkt_len, now_ns, EVENT_REASON_EGRESS_IP);
            }
            if (cfg->mode == 1) return TC_ACT_OK; /* monitor-only */
            return TC_ACT_SHOT;
        }
    }
    if (l4_short)
        return TC_ACT_OK;

    /* ── 4. Egress port policy ────────────────────────────────────────── */
    if (dport != 0 && !cp_peer && !exempt) {
        __u16 dport_host = bpf_ntohs(dport);
        int action = check_port_policy_egress(dport_host, headers.proto, now_ns);
        if (action == ACTION_DROP) {
            struct metrics_val *metrics = tc_get_metrics();
            if (metrics) {
                record_firewall_drop(metrics, pkt_len, cfg->mode);
                if (cfg->mode != 1) __sync_fetch_and_add(&metrics->port_policy_drops, 1);
            }
            if (cfg->log_blocked) {
                tc_egress_drop_event(skb, cfg, &src_key, &dst_key, sport, dport,
                                     headers.proto, pkt_len, now_ns, EVENT_REASON_PORT_POLICY);
            }
            if (cfg->mode == 1) return TC_ACT_OK;
            return TC_ACT_SHOT;
        }
    }

    /* ── 5. Track outbound flows for stateful reply handling ───────────── */
    /* Replies of an inbound connection are not tracked here (XDP owns that
     * entry). Any other flow gets a CONN_OUTBOUND entry: on SYN (expects a
     * SYN-ACK, state 0), and on a mid-flow ACK of a flow no map knows
     * (state 1), so connections that predate an agent restart or a map
     * reset keep receiving their replies under ingress Deny All. */
    if (track && !inbound_reply) {
        __u64 ttl = headers.proto == IPPROTO_TCP ? CONN_TCP_TTL_NS : CONN_UDP_TTL_NS;
        if (headers.proto == IPPROTO_TCP && (tcp_flags & 0x05)) {
            bpf_map_delete_elem(&wafio_conntrack, &ck);
        } else if (host_flow && cv && ct_fresh(now_ns, cv->last_seen_ns, ttl)) {
            cv->last_seen_ns = now_ns;
            __sync_fetch_and_add(&cv->packets, 1);
            __sync_fetch_and_add(&cv->bytes, pkt_len);
        } else if (headers.proto == IPPROTO_UDP ||
                   (tcp_flags & 0x12) == 0x02 ||
                   ((tcp_flags & 0x12) == 0x10 && (host_flow || inbound == INBOUND_ABSENT || inbound == INBOUND_FOREIGN))) {
            struct conn_val initial = {
                .first_seen_ns = now_ns,
                .last_seen_ns = now_ns,
                .packets = 1,
                .bytes = pkt_len,
                .tcp_state = (tcp_flags & 0x12) == 0x10 ? 1 : 0,
                .flags_seen = CONN_OUTBOUND | tcp_flags,
            };
            if (bpf_map_update_elem(&wafio_conntrack, &ck, &initial, BPF_ANY) == 0) {
                struct metrics_val *metrics = tc_get_metrics();
                if (metrics)
                    __sync_fetch_and_add(&metrics->conntrack_entries, 1);
            }
        }
    }

    /* ── 6. A first fragment passed: admit its later fragments ─────────── */
    if (frag_head)
        tc_frag_passed(&headers, &src_key, &dst_key, now_ns);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
