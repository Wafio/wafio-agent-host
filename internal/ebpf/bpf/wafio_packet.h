// SPDX-License-Identifier: GPL-2.0
#ifndef __WAFIO_PACKET_H__
#define __WAFIO_PACKET_H__

#ifndef barrier_var                     /* libbpf bpf_helpers.h >= 0.7 */
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

/* Supported: Ethernet + up to two VLAN tags, IPv4 options, IPv6 extension
 * chains (up to eight). Fragment reassembly is unavailable: every IP fragment
 * is -2. XDP and TC ingress reject them when the firewall is enabled; TC
 * egress reads the PH_FRAG* flags to police them without reassembly. */
struct packet_headers {
    __u32 network_offset;
    __u32 l4_offset;
    __u32 end_offset;
    /* PH_FRAGMENT: IPv4 identification (zero-extended) or IPv6 fragment
     * identification, both as on the wire. */
    __u32 frag_id;
    __u16 eth_proto;
    __u16 frag_offset;      /* PH_FRAGMENT: offset in 8-byte units */
    __u8 proto;
    __u8 family;
    /* parse_flags: PH_DECLARED_EXCEEDS — the declared IP total length exceeds
     * the linear RX buffer. Legit on virtio_net mergeable RX / scatter-gather,
     * so the packet is NOT dropped for it; the caller counts it for
     * visibility only. PH_FRAG* — see below. */
    __u8 parse_flags;
    /* PH_FRAGMENT: the protocol every fragment of the datagram names — IPv4
     * protocol, or the IPv6 fragment header's next header. */
    __u8 frag_proto;
};

#define PH_DECLARED_EXCEEDS (1 << 0)
/* An IP fragment: IPv4 MF or a non-zero offset, or an IPv6 fragment header
 * with M or a non-zero offset (atomic fragments are not). family,
 * network_offset, end_offset, proto and l4_offset are set; for a non-first
 * fragment no L4 header follows, and for IPv6 proto is the fragment
 * header's next header. */
#define PH_FRAGMENT         (1 << 1)
#define PH_FRAG_MORE        (1 << 2)   /* MF / M: more fragments follow */
/* A first fragment (offset 0) whose L4 header passed the same checks as an
 * unfragmented packet: its ports can be policed. IPv6: only when the fragment
 * header is the first extension header and the upper-layer header follows it
 * directly — how Linux fragments a datagram without per-fragment or
 * fragmentable-part extension headers (RFC 8200 4.5). Any other IPv6 first
 * fragment gets no PH_FRAG_L4 (no readable ports): walking on past a
 * fragment header tripled the verifier's work on every program that parses
 * (TC egress then hit the 1M instruction limit). */
#define PH_FRAG_L4          (1 << 3)

/* parse_l4: bounds of the TCP/UDP header at l4_offset. 1 = fine, -3 = cut
 * by the buffer, -1 = beyond the declared IP length (end_offset) or
 * invalid. */
static __always_inline int
parse_l4(void *data, void *data_end, __u32 l4_offset, __u32 end_offset, __u8 proto) {
    if (proto == IPPROTO_TCP) {
        /* Truncation (buffer ends first) is -3: pass, virtio mergeable RX.
         * An L4 header that IS in the buffer but beyond the declared IP
         * length is a spec violation — malformed, callers drop it. */
        if (data + l4_offset + sizeof(struct tcphdr) > data_end)
            return -3;
        if (l4_offset + sizeof(struct tcphdr) > end_offset)
            return -1;
        struct tcphdr *tcp = data + l4_offset;
        __u32 len = tcp->doff * 4;
        if (len < 20)
            return -1;
        if (data + l4_offset + len > data_end)
            return -3; /* TCP options truncated by the buffer */
        if (l4_offset + len > end_offset)
            return -1; /* TCP options beyond the declared IP length */
    } else if (proto == IPPROTO_UDP) {
        if (data + l4_offset + sizeof(struct udphdr) > data_end)
            return -3;
        if (l4_offset + sizeof(struct udphdr) > end_offset)
            return -1;
        struct udphdr *udp = data + l4_offset;
        volatile __u32 wire_udp_len = bpf_ntohs(udp->len);
        __u32 len = wire_udp_len;
        if (len > 65535) return -1;
        if (len < 8 && len != 0)
            return -1;
    }
    return 1;
}

/* 1 = parsed IP, 0 = other L2 protocol (e.g. ARP), negative = malformed or
 * unsupported encapsulation. No L4 policy reads bytes outside declared IP.
 * Negative codes:
 *   -1 malformed (bad version / header lengths / sizes)
 *   -2 valid but unsupported (IP fragments, >2 VLAN tags, IPv6 ext chains);
 *      a fragment also sets PH_FRAGMENT, plus PH_FRAG_L4 for a first
 *      fragment with a complete L4 header (IPv6: see PH_FRAG_L4). A
 *      non-atomic fragment header ends the IPv6 walk, so a second one is
 *      never read
 *   -3 TRUNCATED frame — header is valid but the RX buffer ends before the
 *      declared IP total length. virtio_net mergeable RX hands XDP only the
 *      first buffer, so full-size (1500B) data frames truncate here. Dropping
 *      these in enforce mode locks the whole host out; callers must treat -3
 *      as pass-with-visibility (TC later sees the full skb). */
static __noinline int
parse_packet(void *data, void *data_end, struct packet_headers *h) {
    __builtin_memset(h, 0, sizeof(*h));
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    __u32 off = sizeof(*eth);
    __u16 protocol = bpf_ntohs(eth->h_proto);
    for (int i = 0; i < 2; i++) {
        if (protocol != 0x8100 && protocol != 0x88a8)
            break;
        __u8 *vlan = data + off;
        if ((void *)(vlan + 4) > data_end)
            return -1;
        protocol = ((__u16)vlan[2] << 8) | vlan[3];
        off += 4;
    }
    if (protocol == 0x8100 || protocol == 0x88a8)
        return -2;
    h->network_offset = off;
    h->eth_proto = protocol;
    if (protocol == ETH_P_IP) {
        struct iphdr *ip = data + off;
        if ((void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5)
            return -1;
        __u32 header_len = ip->ihl * 4;
        if (data + off + header_len > data_end)
            return -1;
        volatile __u32 wire_len = bpf_ntohs(ip->tot_len);
        __u32 len = wire_len;
        if (wire_len != 0 && len < header_len)
            return -1;
        __u16 frag = bpf_ntohs(ip->frag_off);
        h->family = 2;
        h->proto = ip->protocol;
        h->l4_offset = off + header_len;
        /* When wire_len == 0 (TSO/GSO offload super-packet) or the declared
         * total length exceeds this linear RX buffer (scatter-gather / paged
         * frags), bound end_offset to the current buffer end. The exceeds
         * case is flagged, not failed — virtio_net mergeable RX legitimately
         * truncates the linear buffer. */
        if (wire_len == 0 || data + off + len > data_end) {
            if (wire_len != 0)
                h->parse_flags |= PH_DECLARED_EXCEEDS;
            h->end_offset = (__u32)(data_end - data);
        } else {
            h->end_offset = off + len;
        }
        if (frag & 0x3fff) {
            h->parse_flags |= PH_FRAGMENT;
            if (frag & 0x2000)
                h->parse_flags |= PH_FRAG_MORE;
            h->frag_id = ip->id;
            h->frag_proto = ip->protocol;
            h->frag_offset = frag & 0x1fff;
            if (h->frag_offset)
                return -2; /* no L4 header in a non-first fragment */
        }
    } else if (protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip = data + off;
        if ((void *)(ip + 1) > data_end || ip->version != 6)
            return -1;
        if (data + off + sizeof(*ip) > data_end)
            return -1;
        volatile __u32 wire_payload = bpf_ntohs(ip->payload_len);
        __u32 payload = wire_payload;
        h->family = 10;
        if (wire_payload == 0 || data + off + sizeof(*ip) + payload > data_end) {
            h->end_offset = (__u32)(data_end - data);
        } else {
            h->end_offset = off + sizeof(*ip) + payload;
        }
        off += sizeof(*ip);
        __u8 next = ip->nexthdr;
        for (int i = 0; i < 8; i++) {
            if (next != 0 && next != 43 && next != 60 && next != 51 && next != 44)
                break;
            __u8 *ext = data + off;
            if (off + 8 > h->end_offset || (void *)(ext + 8) > data_end)
                return -1;
            __u32 len;
            if (next == 44) {
                __u16 fo = ((__u16)ext[2] << 8) | ext[3];
                if (fo & 0xfff9) {
                    h->parse_flags |= PH_FRAGMENT;
                    if (fo & 1)
                        h->parse_flags |= PH_FRAG_MORE;
                    __builtin_memcpy(&h->frag_id, ext + 4, 4);
                    h->frag_proto = ext[0];
                    h->frag_offset = fo >> 3;
                    if (h->frag_offset) {
                        h->proto = ext[0];
                        h->l4_offset = off + 8;
                        return -2; /* no upper-layer header here */
                    }
                    /* A first fragment: its ports are read only when this
                     * fragment header is the first extension header and
                     * the upper-layer header follows it (checked after
                     * the loop); otherwise -2 without PH_FRAG_L4. */
                    if (i != 0)
                        return -2;
                    next = ext[0];
                    off += 8;
                    break;
                }
                len = 8; /* atomic fragment */
            } else if (next == 51) {
                len = ((__u32)ext[1] + 2) * 4;
            } else {
                len = ((__u32)ext[1] + 1) * 8;
            }
            if (off + len > h->end_offset || data + off + len > data_end)
                return -1;
            next = ext[0];
            off += len;
        }
        if (next == 0 || next == 43 || next == 60 || next == 51 || next == 44)
            return -2;
        h->proto = next;
        h->l4_offset = off;
    } else {
        return 0;
    }
    int l4 = parse_l4(data, data_end, h->l4_offset, h->end_offset, h->proto);
    if (h->parse_flags & PH_FRAGMENT) {
        /* Still -2 for every caller, so XDP and TC ingress keep rejecting
         * fragments; TC egress polices a first fragment by the L4 header
         * checked here. */
        if (l4 == 1)
            h->parse_flags |= PH_FRAG_L4;
        return -2;
    }
    return l4;
}

/* reparse_l4: parse_packet returned -3 (an unfragmented datagram whose L4
 * header ends past the buffer) and the caller has since grown the buffer
 * (TC: bpf_skb_pull_data). The headers before L4 are where parse_packet
 * found them and passed its checks against a smaller buffer; only the
 * buffer end moved. Recomputes end_offset as parse_packet does and checks
 * the L4 header again: the result a fresh parse_packet would give, without
 * a second walk of the parser for the verifier. */
static __always_inline int
reparse_l4(void *data, void *data_end, struct packet_headers *h) {
    /* The caller's copy of the headers is plain memory to the verifier:
     * bound what feeds pointer arithmetic (parse_packet's own limits).
     * 64-bit locals and barrier_var: the checked register is the one used
     * below, not a copy the compiler zero-extends or loaded earlier. */
    __u64 off = h->network_offset;
    __u64 l4_offset = h->l4_offset;
    barrier_var(off);
    barrier_var(l4_offset);
    if (off > 22 || l4_offset > 16446)
        return -1;
    /* volatile: the byte swap leaves the value unbounded for the verifier,
     * and without it the compiler drops the explicit bound below. */
    volatile __u32 wire_len;
    if (h->family == 2) {
        struct iphdr *ip = data + off;
        if ((void *)(ip + 1) > data_end)
            return -1;
        wire_len = bpf_ntohs(ip->tot_len);
    } else {
        struct ipv6hdr *ip = data + off;
        if ((void *)(ip + 1) > data_end)
            return -1;
        wire_len = bpf_ntohs(ip->payload_len);
    }
    __u64 declared = wire_len;
    if (declared > 0xffff)
        return -1;
    if (declared && h->family != 2)
        declared += sizeof(struct ipv6hdr);
    __u32 end;
    h->parse_flags &= ~PH_DECLARED_EXCEEDS;
    if (declared == 0 || data + off + declared > data_end) {
        if (declared && h->family == 2)
            h->parse_flags |= PH_DECLARED_EXCEEDS;
        end = (__u32)(data_end - data);
    } else {
        end = off + declared;
    }
    h->end_offset = end;
    return parse_l4(data, data_end, l4_offset, end, h->proto);
}

/* ipv6_neighbour_discovery: ICMPv6 router/neighbour solicitation and
 * advertisement and redirect (types 133-137, RFC 4861) with hop limit 255,
 * i.e. a packet that never crossed a router. XDP and TC pass these before
 * any list: a ::/0 block must not cost the host its neighbours
 * and its default route. */
static __always_inline int
ipv6_neighbour_discovery(void *data, void *data_end, struct packet_headers *h) {
    if (h->family != 10 || h->proto != WAFIO_IPPROTO_ICMPV6)
        return 0;
    if (h->network_offset > 22 || h->l4_offset > 16446)
        return 0;
    struct ipv6hdr *ip6 = data + h->network_offset;
    if ((void *)(ip6 + 1) > data_end || ip6->hop_limit != 255)
        return 0;
    volatile __u32 wire = h->l4_offset;
    __u32 off = wire;
    if (off > 16446)
        return 0;
    __u8 *icmp = data + off;
    if ((void *)(icmp + 1) > data_end)
        return 0;
    return icmp[0] >= 133 && icmp[0] <= 137;
}

/* ipv6_nd_to_link: neighbour discovery the host SENDS may only go to a
 * link-local (fe80::/10) or multicast (ff00::/8) address (anything that
 * can emit ICMPv6 must not reach arbitrary destinations through the ND
 * exemption). */
static __always_inline int
ipv6_nd_to_link(void *data, void *data_end, struct packet_headers *h) {
    if (!ipv6_neighbour_discovery(data, data_end, h))
        return 0;
    if (h->network_offset > 22)
        return 0;
    struct ipv6hdr *ip6 = data + h->network_offset;
    if ((void *)(ip6 + 1) > data_end)
        return 0;
    __u8 d0 = ip6->daddr.in6_u.u6_addr8[0];
    __u8 d1 = ip6->daddr.in6_u.u6_addr8[1];
    return d0 == 0xff || (d0 == 0xfe && (d1 & 0xc0) == 0x80);
}

/* DHCP message bounds (UDP length incl. its 8-byte header): DHCPv4 needs
 * the 236-byte BOOTP header, DHCPv6 the 4-byte message header. */
#define DHCP4_MIN_UDP_LEN (8 + 236)
#define DHCP6_MIN_UDP_LEN (8 + 4)
#define DHCP_MAX_UDP_LEN  1500

#endif
