package ebpf

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// Native C harness for IP fragments on TC egress. parse_packet and
// the TC egress helpers are compiled with the host compiler, BPF helpers and
// maps mocked; the whole-program behaviour (BPF_PROG_TEST_RUN) is covered by
// TestKernelEgressFragments in the kernel lab.

const nativePacketTypes = `typedef uint8_t __u8; typedef uint16_t __u16; typedef uint32_t __u32; typedef uint64_t __u64;
typedef __u16 __be16; typedef __u32 __be32; typedef __u16 __sum16;
/* Little-endian host (arm64, x86_64), like the kernels the objects target. */
#define bpf_ntohs(x) ((__u16)((((__u16)(x)) >> 8) | (((__u16)(x)) << 8)))
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
/* Linux layouts (vmlinux.h, little-endian bitfields). */
struct ethhdr { unsigned char h_dest[6]; unsigned char h_source[6]; __be16 h_proto; } __attribute__((packed));
struct iphdr { __u8 ihl:4, version:4; __u8 tos; __be16 tot_len; __be16 id; __be16 frag_off; __u8 ttl; __u8 protocol; __sum16 check; __be32 saddr; __be32 daddr; };
struct in6_addr { union { __u8 u6_addr8[16]; __be16 u6_addr16[8]; __be32 u6_addr32[4]; } in6_u; };
struct ipv6hdr { __u8 priority:4, version:4; __u8 flow_lbl[3]; __be16 payload_len; __u8 nexthdr; __u8 hop_limit; struct in6_addr saddr; struct in6_addr daddr; };
struct tcphdr { __be16 source; __be16 dest; __be32 seq; __be32 ack_seq; __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1; __be16 window; __sum16 check; __be16 urg_ptr; };
struct udphdr { __be16 source; __be16 dest; __be16 len; __sum16 check; };
`

func ethFrame(ethType uint16, l3 []byte) []byte {
	p := make([]byte, 14, 14+len(l3))
	binary.BigEndian.PutUint16(p[12:14], ethType)
	return append(p, l3...)
}

// ipv4Frame: IPv4 header (20 bytes, tot_len = header + payload) + payload.
func ipv4Frame(proto byte, id, frag uint16, payload []byte) []byte {
	h := make([]byte, 20, 20+len(payload))
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(h[4:6], id)
	binary.BigEndian.PutUint16(h[6:8], frag)
	h[8] = 64
	h[9] = proto
	copy(h[12:16], []byte{192, 0, 2, 10})
	copy(h[16:20], []byte{198, 51, 100, 10})
	return ethFrame(0x0800, append(h, payload...))
}

// ipv6Frame: IPv6 header (payload_len = len(payload)) + payload.
func ipv6Frame(next byte, payload []byte) []byte {
	h := make([]byte, 40, 40+len(payload))
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:6], uint16(len(payload)))
	h[6] = next
	h[7] = 64
	copy(h[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10})
	copy(h[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10})
	return ethFrame(0x86dd, append(h, payload...))
}

// fragHeader: IPv6 fragment header; offset in 8-byte units.
func fragHeader(next byte, offset uint16, more bool, id uint32) []byte {
	h := make([]byte, 8)
	h[0] = next
	fo := offset << 3
	if more {
		fo |= 1
	}
	binary.BigEndian.PutUint16(h[2:4], fo)
	binary.BigEndian.PutUint32(h[4:8], id)
	return h
}

// extHeader: an 8-byte IPv6 extension header (hop-by-hop, routing,
// destination options) naming next.
func extHeader(next byte) []byte {
	h := make([]byte, 8)
	h[0] = next
	return h
}

func udpHeader(sport, dport, length uint16) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint16(h[4:6], length)
	return h
}

func tcpHeader(sport, dport uint16, flags byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	h[12] = 0x50
	h[13] = flags
	return h
}

func cBytes(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("0x%02x", v)
	}
	return strings.Join(parts, ",")
}

// TestParsePacketFragments: every IP fragment is still -2 (XDP and TC ingress
// reject them as before), now with PH_FRAGMENT and, for a first fragment
// whose L4 header is complete, PH_FRAG_L4 — so TC egress can police its
// ports and let the later fragments of that datagram follow.
func TestParsePacketFragments(t *testing.T) {
	const (
		frag = 1 << 1
		more = 1 << 2
		l4   = 1 << 3
	)
	pad := make([]byte, 64)
	v4id := binary.NativeEndian.Uint32([]byte{0x12, 0x34, 0, 0})
	v6id := binary.NativeEndian.Uint32([]byte{0xde, 0xad, 0xbe, 0xef})
	cases := []struct {
		name   string
		packet []byte
		rc     int
		flags  int
		proto  int
		off    int
		id     uint32
		l4off  int
	}{
		{"v4_tcp", ipv4Frame(6, 0x1234, 0x4000, tcpHeader(40000, 443, 0x02)), 1, 0, 6, 0, 0, 34},
		{"v4_udp_first", ipv4Frame(17, 0x1234, 0x2000, append(udpHeader(40000, 9999, 3000), pad...)), -2, frag | more | l4, 17, 0, v4id, 34},
		{"v4_middle", ipv4Frame(17, 0x1234, 0x2000|185, pad), -2, frag | more, 17, 185, v4id, 34},
		{"v4_last", ipv4Frame(17, 0x1234, 185, pad), -2, frag, 17, 185, v4id, 34},
		{"v4_tcp_offset_1", ipv4Frame(6, 0x1234, 0x2000|1, pad), -2, frag | more, 6, 1, v4id, 34},
		// RFC 1858 tiny fragment: the TCP header does not fit the first fragment.
		{"v4_tiny_first", ipv4Frame(6, 0x1234, 0x2000, tcpHeader(40000, 443, 0x02)[:8]), -2, frag | more, 6, 0, v4id, 34},
		// First fragment cut by the buffer (-3 unfragmented) stays -2, no
		// PH_FRAG_L4; the cut also sets PH_DECLARED_EXCEEDS (1).
		{"v4_first_truncated", ipv4Frame(17, 0x1234, 0x2000, append(udpHeader(40000, 53, 3000), pad...))[:38], -2, 1 | frag | more, 17, 0, v4id, 34},
		{"v6_udp", ipv6Frame(17, append(udpHeader(40000, 53, 16), pad[:8]...)), 1, 0, 17, 0, 0, 54},
		{"v6_first", ipv6Frame(44, append(fragHeader(17, 0, true, 0xdeadbeef), append(udpHeader(40000, 9999, 3000), pad...)...)), -2, frag | more | l4, 17, 0, v6id, 62},
		{"v6_later", ipv6Frame(44, append(fragHeader(17, 100, false, 0xdeadbeef), pad...)), -2, frag, 17, 100, v6id, 62},
		{"v6_atomic", ipv6Frame(44, append(fragHeader(17, 0, false, 0xdeadbeef), udpHeader(40000, 53, 16)...)), 1, 0, 17, 0, 0, 62},
		{"v6_two_fragment_headers", ipv6Frame(44, append(fragHeader(44, 0, true, 0xdeadbeef), append(fragHeader(17, 0, true, 1), udpHeader(40000, 53, 16)...)...)), -2, frag | more, 0, 0, v6id, 0},
		// Ports of an IPv6 first fragment are read only when its fragment
		// header is the first extension header and L4 follows it directly
		// (walking on tripled the verifier's work). Anything else
		// is a first fragment without PH_FRAG_L4: no readable ports.
		{"v6_first_then_dstopts", ipv6Frame(44, append(fragHeader(60, 0, true, 0xdeadbeef), append(extHeader(17), append(udpHeader(40000, 9999, 3000), pad...)...)...)), -2, frag | more, 0, 0, v6id, 0},
		{"v6_first_after_hbh", ipv6Frame(0, append(extHeader(44), append(fragHeader(17, 0, true, 0xdeadbeef), append(udpHeader(40000, 9999, 3000), pad...)...)...)), -2, frag | more, 0, 0, v6id, 0},
		// Later and atomic fragments behind other extension headers: as before.
		{"v6_later_after_hbh", ipv6Frame(0, append(extHeader(44), append(fragHeader(17, 100, false, 0xdeadbeef), pad...)...)), -2, frag, 17, 100, v6id, 70},
		{"v6_atomic_after_hbh", ipv6Frame(0, append(extHeader(44), append(fragHeader(17, 0, false, 0xdeadbeef), udpHeader(40000, 53, 16)...)...)), 1, 0, 17, 0, 0, 70},
	}
	var calls, want strings.Builder
	for i, c := range cases {
		// frag_proto: what every fragment of the datagram names (the frag
		// map key) — the fragment header's next header: the L4 protocol,
		// except where another extension header follows it.
		fproto := 0
		if c.flags&frag != 0 {
			fproto = c.proto
			switch c.name {
			case "v6_two_fragment_headers":
				fproto = 44
			case "v6_first_then_dstopts":
				fproto = 60
			case "v6_first_after_hbh":
				fproto = 17
			}
		}
		fmt.Fprintf(&calls, "  { static const unsigned char p%d[] = {%s}; run(%q, p%d, sizeof p%d); }\n", i, cBytes(c.packet), c.name, i, i)
		fmt.Fprintf(&want, "%s rc=%d flags=%d proto=%d fproto=%d off=%d id=%08x l4=%d\n", c.name, c.rc, c.flags, c.proto, fproto, c.off, c.id, c.l4off)
	}
	src := nativePacketTypes +
		bpfSourceDefines(t, "wafio_compat.h", "ETH_P_") +
		bpfSourceStruct(t, "wafio_packet.h", "packet_headers") +
		bpfSourceDefines(t, "wafio_packet.h", "PH_") +
		bpfSourceHelper(t, "wafio_packet.h", "parse_l4") + "\n" +
		bpfSourceHelper(t, "wafio_packet.h", "parse_packet") + `
static unsigned char buf[256];
static void run(const char *name, const unsigned char *p, unsigned long n) {
  memcpy(buf, p, n); /* data_end is exact: nothing past the frame is readable */
  struct packet_headers h;
  int rc = parse_packet(buf, buf + n, &h);
  printf("%s rc=%d flags=%u proto=%u fproto=%u off=%u id=%08x l4=%u\n", name, rc, (unsigned)h.parse_flags,
         (unsigned)h.proto, (unsigned)h.frag_proto, (unsigned)h.frag_offset, (unsigned)h.frag_id, (unsigned)h.l4_offset);
}
int main(void) {
` + calls.String() + `  return 0;
}
`
	if got := runNativeC(t, "parse_fragments", src); got != want.String() {
		t.Fatalf("parse_packet fragments:\n got:\n%s\nwant:\n%s", got, want.String())
	}
}

// TestTCEgressUnverifiableVerdict: a TC egress packet without readable ports.
// A later fragment passes when its first fragment passed within
// FRAG_PASS_TTL_NS (same src, dst, protocol and id), and otherwise fails
// closed only on a matching egress block or egress Deny All. A TCP fragment
// at offset 8 is always dropped (RFC 1858). A packet whose L4 header should
// be readable but is not (tiny first fragment, parser reject) fails closed
// on a matching block or whenever the port policy is enabled.
func TestTCEgressUnverifiableVerdict(t *testing.T) {
	src := nativePacketTypes +
		bpfSourceDefines(t, "wafio_compat.h", "AF_INET") +
		bpfSourceDefines(t, "wafio_common.h", "ACTION_", "EVENT_REASON_EGRESS_IP", "EVENT_REASON_PORT_POLICY", "EVENT_REASON_PACKET_PARSE") +
		bpfSourceDefines(t, "wafio_tc.c", "FRAG_PASS_TTL_NS") + `
struct ip_key { __u8 family; __u8 pad[3]; union { __be32 v4; struct in6_addr v6; } addr; } __attribute__((packed));
` + bpfSourceStruct(t, "wafio_common.h", "ip_list_val") +
		bpfSourceStruct(t, "wafio_common.h", "subnet_v4_key") +
		bpfSourceStruct(t, "wafio_common.h", "subnet_v6_key") +
		bpfSourceStruct(t, "wafio_common.h", "subnet_val") +
		bpfSourceStruct(t, "wafio_common.h", "port_policy_config") +
		bpfSourceStruct(t, "wafio_tc.c", "frag_key") +
		bpfSourceStruct(t, "wafio_packet.h", "packet_headers") +
		bpfSourceDefines(t, "wafio_packet.h", "PH_") + `
static int wafio_egress_blocklist, wafio_egress_subnet_v4, wafio_egress_subnet_v6, wafio_port_policy_config, wafio_frag_pass;
static struct ip_key blocked; static int have_blocked; static struct ip_list_val block_val;
static struct port_policy_config pcfg;
static struct frag_key passed_key; static __u64 passed_at; static int have_passed;
static void *bpf_map_lookup_elem(void *map, const void *key) {
  if (map == &wafio_egress_blocklist) return have_blocked && !memcmp(key, &blocked, sizeof blocked) ? (void *)&block_val : NULL;
  if (map == &wafio_port_policy_config) return &pcfg;
  if (map == &wafio_frag_pass) return have_passed && !memcmp(key, &passed_key, sizeof passed_key) ? (void *)&passed_at : NULL;
  return NULL; /* subnet tries: empty */
}
static long bpf_map_delete_elem(void *map, const void *key) {
  if (map == &wafio_frag_pass && have_passed && !memcmp(key, &passed_key, sizeof passed_key)) have_passed = 0;
  return 0;
}
static void ip4(struct ip_key *k, __u8 last) { memset(k, 0, sizeof *k); k->family = 2; k->addr.v4 = 198 | 51 << 8 | 100 << 16 | (__u32)last << 24; }
` + bpfSourceHelper(t, "wafio_tc.c", "check_egress_ip") +
		bpfSourceHelper(t, "wafio_tc.c", "egress_default_deny") +
		bpfSourceHelper(t, "wafio_tc.c", "egress_port_rules_on") +
		bpfSourceHelper(t, "wafio_tc.c", "tc_unverifiable_reason") + `
static struct frag_key fk;
static struct packet_headers h;
static const __u64 now = 100000000000ULL;
/* A fragment of datagram 0x1234 from 192.0.2.10 to 198.51.100.10. */
static void frag(__u8 proto, __u16 off, int more) {
  memset(&fk, 0, sizeof fk); memset(&h, 0, sizeof h);
  fk.src.family = 2; fk.src.addr.v4 = 192 | 0 << 8 | 2 << 16 | 10u << 24; ip4(&fk.dst, 10);
  h.family = 2; h.proto = proto; h.frag_proto = proto; h.frag_offset = off; h.frag_id = 0x3412;
  h.parse_flags = PH_FRAGMENT | (more ? PH_FRAG_MORE : 0);
}
/* The first fragment passed and was recorded as tc_frag_passed does. */
static void head_passed(__u8 proto, __u64 at) {
  passed_key = fk; passed_key.id = 0x3412; passed_key.proto = proto; passed_at = at; have_passed = 1;
}
static void reset(void) { have_blocked = 0; have_passed = 0; memset(&pcfg, 0, sizeof pcfg); }
static void deny_all(void) { pcfg.enabled = 1; pcfg.default_egress = 1; }
static void port_rules(void) { pcfg.enabled = 1; pcfg.default_egress = 0; }
/* The verdict is taken before have_passed is read (it may clear it): C leaves
 * the evaluation order of printf's arguments unspecified. */
static void check(const char *name, int have_ip) {
  int reason = tc_unverifiable_reason(&h, &fk, have_ip, now);
  printf("%s %d passed=%d\n", name, reason, have_passed);
}
int main(void) {
  reset(); frag(17, 185, 1); head_passed(17, now - 1000); deny_all();
  check("middle_after_head", 1);
  frag(17, 370, 0); check("last_after_head", 1);            /* passes, forgets the datagram */
  frag(17, 555, 0); check("after_last", 1);                 /* nothing left: deny all drops */

  reset(); frag(17, 185, 1); head_passed(17, now - FRAG_PASS_TTL_NS); deny_all(); check("head_expired", 1);
  reset(); frag(6, 185, 1); head_passed(17, now - 1000); deny_all(); check("other_protocol", 1);

  /* A later fragment without a passed head: only a block or deny all. */
  reset(); frag(17, 185, 1); check("no_policy", 1);
  port_rules(); check("later_port_rules", 1);
  deny_all(); check("deny_all", 1);
  pcfg.enabled = 0; check("port_policy_off", 1);
  reset(); frag(17, 185, 1); ip4(&blocked, 10); have_blocked = 1; check("dst_blocked", 1);
  reset(); frag(17, 185, 1); memset(&blocked, 0, sizeof blocked); blocked.family = 0xFD; have_blocked = 1; check("v4_wildcard", 1);
  reset(); frag(17, 185, 1); ip4(&blocked, 99); have_blocked = 1; check("other_dst_blocked", 1);

  /* RFC 1858: a TCP fragment at offset 8 is always dropped. */
  reset(); frag(6, 1, 1); head_passed(6, now - 1000); deny_all(); check("tcp_offset_1_after_head", 1);
  reset(); frag(6, 1, 1); check("tcp_offset_1_no_policy", 1);
  reset(); frag(6, 2, 1); head_passed(6, now - 1000); deny_all(); check("tcp_offset_2_after_head", 1);
  reset(); frag(17, 1, 1); check("udp_offset_1_no_policy", 1);

  /* A first fragment whose L4 header is cut: any port rule fails it closed. */
  reset(); frag(6, 0, 1); head_passed(6, now - 1000); deny_all(); check("tiny_head_deny_all", 1);
  reset(); frag(6, 0, 1); port_rules(); check("tiny_head_port_rules", 1);
  reset(); frag(17, 0, 1); port_rules(); check("tiny_udp_head_port_rules", 1);
  reset(); frag(6, 0, 1); check("tiny_head_no_policy", 1);

  /* Parser rejects (-1, -2 without addresses, -3 still cut after the pull). */
  reset(); memset(&h, 0, sizeof h); memset(&fk, 0, sizeof fk); check("malformed_open", 0);
  port_rules(); check("malformed_port_rules", 0);
  deny_all(); check("malformed_deny_all", 0);
  return 0;
}
`
	got := runNativeC(t, "tc_unverifiable", src)
	want := `middle_after_head 0 passed=1
last_after_head 0 passed=0
after_last 11 passed=0
head_expired 11 passed=1
other_protocol 11 passed=1
no_policy 0 passed=0
later_port_rules 0 passed=0
deny_all 11 passed=0
port_policy_off 0 passed=0
dst_blocked 12 passed=0
v4_wildcard 12 passed=0
other_dst_blocked 0 passed=0
tcp_offset_1_after_head 13 passed=1
tcp_offset_1_no_policy 13 passed=0
tcp_offset_2_after_head 0 passed=1
udp_offset_1_no_policy 0 passed=0
tiny_head_deny_all 11 passed=1
tiny_head_port_rules 11 passed=0
tiny_udp_head_port_rules 11 passed=0
tiny_head_no_policy 0 passed=0
malformed_open 0 passed=0
malformed_port_rules 11 passed=0
malformed_deny_all 11 passed=0
`
	if got != want {
		t.Fatalf("TC egress unverifiable verdict:\n got:\n%s\nwant:\n%s", got, want)
	}
}

// TestReparseL4AfterPull: TC egress pulls a -3 packet's L4 header into the
// linear buffer and then re-checks only the L4 header (reparse_l4) instead
// of running parse_packet a second time, which the verifier could not afford.
// The re-check must give what a fresh parse_packet of the grown
// buffer gives — result, end_offset, PH_DECLARED_EXCEEDS.
func TestReparseL4AfterPull(t *testing.T) {
	tcp := tcpHeader(40000, 443, 0x02)
	tcpOpts := append(append([]byte{}, tcp...), make([]byte, 12)...)
	tcpOpts[12] = 0x80 // 32-byte header
	tcpDoff8 := append([]byte{}, tcp...)
	tcpDoff8[12] = 0x80 // claims 32 bytes, the datagram declares 20
	cases := []struct {
		name        string
		packet      []byte
		cut, grown  int
		first, flag int
		again, end  int
		l4          int
	}{
		{"v4_tcp", ipv4Frame(6, 1, 0x4000, tcp), 44, 54, -3, 1, 1, 54, 34},
		{"v4_tcp_still_cut", ipv4Frame(6, 1, 0x4000, tcp), 44, 50, -3, 1, -3, 50, 34},
		{"v4_tcp_options", ipv4Frame(6, 1, 0x4000, tcpOpts), 58, 66, -3, 1, 1, 66, 34},
		{"v4_options_beyond_declared", append(ipv4Frame(6, 1, 0x4000, tcpDoff8), make([]byte, 12)...), 58, 66, -3, 0, -1, 54, 34},
		{"v6_udp", ipv6Frame(17, append(udpHeader(40000, 53, 16), make([]byte, 8)...)), 58, 70, -3, 0, 1, 70, 54},
		{"v6_dstopts_tcp", ipv6Frame(60, append(extHeader(6), tcp...)), 72, 82, -3, 0, 1, 82, 62},
	}
	var calls, want strings.Builder
	for i, c := range cases {
		fmt.Fprintf(&calls, "  { static const unsigned char p%d[] = {%s}; run(%q, p%d, sizeof p%d, %d, %d); }\n", i, cBytes(c.packet), c.name, i, i, c.cut, c.grown)
		fmt.Fprintf(&want, "%s first=%d exceeds=%d again=%d end=%d l4=%d fresh=%d fresh_end=%d\n", c.name, c.first, c.flag, c.again, c.end, c.l4, c.again, c.end)
	}
	src := nativePacketTypes +
		bpfSourceDefines(t, "wafio_compat.h", "ETH_P_") +
		bpfSourceStruct(t, "wafio_packet.h", "packet_headers") +
		bpfSourceDefines(t, "wafio_packet.h", "PH_") +
		bpfSourceHelper(t, "wafio_packet.h", "parse_l4") + "\n" +
		bpfSourceHelper(t, "wafio_packet.h", "parse_packet") + "\n" +
		bpfSourceHelper(t, "wafio_packet.h", "reparse_l4") + `
static unsigned char buf[256];
/* parse_packet sees the first cut bytes (the linear part), reparse_l4 the
 * grown buffer (after bpf_skb_pull_data); fresh = parse_packet of that. */
static void run(const char *name, const unsigned char *p, unsigned long n, unsigned long cut, unsigned long grown) {
  memcpy(buf, p, n);
  struct packet_headers h, f;
  int first = parse_packet(buf, buf + cut, &h);
  unsigned exceeds = h.parse_flags & PH_DECLARED_EXCEEDS;
  int again = reparse_l4(buf, buf + grown, &h);
  int fresh = parse_packet(buf, buf + grown, &f);
  if ((h.parse_flags & PH_DECLARED_EXCEEDS) != (f.parse_flags & PH_DECLARED_EXCEEDS))
    printf("%s flags differ: %u vs %u\n", name, (unsigned)h.parse_flags, (unsigned)f.parse_flags);
  printf("%s first=%d exceeds=%u again=%d end=%u l4=%u fresh=%d fresh_end=%u\n", name, first, exceeds, again,
         (unsigned)h.end_offset, (unsigned)h.l4_offset, fresh, (unsigned)f.end_offset);
}
int main(void) {
` + calls.String() + `  return 0;
}
`
	if got := runNativeC(t, "reparse_l4", src); got != want.String() {
		t.Fatalf("reparse_l4 after a pull:\n got:\n%s\nwant:\n%s", got, want.String())
	}
}
