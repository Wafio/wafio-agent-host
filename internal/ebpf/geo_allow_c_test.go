package ebpf

import (
	"strings"
	"testing"
)

// Native C harness for the XDP geo allow-mode helpers (wafio_xdp.c): the
// exempt source ranges and their per-protocol rule, the exempt ICMP types,
// the established-connection exemption and the verdict. BPF helpers and
// maps are mocked; the whole program runs under BPF_PROG_TEST_RUN in
// TestKernelGeo* (lab).
func TestXDPGeoAllowHelpers(t *testing.T) {
	src := nativePacketTypes + `
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htons(x) ((__u16)((((__u16)(x)) >> 8) | (((__u16)(x)) << 8)))
#define ACTION_ALLOW 0
#define ACTION_DROP 1
#define IPPROTO_ICMP 1
#define WAFIO_IPPROTO_ICMPV6 58
` + bpfSourceDefines(t, "wafio_common.h", "CONN_") +
		bpfSourceDefines(t, "wafio_xdp.c", "GEO_") +
		bpfSourceStruct(t, "wafio_common.h", "ip_key") +
		bpfSourceStruct(t, "wafio_common.h", "conn_key") +
		bpfSourceStruct(t, "wafio_common.h", "conn_val") +
		bpfSourceStruct(t, "wafio_xdp.c", "geo_config") +
		bpfSourceStruct(t, "wafio_xdp.c", "xdp_ct_scratch") + `
struct geo_cidr_v4_key { __u32 prefixlen; __be32 addr; };
struct geo_cidr_v6_key { __u32 prefixlen; __u8 addr[16]; };
static int wafio_conntrack, wafio_geo_config, wafio_geo_local4, wafio_geo_local6, wafio_xdp_ct_buf;
static struct xdp_ct_scratch ct_scratch; /* geo_tracked_inbound builds its key here */
static struct geo_config gc; static int have_gc;
static struct conn_key ck; static struct conn_val cv; static int have_cv;
static __u8 one = 1;
/* Connected subnets: 10.1.2.0/24 and fd00:1::/64 (prefix match by hand). */
static void *bpf_map_lookup_elem(void *map, const void *key) {
  if (map == &wafio_geo_config) return have_gc ? &gc : NULL;
  if (map == &wafio_xdp_ct_buf) return &ct_scratch;
  if (map == &wafio_conntrack && have_cv && !memcmp(key, &ck, sizeof ck)) return &cv;
  if (map == &wafio_geo_local4) {
    const struct geo_cidr_v4_key *k = key;
    return (bpf_ntohl(k->addr) & 0xffffff00) == 0x0a010200 ? &one : NULL;
  }
  if (map == &wafio_geo_local6) {
    const struct geo_cidr_v6_key *k = key;
    static const __u8 net[8] = {0xfd, 0x00, 0x00, 0x01, 0, 0, 0, 0};
    return !memcmp(k->addr, net, 8) ? &one : NULL;
  }
  return NULL;
}
` + bpfSourceHelper(t, "wafio_common.h", "ct_fresh") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "geo_config_get") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "geo_exempt_v4") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "geo_exempt_v6") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "geo_exempt_source_v4") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "geo_exempt_source_v6") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "geo_icmp4_exempt") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "geo_icmp6_exempt") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "geo_tracked_inbound") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "geo_allow_verdict") + `
static __be32 v4(int a, int b, int c, int d) { return bpf_ntohl((__u32)a << 24 | b << 16 | c << 8 | d); }
static __be16 be16(__u16 v) { return (__be16)(v >> 8 | v << 8); }
static struct in6_addr v6(__u16 w0, __u16 w1, __u16 w7) {
  struct in6_addr a; memset(&a, 0, sizeof a);
  a.in6_u.u6_addr8[0] = w0 >> 8; a.in6_u.u6_addr8[1] = w0 & 0xff;
  a.in6_u.u6_addr8[2] = w1 >> 8; a.in6_u.u6_addr8[3] = w1 & 0xff;
  a.in6_u.u6_addr8[14] = w7 >> 8; a.in6_u.u6_addr8[15] = w7 & 0xff;
  return a;
}
static struct geo_cidr_v6_key key6(const struct in6_addr *a) {
  struct geo_cidr_v6_key k = { .prefixlen = 128 };
  memcpy(k.addr, a, 16);
  return k;
}
static struct geo_cidr_v6_key k6;
static const __u64 now = 1000000000000000ULL;
static const __u64 since = now - 3600000000000ULL; /* allow mode live for an hour */
static struct ip_key R = { .family = 2 }, L = { .family = 2 };
static int verdict(__u16 sport, __u8 proto, __u8 flags) {
  return geo_allow_verdict(NULL, &R, &L, be16(sport), be16(22), proto, flags, since, now);
}
int main(void) {
  printf("cfg_nomap=%d ", geo_config_get() != NULL);
  have_gc = 1; printf("cfg=%d\n", geo_config_get() == &gc);

  printf("v4_10=%d v4_172_16=%d v4_172_32=%d v4_192_168=%d v4_100_64=%d v4_100_128=%d\n",
    geo_exempt_v4(v4(10,1,2,3)), geo_exempt_v4(v4(172,16,0,1)), geo_exempt_v4(v4(172,32,0,1)),
    geo_exempt_v4(v4(192,168,1,1)), geo_exempt_v4(v4(100,64,0,1)), geo_exempt_v4(v4(100,128,0,1)));
  printf("v4_127=%d v4_169_254=%d v4_0=%d v4_224=%d v4_239=%d v4_8888=%d v4_36=%d v4_240=%d\n",
    geo_exempt_v4(v4(127,0,0,1)), geo_exempt_v4(v4(169,254,1,1)), geo_exempt_v4(v4(0,0,0,0)),
    geo_exempt_v4(v4(224,0,0,1)), geo_exempt_v4(v4(239,255,255,250)), geo_exempt_v4(v4(8,8,8,8)),
    geo_exempt_v4(v4(36,70,1,1)), geo_exempt_v4(v4(240,0,0,1)));
  struct in6_addr a;
  a = v6(0, 0, 0); printf("v6_unspec=%d ", geo_exempt_v6(&a));
  a = v6(0, 0, 1); printf("v6_loop=%d ", geo_exempt_v6(&a));
  a = v6(0, 0, 2); printf("v6_2=%d ", geo_exempt_v6(&a));
  a = v6(0xfe80, 0, 1); printf("v6_ll=%d ", geo_exempt_v6(&a));
  a = v6(0xfebf, 0, 1); printf("v6_ll_top=%d ", geo_exempt_v6(&a));
  a = v6(0xfec0, 0, 1); printf("v6_site=%d ", geo_exempt_v6(&a));
  a = v6(0xfd00, 0, 1); printf("v6_ula=%d ", geo_exempt_v6(&a));
  a = v6(0xfc00, 0, 1); printf("v6_fc=%d ", geo_exempt_v6(&a));
  a = v6(0xff02, 0, 1); printf("v6_mc=%d ", geo_exempt_v6(&a));
  a = v6(0x2001, 0, 1); printf("v6_global=%d\n", geo_exempt_v6(&a));

  /* Per protocol: a private source passes for TCP and
   * ICMP; UDP only from a connected subnet (10.1.2.0/24, fd00:1::/64). */
  printf("src4 tcp_10=%d icmp_10=%d udp_10_connected=%d udp_10_other=%d udp_192_168=%d esp_10_other=%d udp_0_dhcp=%d udp_0_other=%d udp_public=%d\n",
    geo_exempt_source_v4(v4(10,9,9,9), IPPROTO_TCP, be16(53)),
    geo_exempt_source_v4(v4(10,9,9,9), IPPROTO_ICMP, 0),
    geo_exempt_source_v4(v4(10,1,2,7), IPPROTO_UDP, be16(53)),
    geo_exempt_source_v4(v4(10,9,9,9), IPPROTO_UDP, be16(53)),
    geo_exempt_source_v4(v4(192,168,1,1), IPPROTO_UDP, be16(161)),
    geo_exempt_source_v4(v4(10,9,9,9), 50, 0),
    geo_exempt_source_v4(v4(0,0,0,0), IPPROTO_UDP, be16(67)),
    geo_exempt_source_v4(v4(0,0,0,0), IPPROTO_UDP, be16(53)),
    geo_exempt_source_v4(v4(8,8,8,8), IPPROTO_TCP, be16(53)));
  a = v6(0xfd00, 1, 5); k6 = key6(&a); printf("src6 udp_ula_connected=%d ", geo_exempt_source_v6(&a, IPPROTO_UDP, &k6));
  a = v6(0xfd00, 2, 5); k6 = key6(&a); printf("udp_ula_other=%d ", geo_exempt_source_v6(&a, IPPROTO_UDP, &k6));
  printf("tcp_ula_other=%d ", geo_exempt_source_v6(&a, IPPROTO_TCP, &k6));
  printf("icmp6_ula_other=%d\n", geo_exempt_source_v6(&a, WAFIO_IPPROTO_ICMPV6, &k6));

  printf("icmp4 echo_reply=%d unreach=%d time=%d param=%d echo=%d redirect=%d\n",
    geo_icmp4_exempt(0), geo_icmp4_exempt(3), geo_icmp4_exempt(11), geo_icmp4_exempt(12),
    geo_icmp4_exempt(8), geo_icmp4_exempt(5));
  printf("icmp6 unreach=%d ptb=%d time=%d param=%d echo_reply=%d echo=%d ns=%d\n",
    geo_icmp6_exempt(1), geo_icmp6_exempt(2), geo_icmp6_exempt(3), geo_icmp6_exempt(4),
    geo_icmp6_exempt(129), geo_icmp6_exempt(128), geo_icmp6_exempt(135));

  R.addr.v4 = v4(203,0,113,9); L.addr.v4 = v4(198,51,100,10);
  memset(&ck, 0, sizeof ck);
  memcpy(&ck.src, &R, sizeof R); memcpy(&ck.dst, &L, sizeof L);
  ck.sport = be16(50000); ck.dport = be16(22); ck.proto = IPPROTO_TCP;
  __u8 allowed = GEO_CIDR_ALLOWED, blocked = GEO_CIDR_BLOCKED;
  printf("verdict_allowed=%d verdict_blocked_value=%d verdict_none=%d\n",
    geo_allow_verdict(&allowed, &R, &L, be16(50000), be16(22), IPPROTO_TCP, 0x02, since, now),
    geo_allow_verdict(&blocked, &R, &L, be16(50000), be16(22), IPPROTO_TCP, 0x10, since, now),
    verdict(50000, IPPROTO_TCP, 0x10));
  /* An established, verified connection first seen before allow mode. */
  have_cv = 1;
  struct conn_val base = { .first_seen_ns = since - 1000, .last_seen_ns = now - 1000000000ULL, .tcp_state = 1, .flags_seen = CONN_VERIFIED | 0x12 };
  cv = base; printf("established=%d ", verdict(50000, IPPROTO_TCP, 0x10));
  cv = base; printf("syn_on_tuple=%d ", verdict(50000, IPPROTO_TCP, 0x02));
  cv = base; printf("synack_on_tuple=%d ", verdict(50000, IPPROTO_TCP, 0x12));
  cv = base; printf("other_port=%d ", verdict(50001, IPPROTO_TCP, 0x10));
  cv = base; printf("udp=%d ", verdict(50000, IPPROTO_UDP, 0));
  cv = base; cv.first_seen_ns = since + 1; printf("after_switch=%d ", verdict(50000, IPPROTO_TCP, 0x10));
  cv = base; cv.last_seen_ns = now - 4 * 86400000000000ULL; printf("est_idle_4d=%d ", verdict(50000, IPPROTO_TCP, 0x10));
  cv = base; cv.tcp_state = 2; printf("fin_fresh=%d ", verdict(50000, IPPROTO_TCP, 0x10));
  cv = base; cv.tcp_state = 2; cv.last_seen_ns = now - 301000000000ULL; printf("fin_stale=%d ", verdict(50000, IPPROTO_TCP, 0x10));
  /* A stale closing entry: FIN seen, last seen 4 days ago, new SYN. */
  cv = base; cv.tcp_state = 2; cv.last_seen_ns = now - 4 * 86400000000000ULL; printf("fin_4d_syn=%d ", verdict(50000, IPPROTO_TCP, 0x02));
  cv = base; cv.tcp_state = 3; printf("rst=%d ", verdict(50000, IPPROTO_TCP, 0x10));
  cv = base; cv.tcp_state = 0; printf("syn_only=%d ", verdict(50000, IPPROTO_TCP, 0x10));
  cv = base; cv.flags_seen = 0x12; printf("unverified=%d ", verdict(50000, IPPROTO_TCP, 0x10));
  cv = base; cv.flags_seen |= CONN_REPLY; printf("reply_entry=%d ", verdict(50000, IPPROTO_TCP, 0x10));
  cv = base; cv.flags_seen |= CONN_OUTBOUND; printf("outbound_entry=%d ", verdict(50000, IPPROTO_TCP, 0x10));
  cv = base; cv.last_seen_ns = now - CONN_TCP_EST_TTL_NS - 1; printf("stale=%d\n", verdict(50000, IPPROTO_TCP, 0x10));
  return 0;
}
`
	out := runNativeC(t, "geo_allow", src)
	want := []string{
		"cfg_nomap=0 cfg=1",
		"v4_10=1 v4_172_16=1 v4_172_32=0 v4_192_168=1 v4_100_64=1 v4_100_128=0",
		"v4_127=1 v4_169_254=1 v4_0=1 v4_224=1 v4_239=1 v4_8888=0 v4_36=0 v4_240=0",
		"v6_unspec=1 v6_loop=1 v6_2=0 v6_ll=1 v6_ll_top=1 v6_site=0 v6_ula=1 v6_fc=1 v6_mc=1 v6_global=0",
		"src4 tcp_10=1 icmp_10=1 udp_10_connected=1 udp_10_other=0 udp_192_168=0 esp_10_other=0 udp_0_dhcp=1 udp_0_other=0 udp_public=0",
		"src6 udp_ula_connected=1 udp_ula_other=0 tcp_ula_other=1 icmp6_ula_other=1",
		"icmp4 echo_reply=1 unreach=1 time=1 param=1 echo=0 redirect=0",
		"icmp6 unreach=1 ptb=1 time=1 param=1 echo_reply=1 echo=0 ns=0",
		// ACTION_ALLOW=0, ACTION_DROP=1
		"verdict_allowed=0 verdict_blocked_value=1 verdict_none=1",
		"established=0 syn_on_tuple=1 synack_on_tuple=1 other_port=1 udp=1 after_switch=1 est_idle_4d=0 fin_fresh=0 fin_stale=1 fin_4d_syn=1 rst=1 syn_only=1 unverified=1 reply_entry=1 outbound_entry=1 stale=1",
	}
	for _, w := range want {
		if !strings.Contains(out, w+"\n") {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}
