package ebpf

import (
	"fmt"
	"testing"
)

// Native C harness for the TC inbound check (tc_confirm_inbound). An inbound
// entry XDP wrote (remote → local) is verified once — by the host's SYN-ACK
// to the SYN XDP saw, or by the socket check (a connection for exactly
// the 4-tuple in an established-side state and a TCP listener on the local
// port) — or marked CONN_REPLY: the remote side of a flow this host opened,
// which egress policy then governs. No entry at all is adopted only on the
// same socket check, and the entry adoption writes starts verified.
// BPF helpers and maps are mocked; the whole program (BPF_PROG_TEST_RUN, real
// sockets) is covered by the TestKernelMidFlow* and adoption tests in the lab.
func TestTCConfirmInbound(t *testing.T) {
	src := nativePacketTypes +
		bpfSourceDefines(t, "wafio_common.h", "CONN_") +
		bpfSourceDefines(t, "wafio_tc.c", "INBOUND_") +
		bpfSourceStruct(t, "wafio_common.h", "ip_key") +
		bpfSourceStruct(t, "wafio_common.h", "conn_key") +
		bpfSourceStruct(t, "wafio_common.h", "conn_val") + `
struct bpf_sock_tuple {
  union {
    struct { __be32 saddr; __be32 daddr; __be16 sport; __be16 dport; } ipv4;
    struct { __be32 saddr[4]; __be32 daddr[4]; __be16 sport; __be16 dport; } ipv6;
  };
};
struct __sk_buff { int unused; };
struct bpf_sock { __u32 state; };
#define BPF_F_CURRENT_NETNS (-1)
enum { BPF_TCP_ESTABLISHED = 1, BPF_TCP_SYN_SENT, BPF_TCP_SYN_RECV, BPF_TCP_FIN_WAIT1,
       BPF_TCP_FIN_WAIT2, BPF_TCP_TIME_WAIT, BPF_TCP_CLOSE, BPF_TCP_CLOSE_WAIT,
       BPF_TCP_LAST_ACK, BPF_TCP_LISTEN, BPF_TCP_CLOSING, BPF_TCP_NEW_SYN_RECV };
#define BPF_NOEXIST 1
` + bpfSourceStruct(t, "wafio_tc.c", "adopt_buf") + `
static int wafio_conntrack, wafio_adopt_buf;
static struct adopt_buf scratch; static int no_scratch;
static struct conn_key keys[4]; static struct conn_val vals[4]; static int entries;
static struct ip_key L, R;        /* local and remote address */
static struct conn_key out, in;   /* TC's key local:40000 → remote:5432, XDP's reverse */
static void *bpf_map_lookup_elem(void *map, const void *key) {
  if (map == &wafio_adopt_buf) return no_scratch ? NULL : &scratch;
  for (int i = 0; i < entries; i++)
    if (!memcmp(key, &keys[i], sizeof keys[i])) return &vals[i];
  return NULL;
}
static long bpf_map_update_elem(void *map, const void *key, const void *val, __u64 flags) {
  if (map != &wafio_conntrack || entries == 4 || bpf_map_lookup_elem(map, key)) return -1;
  memcpy(&keys[entries], key, sizeof keys[0]); memcpy(&vals[entries], val, sizeof vals[0]); entries++;
  return 0;
}
/* The socket table of the host: a listener on the local port (listening), and
 * a socket for exactly the flow's 4-tuple in state conn.state (conn_open). A
 * lookup with sport 0 matches only the listener, one with the remote's port
 * only the connection. */
static struct bpf_sock listener = { BPF_TCP_LISTEN }, conn;
static int listening, conn_open;
static int lookups; static struct bpf_sock_tuple tuples[2]; static __u32 sizes[2];
static struct bpf_sock *bpf_sk_lookup_tcp(struct __sk_buff *skb, struct bpf_sock_tuple *t, __u32 size, __u64 netns, __u64 flags) {
  if (lookups < 2) { tuples[lookups] = *t; sizes[lookups] = size; }
  lookups++;
  int v4 = size == sizeof t->ipv4;
  __be16 sport = v4 ? t->ipv4.sport : t->ipv6.sport, dport = v4 ? t->ipv4.dport : t->ipv6.dport;
  if (dport != out.sport) return NULL;
  if (sport == 0) return listening ? &listener : NULL;
  return sport == out.dport && conn_open ? &conn : NULL;
}
static long bpf_sk_release(void *sk) { return 0; }
/* tc_adopt_inbound counts the entry it creates. */
struct metrics_val { __u64 conntrack_entries; };
static struct metrics_val tc_metrics;
static struct metrics_val *tc_get_metrics(void) { return &tc_metrics; }
` + bpfSourceHelper(t, "wafio_common.h", "ct_fresh") + "\n" +
		bpfSourceHelper(t, "wafio_tc.c", "tc_inbound_state") + "\n" +
		bpfSourceHelper(t, "wafio_tc.c", "tc_adopt_lookup") + "\n" +
		bpfSourceHelper(t, "wafio_tc.c", "tc_inbound_socket") + "\n" +
		bpfSourceHelper(t, "wafio_tc.c", "tc_verify_inbound") + "\n" +
		bpfSourceHelper(t, "wafio_tc.c", "tc_adopt_inbound") + "\n" +
		bpfSourceHelper(t, "wafio_tc.c", "tc_confirm_inbound") + `
static const __u64 now = 100000000000ULL;
static struct __sk_buff skb;
static __be16 be16(__u16 v) { return (__be16)(v >> 8 | v << 8); }
/* Sockets present: none, the listener alone, the connection alone, both. */
enum { NONE, LISTENER, CONN, BOTH };
static void setup(int v6, int socks, __u32 conn_state) {
  memset(&scratch, 0, sizeof scratch); no_scratch = 0; entries = 0; lookups = 0; memset(tuples, 0, sizeof tuples);
  listening = socks == LISTENER || socks == BOTH; conn_open = socks == CONN || socks == BOTH; conn.state = conn_state;
  memset(&L, 0, sizeof L); memset(&R, 0, sizeof R);
  if (v6) {
    L.family = R.family = 10;
    L.addr.v6.in6_u.u6_addr8[0] = R.addr.v6.in6_u.u6_addr8[0] = 0x20;
    L.addr.v6.in6_u.u6_addr8[15] = 1; R.addr.v6.in6_u.u6_addr8[15] = 2;
  } else {
    L.family = R.family = 2;
    L.addr.v4 = 192 | 0 << 8 | 2 << 16 | 10u << 24; R.addr.v4 = 198 | 51 << 8 | 100 << 16 | 10u << 24;
  }
  memset(&out, 0, sizeof out); out.src = L; out.dst = R; out.sport = be16(40000); out.dport = be16(5432); out.proto = IPPROTO_TCP;
  memset(&in, 0, sizeof in); in.src = R; in.dst = L; in.sport = out.dport; in.dport = out.sport; in.proto = IPPROTO_TCP;
}
/* The entry update_conntrack writes for a remote packet. */
static struct conn_val *xdp_saw(__u32 flags) {
  struct conn_val v = { .first_seen_ns = now, .last_seen_ns = now, .packets = 1, .flags_seen = flags };
  bpf_map_update_elem(&wafio_conntrack, &in, &v, 0);
  return bpf_map_lookup_elem(&wafio_conntrack, &in);
}
/* Lookup i was seen from the client side (remote → local) with client port
 * sport: the connection lookup carries the remote's port, the listener one 0. */
static int tuple_ok(int i, __be16 sport) {
  struct bpf_sock_tuple *t = &tuples[i];
  if (L.family == 2)
    return sizes[i] == sizeof t->ipv4 && t->ipv4.saddr == R.addr.v4 && t->ipv4.daddr == L.addr.v4 &&
           t->ipv4.sport == sport && t->ipv4.dport == out.sport;
  return sizes[i] == sizeof t->ipv6 && !memcmp(t->ipv6.saddr, &R.addr.v6, 16) &&
         !memcmp(t->ipv6.daddr, &L.addr.v6, 16) && t->ipv6.sport == sport && t->ipv6.dport == out.sport;
}
/* TC's next look at the flow: the state tc_inbound_state gives it. */
static void report(const char *name, int state) {
  struct conn_val *e = bpf_map_lookup_elem(&wafio_conntrack, &in), *iv = NULL;
  int next = tc_inbound_state(&L, &R, out.sport, out.dport, IPPROTO_TCP, now, &iv);
  printf("%s state=%d flags=%08x tcp_state=%u lookups=%d tuples=%d%d next=%d\n", name, state,
         e ? (unsigned)e->flags_seen : 0u, e ? (unsigned)e->tcp_state : 0u, lookups,
         lookups > 0 ? tuple_ok(0, out.dport) : 9, lookups > 1 ? tuple_ok(1, 0) : 9, next);
}
static void verify(const char *name, int v6, __u32 xdp_flags, __u32 tcp_flags, int socks, __u32 conn_state) {
  setup(v6, socks, conn_state);
  struct conn_val *iv = xdp_saw(xdp_flags);
  report(name, tc_confirm_inbound(&skb, &out, iv, tcp_flags, now));
}
static void adopt(const char *name, int socks, __u32 conn_state) {
  setup(0, socks, conn_state);
  report(name, tc_confirm_inbound(&skb, &out, NULL, 0x18, now));
}
int main(void) {
  printf("marks %08x %08x %08x\n", (unsigned)CONN_OUTBOUND, (unsigned)CONN_REPLY, (unsigned)CONN_VERIFIED);
  /* The remote side spoke first on a flow nobody tracked (predates the
   * attach, or its entries were evicted). Only an accepted connection — the
   * 4-tuple's socket and a listener — verifies it. A listener alone is what a
   * forged reply from a listening port (CAP_NET_RAW) finds; a connection
   * alone is a flow the host opened. */
  verify("midflow_no_socket", 0, 0x18, 0x18, NONE, 0);
  verify("midflow_listener_only", 0, 0x18, 0x18, LISTENER, 0);
  verify("midflow_connection_only", 0, 0x18, 0x18, CONN, BPF_TCP_ESTABLISHED);
  verify("midflow_accepted", 0, 0x18, 0x18, BOTH, BPF_TCP_ESTABLISHED);
  verify("midflow_accepted_close_wait", 0, 0x18, 0x18, BOTH, BPF_TCP_CLOSE_WAIT);
  verify("midflow_accepted_last_ack", 0, 0x18, 0x18, BOTH, BPF_TCP_LAST_ACK);
  verify("midflow_tuple_is_listener", 0, 0x18, 0x18, BOTH, BPF_TCP_LISTEN);
  verify("midflow_tuple_syn_recv", 0, 0x18, 0x18, BOTH, BPF_TCP_SYN_RECV);
  verify("midflow_accepted_v6", 1, 0x18, 0x18, BOTH, BPF_TCP_ESTABLISHED);
  verify("midflow_listener_only_v6", 1, 0x18, 0x18, LISTENER, 0);
  verify("midflow_no_socket_v6", 1, 0x18, 0x18, NONE, 0);
  /* A handshake XDP saw: the host's SYN-ACK proves it, even with no socket
   * in this namespace (DNAT to a container). A SYN or SYN-ACK the remote sent
   * on a host-opened flow draws a plain ACK, never a SYN-ACK. */
  verify("syn_answered", 0, 0x02, 0x12, NONE, 0);
  verify("syn_answered_by_ack", 0, 0x02, 0x10, NONE, 0);
  verify("remote_syn_ack", 0, 0x12, 0x10, NONE, 0);
  verify("syn_ack_without_syn", 0, 0x10, 0x12, NONE, 0);
  verify("syn_accepted", 0, 0x12, 0x10, BOTH, BPF_TCP_ESTABLISHED);
  /* Without the scratch value only the SYN-ACK verifies; nothing is adopted. */
  setup(0, BOTH, BPF_TCP_ESTABLISHED); no_scratch = 1;
  report("no_scratch_accepted", tc_confirm_inbound(&skb, &out, xdp_saw(0x18), 0x18, now));
  setup(0, NONE, 0); no_scratch = 1;
  report("no_scratch_syn_answered", tc_confirm_inbound(&skb, &out, xdp_saw(0x02), 0x12, now));
  setup(0, BOTH, BPF_TCP_ESTABLISHED); no_scratch = 1;
  report("no_scratch_adopt", tc_confirm_inbound(&skb, &out, NULL, 0x18, now));
  /* No entry in either direction (adoption): the entry it writes is
   * the one XDP would have, already verified. */
  adopt("adopt_accepted", BOTH, BPF_TCP_ESTABLISHED);
  adopt("adopt_accepted_fin_wait1", BOTH, BPF_TCP_FIN_WAIT1);
  adopt("adopt_listener_only", LISTENER, 0);
  adopt("adopt_connection_only", CONN, BPF_TCP_ESTABLISHED);
  adopt("adopt_no_socket", NONE, 0);
  return 0;
}
`
	got := runNativeC(t, "tc_confirm_inbound", src)
	want := fmt.Sprintf("marks %08x %08x %08x\n", ConnOutbound, ConnReply, ConnVerified) +
		`midflow_no_socket state=3 flags=40000018 tcp_state=0 lookups=1 tuples=19 next=3
midflow_listener_only state=3 flags=40000018 tcp_state=0 lookups=1 tuples=19 next=3
midflow_connection_only state=3 flags=40000018 tcp_state=0 lookups=2 tuples=11 next=3
midflow_accepted state=1 flags=20000018 tcp_state=0 lookups=2 tuples=11 next=1
midflow_accepted_close_wait state=1 flags=20000018 tcp_state=0 lookups=2 tuples=11 next=1
midflow_accepted_last_ack state=1 flags=20000018 tcp_state=0 lookups=2 tuples=11 next=1
midflow_tuple_is_listener state=3 flags=40000018 tcp_state=0 lookups=1 tuples=19 next=3
midflow_tuple_syn_recv state=3 flags=40000018 tcp_state=0 lookups=1 tuples=19 next=3
midflow_accepted_v6 state=1 flags=20000018 tcp_state=0 lookups=2 tuples=11 next=1
midflow_listener_only_v6 state=3 flags=40000018 tcp_state=0 lookups=1 tuples=19 next=3
midflow_no_socket_v6 state=3 flags=40000018 tcp_state=0 lookups=1 tuples=19 next=3
syn_answered state=1 flags=20000002 tcp_state=0 lookups=0 tuples=99 next=1
syn_answered_by_ack state=3 flags=40000002 tcp_state=0 lookups=1 tuples=19 next=3
remote_syn_ack state=3 flags=40000012 tcp_state=0 lookups=1 tuples=19 next=3
syn_ack_without_syn state=3 flags=40000010 tcp_state=0 lookups=1 tuples=19 next=3
syn_accepted state=1 flags=20000012 tcp_state=0 lookups=2 tuples=11 next=1
no_scratch_accepted state=3 flags=40000018 tcp_state=0 lookups=0 tuples=99 next=3
no_scratch_syn_answered state=1 flags=20000002 tcp_state=0 lookups=0 tuples=99 next=1
no_scratch_adopt state=0 flags=00000000 tcp_state=0 lookups=0 tuples=99 next=0
adopt_accepted state=1 flags=20000018 tcp_state=1 lookups=2 tuples=11 next=1
adopt_accepted_fin_wait1 state=1 flags=20000018 tcp_state=1 lookups=2 tuples=11 next=1
adopt_listener_only state=0 flags=00000000 tcp_state=0 lookups=1 tuples=19 next=0
adopt_connection_only state=0 flags=00000000 tcp_state=0 lookups=2 tuples=11 next=0
adopt_no_socket state=0 flags=00000000 tcp_state=0 lookups=1 tuples=19 next=0
`
	if got != want {
		t.Fatalf("tc_confirm_inbound:\n got:\n%s\nwant:\n%s", got, want)
	}
}

// Native C harness for tc_bare_rst: the only reset that passes an unverified
// inbound entry without the check is RST or RST|ACK, reserved/AE bits clear,
// no payload up to the packet's full length, not a fragment. A reset with
// data or other flags goes through tc_verify_inbound. The egress program's
// use of it runs in TestKernelOnlyBareResetSkipsInboundCheck.
func TestTCBareRst(t *testing.T) {
	src := nativePacketTypes + bpfSourceHelper(t, "wafio_tc.c", "tc_bare_rst") + `
static void c(const char *name, __u8 off, __u8 flags, __u32 l4, __u32 len, int frag) {
  printf("%s=%d\n", name, tc_bare_rst(off, flags, l4, len, frag));
}
int main(void) {
  c("rst", 0x50, 0x04, 34, 54, 0);
  c("rst_ack", 0x50, 0x14, 34, 54, 0);
  c("rst_ack_v6", 0x50, 0x14, 54, 74, 0);
  c("rst_ack_timestamps", 0x80, 0x14, 34, 66, 0);
  c("rst_payload", 0x50, 0x04, 34, 55, 0);
  c("rst_ack_payload", 0x50, 0x14, 34, 1054, 0);
  c("rst_options_payload", 0x80, 0x14, 34, 67, 0);
  c("rst_header_past_packet", 0x80, 0x14, 34, 54, 0);
  c("rst_doff_4", 0x40, 0x04, 34, 50, 0);
  c("rst_psh_ack", 0x50, 0x1c, 34, 54, 0);
  c("rst_syn", 0x50, 0x06, 34, 54, 0);
  c("rst_fin", 0x50, 0x05, 34, 54, 0);
  c("rst_urg", 0x50, 0x24, 34, 54, 0);
  c("rst_ece", 0x50, 0x44, 34, 54, 0);
  c("rst_cwr", 0x50, 0x84, 34, 54, 0);
  c("rst_ae", 0x51, 0x04, 34, 54, 0);
  c("rst_reserved", 0x52, 0x14, 34, 54, 0);
  c("rst_fragment", 0x50, 0x14, 34, 54, 1);
  c("ack", 0x50, 0x10, 34, 54, 0);
  return 0;
}
`
	got := runNativeC(t, "tc_bare_rst", src)
	want := `rst=1
rst_ack=1
rst_ack_v6=1
rst_ack_timestamps=1
rst_payload=0
rst_ack_payload=0
rst_options_payload=0
rst_header_past_packet=0
rst_doff_4=0
rst_psh_ack=0
rst_syn=0
rst_fin=0
rst_urg=0
rst_ece=0
rst_cwr=0
rst_ae=0
rst_reserved=0
rst_fragment=0
ack=0
`
	if got != want {
		t.Fatalf("tc_bare_rst:\n got:\n%s\nwant:\n%s", got, want)
	}
}
