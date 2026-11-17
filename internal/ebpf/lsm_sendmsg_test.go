package ebpf

import "testing"

// sendCb records the socket_sendmsg-aware pushes.
type sendCb struct {
	pushed map[string]uint32
	send   map[string]bool
	calls  int
}

func newSendCb() *sendCb { return &sendCb{pushed: map[string]uint32{}, send: map[string]bool{}} }

func (c *sendCb) push(ip string, id uint32, send bool) error {
	c.pushed[ip] = id
	c.send[ip] = send
	c.calls++
	return nil
}

// With the socket_sendmsg hook wired, a dest-IP-only
// block/kill policy that selects sendto marks its blocklist entry for sends,
// and a sendto to that IPv4 address (or its IPv4-mapped form) is denied in
// the kernel — sys_enter_sendto traced it first, so userspace counts the hit
// and takes no second action (no kill for a send that never happened).
func TestSendBlocklistCoversAddressedSends(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	pe.SetConnectCallbacks(cb.push, cb.remove)
	pe.SetConnectBlocklistIPv4Mapped(true)
	sc := newSendCb()
	if err := pe.SetSendBlocklist(sc.push); err != nil {
		t.Fatal(err)
	}
	p := addPolicy(t, pe, EnforcementPolicy{
		Name: "c2", Enabled: true, Action: "kill", MatchDestIP: "203.0.113.9", KernelEnforce: true,
	})
	if sc.pushed["203.0.113.9"] != p.ID || !sc.send["203.0.113.9"] {
		t.Fatalf("entry not pushed with the send flag: pushed=%v send=%v", sc.pushed, sc.send)
	}
	if len(cb.pushed) != 0 {
		t.Fatalf("entry written through the flagless pusher too: %v", cb.pushed)
	}
	denied := []TraceEvent{
		{EventName: "sendto", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 53},
		{EventName: "sendto", Comm: "implant", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9", Port: 53},
		{EventName: "connect", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443},
	}
	for _, evt := range denied {
		if action, id := pe.Evaluate(evt); action != ActionMonitor || id != 0 {
			t.Errorf("%s to %s denied in the kernel, acted on again: action=%d policy=%d", evt.EventName, evt.Addr, action, id)
		}
	}
	if got, _ := pe.GetPolicy(p.ID); got.HitCount != uint64(len(denied)) {
		t.Errorf("hit count = %d, want %d", got.HitCount, len(denied))
	}
	// Unwired again (hook detached): the flag is cleared and sendto goes
	// back to userspace.
	if err := pe.SetSendBlocklist(nil); err != nil {
		t.Fatal(err)
	}
	if cb.pushed["203.0.113.9"] != p.ID {
		t.Fatalf("entry not rewritten without the flag after unwiring: %v", cb.pushed)
	}
	if action, id := pe.Evaluate(denied[0]); action != ActionKill || id != p.ID {
		t.Errorf("sendto without the sendmsg hook: action=%d policy=%d, want kill", action, id)
	}
}

// The send flag follows the policies' event types: a connect-only policy
// never lets the sendmsg hook deny a send it does not select; a second
// policy for the same IP that selects sendto sets it, and removing that
// policy clears it again. Unchanged entries are not rewritten.
func TestSendBlocklistFlagFollowsEventTypes(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	pe.SetConnectCallbacks(cb.push, cb.remove)
	sc := newSendCb()
	if err := pe.SetSendBlocklist(sc.push); err != nil {
		t.Fatal(err)
	}
	a := addPolicy(t, pe, EnforcementPolicy{
		Name: "connect-only", Enabled: true, Action: "block", EventTypes: []string{"connect"},
		MatchDestIP: "198.51.100.7", KernelEnforce: true,
	})
	if !a.KernelEnforce || sc.pushed["198.51.100.7"] != a.ID || sc.send["198.51.100.7"] {
		t.Fatalf("connect-only policy: mode=%s pushed=%v send=%v", a.EnforcementMode, sc.pushed, sc.send)
	}
	sendto := TraceEvent{EventName: "sendto", Comm: "dig", AddrFamily: testAFInet, Addr: "198.51.100.7", Port: 53}
	if action, _ := pe.Evaluate(sendto); action != ActionMonitor {
		t.Errorf("connect-only policy acted on a sendto: %d", action)
	}
	b := addPolicy(t, pe, EnforcementPolicy{
		Name: "all", Enabled: true, Action: "block", MatchDestIP: "198.51.100.7", KernelEnforce: true,
	})
	if !sc.send["198.51.100.7"] {
		t.Fatalf("policy selecting sendto did not set the flag: %v", sc.send)
	}
	if got, _ := pe.GetPolicy(b.ID); got.HitCount != 0 {
		t.Fatalf("setup: unexpected hits %d", got.HitCount)
	}
	if action, _ := pe.Evaluate(sendto); action != ActionMonitor {
		t.Errorf("kernel-denied sendto acted on in userspace: %d", action)
	}
	if got, _ := pe.GetPolicy(b.ID); got.HitCount != 1 {
		t.Errorf("kernel-denied sendto not counted: %d", got.HitCount)
	}
	calls := sc.calls
	if _, err := pe.UpdatePolicy(a.ID, EnforcementPolicy{
		Name: "connect-only renamed", Enabled: true, Action: "block", EventTypes: []string{"connect"},
		MatchDestIP: "198.51.100.7", KernelEnforce: true,
	}); err != nil {
		t.Fatal(err)
	}
	if sc.calls != calls {
		t.Errorf("unchanged entry rewritten (%d pushes)", sc.calls-calls)
	}
	if err := pe.DeletePolicy(b.ID); err != nil {
		t.Fatal(err)
	}
	if sc.send["198.51.100.7"] || sc.pushed["198.51.100.7"] != a.ID {
		t.Errorf("flag not cleared after the sendto policy went: pushed=%v send=%v", sc.pushed, sc.send)
	}
}

func TestSendHookCoversEvent(t *testing.T) {
	cases := []struct {
		name string
		evt  TraceEvent
		want bool
	}{
		{"inet", TraceEvent{EventName: "sendto", AddrFamily: testAFInet, Addr: "203.0.113.9"}, true},
		{"inet6_mapped", TraceEvent{EventName: "SENDTO", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9"}, true},
		{"inet6_mapped_dotted", TraceEvent{EventName: "sendto", AddrFamily: testAFInet6, Addr: "203.0.113.9"}, true},
		{"inet6_native", TraceEvent{EventName: "sendto", AddrFamily: testAFInet6, Addr: "2001:db8::1"}, false},
		{"connect", TraceEvent{EventName: "connect", AddrFamily: testAFInet, Addr: "203.0.113.9"}, false},
		{"no_family", TraceEvent{EventName: "sendto", Addr: "203.0.113.9"}, false},
	}
	for _, tc := range cases {
		if got := sendHookCoversEvent(tc.evt); got != tc.want {
			t.Errorf("%s: sendHookCoversEvent = %v, want %v", tc.name, got, tc.want)
		}
	}
	if fam, note := lsmConnectFamily(WafioLSMEvent{Hook: LSMHookSendmsg, Family: 10}); fam != 10 || note == "" {
		t.Errorf("sendmsg event family: (%d, %q)", fam, note)
	}
}

// TestLSMSendIPv4Target compiles the socket_sendmsg destination helper of
// wafio_lsm.c natively: an addressed send reaches an IPv4
// peer through AF_INET, an IPv4-mapped AF_INET6 address, or AF_UNSPEC on an
// AF_INET socket (udp_sendmsg and raw_sendmsg read it as AF_INET); AF_UNSPEC
// on an AF_INET6 socket names no destination.
func TestLSMSendIPv4Target(t *testing.T) {
	src := `typedef uint8_t __u8; typedef uint16_t __u16; typedef uint32_t __u32; typedef uint64_t __u64;
typedef __u16 __be16; typedef __u32 __be32;
#define BPF_CORE_READ(p, f) ((p)->f)
static long bpf_core_read(void *dst, __u32 sz, const void *src) { memcpy(dst, src, sz); return 0; }
struct sockaddr { unsigned short sa_family; char sa_data[14]; };
struct in_addr { __be32 s_addr; };
struct sockaddr_in { unsigned short sin_family; __be16 sin_port; struct in_addr sin_addr; unsigned char __pad[8]; };
struct in6_addr { union { __u8 u6_addr8[16]; __be16 u6_addr16[8]; __be32 u6_addr32[4]; } in6_u; };
struct sockaddr_in6 { unsigned short sin6_family; __be16 sin6_port; __be32 sin6_flowinfo; struct in6_addr sin6_addr; __u32 sin6_scope_id; };
struct socket { __u16 family; };
static __u16 lsm_sock_family(struct socket *sock) { return sock->family; }
` + bpfSourceDefines(t, "wafio_lsm.c", "AF_", "LSM_SIN6_LEN") +
		bpfSourceHelper(t, "wafio_lsm.c", "lsm_connect_ipv4") + "\n" +
		bpfSourceHelper(t, "wafio_lsm.c", "lsm_send_ipv4") + `
static unsigned char storage[128];
static void v4(unsigned short family, const __u8 ip[4], __u16 port) {
  memset(storage, 0xAA, sizeof storage);
  struct sockaddr_in *s = (struct sockaddr_in *)storage;
  s->sin_family = family; s->sin_port = (__be16)((port >> 8) | (port << 8)); memcpy(&s->sin_addr, ip, 4);
}
static void v6(const __u8 ip[16], __u16 port) {
  memset(storage, 0xAA, sizeof storage);
  struct sockaddr_in6 *s = (struct sockaddr_in6 *)storage;
  s->sin6_family = AF_INET6; s->sin6_port = (__be16)((port >> 8) | (port << 8)); s->sin6_flowinfo = 0;
  memcpy(&s->sin6_addr, ip, 16); s->sin6_scope_id = 0;
}
static void check(const char *name, __u16 sock_family, int addrlen) {
  struct socket sock = { sock_family };
  __be32 addr = 0; __be16 port = 0; __u16 family = 0;
  int ok = lsm_send_ipv4(&sock, (struct sockaddr *)storage, addrlen, &addr, &port, &family);
  const __u8 *b = (const __u8 *)&addr;
  if (ok)
    printf("%s ok %u.%u.%u.%u:%u family=%u\n", name, (unsigned)b[0], (unsigned)b[1], (unsigned)b[2], (unsigned)b[3], (unsigned)(__u16)((port >> 8) | (port << 8)), (unsigned)family);
  else
    printf("%s none\n", name);
}
int main(void) {
  const __u8 blocked[4] = { 203, 0, 113, 9 };
  const __u8 mapped[16] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 203,0,113,9 };
  const __u8 native[16] = { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
  v4(AF_INET, blocked, 53);   check("udp4_inet", AF_INET, 16);
  v4(AF_INET, blocked, 53);   check("udp6_inet", AF_INET6, 16);   /* udpv6_sendmsg hands AF_INET to udp_sendmsg */
  v4(AF_UNSPEC, blocked, 53); check("udp4_unspec", AF_INET, 16);
  v4(AF_UNSPEC, blocked, 53); check("udp4_unspec_short", AF_INET, 8);
  v4(AF_UNSPEC, blocked, 53); check("udp6_unspec", AF_INET6, 28);
  v6(mapped, 53);             check("udp6_mapped", AF_INET6, 28);
  v6(native, 53);             check("udp6_native", AF_INET6, 28);
  v4(AF_INET, blocked, 443);  check("tfo_inet_short", AF_INET, 15);
  return 0;
}
`
	got := runNativeC(t, "lsm_send", src)
	want := `udp4_inet ok 203.0.113.9:53 family=2
udp6_inet ok 203.0.113.9:53 family=2
udp4_unspec ok 203.0.113.9:53 family=2
udp4_unspec_short none
udp6_unspec none
udp6_mapped ok 203.0.113.9:53 family=10
udp6_native none
tfo_inet_short none
`
	if got != want {
		t.Fatalf("socket_sendmsg IPv4 target:\n got:\n%s\nwant:\n%s", got, want)
	}
}
