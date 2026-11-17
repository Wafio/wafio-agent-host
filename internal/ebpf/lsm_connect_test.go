package ebpf

import "testing"

// An LSM object whose socket_connect hook maps IPv4-mapped AF_INET6
// destinations (it carries wafio_lsm_connect_v4mapped) denies
// connect(AF_INET6, ::ffff:203.0.113.9) in the kernel, exactly like the
// AF_INET connect. Userspace must then skip its own action for that connect
// too — sys_enter_connect traced it before the hook denied it — but still
// count the policy hit (kernel blocklist hits were
// uncounted).
func TestConnectBlocklistCoversIPv4MappedConnect(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	pe.SetConnectCallbacks(cb.push, cb.remove)
	pe.SetConnectBlocklistIPv4Mapped(true)
	p := addPolicy(t, pe, EnforcementPolicy{
		Name: "c2", Enabled: true, Action: "kill", MatchDestIP: "203.0.113.9", KernelEnforce: true,
	})
	if !p.KernelEnforce || cb.pushed["203.0.113.9"] != p.ID {
		t.Fatalf("setup: policy not on the connect blocklist (mode=%s pushed=%v)", p.EnforcementMode, cb.pushed)
	}

	denied := []TraceEvent{
		{EventName: "connect", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443},
		{EventName: "connect", Comm: "implant", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9", Port: 443},
		// net.IP renders a mapped sin6_addr in dotted form (ToTraceEvent).
		{EventName: "connect", Comm: "implant", AddrFamily: testAFInet6, Addr: "203.0.113.9", Port: 443},
	}
	for _, evt := range denied {
		if action, id := pe.Evaluate(evt); action != ActionMonitor || id != 0 {
			t.Errorf("family=%d %s denied by the LSM hook, acted on again in userspace: action=%d policy=%d",
				evt.AddrFamily, evt.Addr, action, id)
		}
	}
	if n := pe.EnforcementLogCount(); n != 0 {
		t.Errorf("LSM-denied connects produced %d userspace enforcement entries", n)
	}
	if got, _ := pe.GetPolicy(p.ID); got.HitCount != uint64(len(denied)) {
		t.Errorf("hit count = %d, want %d (kernel-denied connects are hits)", got.HitCount, len(denied))
	}

	// sendto never passes socket_connect: userspace still enforces it.
	sendto := TraceEvent{EventName: "sendto", Comm: "implant", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9", Port: 53}
	if action, id := pe.Evaluate(sendto); action != ActionKill || id != p.ID {
		t.Errorf("sendto to a mapped address not enforced in userspace: action=%d policy=%d", action, id)
	}
	// A native IPv6 destination never equals the IPv4 policy address.
	if action, _ := pe.Evaluate(TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: "2001:db8::1"}); action != ActionMonitor {
		t.Errorf("native IPv6 connect got action=%d", action)
	}
}

// An LSM object without the marker returns early for AF_INET6: the mapped
// connect reaches the IPv4 address, so userspace must still act on it.
func TestConnectBlocklistMappedNeedsTheNewObject(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	pe.SetConnectCallbacks(cb.push, cb.remove)
	pe.SetConnectBlocklistIPv4Mapped(false)
	p := addPolicy(t, pe, EnforcementPolicy{
		Name: "c2", Enabled: true, Action: "kill", MatchDestIP: "203.0.113.9", KernelEnforce: true,
	})
	evt := TraceEvent{EventName: "connect", Comm: "implant", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9", Port: 443}
	if action, id := pe.Evaluate(evt); action != ActionKill || id != p.ID {
		t.Errorf("mapped connect with an old LSM object: action=%d policy=%d, want kill by %d", action, id, p.ID)
	}
}

func TestConnectHookCoversEvent(t *testing.T) {
	cases := []struct {
		name   string
		evt    TraceEvent
		mapped bool
		want   bool
	}{
		{"inet", TraceEvent{EventName: "connect", AddrFamily: testAFInet, Addr: "203.0.113.9"}, false, true},
		{"inet_mapped_abi", TraceEvent{EventName: "connect", AddrFamily: testAFInet, Addr: "203.0.113.9"}, true, true},
		{"inet6_mapped_old", TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9"}, false, false},
		{"inet6_mapped_new", TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9"}, true, true},
		{"inet6_mapped_dotted", TraceEvent{EventName: "CONNECT", AddrFamily: testAFInet6, Addr: "203.0.113.9"}, true, true},
		{"inet6_native", TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: "2001:db8::1"}, true, false},
		{"inet6_compat", TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: "::203.0.113.9"}, true, false},
		{"inet6_garbage", TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: "not-an-ip"}, true, false},
		{"sendto", TraceEvent{EventName: "sendto", AddrFamily: testAFInet, Addr: "203.0.113.9"}, true, false},
		{"unix", TraceEvent{EventName: "connect", AddrFamily: 1}, true, false},
	}
	for _, tc := range cases {
		if got := connectHookCoversEvent(tc.evt, tc.mapped); got != tc.want {
			t.Errorf("%s: connectHookCoversEvent = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The blocked-connect event of an object with the marker names the socket
// family, so the operator can tell an IPv4-mapped IPv6 connect from a plain
// IPv4 one. Objects without it leave the field unset (any value but 2/10 is
// ignored).
func TestLSMConnectEventFamily(t *testing.T) {
	cases := []struct {
		family uint16
		want   uint16
		note   string
	}{
		{2, 2, ""},
		{10, 10, " (IPv4-mapped IPv6)"},
		{0, 0, ""},
		{0xAAAA, 0, ""},
	}
	for _, tc := range cases {
		fam, note := lsmConnectFamily(WafioLSMEvent{Hook: LSMHookConnect, Family: tc.family})
		if fam != tc.want || note != tc.note {
			t.Errorf("family %#x: got (%d, %q), want (%d, %q)", tc.family, fam, note, tc.want, tc.note)
		}
	}
	if fam, note := lsmConnectFamily(WafioLSMEvent{Hook: 0, Family: 10}); fam != 0 || note != "" {
		t.Errorf("unknown hook reported a socket family: (%d, %q)", fam, note)
	}
}
