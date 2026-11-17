package ebpf

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

// matchPolicy never compared MatchDestIP, and validation counts
// match_dest_ip as narrowing, so "kill connect to 203.0.113.9" was accepted
// without kill_acknowledged and killed every process that called connect()
// (with no event types: every traced process).

const (
	testAFInet  uint16 = 2
	testAFInet6 uint16 = 10
)

// v4MappedAddr is the 16-byte sin6_addr of ::ffff:a.b.c.d as the trace
// program copies it into the event.
func v4MappedAddr(t *testing.T, v4 string) [16]byte {
	t.Helper()
	var out [16]byte
	copy(out[:], net.ParseIP(v4).To16())
	return out
}

func TestMatchPolicyDestIP(t *testing.T) {
	pe := NewPolicyEngine()
	policy := &EnforcementPolicy{Name: "c2", Enabled: true, Action: "kill", MatchDestIP: "203.0.113.9"}

	cases := []struct {
		name string
		evt  TraceEvent
		want bool
	}{
		{"connect to the IP", TraceEvent{EventName: "connect", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443}, true},
		{"connect elsewhere", TraceEvent{EventName: "connect", AddrFamily: testAFInet, Addr: "8.8.8.8", Port: 53}, false},
		{"sendto the IP", TraceEvent{EventName: "sendto", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 53}, true},
		{"sendto elsewhere", TraceEvent{EventName: "sendto", AddrFamily: testAFInet, Addr: "192.0.2.1", Port: 53}, false},
		{"event without an address", TraceEvent{EventName: "execve", Comm: "bash", Filename: "/bin/bash"}, false},
		{"connect with empty address", TraceEvent{EventName: "connect", Port: 443}, false},
		{"unparseable address", TraceEvent{EventName: "connect", AddrFamily: testAFInet, Addr: "not-an-ip"}, false},
		{"IPv6 destination", TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: "2001:db8::1", Port: 443}, false},
		{"IPv4-compatible IPv6 is not the IPv4 address", TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: "::203.0.113.9"}, false},
		{"IPv4-mapped IPv6 reaches the IPv4 address", TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9"}, true},
		{"IPv4-mapped IPv6 as formatAddr renders it", TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: formatAddr(v4MappedAddr(t, "203.0.113.9"), testAFInet6)}, true},
		{"IPv4-mapped IPv6 elsewhere", TraceEvent{EventName: "connect", AddrFamily: testAFInet6, Addr: formatAddr(v4MappedAddr(t, "8.8.8.8"), testAFInet6)}, false},
		// bind's address is the local one; a destination-IP policy must not
		// kill a server binding an address the host owns.
		{"bind to the IP is not a destination", TraceEvent{EventName: "bind", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 8080}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pe.matchPolicy(policy, tc.evt); got != tc.want {
				t.Fatalf("matchPolicy(dest %s, %s %q) = %v, want %v", policy.MatchDestIP, tc.evt.EventName, tc.evt.Addr, got, tc.want)
			}
		})
	}

	// Validation trims and accepts the IPv4-mapped spelling; matching must
	// read the policy the same way.
	for _, spelled := range []string{" 203.0.113.9 ", "::ffff:203.0.113.9"} {
		p := &EnforcementPolicy{Name: "c2", Enabled: true, Action: "kill", MatchDestIP: spelled}
		if err := ValidateEnforcementPolicy(*p); err != nil {
			t.Fatalf("validation rejected %q: %v", spelled, err)
		}
		evt := TraceEvent{EventName: "connect", AddrFamily: testAFInet, Addr: "203.0.113.9"}
		if !pe.matchPolicy(p, evt) {
			t.Errorf("policy dest %q did not match a connect to 203.0.113.9", spelled)
		}
	}
}

// The destination-IP scenario end to end through Evaluate: a narrowed kill
// policy must leave every other connect — and every other event — alone.
func TestEvaluateDestIPKillOnlyHitsThatDestination(t *testing.T) {
	for _, eventTypes := range [][]string{{"connect"}, nil} {
		pe := NewPolicyEngine()
		p := addPolicy(t, pe, EnforcementPolicy{
			Name: "kill c2", Enabled: true, Action: "kill",
			EventTypes: eventTypes, MatchDestIP: "203.0.113.9",
		})
		for _, evt := range []TraceEvent{
			{EventName: "connect", Comm: "wafio-waf-agent", AddrFamily: testAFInet, Addr: "8.8.8.8", Port: 443},
			{EventName: "connect", Comm: "nginx", AddrFamily: testAFInet6, Addr: "2001:db8::10", Port: 80},
			{EventName: "execve", Comm: "bash", Filename: "/usr/bin/apt"},
			{EventName: "open", Comm: "systemd-resolve", Filename: "/etc/resolv.conf"},
		} {
			if action, id := pe.Evaluate(evt); action != ActionMonitor || id != 0 {
				t.Errorf("event_types=%v: %s %q got action=%d policy=%d; want untouched", eventTypes, evt.EventName, evt.Addr, action, id)
			}
		}
		hit := TraceEvent{EventName: "connect", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443}
		if action, id := pe.Evaluate(hit); action != ActionKill || id != p.ID {
			t.Errorf("event_types=%v: connect to 203.0.113.9 got action=%d policy=%d; want kill by %d", eventTypes, action, id, p.ID)
		}
	}
}

// Validation counts a set of criteria as "narrowing" to decide whether a kill
// policy needs kill_acknowledged. Each of them must actually be compared by
// matchPolicy, or a policy that looks narrow kills host-wide. This
// test reflects over that list and fails for any criterion that does not
// change matchPolicy's result, and for any Match* field missing from it.
func TestEveryNarrowingFieldIsMatched(t *testing.T) {
	// One event that each sample below either matches or misses.
	base := TraceEvent{
		EventName: "connect", Comm: "curl", Filename: "/usr/bin/curl", UID: 1000,
		AddrFamily: testAFInet, Addr: "198.51.100.7", Port: 443,
	}
	samples := map[string]struct{ match, miss any }{
		"MatchComm":     {"curl", "wget"},
		"MatchFilename": {"/usr/bin/curl", "/dev/shm/"}, // bare system dirs do not narrow
		"MatchUID":      {uidPtr(1000), uidPtr(1001)},   // UID 0 does not narrow
		"MatchDestPort": {"443", "4444"},
		"MatchDestIP":   {"198.51.100.7", "203.0.113.9"},
	}

	listed := make(map[string]bool, len(narrowingMatchFields))
	for _, f := range narrowingMatchFields {
		listed[f.Field] = true
	}
	policyType := reflect.TypeOf(EnforcementPolicy{})
	for i := 0; i < policyType.NumField(); i++ {
		if name := policyType.Field(i).Name; strings.HasPrefix(name, "Match") && !listed[name] && !matchModifierFields[name] {
			t.Errorf("EnforcementPolicy.%s is a match criterion but not in narrowingMatchFields", name)
		}
	}

	pe := NewPolicyEngine()
	if !pe.matchPolicy(&EnforcementPolicy{Name: "base", Enabled: true}, base) {
		t.Fatal("a criteria-free policy must match the base event")
	}
	for _, nf := range narrowingMatchFields {
		t.Run(nf.Field, func(t *testing.T) {
			sample, ok := samples[nf.Field]
			if !ok {
				t.Fatalf("no match/miss sample for narrowing field %s: add one so matchPolicy is proven to compare it", nf.Field)
			}
			for _, c := range []struct {
				value any
				want  bool
			}{{sample.match, true}, {sample.miss, false}} {
				p := EnforcementPolicy{Name: "narrowed", Enabled: true, Action: "kill"}
				field := reflect.ValueOf(&p).Elem().FieldByName(nf.Field)
				if !field.IsValid() {
					t.Fatalf("narrowing field %s does not exist on EnforcementPolicy", nf.Field)
				}
				field.Set(reflect.ValueOf(c.value))
				if !policyHasNarrowingMatch(p) {
					t.Fatalf("%s set, but policyHasNarrowingMatch says the policy is not narrowed", nf.Field)
				}
				if err := ValidateEnforcementPolicy(p); err != nil {
					t.Fatalf("%s-narrowed kill rejected: %v", nf.Field, err)
				}
				if got := pe.matchPolicy(&p, base); got != c.want {
					t.Errorf("%s=%v: matchPolicy = %v, want %v (the field is counted as narrowing but not compared)",
						nf.Field, reflect.Indirect(reflect.ValueOf(c.value)), got, c.want)
				}
			}
		})
	}
}

// A kernel-mode dest-IP policy is enforced by the BPF-LSM connect blocklist:
// socket_connect denies the connect with -EPERM, but sys_enter_connect has
// already traced it, so the same event still reaches Evaluate. Userspace must
// not act on it a second time (kill a process whose connect never happened).
func TestEvaluateSkipsPoliciesEnforcedByConnectBlocklist(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	pe.SetConnectCallbacks(cb.push, cb.remove)
	p := addPolicy(t, pe, EnforcementPolicy{
		Name: "c2", Enabled: true, Action: "kill", MatchDestIP: "203.0.113.9", KernelEnforce: true,
	})
	if !p.KernelEnforce || cb.pushed["203.0.113.9"] != p.ID {
		t.Fatalf("setup: policy not on the connect blocklist (mode=%s pushed=%v)", p.EnforcementMode, cb.pushed)
	}

	denied := TraceEvent{EventName: "connect", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443}
	if action, id := pe.Evaluate(denied); action != ActionMonitor || id != 0 {
		t.Errorf("LSM-denied connect acted on again in userspace: action=%d policy=%d", action, id)
	}
	if n := pe.EnforcementLogCount(); n != 0 {
		t.Errorf("LSM-denied connect produced %d userspace enforcement entries", n)
	}

	// An LSM object without the mapped-connect marker sees AF_INET connects
	// only, and no object sees sendto: for those the policy's own action still
	// applies from userspace (the object with the marker:
	// lsm_connect_test.go).
	for _, evt := range []TraceEvent{
		{EventName: "connect", Comm: "implant", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9", Port: 443},
		{EventName: "sendto", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 53},
	} {
		if action, id := pe.Evaluate(evt); action != ActionKill || id != p.ID {
			t.Errorf("%s family=%d %s not seen by the LSM hook: action=%d policy=%d, want kill by %d",
				evt.EventName, evt.AddrFamily, evt.Addr, action, id, p.ID)
		}
	}
	// Other destinations stay untouched either way.
	if action, _ := pe.Evaluate(TraceEvent{EventName: "connect", AddrFamily: testAFInet, Addr: "8.8.8.8"}); action != ActionMonitor {
		t.Errorf("connect to 8.8.8.8 got action=%d", action)
	}
}

// Without the LSM path the same policy downgrades and userspace enforces it.
func TestDowngradedDestIPPolicyIsEnforcedInUserspace(t *testing.T) {
	pe := NewPolicyEngine()
	p := addPolicy(t, pe, EnforcementPolicy{
		Name: "c2", Enabled: true, Action: "kill", MatchDestIP: "203.0.113.9", KernelEnforce: true,
	})
	if p.KernelEnforce || p.EnforcementMode != "downgraded" {
		t.Fatalf("setup: mode=%s, want downgraded", p.EnforcementMode)
	}
	evt := TraceEvent{EventName: "connect", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443}
	if action, id := pe.Evaluate(evt); action != ActionKill || id != p.ID {
		t.Errorf("downgraded dest-IP kill not enforced in userspace: action=%d policy=%d", action, id)
	}
}

// The connect blocklist has one effect, -EPERM. Only block and kill policies
// may ride it; an alert or monitor dest-IP policy put there would block every
// connect to that IP instead of alerting on it.
func TestConnectBlocklistCarriesOnlyDenyingActions(t *testing.T) {
	evt := TraceEvent{EventName: "connect", Comm: "curl", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443}
	for _, action := range []string{"alert", "monitor"} {
		pe := NewPolicyEngine()
		cb := newConnectCb()
		pe.SetConnectCallbacks(cb.push, cb.remove)
		p := addPolicy(t, pe, EnforcementPolicy{
			Name: action, Enabled: true, Action: action, MatchDestIP: "203.0.113.9", KernelEnforce: true,
		})
		if p.KernelEnforce || len(cb.pushed) != 0 {
			t.Errorf("%s dest-IP policy put on the deny-only connect blocklist (mode=%s pushed=%v)", action, p.EnforcementMode, cb.pushed)
		}
		if got, _ := pe.Evaluate(evt); got != ParseActionName(action) {
			t.Errorf("%s dest-IP policy: Evaluate action=%d, want %d", action, got, ParseActionName(action))
		}
	}
	for _, action := range []string{"block", "kill"} {
		pe := NewPolicyEngine()
		cb := newConnectCb()
		pe.SetConnectCallbacks(cb.push, cb.remove)
		p := addPolicy(t, pe, EnforcementPolicy{
			Name: action, Enabled: true, Action: action, MatchDestIP: "203.0.113.9", KernelEnforce: true,
		})
		if !p.KernelEnforce || cb.pushed["203.0.113.9"] != p.ID {
			t.Errorf("%s dest-IP policy not on the connect blocklist (mode=%s pushed=%v)", action, p.EnforcementMode, cb.pushed)
		}
	}
}

// The LSM hook denies every connect to the IP, whatever the event type or
// severity. A policy restricted to other event types or to a severity above
// the lowest must stay in userspace, or it would EPERM connects it never
// selects.
func TestConnectBlocklistOnlyForConnectAtAnySeverity(t *testing.T) {
	cases := []struct {
		name        string
		eventTypes  []string
		minSeverity string
		blocklisted bool
	}{
		{"sendto only", []string{"sendto"}, "", false},
		{"execve only", []string{"execve"}, "", false},
		{"connect_exit only", []string{"connect_exit"}, "", false},
		{"min severity critical", nil, "critical", false},
		{"connect at min severity low", []string{"connect"}, "low", false},
		{"connect, no min severity", []string{"connect"}, "", true},
		{"connect, min severity info", []string{"connect"}, "info", true},
		{"any event type", nil, "", true},
		{"connect among others", []string{"sendto", "CONNECT"}, "", true},
	}
	connect := TraceEvent{EventName: "connect", Comm: "curl", Severity: SevInfo, AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pe := NewPolicyEngine()
			cb := newConnectCb()
			pe.SetConnectCallbacks(cb.push, cb.remove)
			p := addPolicy(t, pe, EnforcementPolicy{
				Name: tc.name, Enabled: true, Action: "kill", EventTypes: tc.eventTypes,
				MinSeverity: tc.minSeverity, MatchDestIP: "203.0.113.9", KernelEnforce: true,
			})
			_, pushed := cb.pushed["203.0.113.9"]
			if pushed != tc.blocklisted || p.KernelEnforce != tc.blocklisted {
				t.Fatalf("blocklisted=%v kernel=%v (mode=%s), want %v", pushed, p.KernelEnforce, p.EnforcementMode, tc.blocklisted)
			}
			if tc.blocklisted {
				return
			}
			// Kept in userspace: an info connect to the IP gets exactly what
			// matchPolicy says, never a kernel-wide EPERM.
			want := uint32(ActionMonitor)
			if pe.matchPolicy(p, connect) {
				want = ActionKill
			}
			if got, _ := pe.Evaluate(connect); got != want {
				t.Errorf("Evaluate(connect) = %d, want %d", got, want)
			}
		})
	}
}

// The engine may skip userspace action on a connect only if the blocklist
// really denies it: map loaded, socket_connect hook attached, LSM config
// written, block_connect on. Any gap keeps dest-IP policies in userspace.
func TestConnectBlocklistWiredOnlyWhenItDenies(t *testing.T) {
	cases := []struct {
		name                                  string
		mapLoaded, hookAttached, blockConnect bool
		configErr                             error
		want                                  bool
	}{
		{"all in place", true, true, true, nil, true},
		{"map missing", false, true, true, nil, false},
		{"socket_connect attach failed", true, false, true, nil, false},
		{"config write failed", true, true, true, fmt.Errorf("map update: EPERM"), false},
		{"report-only", true, true, false, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := connectBlocklistDenies(tc.mapLoaded, tc.hookAttached, tc.blockConnect, tc.configErr)
			if got != tc.want {
				t.Fatalf("connectBlocklistDenies = %v (%s), want %v", got, reason, tc.want)
			}
			if !got && reason == "" {
				t.Fatal("refusal without a reason for the agent log")
			}
		})
	}
}

// The kernel blocklist is keyed by the four address bytes. Validation accepts
// both "198.51.100.1" and "::ffff:198.51.100.1"; if the engine tracked them
// as two entries, deleting one policy would delete the kernel entry the other
// still relies on, and Evaluate would keep skipping it as LSM-enforced.
func TestConnectBlockKeysAreCanonical(t *testing.T) {
	kernel := map[[4]byte]uint32{}
	key := func(ip string) [4]byte {
		var k [4]byte
		copy(k[:], net.ParseIP(strings.TrimSpace(ip)).To4())
		return k
	}
	pe := NewPolicyEngine()
	pe.SetConnectCallbacks(
		func(ip string, id uint32) error { kernel[key(ip)] = id; return nil },
		func(ip string) error { delete(kernel, key(ip)); return nil },
	)
	a := addPolicy(t, pe, EnforcementPolicy{Name: "a", Enabled: true, Action: "block", MatchDestIP: "198.51.100.1", KernelEnforce: true})
	b := addPolicy(t, pe, EnforcementPolicy{Name: "b", Enabled: true, Action: "block", MatchDestIP: "::ffff:198.51.100.1", KernelEnforce: true})
	if !a.KernelEnforce || !b.KernelEnforce {
		t.Fatalf("setup: modes %s/%s, want kernel", a.EnforcementMode, b.EnforcementMode)
	}
	if err := pe.DeletePolicy(a.ID); err != nil {
		t.Fatal(err)
	}
	if got, ok := kernel[key("198.51.100.1")]; !ok || got != b.ID {
		t.Fatalf("after deleting policy %d the kernel entry is %d (present=%v); want policy %d", a.ID, got, ok, b.ID)
	}
}
