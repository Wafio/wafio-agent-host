package ebpf

import (
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

// A dest-IP policy always downgrades to userspace, whatever kernel mode was
// asked for, and userspace enforces every connect and sendto to the address,
// including a connect from an IPv6 socket to its IPv4-mapped form.
func TestDestIPKillIsEnforcedInUserspace(t *testing.T) {
	pe := NewPolicyEngine()
	p := addPolicy(t, pe, EnforcementPolicy{
		Name: "c2", Enabled: true, Action: "kill", MatchDestIP: "203.0.113.9", KernelEnforce: true,
	})
	if p.KernelEnforce || p.EnforcementMode != "downgraded" {
		t.Fatalf("setup: mode=%s, want downgraded", p.EnforcementMode)
	}
	events := []TraceEvent{
		{EventName: "connect", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443},
		{EventName: "connect", Comm: "implant", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9", Port: 443},
		{EventName: "sendto", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 53},
	}
	for _, evt := range events {
		if action, id := pe.Evaluate(evt); action != ActionKill || id != p.ID {
			t.Errorf("%s family=%d %s: action=%d policy=%d, want kill by %d", evt.EventName, evt.AddrFamily, evt.Addr, action, id, p.ID)
		}
	}
	if n := pe.EnforcementLogCount(); n != len(events) {
		t.Errorf("%d enforcement entries, want %d", n, len(events))
	}
	if got, _ := pe.GetPolicy(p.ID); got.HitCount != uint64(len(events)) {
		t.Errorf("hit count = %d, want %d", got.HitCount, len(events))
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "connect", AddrFamily: testAFInet, Addr: "8.8.8.8"}); action != ActionMonitor {
		t.Errorf("connect to 8.8.8.8 got action=%d", action)
	}
}
