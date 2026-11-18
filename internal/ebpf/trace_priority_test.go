package ebpf

import (
	"maps"
	"strings"
	"testing"
	"time"
)

// allTypes returns every trace event type at sev.
func allTypes(sev uint32) map[uint32]uint32 {
	out := make(map[uint32]uint32, TraceEventMax)
	for et := uint32(1); et <= TraceEventMax; et++ {
		out[et] = sev
	}
	return out
}

func policySet(ps ...EnforcementPolicy) map[uint32]*EnforcementPolicy {
	out := make(map[uint32]*EnforcementPolicy, len(ps))
	for i := range ps {
		p := ps[i]
		if p.ID == 0 {
			p.ID = uint32(i + 1)
		}
		out[p.ID] = &p
	}
	return out
}

// The kernel routes an event to the small priority ring when some
// enabled Kill policy that userspace evaluates could select it (event type
// and minimum severity), so a flood of other events cannot push the event
// that should trigger the kill out of the shared 16 MB ring.
func TestKillCandidateRoutes(t *testing.T) {
	cases := []struct {
		name     string
		policies map[uint32]*EnforcementPolicy
		want     map[uint32]uint32
	}{
		{
			name:     "kill on openat at high",
			policies: policySet(EnforcementPolicy{Enabled: true, Action: "kill", EventTypes: []string{"openat"}, MinSeverity: "high", MatchFilename: "/etc/shadow"}),
			want:     map[uint32]uint32{TraceOpen: SevHigh},
		},
		{
			name: "lowest severity wins per type",
			policies: policySet(
				EnforcementPolicy{Enabled: true, Action: "kill", EventTypes: []string{"openat"}, MinSeverity: "high", MatchComm: "curl"},
				EnforcementPolicy{Enabled: true, Action: "kill", EventTypes: []string{"OpenAt", "execve"}, MinSeverity: "medium", MatchComm: "wget"},
			),
			want: map[uint32]uint32{TraceOpen: SevMedium, TraceExecve: SevMedium},
		},
		{
			name:     "no event types selects every type",
			policies: policySet(EnforcementPolicy{Enabled: true, Action: "kill", MatchComm: "xmrig"}),
			want:     allTypes(SevInfo),
		},
		{
			name: "only enabled kill policies",
			policies: policySet(
				EnforcementPolicy{Enabled: true, Action: "alert", EventTypes: []string{"openat"}},
				EnforcementPolicy{Enabled: true, Action: "simulate", EventTypes: []string{"execve"}},
				EnforcementPolicy{Enabled: true, Action: "block", EventTypes: []string{"connect"}, MatchComm: "nc"},
				EnforcementPolicy{Enabled: true, Action: "monitor"},
				EnforcementPolicy{Enabled: false, Action: "kill", EventTypes: []string{"ptrace"}},
			),
			want: map[uint32]uint32{},
		},
		{
			name:     "unknown type names are ignored",
			policies: policySet(EnforcementPolicy{Enabled: true, Action: "kill", EventTypes: []string{"bogus", "ptrace"}, MatchComm: "gdb"}),
			want:     map[uint32]uint32{TracePtrace: SevInfo},
		},
		{
			name:     "a dest-IP policy only matches connect and sendto",
			policies: policySet(EnforcementPolicy{Enabled: true, Action: "kill", MatchDestIP: "203.0.113.9", MatchComm: "implant"}),
			want:     map[uint32]uint32{TraceConnect: SevInfo, TraceSendto: SevInfo},
		},
		{
			name:     "dest-IP policy with an unrelated event type list selects nothing",
			policies: policySet(EnforcementPolicy{Enabled: true, Action: "kill", EventTypes: []string{"openat"}, MatchDestIP: "203.0.113.9", MatchComm: "implant"}),
			want:     map[uint32]uint32{},
		},
		{
			// Nothing denies a connect in the kernel, so a kernel-mode Kill
			// policy for an address still needs the userspace kill.
			name:     "kernel-mode dest-IP kill keeps connect and sendto",
			policies: policySet(EnforcementPolicy{Enabled: true, Action: "kill", MatchDestIP: "203.0.113.9", KernelEnforce: true}),
			want:     map[uint32]uint32{TraceConnect: SevInfo, TraceSendto: SevInfo},
		},
		{
			name:     "no policies",
			policies: policySet(),
			want:     map[uint32]uint32{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, p := range tc.policies {
				normalizeEnforcementMode(p)
			}
			got := killCandidateRoutes(tc.policies)
			if !maps.Equal(got, tc.want) {
				t.Fatalf("routes = %v, want %v", got, tc.want)
			}
		})
	}
}

// The engine hands the routes to the TraceManager when the callback is set
// and after every policy change, so the kernel map follows the policy set.
func TestKillCandidateRoutingFollowsPolicies(t *testing.T) {
	pe := NewPolicyEngine()
	var calls []map[uint32]uint32
	pe.SetKillCandidateRouting(func(r killRoutes) { calls = append(calls, maps.Clone(r.Types)) })
	if len(calls) != 1 || len(calls[0]) != 0 {
		t.Fatalf("initial routes = %v, want one empty push", calls)
	}

	p := addPolicy(t, pe, EnforcementPolicy{Name: "shadow", Enabled: true, Action: "kill", EventTypes: []string{"openat"}, MinSeverity: "high", MatchFilename: "/etc/shadow"})
	if last := calls[len(calls)-1]; !maps.Equal(last, map[uint32]uint32{TraceOpen: SevHigh}) {
		t.Fatalf("after add: %v", last)
	}
	upd := *p
	upd.Action = "alert"
	if _, err := pe.UpdatePolicy(p.ID, upd); err != nil {
		t.Fatal(err)
	}
	if last := calls[len(calls)-1]; len(last) != 0 {
		t.Fatalf("after downgrade to alert: %v", last)
	}
	if err := pe.ReplacePolicies([]EnforcementPolicy{{ID: 9, Name: "x", Enabled: true, Action: "kill", EventTypes: []string{"ptrace"}, MatchComm: "gdb"}}); err != nil {
		t.Fatal(err)
	}
	if last := calls[len(calls)-1]; !maps.Equal(last, map[uint32]uint32{TracePtrace: SevInfo}) {
		t.Fatalf("after replace: %v", last)
	}
	if err := pe.DeletePolicy(9); err != nil {
		t.Fatal(err)
	}
	if last := calls[len(calls)-1]; len(last) != 0 {
		t.Fatalf("after delete: %v", last)
	}
}

// A rise in the kernel drop counters becomes one alert event per check,
// so an operator learns that kill-relevant events may have been missed.
func TestTraceLossAlert(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	base := traceLossCounters{BulkLost: 10, PriorityFull: 4, PriorityLost: 1}

	if _, ok := traceLossAlert(base, base, now); ok {
		t.Fatal("alert without any new loss")
	}

	evt, ok := traceLossAlert(base, traceLossCounters{BulkLost: 25, PriorityFull: 4, PriorityLost: 1}, now)
	if !ok || evt.Severity != SevMedium || evt.EventName != traceLossEventName || evt.Category != "security" {
		t.Fatalf("bulk-only loss: ok=%v %+v", ok, evt)
	}
	if !strings.Contains(evt.Description, "15 events dropped") {
		t.Errorf("bulk-only description: %q", evt.Description)
	}

	evt, ok = traceLossAlert(base, traceLossCounters{BulkLost: 10, PriorityFull: 4, PriorityLost: 3}, now)
	if !ok || evt.Severity != SevHigh {
		t.Fatalf("kill-candidate loss must be high: ok=%v sev=%d", ok, evt.Severity)
	}
	if !strings.Contains(evt.Description, "2 kill-candidate events lost") {
		t.Errorf("priority-loss description: %q", evt.Description)
	}

	evt, ok = traceLossAlert(base, traceLossCounters{BulkLost: 10, PriorityFull: 9, PriorityLost: 1}, now)
	if !ok || evt.Severity != SevLow || !strings.Contains(evt.Description, "5 kill-candidate events") {
		t.Fatalf("fallback-only (nothing lost) must be low: ok=%v %+v", ok, evt)
	}

	// Counters restart at zero with a new trace object: the new values are
	// the delta, never a wrapped subtraction.
	evt, ok = traceLossAlert(base, traceLossCounters{BulkLost: 2}, now)
	if !ok || !strings.Contains(evt.Description, "2 events dropped") {
		t.Fatalf("after counter reset: ok=%v %q", ok, evt.Description)
	}
	if evt.Timestamp != "2026-09-28T12:00:00Z" {
		t.Errorf("timestamp = %q", evt.Timestamp)
	}
}
