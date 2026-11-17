package ebpf

import (
	"fmt"
	"testing"
)

// PolicyEngine decides whether a process on a customer's host gets killed. It
// had no tests at all. These cover the decision itself -- what matches, what
// wins when several policies match, and the two behaviours that are easy to
// walk into and expensive to discover in production.

func uidPtr(u uint32) *uint32 { return &u }

func addPolicy(t *testing.T, pe *PolicyEngine, p EnforcementPolicy) *EnforcementPolicy {
	t.Helper()
	out, err := pe.AddPolicy(p)
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	return out
}

func TestEvaluateNoPoliciesMonitorsOnly(t *testing.T) {
	pe := NewPolicyEngine()
	action, id := pe.Evaluate(TraceEvent{EventName: "execve", Comm: "bash"})
	if action != ActionMonitor || id != 0 {
		t.Fatalf("empty engine returned action=%d policy=%d; want monitor and no policy", action, id)
	}
}

// A policy with no criteria matches every event. That is what the field
// comments say -- "empty = any" on each one -- but combined with action "kill"
// it means one saved policy with nothing filled in kills every traced process
// on the host. Asserted so the behaviour is a decision on record rather than a
// surprise. Validation now refuses such a policy unless kill_acknowledged is
// set (TestBroadKillPolicyRequiresAcknowledgement); matching is unchanged.
func TestPolicyWithNoCriteriaMatchesEverything(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{Name: "catch-all", Enabled: true, Action: "kill", KillAcknowledged: true})

	for _, evt := range []TraceEvent{
		{EventName: "execve", Comm: "bash"},
		{EventName: "connect", Comm: "sshd", Port: 22},
		{EventName: "open", Filename: "/etc/hosts"},
	} {
		if action, _ := pe.Evaluate(evt); action != ActionKill {
			t.Errorf("event %+v did not match the criteria-free policy", evt)
		}
	}
}

func TestDisabledPolicyNeverMatches(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{
		Name: "off", Enabled: false, Action: "kill", MatchComm: "ncat",
	})
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Comm: "ncat"}); action != ActionMonitor {
		t.Fatalf("a disabled policy was applied: action=%d", action)
	}
}

// A substring comm policy meant for "sh" also fires on "bash", "ssh" and
// "flush". For a kill action that is the difference between stopping a reverse
// shell and killing the operator's session. Tightened on purpose: new
// policies default to word matching, the substring mode must be chosen
// explicitly, and a two-letter kill term needs kill_acknowledged.
func TestCommMatchIsSubstringAndOverReaches(t *testing.T) {
	pe := NewPolicyEngine()
	if _, err := pe.AddPolicy(EnforcementPolicy{Name: "shells", Enabled: true, Action: "kill", MatchComm: "sh"}); err == nil {
		t.Fatal("a two-letter kill term was accepted without kill_acknowledged")
	}
	addPolicy(t, pe, EnforcementPolicy{
		Name: "shells", Enabled: true, Action: "kill", MatchComm: "sh",
		MatchCommMode: CommMatchSubstring, KillAcknowledged: true,
	})
	for _, comm := range []string{"sh", "bash", "ssh", "flush"} {
		if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Comm: comm}); action != ActionKill {
			t.Errorf("comm %q did not match the substring policy", comm)
		}
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Comm: "python3"}); action != ActionMonitor {
		t.Error("comm 'python3' matched a policy for 'sh'")
	}

	word := NewPolicyEngine()
	addPolicy(t, word, EnforcementPolicy{Name: "shells", Enabled: true, Action: "kill", MatchComm: "sh", KillAcknowledged: true})
	for comm, want := range map[string]uint32{"sh": ActionKill, "bash": ActionMonitor, "ssh": ActionMonitor, "flush": ActionMonitor} {
		if action, _ := word.Evaluate(TraceEvent{EventName: "execve", Comm: comm}); action != want {
			t.Errorf("word policy for sh: comm %q action=%d, want %d", comm, action, want)
		}
	}
}

func TestCommMatchIsCaseInsensitiveAndCommaSeparated(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{
		Name: "tools", Enabled: true, Action: "alert", MatchComm: "nc, Ncat , socat",
	})
	for _, comm := range []string{"nc", "NCAT", "socat"} {
		if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Comm: comm}); action != ActionAlert {
			t.Errorf("comm %q did not match", comm)
		}
	}
}

// On execve the kernel reports the *calling* process's comm, so a policy for
// "dig" would never fire without the basename fallback. This is the reason that
// fallback exists; without it the feature silently does nothing.
func TestExecveFallsBackToTheExecutedFilename(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{
		Name: "dig", Enabled: true, Action: "alert", MatchComm: "dig",
	})

	// comm is the shell that called it, not the program being run.
	evt := TraceEvent{EventName: "execve", Comm: "sh", Filename: "/usr/bin/dig"}
	if action, _ := pe.Evaluate(evt); action != ActionAlert {
		t.Fatal("execve did not fall back to the executed filename; policies on program names would never fire")
	}

	// The fallback is only for execve. On other events the filename must not
	// stand in for comm, or a policy on a process name would match any event
	// that merely touched a file with that name.
	other := TraceEvent{EventName: "open", Comm: "sh", Filename: "/usr/bin/dig"}
	if action, _ := pe.Evaluate(other); action != ActionMonitor {
		t.Error("the execve filename fallback leaked into a non-execve event")
	}
}

func TestEventTypeFilter(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{
		Name: "connects", Enabled: true, Action: "alert",
		EventTypes: []string{"connect", "bind"},
	})
	if action, _ := pe.Evaluate(TraceEvent{EventName: "CONNECT"}); action != ActionAlert {
		t.Error("event type matching should be case-insensitive")
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve"}); action != ActionMonitor {
		t.Error("an event outside the policy's list matched")
	}
}

func TestMinSeverityFilter(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{
		Name: "high only", Enabled: true, Action: "alert", MinSeverity: "high",
	})
	high := ParseSeverityName("high")
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Severity: high}); action != ActionAlert {
		t.Error("an event at exactly the minimum severity was excluded")
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Severity: high - 1}); action != ActionMonitor {
		t.Error("an event below the minimum severity matched")
	}
}

func TestUIDFilterDistinguishesZeroFromUnset(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{
		Name: "root only", Enabled: true, Action: "alert", MatchUID: uidPtr(0),
	})
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", UID: 0}); action != ActionAlert {
		t.Error("uid 0 did not match a policy for uid 0")
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", UID: 1000}); action != ActionMonitor {
		t.Error("uid 1000 matched a policy for uid 0")
	}

	// The pointer is what separates "match root" from "match anyone". If
	// MatchUID were a plain uint32, a policy meaning "any user" would silently
	// become "root only".
	pe2 := NewPolicyEngine()
	addPolicy(t, pe2, EnforcementPolicy{Name: "any uid", Enabled: true, Action: "alert"})
	if action, _ := pe2.Evaluate(TraceEvent{EventName: "execve", UID: 1000}); action != ActionAlert {
		t.Error("a policy with no UID criterion failed to match a non-root event")
	}
}

func TestDestPortListAndBadEntries(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{
		Name: "c2 ports", Enabled: true, Action: "kill",
		EventTypes: []string{"connect"}, MatchDestPort: "4444, 1337 ,443",
	})
	for _, port := range []uint16{4444, 1337, 443} {
		if action, _ := pe.Evaluate(TraceEvent{EventName: "connect", Port: port}); action != ActionKill {
			t.Errorf("port %d did not match", port)
		}
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "connect", Port: 80}); action != ActionMonitor {
		t.Error("port 80 matched a policy that does not list it")
	}

	// An unparseable entry must not become a wildcard.
	pe2 := NewPolicyEngine()
	if _, err := pe2.AddPolicy(EnforcementPolicy{
		Name: "typo", Enabled: true, Action: "kill",
		EventTypes: []string{"connect"}, MatchDestPort: "44a4",
	}); err == nil {
		t.Fatal("malformed port accepted")
	}
	if action, _ := pe2.Evaluate(TraceEvent{EventName: "connect", Port: 4444}); action != ActionMonitor {
		t.Error("a malformed port entry matched an event; a typo must not widen a kill policy")
	}
}

// Criteria are AND-ed. A policy naming both a process and a file must not fire
// on an event that satisfies only one.
func TestCriteriaAreAnded(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{
		Name: "curl writing to tmp", Enabled: true, Action: "kill",
		MatchComm: "curl", MatchFilename: "/tmp/",
	})
	if action, _ := pe.Evaluate(TraceEvent{EventName: "open", Comm: "curl", Filename: "/tmp/x"}); action != ActionKill {
		t.Error("an event meeting both criteria did not match")
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "open", Comm: "curl", Filename: "/etc/passwd"}); action != ActionMonitor {
		t.Error("an event meeting only the comm criterion matched")
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "open", Comm: "vim", Filename: "/tmp/x"}); action != ActionMonitor {
		t.Error("an event meeting only the filename criterion matched")
	}
}

// When several policies match, the most severe action wins, whatever order
// they happen to be stored in.
func TestMostSevereMatchingActionWins(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{Name: "a", Enabled: true, Action: "alert", MatchComm: "ncat"})
	kill := addPolicy(t, pe, EnforcementPolicy{Name: "k", Enabled: true, Action: "kill", MatchComm: "ncat"})
	addPolicy(t, pe, EnforcementPolicy{Name: "s", Enabled: true, Action: "simulate", MatchComm: "ncat"})

	action, id := pe.Evaluate(TraceEvent{EventName: "execve", Comm: "ncat"})
	if action != ActionKill {
		t.Fatalf("action = %d, want kill; the most severe matching policy must win", action)
	}
	if id != kill.ID {
		t.Errorf("reported policy %d, want the kill policy %d", id, kill.ID)
	}
}

func TestActionPriorityOrdering(t *testing.T) {
	if !(ActionPriority(ActionKill) > ActionPriority(ActionAlert) &&
		ActionPriority(ActionAlert) > ActionPriority(ActionSimulate) &&
		ActionPriority(ActionSimulate) > ActionPriority(ActionMonitor)) {
		t.Fatal("action priority is not ordered monitor < simulate < alert < kill")
	}
}

// simulate exists so a policy can be trialled without killing anything. It must
// be reported and logged, but it must never be the same value as kill.
func TestSimulateIsAuditedButIsNotKill(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{
		Name: "dry run", Enabled: true, Action: "simulate", MatchComm: "nc",
	})
	action, id := pe.Evaluate(TraceEvent{EventName: "execve", Comm: "nc"})
	if action == ActionKill {
		t.Fatal("a simulate policy resolved to kill")
	}
	if action != ActionSimulate || id == 0 {
		t.Fatalf("simulate should report itself: action=%d policy=%d", action, id)
	}
	if n := pe.EnforcementLogCount(); n != 1 {
		t.Errorf("simulate produced %d audit entries, want 1 -- a dry run that leaves no record is not a dry run", n)
	}
}

// Monitor is the default and produces no audit entry; otherwise every traced
// syscall on the host would be logged as an enforcement.
func TestMonitorProducesNoEnforcementLog(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{Name: "watch", Enabled: true, Action: "monitor", MatchComm: "nc"})
	pe.Evaluate(TraceEvent{EventName: "execve", Comm: "nc"})
	if n := pe.EnforcementLogCount(); n != 0 {
		t.Errorf("monitor wrote %d enforcement entries, want 0", n)
	}
}

// The log is in memory on a host that may run for months. It has to be bounded.
func TestEnforcementLogIsBounded(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{Name: "noisy", Enabled: true, Action: "alert", MatchComm: "nc"})

	for i := 0; i < pe.maxLogEntries*2; i++ {
		pe.Evaluate(TraceEvent{EventName: "execve", Comm: "nc"})
	}
	if n := pe.EnforcementLogCount(); n > pe.maxLogEntries {
		t.Fatalf("enforcement log holds %d entries, above its own cap of %d", n, pe.maxLogEntries)
	}
}

func TestDeletedPolicyStopsMatching(t *testing.T) {
	pe := NewPolicyEngine()
	p := addPolicy(t, pe, EnforcementPolicy{Name: "temp", Enabled: true, Action: "kill", MatchComm: "ncat"})
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Comm: "ncat"}); action != ActionKill {
		t.Fatal("policy did not take effect")
	}
	if err := pe.DeletePolicy(p.ID); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Comm: "ncat"}); action != ActionMonitor {
		t.Fatal("a deleted policy still killed a process")
	}
}

func TestKernelPortPredicateNeverBroadens(t *testing.T) {
	pe := NewPolicyEngine()
	pushed := 0
	pe.SetKernelCallbacks(func(uint32, TraceEnforceRuleBPF) error { pushed++; return nil }, func(uint32) error { return nil })
	p := addPolicy(t, pe, EnforcementPolicy{Name: "port", Enabled: true, Action: "kill", KernelEnforce: true, EventTypes: []string{"connect"}, MatchDestPort: "4444"})
	if p.KernelEnforce || !p.AutoDowngraded || pushed != 0 {
		t.Fatalf("port predicate broadened: %+v pushed=%d", p, pushed)
	}
	if a, _ := pe.Evaluate(TraceEvent{EventName: "connect", Port: 443}); a != ActionMonitor {
		t.Fatal("unrelated port matched")
	}
}

func TestEqualPriorityUsesLowestStablePolicyID(t *testing.T) {
	pe := NewPolicyEngine()
	first := addPolicy(t, pe, EnforcementPolicy{Name: "first", Enabled: true, Action: "alert"})
	addPolicy(t, pe, EnforcementPolicy{Name: "second", Enabled: true, Action: "alert"})
	for i := 0; i < 100; i++ {
		if _, id := pe.Evaluate(TraceEvent{}); id != first.ID {
			t.Fatalf("unstable winner %d", id)
		}
	}
}

func TestReplacePoliciesPreservesIDsAndClearsLast(t *testing.T) {
	pe := NewPolicyEngine()
	snapshot := []EnforcementPolicy{{ID: 42, Name: "server", Enabled: true, Action: "alert"}}
	if err := pe.ReplacePolicies(snapshot); err != nil {
		t.Fatal(err)
	}
	if _, id := pe.Evaluate(TraceEvent{}); id != 42 {
		t.Fatalf("lost server identity: %d", id)
	}
	if err := pe.ReplacePolicies(snapshot); err != nil {
		t.Fatal(err)
	}
	if p, _ := pe.GetPolicy(42); p.HitCount != 1 {
		t.Fatal("idempotent replay reset counters")
	}
	if err := pe.ReplacePolicies([]EnforcementPolicy{{ID: 43, Name: "valid"}, {ID: 0, Name: "invalid"}}); err == nil {
		t.Fatal("accepted invalid snapshot")
	}
	if _, err := pe.GetPolicy(42); err != nil {
		t.Fatal("invalid snapshot destroyed prior state")
	}
	if err := pe.ReplacePolicies(nil); err != nil {
		t.Fatal(err)
	}
	if a, _ := pe.Evaluate(TraceEvent{}); a != ActionMonitor {
		t.Fatal("empty snapshot did not clear")
	}
}

func TestKernelOverlappingThresholdsRetainBothPolicies(t *testing.T) {
	pe := NewPolicyEngine()
	rules := map[uint32]TraceEnforceRuleBPF{}
	pe.SetKernelCallbacks(func(k uint32, r TraceEnforceRuleBPF) error { rules[k] = r; return nil }, func(k uint32) error { delete(rules, k); return nil })
	addPolicy(t, pe, EnforcementPolicy{Name: "alert low", Enabled: true, Action: "alert", KernelEnforce: true, MinSeverity: "low", EventTypes: []string{"connect"}})
	addPolicy(t, pe, EnforcementPolicy{Name: "kill critical", Enabled: true, Action: "kill", KernelEnforce: true, MinSeverity: "critical", EventTypes: []string{"connect"}, KillAcknowledged: true})
	if len(rules) != 0 {
		t.Fatal("single-slot kernel rule loses the lower threshold; must use userspace")
	}
	if a, _ := pe.Evaluate(TraceEvent{EventName: "connect", Severity: SevLow}); a != ActionAlert {
		t.Fatal("lost low alert")
	}
	if a, _ := pe.Evaluate(TraceEvent{EventName: "connect", Severity: SevCritical}); a != ActionKill {
		t.Fatal("lost critical kill")
	}
}

func TestKernelKillWithoutOutcomeIsUnknown(t *testing.T) {
	pe := NewPolicyEngine()
	pe.RecordKernelEnforcement(TraceEvent{Action: ActionKill, PolicyID: 1})
	if pe.GetEnforcementLog(1)[0].Success {
		t.Fatal("unconfirmed kernel kill reported success")
	}
}

func TestKernelAlertStillAllowsStrongerUserspaceAction(t *testing.T) {
	pe := NewPolicyEngine()
	alert := addPolicy(t, pe, EnforcementPolicy{Name: "kernel alert", Enabled: true, Action: "alert"})
	kill := addPolicy(t, pe, EnforcementPolicy{Name: "scoped kill", Enabled: true, Action: "kill", MatchDestPort: "4444"})
	evt := TraceEvent{Action: ActionAlert, PolicyID: alert.ID, Port: 4444}
	if a, id := pe.Evaluate(evt); a != ActionKill || id != kill.ID {
		t.Fatalf("kernel alert hid userspace kill: %d %d", a, id)
	}
}

func TestPolicyValidationRejectsFallbacksThatBroaden(t *testing.T) {
	for _, p := range []EnforcementPolicy{
		{Name: "typo", MinSeverity: "critical "},
		{Name: "typo", Action: "kil"},
		{Name: "typo", EventTypes: []string{"missing_probe"}},
		{Name: "port", MatchDestPort: "4444,invalid"},
	} {
		if _, err := NewPolicyEngine().AddPolicy(p); err == nil {
			t.Errorf("invalid policy accepted: %+v", p)
		}
	}
}

func TestReplacePolicyMapFailureRestoresPriorSnapshot(t *testing.T) {
	pe := NewPolicyEngine()
	rules := map[uint32]TraceEnforceRuleBPF{}
	fail := false
	pe.SetKernelCallbacks(func(k uint32, r TraceEnforceRuleBPF) error {
		if fail && r.PolicyID == 2 {
			fail = false
			return fmt.Errorf("injected map failure")
		}
		rules[k] = r
		return nil
	}, func(k uint32) error { delete(rules, k); return nil })
	if err := pe.ReplacePolicies([]EnforcementPolicy{{ID: 1, Name: "old", Enabled: true, Action: "alert", KernelEnforce: true, EventTypes: []string{"connect"}}}); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := pe.ReplacePolicies([]EnforcementPolicy{{ID: 2, Name: "new", Enabled: true, Action: "kill", KernelEnforce: true, EventTypes: []string{"execve"}, KillAcknowledged: true}}); err == nil {
		t.Fatal("map failure swallowed")
	}
	if _, err := pe.GetPolicy(1); err != nil {
		t.Fatal("last-known-good policy lost")
	}
	if len(rules) != 1 || rules[TraceConnect].PolicyID != 1 {
		t.Fatalf("kernel rollback failed: %+v", rules)
	}
}

func TestDeferredSignalLogNeverClaimsSuccessBeforeAcceptance(t *testing.T) {
	pe := NewPolicyEngine()
	p := addPolicy(t, pe, EnforcementPolicy{Name: "deferred", Enabled: true, Action: "kill", KillAcknowledged: true})
	evt := TraceEvent{PID: 4242, TimestampNs: 123}
	pe.Evaluate(evt)
	pe.RecordSignalRequested(p.ID, evt)
	logs := pe.GetEnforcementLog(1)
	if len(logs) != 1 || logs[0].Success || logs[0].Event.SignalOutcome != "requested" || logs[0].Mode != "deferred" {
		t.Fatalf("premature outcome: %+v", logs)
	}
	evt.SignalOutcome = "expired"
	pe.RecordSignalOutcome(p.ID, evt, fmt.Errorf("expired"))
	logs = pe.GetEnforcementLog(1)
	if logs[0].Success || logs[0].Event.SignalOutcome != "expired" {
		t.Fatalf("expiry lost: %+v", logs)
	}
}

func TestDeferredOutcomeSurvivesRequestedDrain(t *testing.T) {
	pe := NewPolicyEngine()
	p := addPolicy(t, pe, EnforcementPolicy{Name: "deferred", Enabled: true, Action: "kill", KillAcknowledged: true})
	evt := TraceEvent{PID: 4242, TimestampNs: 123, ProcessStartNs: 456}
	pe.Evaluate(evt)
	pe.RecordSignalRequested(p.ID, evt)
	requested := pe.DrainEnforcementLog(1)
	pe.RecordSignalOutcome(p.ID, evt, nil)
	outcomes := pe.DrainEnforcementLog(1)
	if len(outcomes) != 1 || !outcomes[0].Success || outcomes[0].Event.SignalOutcome != "accepted" || outcomes[0].Mode != "deferred_outcome" {
		t.Fatalf("lost outcome %+v", outcomes)
	}
	if outcomes[0].Event.TimestampNs != requested[0].Event.TimestampNs || outcomes[0].Timestamp == requested[0].Timestamp {
		t.Fatal("outcome correlation or record identity lost")
	}
}

func TestEnforcementBufferOverflowIsCounted(t *testing.T) {
	pe := NewPolicyEngine()
	pe.maxLogEntries = 1
	addPolicy(t, pe, EnforcementPolicy{Name: "alert", Enabled: true, Action: "alert"})
	pe.Evaluate(TraceEvent{PID: 42, TimestampNs: 1})
	pe.Evaluate(TraceEvent{PID: 42, TimestampNs: 2})
	if pe.EnforcementDropped() != 1 {
		t.Fatal("silent enforcement log loss")
	}
	pe.DrainEnforcementLog(1)
	if pe.EnforcementDropped() != 1 {
		t.Fatal("drain erased cumulative loss")
	}
}

func TestExecveMissingFilenameDoesNotInventCommMatch(t *testing.T) {
	pe := NewPolicyEngine()
	// "." is a one-character (broad) substring term: acknowledged explicitly.
	addPolicy(t, pe, EnforcementPolicy{Name: "dotted programs", Enabled: true, Action: "kill", MatchComm: ".", MatchCommMode: CommMatchSubstring, KillAcknowledged: true})
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Comm: "sh"}); action != ActionMonitor {
		t.Fatal("missing exec filename became '.' and matched a kill policy")
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execveat", Comm: "sh", Filename: "/tmp/script.py"}); action != ActionKill {
		t.Fatal("real filename substring stopped matching")
	}
}

func TestPolicyCriteriaAreIsolatedFromCallerMutation(t *testing.T) {
	for _, source := range []string{"add input", "add output", "update input", "update output", "get", "list", "replace input"} {
		t.Run(source, func(t *testing.T) {
			pe := NewPolicyEngine()
			input := EnforcementPolicy{Name: "scoped kill", Enabled: true, Action: "kill", EventTypes: []string{"connect"}, MatchUID: uidPtr(1000)}
			output := addPolicy(t, pe, input)
			var exposed *EnforcementPolicy
			switch source {
			case "add input":
				exposed = &input
			case "add output":
				exposed = output
			case "update input", "update output":
				update := EnforcementPolicy{Name: input.Name, Enabled: true, Action: "kill", EventTypes: []string{"connect"}, MatchUID: uidPtr(1000)}
				updated, err := pe.UpdatePolicy(output.ID, update)
				if err != nil {
					t.Fatal(err)
				}
				exposed = &update
				if source == "update output" {
					exposed = updated
				}
			case "get":
				var err error
				exposed, err = pe.GetPolicy(output.ID)
				if err != nil {
					t.Fatal(err)
				}
			case "list":
				listed := pe.ListPolicies()
				exposed = &listed[0]
			case "replace input":
				input.ID = output.ID
				if err := pe.ReplacePolicies([]EnforcementPolicy{input}); err != nil {
					t.Fatal(err)
				}
				exposed = &input
			}
			exposed.EventTypes[0] = "execve"
			*exposed.MatchUID = 0
			if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", UID: 0}); action != ActionMonitor {
				t.Fatal("caller mutation broadened the active kill policy to root execs")
			}
			if action, _ := pe.Evaluate(TraceEvent{EventName: "connect", UID: 1000}); action != ActionKill {
				t.Fatal("caller mutation changed the saved policy's original criteria")
			}
		})
	}
}

func TestTraceConfigAcceptedCasePreservesKernelFilters(t *testing.T) {
	for _, severity := range []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		cfg := TraceConfigAPI{Enabled: true, EventTypes: []string{"CONNECT"}, MinSeverity: severity}
		if err := ValidateTraceConfig(cfg); err != nil {
			t.Fatal(err)
		}
		bpf := traceConfigToBPF(cfg, 1)
		if bpf.MinSeverity != ParseSeverityName(severity) {
			t.Errorf("%s became severity %d", severity, bpf.MinSeverity)
		}
		want := traceConfigToBPF(TraceConfigAPI{EventTypes: []string{"connect"}}, 1).EventMaskLo
		if bpf.EventMaskLo != want {
			t.Errorf("accepted uppercase event lost its kernel filter: mask %x want %x", bpf.EventMaskLo, want)
		}
	}
}
