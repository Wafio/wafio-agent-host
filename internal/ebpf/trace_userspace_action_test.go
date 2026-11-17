package ebpf

import (
	"fmt"
	"strings"
	"testing"
)

type recordedEffects struct {
	kills []uint32
	logs  []string
}

func (r *recordedEffects) effects() userspaceActionEffects {
	return userspaceActionEffects{
		kill: func(_ *TraceEvent, policyID uint32) { r.kills = append(r.kills, policyID) },
		logf: func(format string, args ...any) { r.logs = append(r.logs, fmt.Sprintf(format, args...)) },
	}
}

// A Simulate policy logs that it would have killed and never
// reaches the signal path.
func TestSimulateNeverSignals(t *testing.T) {
	pe := NewPolicyEngine()
	sim := addPolicy(t, pe, EnforcementPolicy{Name: "dry run", Enabled: true, Action: "simulate", MatchComm: "xmrig"})
	var fx recordedEffects
	evt := TraceEvent{EventName: "execve", Comm: "xmrig", PID: 4242}
	if !applyUserspacePolicy(&evt, pe, fx.effects()) {
		t.Fatal("simulate verdict not applied")
	}
	if len(fx.kills) != 0 {
		t.Fatalf("simulate reached the signal path %d time(s)", len(fx.kills))
	}
	if evt.Action != ActionSimulate || evt.PolicyID != sim.ID || evt.ActionName != actionName(ActionSimulate) {
		t.Fatalf("event after simulate: action=%d (%s) policy=%d", evt.Action, evt.ActionName, evt.PolicyID)
	}
	if len(fx.logs) != 1 || !strings.Contains(fx.logs[0], "would have been killed") || !strings.Contains(fx.logs[0], "pid=4242") {
		t.Fatalf("simulate log = %q", fx.logs)
	}
}

func TestUserspaceKillUsesSignalPath(t *testing.T) {
	pe := NewPolicyEngine()
	kill := addPolicy(t, pe, EnforcementPolicy{Name: "kill miner", Enabled: true, Action: "kill", MatchComm: "xmrig"})
	var fx recordedEffects
	evt := TraceEvent{EventName: "execve", Comm: "xmrig", PID: 7}
	applyUserspacePolicy(&evt, pe, fx.effects())
	if len(fx.kills) != 1 || fx.kills[0] != kill.ID || evt.Action != ActionKill {
		t.Fatalf("kill: signal calls %v, action %d", fx.kills, evt.Action)
	}
	if len(fx.logs) != 0 {
		t.Fatalf("kill logged a dry run: %q", fx.logs)
	}
}

// A kill the kernel already did is not evaluated again, and a userspace
// verdict that does not outrank the kernel's action changes nothing.
func TestUserspacePolicySkipsKernelKillAndLowerVerdicts(t *testing.T) {
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{Name: "dry run", Enabled: true, Action: "simulate", MatchComm: "xmrig"})
	var fx recordedEffects
	for _, kernel := range []uint32{ActionKill, ActionAlert} {
		evt := TraceEvent{EventName: "execve", Comm: "xmrig", Action: kernel, PolicyID: 99}
		if applyUserspacePolicy(&evt, pe, fx.effects()) {
			t.Fatalf("kernel action %d overridden by simulate", kernel)
		}
		if evt.Action != kernel || evt.PolicyID != 99 {
			t.Fatalf("event changed: %+v", evt)
		}
	}
	if len(fx.kills)+len(fx.logs) != 0 {
		t.Fatalf("effects ran: kills=%v logs=%q", fx.kills, fx.logs)
	}
}
