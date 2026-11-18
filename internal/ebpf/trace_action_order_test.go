package ebpf

import "testing"

// An older control plane can still send action "block". Nothing denies a
// connect any more, so such a policy acts as alert whichever way it arrives:
// it matches, it is recorded, and nothing is killed.
func TestBlockPolicyActsAsAlert(t *testing.T) {
	policy := func(id uint32, action string) EnforcementPolicy {
		return EnforcementPolicy{ID: id, Name: "block", Enabled: true, Action: action, EventTypes: []string{"execve"}, MatchComm: "xmrig"}
	}
	load := map[string]func(pe *PolicyEngine) (uint32, error){
		"add": func(pe *PolicyEngine) (uint32, error) {
			p, err := pe.AddPolicy(policy(0, "block"))
			if err != nil {
				return 0, err
			}
			return p.ID, nil
		},
		"replace": func(pe *PolicyEngine) (uint32, error) {
			return 7, pe.ReplacePolicies([]EnforcementPolicy{policy(7, "Block")})
		},
		"update": func(pe *PolicyEngine) (uint32, error) {
			p, err := pe.AddPolicy(policy(0, "monitor"))
			if err != nil {
				return 0, err
			}
			_, err = pe.UpdatePolicy(p.ID, policy(p.ID, "block"))
			return p.ID, err
		},
	}
	evt := TraceEvent{EventName: "execve", Comm: "xmrig", Filename: "/tmp/xmrig"}
	for name, fn := range load {
		t.Run(name, func(t *testing.T) {
			pe := NewPolicyEngine()
			id, err := fn(pe)
			if err != nil {
				t.Fatal(err)
			}
			if p, err := pe.GetPolicy(id); err != nil || p.Action != "alert" {
				t.Fatalf("stored action = %+v, %v; want alert", p, err)
			}
			if action, got := pe.Evaluate(evt); action != ActionAlert || got != id {
				t.Fatalf("Evaluate: action=%d policy=%d, want alert by %d", action, got, id)
			}
			log := pe.GetEnforcementLog(0)
			if len(log) != 1 || log[0].Action != "alert" || !log[0].Success || log[0].PolicyID != id {
				t.Fatalf("enforcement log = %+v, want one successful alert entry", log)
			}
			if p, _ := pe.GetPolicy(id); p.HitCount != 1 {
				t.Fatalf("hit count = %d, want 1", p.HitCount)
			}
		})
	}
}

// A Block policy never suppresses a Kill policy that matches the same event.
func TestBlockMatchNeverSuppressesUserspaceKill(t *testing.T) {
	cases := []struct {
		name  string
		match EnforcementPolicy
		evt   TraceEvent
	}{
		{"execve", EnforcementPolicy{EventTypes: []string{"execve"}, MatchComm: "xmrig"},
			TraceEvent{EventName: "execve", Comm: "xmrig", Filename: "/tmp/xmrig"}},
		{"openat", EnforcementPolicy{EventTypes: []string{"openat"}, MatchFilename: "/etc/shadow"},
			TraceEvent{EventName: "openat", Comm: "cat", Filename: "/etc/shadow"}},
		{"connect to an address", EnforcementPolicy{MatchDestIP: "203.0.113.9"},
			TraceEvent{EventName: "connect", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pe := NewPolicyEngine()
			block := tc.match
			block.Name, block.Enabled, block.Action = "block", true, "block"
			kill := tc.match
			kill.Name, kill.Enabled, kill.Action = "kill", true, "kill"
			b := addPolicy(t, pe, block) // lower ID: would also win a tie
			k := addPolicy(t, pe, kill)
			if action, id := pe.Evaluate(tc.evt); action != ActionKill || id != k.ID {
				t.Fatalf("block %d + kill %d both match: action=%d policy=%d, want kill by %d", b.ID, k.ID, action, id, k.ID)
			}
		})
	}
}

// The single trace_enforce_map slot per event type goes to Kill over a policy
// that asked for Block, and that policy's own rule carries alert.
func TestKernelSlotPrefersKillOverBlock(t *testing.T) {
	pe := NewPolicyEngine()
	pushed := map[uint32]TraceEnforceRuleBPF{}
	pe.SetKernelCallbacks(
		func(et uint32, r TraceEnforceRuleBPF) error { pushed[et] = r; return nil },
		func(et uint32) error { delete(pushed, et); return nil },
	)
	b := addPolicy(t, pe, EnforcementPolicy{Name: "block", Enabled: true, Action: "block", EventTypes: []string{"execve"}, KernelEnforce: true})
	if r := pushed[TraceExecve]; r.Action != ActionAlert || r.PolicyID != b.ID {
		t.Fatalf("execve kernel slot = %+v, want alert by policy %d", r, b.ID)
	}
	k := addPolicy(t, pe, EnforcementPolicy{Name: "kill", Enabled: true, Action: "kill", EventTypes: []string{"execve"}, KernelEnforce: true, KillAcknowledged: true})
	if r := pushed[TraceExecve]; r.Action != ActionKill || r.PolicyID != k.ID {
		t.Fatalf("execve kernel slot = %+v, want kill by policy %d", r, k.ID)
	}
}
