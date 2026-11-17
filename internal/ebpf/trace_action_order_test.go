package ebpf

import "testing"

// Block is enforced only by the BPF-LSM hooks, before the event (the IP
// blocklist). From a traced event nothing can block
// any more: trace_enforce_map ignores it and userspace has no block path. It
// used to outrank Kill, so a matching Block policy won the event, did
// nothing, and suppressed a Kill that could have acted.

func TestActionPriorityKillOutranksBlock(t *testing.T) {
	if !(ActionPriority(ActionKill) > ActionPriority(ActionBlock) &&
		ActionPriority(ActionBlock) > ActionPriority(ActionAlert)) {
		t.Fatalf("want kill > block > alert, got kill=%d block=%d alert=%d",
			ActionPriority(ActionKill), ActionPriority(ActionBlock), ActionPriority(ActionAlert))
	}
}

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

// The kernel records a Block rule from trace_enforce_map on the event but
// cannot act on it; the userspace Kill that also matches still fires.
func TestKernelBlockRecordDoesNotSuppressUserspaceKill(t *testing.T) {
	pe := NewPolicyEngine()
	k := addPolicy(t, pe, EnforcementPolicy{Name: "kill", Enabled: true, Action: "kill", EventTypes: []string{"execve"}, MatchComm: "xmrig"})
	evt := TraceEvent{EventName: "execve", Comm: "xmrig", Action: ActionBlock, PolicyID: 999}
	action, id := pe.Evaluate(evt)
	if action != ActionKill || id != k.ID {
		t.Fatalf("kernel block record suppressed the kill: action=%d policy=%d", action, id)
	}
	// ringbufLoop applies the userspace result only when it outranks the
	// kernel's (ActionPriority): it must.
	if ActionPriority(action) <= ActionPriority(evt.Action) {
		t.Fatal("userspace kill does not outrank the kernel block record")
	}
}

// The single trace_enforce_map slot per event type goes to the action the
// kernel can carry out: Kill over Block.
func TestKernelSlotPrefersKillOverBlock(t *testing.T) {
	pe := NewPolicyEngine()
	pushed := map[uint32]TraceEnforceRuleBPF{}
	pe.SetKernelCallbacks(
		func(et uint32, r TraceEnforceRuleBPF) error { pushed[et] = r; return nil },
		func(et uint32) error { delete(pushed, et); return nil },
	)
	addPolicy(t, pe, EnforcementPolicy{Name: "block", Enabled: true, Action: "block", EventTypes: []string{"execve"}, KernelEnforce: true})
	k := addPolicy(t, pe, EnforcementPolicy{Name: "kill", Enabled: true, Action: "kill", EventTypes: []string{"execve"}, KernelEnforce: true, KillAcknowledged: true})
	if r := pushed[TraceExecve]; r.Action != ActionKill || r.PolicyID != k.ID {
		t.Fatalf("execve kernel slot = %+v, want kill by policy %d", r, k.ID)
	}
}

// Block and Kill on the same destination both ride the LSM connect
// blocklist: the kernel denies the connect once, and userspace adds nothing
// (no kill of a process whose connect never happened). Both count the hit.
func TestBlockAndKillOnKernelBlockedConnectNoDoubleAction(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	pe.SetConnectCallbacks(cb.push, cb.remove)
	pe.SetConnectBlocklistIPv4Mapped(true)
	b := addPolicy(t, pe, EnforcementPolicy{Name: "block", Enabled: true, Action: "block", MatchDestIP: "203.0.113.9", KernelEnforce: true})
	k := addPolicy(t, pe, EnforcementPolicy{Name: "kill", Enabled: true, Action: "kill", MatchDestIP: "203.0.113.9", KernelEnforce: true})
	if !b.KernelEnforce || !k.KernelEnforce || len(cb.pushed) != 1 {
		t.Fatalf("setup: both policies must ride one blocklist entry (pushed=%v)", cb.pushed)
	}
	for _, evt := range []TraceEvent{
		{EventName: "connect", Comm: "implant", AddrFamily: testAFInet, Addr: "203.0.113.9", Port: 443},
		{EventName: "connect", Comm: "implant", AddrFamily: testAFInet6, Addr: "::ffff:203.0.113.9", Port: 443},
	} {
		if action, id := pe.Evaluate(evt); action != ActionMonitor || id != 0 {
			t.Errorf("family=%d: kernel-blocked connect acted on again: action=%d policy=%d", evt.AddrFamily, action, id)
		}
	}
	if n := pe.EnforcementLogCount(); n != 0 {
		t.Errorf("%d userspace enforcement entries for kernel-blocked connects", n)
	}
	for _, id := range []uint32{b.ID, k.ID} {
		if p, _ := pe.GetPolicy(id); p.HitCount != 2 {
			t.Errorf("policy %d hit count = %d, want 2", id, p.HitCount)
		}
	}
}
