package ebpf

import (
	"fmt"
	"testing"
)

type connectCb struct {
	pushed  map[string]uint32
	removed map[string]bool
	pushErr error
}

func newConnectCb() *connectCb {
	return &connectCb{pushed: map[string]uint32{}, removed: map[string]bool{}}
}

func (c *connectCb) push(ip string, id uint32) error { c.pushed[ip] = id; return c.pushErr }
func (c *connectCb) remove(ip string) error          { c.removed[ip] = true; delete(c.pushed, ip); return nil }

func destIPPolicy(id uint32, name, ip, action string, enabled bool) EnforcementPolicy {
	return EnforcementPolicy{
		ID: id, Name: name, Enabled: enabled, Action: action,
		MatchDestIP: ip, KernelEnforce: true,
	}
}

// A dest-IP-only kernel policy pushes the IP into the LSM connect blocklist;
// deleting the policy removes it again.
func TestConnectBlockLifecycle(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	pe.SetConnectCallbacks(cb.push, cb.remove)

	p, err := pe.AddPolicy(destIPPolicy(0, "c2-block", "203.0.113.9", "block", true))
	if err != nil {
		t.Fatal(err)
	}
	if !p.KernelEnforce {
		t.Fatalf("dest-IP-only policy must stay kernel-enforced, mode=%s", p.EnforcementMode)
	}
	if got := cb.pushed["203.0.113.9"]; got != p.ID {
		t.Fatalf("connect block not pushed: %+v", cb.pushed)
	}

	if err := pe.DeletePolicy(p.ID); err != nil {
		t.Fatal(err)
	}
	if !cb.removed["203.0.113.9"] {
		t.Fatalf("connect block not removed after delete: %+v", cb.removed)
	}
}

// Replacing the snapshot swaps IPs atomically: stale ones removed, new ones pushed.
func TestConnectBlockReplace(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	pe.SetConnectCallbacks(cb.push, cb.remove)

	if err := pe.ReplacePolicies([]EnforcementPolicy{destIPPolicy(10, "a", "198.51.100.1", "block", true)}); err != nil {
		t.Fatal(err)
	}
	if err := pe.ReplacePolicies([]EnforcementPolicy{destIPPolicy(11, "b", "198.51.100.2", "block", true)}); err != nil {
		t.Fatal(err)
	}
	if !cb.removed["198.51.100.1"] || cb.pushed["198.51.100.2"] != 11 {
		t.Fatalf("replace did not reconcile: pushed=%+v removed=%+v", cb.pushed, cb.removed)
	}
}

// Disabled policies must not hold a blocklist entry.
func TestConnectBlockDisabledRemoved(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	pe.SetConnectCallbacks(cb.push, cb.remove)

	p, err := pe.AddPolicy(destIPPolicy(0, "x", "192.0.2.7", "block", true))
	if err != nil {
		t.Fatal(err)
	}
	upd := destIPPolicy(p.ID, "x", "192.0.2.7", "block", false)
	if _, err := pe.UpdatePolicy(p.ID, upd); err != nil {
		t.Fatal(err)
	}
	if !cb.removed["192.0.2.7"] {
		t.Fatalf("disabled policy kept its connect block: %+v", cb.removed)
	}
}

// Without connect callbacks the same policy downgrades to userspace.
func TestConnectBlockUnavailableDowngrades(t *testing.T) {
	pe := NewPolicyEngine()
	p, err := pe.AddPolicy(destIPPolicy(0, "nolsw", "203.0.113.9", "block", true))
	if err != nil {
		t.Fatal(err)
	}
	if p.KernelEnforce || p.EnforcementMode != "downgraded" {
		t.Fatalf("expected downgrade without LSM path, got mode=%s", p.EnforcementMode)
	}
}

// A dest-IP policy combined with comm/uid criteria cannot be kernel-enforced
// (the LSM hook matches only the IP — the rest would be silently ignored).
func TestConnectBlockPlusComplexStillDowngrades(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	pe.SetConnectCallbacks(cb.push, cb.remove)

	mixed := destIPPolicy(0, "mixed", "203.0.113.9", "block", true)
	uid := uint32(0)
	mixed.MatchComm = "curl"
	mixed.MatchUID = &uid
	p, err := pe.AddPolicy(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if p.KernelEnforce || p.EnforcementMode != "downgraded" {
		t.Fatalf("mixed-criteria policy must downgrade, got mode=%s", p.EnforcementMode)
	}
	if len(cb.pushed) != 0 {
		t.Fatalf("downgraded policy must not push: %+v", cb.pushed)
	}
}

// Push failures surface to the caller (snapshot rollback path).
func TestConnectBlockPushErrorPropagates(t *testing.T) {
	pe := NewPolicyEngine()
	cb := newConnectCb()
	cb.pushErr = fmt.Errorf("map full")
	pe.SetConnectCallbacks(cb.push, cb.remove)
	if _, err := pe.AddPolicy(destIPPolicy(0, "e", "203.0.113.9", "block", true)); err == nil {
		t.Fatal("expected push error to propagate")
	}
}
