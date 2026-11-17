package ebpf

import (
	"errors"
	"testing"
)

// fakePortPolicyMap is an in-memory port policy map with an optional write
// failure for one port.
type fakePortPolicyMap struct {
	cfg      *FullConfigAPI
	policy   *PortPolicyConfigAPI
	rules    map[portPolicyMapKey]PortPolicyAPI
	failOn   uint16
	writes   int
	sshPorts []uint16
	after    func(op string) // called after every applied write or removal
}

func (f *fakePortPolicyMap) ListAllowlist(int) ([]AllowlistEntry, error) { return nil, nil }
func (f *fakePortPolicyMap) LiveBlocks() ([]BlocklistEntry, []EgressBlocklistEntry, error) {
	return nil, nil, nil
}
func (f *fakePortPolicyMap) HostFirewallEnv() HostFirewallEnv {
	return HostFirewallEnv{SSHPorts: f.sshPorts, Exemptions: true}
}

func (f *fakePortPolicyMap) GetFullConfig() (*FullConfigAPI, error) { return f.cfg, nil }
func (f *fakePortPolicyMap) GetPortPolicyConfig() (*PortPolicyConfigAPI, error) {
	return f.policy, nil
}
func (f *fakePortPolicyMap) ListPortPolicies(limit int) ([]PortPolicyAPI, error) {
	out := make([]PortPolicyAPI, 0, len(f.rules))
	for _, r := range f.rules {
		if len(out) >= limit {
			break
		}
		out = append(out, r)
	}
	return out, nil
}
func (f *fakePortPolicyMap) AddPortPolicy(p PortPolicyAPI) error {
	f.writes++
	if p.Port == f.failOn {
		return errors.New("map full")
	}
	f.rules[portPolicyKey(p)] = p
	if f.after != nil {
		f.after("add")
	}
	return nil
}
func (f *fakePortPolicyMap) RemovePortPolicy(port uint16, proto, dir string) error {
	delete(f.rules, portPolicyKey(PortPolicyAPI{Port: port, Proto: proto, Direction: dir}))
	if f.after != nil {
		f.after("remove")
	}
	return nil
}

// A port policy batch that passes the lockout check is applied
// all-or-nothing: a failed rule rolls back the ones already written, and a
// batch that would overflow the map writes nothing.
func TestLocalPortPolicyBatchAllOrNothing(t *testing.T) {
	ssh := PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"}
	newMap := func() *fakePortPolicyMap {
		return &fakePortPolicyMap{
			cfg:    &FullConfigAPI{Global: GlobalConfigAPI{EnableConntrack: true}},
			policy: &PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"},
			rules:  map[portPolicyMapKey]PortPolicyAPI{portPolicyKey(ssh): ssh},
		}
	}

	// Move SSH (sshd now listens on 2222): drop 22 + allow 2222. The allow
	// write fails, nothing changes.
	m := newMap()
	m.failOn = 2222
	m.sshPorts = []uint16{2222}
	moveSSH := []PortPolicyAPI{
		{Port: 22, Proto: "tcp", Direction: "ingress", Action: "drop"},
		{Port: 2222, Proto: "tcp", Direction: "ingress", Action: "allow"},
	}
	if _, err := applyLocalPortPolicies(m, moveSSH); !errors.Is(err, ErrPortPolicyBatch) {
		t.Fatalf("err = %v, want ErrPortPolicyBatch", err)
	}
	if got := m.rules[portPolicyKey(ssh)]; got.Action != "allow" || len(m.rules) != 1 {
		t.Fatalf("after failed batch rules = %+v, want only the ssh allow", m.rules)
	}

	// A failing deny after a successful allow rolls the allow back too.
	m = newMap()
	m.failOn = 80
	web := []PortPolicyAPI{
		{Port: 80, Proto: "tcp", Direction: "ingress", Action: "drop"},
		{Port: 443, Proto: "tcp", Direction: "ingress", Action: "allow"},
	}
	if _, err := applyLocalPortPolicies(m, web); !errors.Is(err, ErrPortPolicyBatch) {
		t.Fatalf("err = %v, want ErrPortPolicyBatch", err)
	}
	if len(m.rules) != 1 {
		t.Fatalf("rollback left %d rules, want 1", len(m.rules))
	}

	// Capacity: a batch that would overflow the map is refused unwritten.
	m = newMap()
	for p := 1000; len(m.rules) < maxPortPolicies; p++ {
		r := PortPolicyAPI{Port: uint16(p), Proto: "udp", Direction: "ingress", Action: "drop"}
		m.rules[portPolicyKey(r)] = r
	}
	m.writes = 0
	if _, err := applyLocalPortPolicies(m, []PortPolicyAPI{{Port: 9, Proto: "tcp", Direction: "ingress", Action: "drop"}}); !errors.Is(err, ErrPortPolicyBatch) {
		t.Fatalf("overflow err = %v, want ErrPortPolicyBatch", err)
	}
	if m.writes != 0 {
		t.Fatalf("overflowing batch wrote %d rules, want 0", m.writes)
	}
	// Replacing an existing key needs no new slot.
	if n, err := applyLocalPortPolicies(m, []PortPolicyAPI{ssh}); err != nil || n != 1 {
		t.Fatalf("replace at capacity: n=%d err=%v", n, err)
	}

	// The lockout check still runs before anything is written.
	m = newMap()
	if _, err := applyLocalPortPolicies(m, web[:1]); err != nil {
		t.Fatalf("unrelated drop: %v", err)
	}
	m.writes = 0
	if _, err := applyLocalPortPolicies(m, moveSSH[:1]); !errors.Is(err, ErrIngressDenyNeedsAllow) || m.writes != 0 {
		t.Fatalf("lockout batch: err=%v writes=%d", err, m.writes)
	}
}

// A batch naming one key twice ends with the rule the guard
// validated (the last one), whatever order allow and drop are written in.
func TestLocalPortPolicyBatchSameKeyLastWins(t *testing.T) {
	ssh := PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"}
	m := &fakePortPolicyMap{
		cfg:    &FullConfigAPI{Global: GlobalConfigAPI{EnableConntrack: true}},
		policy: &PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"},
		rules:  map[portPolicyMapKey]PortPolicyAPI{},
	}
	batch := []PortPolicyAPI{{Port: 22, Proto: "tcp", Direction: "ingress", Action: "drop"}, ssh}
	if n, err := applyLocalPortPolicies(m, batch); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := m.rules[portPolicyKey(ssh)]; got.Action != "allow" {
		t.Fatalf("map holds %q, the guard validated allow", got.Action)
	}
}
