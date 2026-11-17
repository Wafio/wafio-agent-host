package ebpf

import (
	"errors"
	"slices"
	"testing"
)

func ppRule(port uint16, action string) PortPolicyAPI {
	return PortPolicyAPI{Port: port, Proto: "tcp", Direction: "ingress", Action: action}
}

func ppMap(rules ...PortPolicyAPI) *fakePortPolicyMap {
	m := &fakePortPolicyMap{rules: map[portPolicyMapKey]PortPolicyAPI{}}
	for _, r := range rules {
		m.rules[portPolicyKey(r)] = r
	}
	return m
}

// A rule that is in both the old and the new set is present after
// every single operation of the swap, and the map ends equal to the new set.
func TestReplacePortPoliciesKeepsSurvivorsAtEveryStep(t *testing.T) {
	old := []PortPolicyAPI{ppRule(22, "allow"), ppRule(80, "allow"), ppRule(443, "allow"), ppRule(3306, "drop"), ppRule(9000, "allow")}
	desired := []PortPolicyAPI{ppRule(22, "allow"), ppRule(80, "drop"), ppRule(443, "allow"), ppRule(8080, "allow"), ppRule(6379, "log")}
	m := ppMap(old...)
	survivors := desired[:3]
	steps := 0
	m.after = func(op string) {
		steps++
		for _, s := range survivors {
			if _, ok := m.rules[portPolicyKey(s)]; !ok {
				t.Fatalf("after step %d (%s) the surviving rule %d is missing", steps, op, s.Port)
			}
		}
	}
	if err := replacePortPolicies(m, desired); err != nil {
		t.Fatal(err)
	}
	if len(m.rules) != len(desired) {
		t.Fatalf("final map has %d rules, want %d: %+v", len(m.rules), len(desired), m.rules)
	}
	for _, d := range desired {
		if got := m.rules[portPolicyKey(d)]; got.Action != d.Action {
			t.Fatalf("rule %d holds %q, want %q", d.Port, got.Action, d.Action)
		}
	}
}

// The upserts come first (allow before drop), then the stale deny rules, and
// the stale allow rules last.
func TestReplacePortPoliciesOrder(t *testing.T) {
	m := ppMap(ppRule(1000, "allow"), ppRule(2000, "drop"))
	var ops []string
	m.after = func(op string) { ops = append(ops, op) }
	if err := replacePortPolicies(m, []PortPolicyAPI{ppRule(3000, "drop"), ppRule(4000, "allow")}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"add", "add", "remove", "remove"}; !slices.Equal(ops, want) {
		t.Fatalf("ops %v, want %v", ops, want)
	}

	// The stale allow stays through every upsert.
	stale := ppRule(1000, "allow")
	m = ppMap(stale)
	m.after = func(op string) {
		if _, ok := m.rules[portPolicyKey(stale)]; op == "add" && !ok {
			t.Fatal("stale allow removed before the upserts finished")
		}
	}
	if err := replacePortPolicies(m, []PortPolicyAPI{ppRule(2000, "allow"), ppRule(3000, "drop")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.rules[portPolicyKey(stale)]; ok {
		t.Fatal("stale allow still present at the end")
	}
}

// A deny that only changes key is covered at every step: its successor is in
// the table before the old key goes (no window with the port open under a
// default-allow policy).
func TestReplacePortPoliciesDenyChangingKeyIsNeverUncovered(t *testing.T) {
	old := PortPolicyAPI{Port: 80, Proto: "tcp", Direction: "ingress", Action: "drop"}
	next := PortPolicyAPI{Port: 80, Proto: "any", Direction: "both", Action: "drop"}
	m := ppMap(old)
	m.after = func(op string) {
		_, hasOld := m.rules[portPolicyKey(old)]
		_, hasNext := m.rules[portPolicyKey(next)]
		if !hasOld && !hasNext {
			t.Fatalf("after %s port 80 has no deny rule", op)
		}
	}
	if err := replacePortPolicies(m, []PortPolicyAPI{next}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.rules[portPolicyKey(old)]; ok || len(m.rules) != 1 {
		t.Fatalf("map after the swap: %+v", m.rules)
	}
}

// An upsert failure keeps the stale allow rules: nothing loosens a deny the
// push meant to keep working.
func TestReplacePortPoliciesUpsertFailureKeepsStaleAllows(t *testing.T) {
	m := ppMap(ppRule(22, "allow"), ppRule(1000, "allow"), ppRule(2000, "drop"))
	m.failOn = 4000
	if err := replacePortPolicies(m, []PortPolicyAPI{ppRule(22, "allow"), ppRule(4000, "allow")}); err == nil {
		t.Fatal("want the upsert error")
	}
	for _, port := range []uint16{22, 1000} {
		if _, ok := m.rules[portPolicyKey(ppRule(port, "allow"))]; !ok {
			t.Fatalf("allow %d dropped after a failed upsert", port)
		}
	}
}

// An invalid rule fails before any write; a duplicate key keeps the last one;
// a set that cannot fit is refused before any write.
func TestReplacePortPoliciesValidation(t *testing.T) {
	m := ppMap(ppRule(22, "allow"), ppRule(1000, "drop"))
	err := replacePortPolicies(m, []PortPolicyAPI{ppRule(22, "allow"), ppRule(80, "maybe")})
	if !errors.Is(err, ErrInvalidPortPolicy) {
		t.Fatalf("err = %v, want ErrInvalidPortPolicy", err)
	}
	if m.writes != 0 || len(m.rules) != 2 {
		t.Fatalf("invalid batch changed the map: writes=%d rules=%+v", m.writes, m.rules)
	}

	m = ppMap()
	if err := replacePortPolicies(m, []PortPolicyAPI{ppRule(22, "drop"), ppRule(22, "allow")}); err != nil {
		t.Fatal(err)
	}
	if got := m.rules[portPolicyKey(ppRule(22, "allow"))]; got.Action != "allow" || len(m.rules) != 1 {
		t.Fatalf("duplicate key: %+v", m.rules)
	}
}

func TestReplacePortPoliciesCapacity(t *testing.T) {
	fill := func(action string) *fakePortPolicyMap {
		m := ppMap()
		for p := 1; len(m.rules) < maxPortPolicies; p++ {
			m.rules[portPolicyKey(ppRule(uint16(p), action))] = ppRule(uint16(p), action)
		}
		return m
	}

	// Full of stale allow rules: they go last, so a new key does not fit and
	// the swap is refused before any write.
	m := fill("allow")
	m.after = func(string) { t.Fatal("wrote although the swap cannot fit") }
	err := replacePortPolicies(m, []PortPolicyAPI{ppRule(60000, "allow")})
	if !errors.Is(err, ErrPortPolicyBatch) {
		t.Fatalf("err = %v, want ErrPortPolicyBatch", err)
	}

	// Full of stale deny rules: those go first, so the new set fits.
	m = fill("drop")
	if err := replacePortPolicies(m, []PortPolicyAPI{ppRule(60000, "allow")}); err != nil {
		t.Fatal(err)
	}
	if len(m.rules) != 1 {
		t.Fatalf("%d rules left, want 1", len(m.rules))
	}

	// Replacing an existing key at capacity needs no new slot.
	m = fill("allow")
	if err := replacePortPolicies(m, []PortPolicyAPI{ppRule(1, "drop")}); err != nil {
		t.Fatalf("replace at capacity: %v", err)
	}
}

// An empty desired set clears the table.
func TestReplacePortPoliciesEmptyClears(t *testing.T) {
	m := ppMap(ppRule(22, "allow"), ppRule(80, "drop"))
	if err := replacePortPolicies(m, []PortPolicyAPI{}); err != nil {
		t.Fatal(err)
	}
	if len(m.rules) != 0 {
		t.Fatalf("rules left: %+v", m.rules)
	}
}
