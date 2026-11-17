package agent

import (
	"errors"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"testing"
)

func TestHostBundleRejectsStaleAndAppliesRedeliveredGenerations(t *testing.T) {
	calls := 0
	a := hostBundleApplier{apply: func([]byte, int64) error { calls++; return nil }}
	bundle := func(gen int64, json string) *agentv1.BundleUpdate {
		return &agentv1.BundleUpdate{Generation: gen, BundleJson: []byte(json)}
	}
	if err := a.applyBundle(bundle(2, `{"trace_policies":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := a.applyBundle(bundle(2, `{"trace_policies":[]}`)); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("duplicate applied again")
	}
	if err := a.applyBundle(bundle(1, `{"trace_policies":[]}`)); err == nil {
		t.Fatal("stale snapshot applied")
	}
	// The same generation re-delivered with different content (a data
	// migration that kept the revision) is applied, not refused forever.
	if err := a.applyBundle(bundle(2, `{"trace_policies":[{}]}`)); err != nil {
		t.Fatalf("re-delivered generation with new content refused: %v", err)
	}
	if calls != 2 {
		t.Fatalf("apply calls = %d, want 2", calls)
	}
	if err := a.applyBundle(bundle(2, `{"trace_policies":[{}]}`)); err != nil || calls != 2 {
		t.Fatalf("duplicate of the new content applied again: %v calls=%d", err, calls)
	}
	if err := a.applyBundle(bundle(1, `{"ebpf_state":{}}`)); err != nil {
		t.Fatal("independent capability generation rejected")
	}
}

func TestHostBundleFailedApplyCanRetrySameGeneration(t *testing.T) {
	fail := true
	a := hostBundleApplier{apply: func([]byte, int64) error {
		if fail {
			return errors.New("map full")
		}
		return nil
	}}
	b := &agentv1.BundleUpdate{Generation: 1, BundleJson: []byte(`{"trace_policies":[]}`)}
	if err := a.applyBundle(b); err == nil {
		t.Fatal("failure swallowed")
	}
	fail = false
	if err := a.applyBundle(b); err != nil {
		t.Fatal(err)
	}
	if a.versions["trace_policies"].generation != 1 {
		t.Fatal("retry did not apply")
	}
}
