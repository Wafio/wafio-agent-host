//go:build linux

package ebpf

import (
	"sort"
	"testing"
)

// TestBPFTraceVerifierBudget: TestBPFFirewallVerifierBudget for
// wafio_trace.o. The open programs carry two path scans, the kill-candidate name
// route (trace_open_name_candidate) and the shed exemption
// (trace_open_keep); every program must stay under verifierInsnBudget.
// Needs root and WAFIO_TEST_BPF_DIR.
func TestBPFTraceVerifierBudget(t *testing.T) {
	c := packetObjectCollection(t, "wafio_trace.o")
	names := make([]string, 0, len(c.Programs))
	for name := range c.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		info, err := c.Programs[name].Info()
		if err != nil {
			t.Fatalf("wafio_trace.o %s: %v", name, err)
		}
		n, ok := info.VerifiedInstructions()
		if !ok {
			t.Logf("wafio_trace.o %s: verified_insns not reported by this kernel", name)
			continue
		}
		t.Logf("wafio_trace.o %s: %d instructions processed", name, n)
		if n > verifierInsnBudget {
			t.Errorf("wafio_trace.o %s: %d processed instructions, keep it under %d (limit 1,000,000)", name, n, verifierInsnBudget)
		}
	}
}
