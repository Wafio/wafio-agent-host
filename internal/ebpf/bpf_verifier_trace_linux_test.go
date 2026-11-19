//go:build linux

package ebpf

import (
	"sort"
	"testing"
)

// TestBPFTraceVerifierBudget: TestBPFFirewallVerifierBudget for
// wafio_trace.o. The open programs carry two path scans, the kill-candidate name
// route (trace_open_name_candidate) and the shed exemption
// (trace_open_keep); every program must stay under verifierInsnBudget, and the
// exec program under its own small cap: it reads one file identity through five
// pointer hops, compares a cgroup name with the unit of a unit-bound image
// (three cgroup hops, two name reads and a compare of six words) and has no
// loop. 367 to 403 instructions on kernels 5.10 to 6.8 and 380 on 6.17.
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
		if limit, ok := traceProgramInsnCaps[name]; ok && n > limit {
			t.Errorf("wafio_trace.o %s: %d processed instructions, keep it under %d", name, n, limit)
		}
	}
}

// traceProgramInsnCaps holds programs that must stay far below
// verifierInsnBudget.
var traceProgramInsnCaps = map[string]uint32{"trace_sched_process_exec": 500}
