//go:build linux

package ebpf

import (
	"sort"
	"testing"
)

// verifierInsnBudget keeps each firewall program well under the verifier's
// 1M processed-instruction limit.
const verifierInsnBudget = 500_000

// TestBPFFirewallVerifierBudget loads wafio_xdp.o and wafio_tc.o (fresh,
// unpinned maps; nothing attached) and reports how many instructions the
// verifier processed per program (bpf_prog_info.verified_insns, Linux 5.16+).
// Needs root and WAFIO_TEST_BPF_DIR, like the other kernel tests.
func TestBPFFirewallVerifierBudget(t *testing.T) {
	for _, obj := range []string{"wafio_xdp.o", "wafio_tc.o"} {
		c := packetObjectCollection(t, obj)
		names := make([]string, 0, len(c.Programs))
		for name := range c.Programs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			info, err := c.Programs[name].Info()
			if err != nil {
				t.Fatalf("%s %s: %v", obj, name, err)
			}
			n, ok := info.VerifiedInstructions()
			if !ok {
				t.Logf("%s %s: verified_insns not reported by this kernel", obj, name)
				continue
			}
			t.Logf("%s %s: %d instructions processed", obj, name, n)
			if n > verifierInsnBudget {
				t.Errorf("%s %s: %d processed instructions, keep it under %d (limit 1,000,000)", obj, name, n, verifierInsnBudget)
			}
		}
	}
}
