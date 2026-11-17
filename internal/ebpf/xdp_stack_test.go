package ebpf

import (
	"os"
	"path/filepath"
	"testing"
)

// TestXDPStackHeadroom is TestTCStackHeadroom for wafio_xdp.c: the entry
// program and the per-family tail-call targets, each with its deepest
// BPF-to-BPF call chain (32-byte rounded frames, as the verifier counts),
// stay within tcStackBudget of the verifier's 512 B. The list walks, the
// flow lookup and the truncated-frame handling add helpers to
// wafio_xdp_v4 / wafio_xdp_v6; this keeps their frames measured. Skipped
// without clang, llvm-objdump or the libbpf headers (WAFIO_BPF_INCLUDE).
func TestXDPStackHeadroom(t *testing.T) {
	clang, objdump := bpfToolchain(t)
	for _, cpu := range []string{"-mcpu=v1", "-mcpu=v2"} {
		t.Run(cpu, func(t *testing.T) {
			flags := []string{cpu, "-D__TARGET_ARCH_x86_64", "-Ibpf", "-I/usr/include"}
			if inc := os.Getenv("WAFIO_BPF_INCLUDE"); inc != "" {
				flags = append(flags, "-I"+inc)
			}
			info := bpfObjectStack(t, clang, objdump, filepath.Join("bpf", "wafio_xdp.c"), flags...)
			for _, p := range []string{"wafio_xdp_firewall", "wafio_xdp_v4", "wafio_xdp_v6"} {
				total, chain, err := info.chainDepth(p)
				if err != nil {
					t.Fatalf("%s: %v", p, err)
				}
				t.Logf("%s: %s = %d of %d", p, chain, total, tcStackBudget)
				if total > tcStackBudget {
					t.Errorf("%s uses %d B of BPF stack along %s; keep it <= %d (limit 512): move locals to a per-CPU map", p, total, chain, tcStackBudget)
				}
			}
		})
	}
}
