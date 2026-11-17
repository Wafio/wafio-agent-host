//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestBPFObjectsPassVerifier loads every shipped BPF object into the running
// kernel, so the in-kernel verifier accepts or rejects each program.
// Nothing is attached, pinned or linked: maps are private and capped,
// and the collection is closed at the end.
//
// Needs root (or CAP_BPF + CAP_PERFMON) and the compiled objects:
//
//	WAFIO_TEST_BPF_DIR=build/ebpf go test -run TestBPFObjectsPassVerifier -v ./internal/ebpf/
//
// CI runs it inside a VM per kernel (the ebpf-verifier-vm job in
// .github/workflows/security.yml); without the variable it skips.
// wafio_lsm.o is optional in production (the tracer runs without it when the
// kernel lacks BPF LSM), so its failure is only fatal with
// WAFIO_TEST_BPF_REQUIRE_LSM=1.
func TestBPFObjectsPassVerifier(t *testing.T) {
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if dir == "" {
		t.Skip("set WAFIO_TEST_BPF_DIR to the compiled objects (needs root)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %+v", err)
	}
	objects := []struct {
		name     string
		optional bool
	}{
		{"wafio_xdp.o", false},
		{"wafio_tc.o", false},
		{"wafio_trace.o", false},
		{"wafio_lsm.o", os.Getenv("WAFIO_TEST_BPF_REQUIRE_LSM") != "1"},
	}
	for _, obj := range objects {
		t.Run(obj.name, func(t *testing.T) {
			spec, err := cebpf.LoadCollectionSpec(filepath.Join(dir, obj.name))
			if err != nil {
				t.Fatalf("parse %s: %+v", obj.name, err)
			}
			for _, m := range spec.Maps {
				m.Pinning = cebpf.PinNone
				if m.Type != cebpf.RingBuf && m.MaxEntries > 4096 {
					m.MaxEntries = 4096
				}
			}
			create := func() (*cebpf.Collection, error) {
				return cebpf.NewCollectionWithOptions(spec, cebpf.CollectionOptions{
					Programs: cebpf.ProgramOptions{LogSizeStart: 1 << 20},
				})
			}
			coll, err := create()
			if err != nil {
				// %+v includes the full verifier log of a rejected program.
				if obj.optional {
					t.Skipf("optional object not loadable on this kernel: %+v", err)
				}
				t.Fatalf("load %s: %+v", obj.name, err)
			}
			defer coll.Close()
			if len(coll.Programs) == 0 {
				t.Fatalf("%s has no programs", obj.name)
			}
			for name := range coll.Programs {
				t.Logf("%s: %s verified", obj.name, name)
			}
		})
	}
}
