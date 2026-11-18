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

// TestBPFObjectMapSizes reads the objects, not the kernel: the size each
// sized map declares is the ceiling of the sizing table, the egress blocklist
// is allocated on insert in both objects that declare it, and the jail is a
// hash map that refuses a new entry when full. Needs the compiled objects but
// no privileges.
func TestBPFObjectMapSizes(t *testing.T) {
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if dir == "" {
		t.Skip("set WAFIO_TEST_BPF_DIR to the compiled objects")
	}
	specs := map[string]*cebpf.CollectionSpec{}
	for _, obj := range []string{"wafio_xdp.o", "wafio_tc.o", "wafio_trace.o"} {
		spec, err := cebpf.LoadCollectionSpec(filepath.Join(dir, obj))
		if err != nil {
			t.Fatalf("parse %s: %+v", obj, err)
		}
		specs[obj] = spec
	}
	find := func(name string) (string, *cebpf.MapSpec) {
		for _, obj := range []string{"wafio_xdp.o", "wafio_tc.o", "wafio_trace.o"} {
			if ms := specs[obj].Maps[name]; ms != nil {
				return obj, ms
			}
		}
		return "", nil
	}
	for _, m := range sizedMaps {
		obj, ms := find(m.name)
		if ms == nil {
			t.Errorf("%s is in the sizing table but no object declares it", m.name)
			continue
		}
		if ms.MaxEntries != m.ceiling {
			t.Errorf("%s declares %d entries in %s, the sizing ceiling is %d", m.name, ms.MaxEntries, obj, m.ceiling)
		}
		want := cebpf.Hash
		if m.lru {
			want = cebpf.LRUHash
		}
		if ms.Type != want {
			t.Errorf("%s is a %s map in %s, want %s", m.name, ms.Type, obj, want)
		}
		if ms.Flags&bpfFNoPrealloc != 0 {
			t.Errorf("%s is allocated on insert: the sizing sizes preallocated maps", m.name)
		}
	}
	// TC holds its own declaration of the shared conntrack map: the same size.
	if ms := specs["wafio_tc.o"].Maps[mapConntrack]; ms == nil || ms.MaxEntries != 500000 {
		t.Errorf("wafio_tc.o conntrack declaration: %+v", ms)
	}
	if ms := specs["wafio_trace.o"].Maps[traceMapEvents]; ms == nil || ms.Type != cebpf.RingBuf || ms.MaxEntries != traceRingMax {
		t.Errorf("trace_events: %+v, want a %d byte ring buffer", ms, traceRingMax)
	}
	for _, obj := range []string{"wafio_xdp.o", "wafio_tc.o"} {
		ms := specs[obj].Maps[mapEgressBlocklist]
		if ms == nil {
			t.Errorf("%s has no egress blocklist", obj)
			continue
		}
		if ms.Flags&bpfFNoPrealloc == 0 || ms.Type != cebpf.Hash || ms.MaxEntries != egressBlocklistCapacity {
			t.Errorf("%s egress blocklist %s flags %#x entries %d: want a hash map allocated on insert, %d entries", obj, ms.Type, ms.Flags, ms.MaxEntries, egressBlocklistCapacity)
		}
	}
	if ms := specs["wafio_xdp.o"].Maps[mapJail]; ms == nil || ms.Type != cebpf.Hash {
		t.Errorf("jail: %+v, want a hash map", ms)
	}
	if ms := specs["wafio_xdp.o"].Maps[mapStateFull]; ms == nil || ms.Type != cebpf.PerCPUArray || ms.MaxEntries != 3 || ms.ValueSize != 8 || ms.KeySize != 4 {
		t.Errorf("wafio_state_full: %+v, want a per-CPU array of three u64", ms)
	}
}
