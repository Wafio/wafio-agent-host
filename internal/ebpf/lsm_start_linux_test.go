//go:build linux

package ebpf

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startLSM must not load or attach anything when the kernel does not list
// bpf, and must say so in the log and in the trace status. LSMObjectPath names
// no file: a load attempt would turn the state into "failed".
func TestStartLSMWithoutKernelBPF(t *testing.T) {
	list := filepath.Join(t.TempDir(), "lsm")
	if err := os.WriteFile(list, []byte(kernelLSMsWithoutBPF+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	tm := NewTraceManager(TraceManagerConfig{LSMEnabled: true, LSMObjectPath: "/nonexistent/wafio_lsm.o"}, log.New(&out, "", 0))

	tm.startLSM(t.Context(), list)

	st := tm.Status()
	if st.LSMActive || st.LSMState != LSMStateKernelLacksBPF || tm.IsLSMActive() {
		t.Fatalf("status active=%t state=%q", st.LSMActive, st.LSMState)
	}
	if tm.lsmLink != nil || tm.lsmColl != nil {
		t.Fatal("LSM programs were loaded")
	}
	logged := out.String()
	for _, want := range []string{"BPF-LSM is not active in this kernel", "lsm=...,bpf", "enforcement is reactive only"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log lacks %q: %q", want, logged)
		}
	}
	if strings.Contains(logged, "hooks attached") || strings.Contains(logged, "proactive blocking enabled") {
		t.Errorf("log claims LSM blocking: %q", logged)
	}
	if n := strings.Count(logged, "\n"); n != 1 {
		t.Errorf("want one line, got %d: %q", n, logged)
	}
	if err := tm.BlockBinaryPath("/usr/bin/true", 1); err == nil {
		t.Error("BlockBinaryPath succeeded without LSM")
	}
}

// With bpf listed, or the list unreadable, startLSM goes on to load the
// object. Here the object is missing, so the load fails and the state says so.
func TestStartLSMTriesToLoadWhenKernelMayRunBPF(t *testing.T) {
	dir := t.TempDir()
	withBPF := filepath.Join(dir, "lsm")
	if err := os.WriteFile(withBPF, []byte("capability,bpf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		list     string
		wantNote string
	}{
		"bpf listed":      {withBPF, ""},
		"list unreadable": {filepath.Join(dir, "missing"), "whether the kernel runs BPF-LSM is unknown"},
	} {
		var out bytes.Buffer
		tm := NewTraceManager(TraceManagerConfig{LSMEnabled: true, LSMObjectPath: "/nonexistent/wafio_lsm.o"}, log.New(&out, "", 0))
		tm.startLSM(t.Context(), tc.list)
		if st := tm.Status(); st.LSMActive || st.LSMState != LSMStateFailed {
			t.Errorf("%s: active=%t state=%q", name, st.LSMActive, st.LSMState)
		}
		if !strings.Contains(out.String(), "BPF-LSM unavailable or not active") || !strings.Contains(out.String(), tc.wantNote) {
			t.Errorf("%s: log %q", name, out.String())
		}
	}
}

// --lsm=false attaches nothing, whatever the kernel lists.
func TestStartLSMSwitchedOff(t *testing.T) {
	list := filepath.Join(t.TempDir(), "lsm")
	if err := os.WriteFile(list, []byte("capability,bpf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	tm := NewTraceManager(TraceManagerConfig{LSMEnabled: false, LSMObjectPath: "/nonexistent/wafio_lsm.o"}, log.New(&out, "", 0))
	tm.startLSM(t.Context(), list)
	if st := tm.Status(); st.LSMActive || st.LSMState != LSMStateDisabled || out.Len() != 0 {
		t.Fatalf("active=%t state=%q log=%q", st.LSMActive, st.LSMState, out.String())
	}
}
