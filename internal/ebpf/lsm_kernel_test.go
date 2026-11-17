package ebpf

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The list an Ubuntu kernel without lsm=...,bpf reports.
const kernelLSMsWithoutBPF = "lockdown,capability,landlock,yama,apparmor,ima,evm"

func TestParseKernelLSMList(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		want       []string
	}{
		{"list from a kernel without bpf", kernelLSMsWithoutBPF, []string{"lockdown", "capability", "landlock", "yama", "apparmor", "ima", "evm"}},
		{"trailing newline", "capability,bpf\n", []string{"capability", "bpf"}},
		{"spaces and stray commas", " capability , ,bpf,", []string{"capability", "bpf"}},
		{"empty file", "", nil},
		{"only a newline", "\n", nil},
	} {
		if got := parseKernelLSMList(tc.data); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDecideLSM(t *testing.T) {
	notRead := errors.New("open /sys/kernel/security/lsm: no such file or directory")
	for _, tc := range []struct {
		name       string
		enabled    bool
		data       string
		readErr    error
		wantAttach bool
		wantState  string
		wantNote   []string // each must appear in the note
	}{
		{"bpf listed", true, "lockdown,capability,yama,apparmor,bpf", nil, true, LSMStateActive, nil},
		{"bpf listed alone", true, "bpf\n", nil, true, LSMStateActive, nil},
		{
			"bpf missing", true, kernelLSMsWithoutBPF, nil, false, LSMStateKernelLacksBPF,
			[]string{"BPF-LSM is not active in this kernel", "lsm=...,bpf", kernelLSMsWithoutBPF, "not attached"},
		},
		{"module names that only contain bpf", true, "capability,bpfilter,xbpf", nil, false, LSMStateKernelLacksBPF, []string{"not active"}},
		{"empty list", true, "", nil, false, LSMStateKernelLacksBPF, []string{"active LSMs: none"}},
		{
			"list unreadable", true, "", notRead, true, LSMStateUnverified,
			[]string{"cannot read the kernel LSM list", notRead.Error(), "unknown"},
		},
		{"switched off, bpf listed", false, "bpf", nil, false, LSMStateDisabled, nil},
		{"switched off, list unreadable", false, "", notRead, false, LSMStateDisabled, nil},
	} {
		got := decideLSM(tc.enabled, tc.data, tc.readErr)
		if got.Attach != tc.wantAttach || got.State != tc.wantState {
			t.Errorf("%s: attach=%t state=%q, want attach=%t state=%q", tc.name, got.Attach, got.State, tc.wantAttach, tc.wantState)
		}
		for _, want := range tc.wantNote {
			if !strings.Contains(got.Note, want) {
				t.Errorf("%s: note %q lacks %q", tc.name, got.Note, want)
			}
		}
		if len(tc.wantNote) == 0 && got.Note != "" {
			t.Errorf("%s: unexpected note %q", tc.name, got.Note)
		}
	}
}

// planLSM reads the list from the path it is given.
func TestPlanLSMReadsTheGivenPath(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	withBPF := write("with-bpf", "capability,apparmor,bpf\n")
	withoutBPF := write("without-bpf", kernelLSMsWithoutBPF+"\n")
	missing := filepath.Join(dir, "missing")

	if p := planLSM(true, withBPF); !p.Attach || p.State != LSMStateActive {
		t.Errorf("bpf listed: %+v", p)
	}
	if p := planLSM(true, withoutBPF); p.Attach || p.State != LSMStateKernelLacksBPF {
		t.Errorf("bpf missing: %+v", p)
	}
	if p := planLSM(true, missing); !p.Attach || p.State != LSMStateUnverified || !strings.Contains(p.Note, missing) {
		t.Errorf("file missing keeps today's attach and names the file: %+v", p)
	}
	if p := planLSM(false, withBPF); p.Attach || p.State != LSMStateDisabled {
		t.Errorf("switched off: %+v", p)
	}
}

// The trace status reports LSM inactive with the reason, and the field is
// always present so the dashboard can tell inactive from an old agent.
func TestTraceStatusReportsLSMState(t *testing.T) {
	b, err := json.Marshal(TraceStatus{LSMState: LSMStateKernelLacksBPF})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"lsm_active":false`, `"lsm_state":"kernel_lacks_bpf"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("status JSON lacks %s: %s", want, b)
		}
	}
}
