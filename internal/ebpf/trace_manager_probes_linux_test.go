//go:build linux

package ebpf

import (
	"io"
	"log"
	"slices"
	"testing"
)

// The objects of the previous release lack the exit programs of the UID calls.
// They emit no event, so their absence is neither an expected probe nor a failed
// one; a program the verifier rejected, or one that carries events, still is.
func TestMissingMaintenanceProgramIsNotAFailedProbe(t *testing.T) {
	probe := func(name string) traceProbe {
		t.Helper()
		i := slices.IndexFunc(traceProbes, func(p traceProbe) bool { return p.name == name })
		if i < 0 {
			t.Fatalf("no probe %s", name)
		}
		return traceProbes[i]
	}
	tm := &TraceManager{log: log.New(io.Discard, "", 0), probeFailures: map[string]string{}}
	for _, name := range []string{"sys_exit_setuid", "sys_exit_setreuid", "sys_exit_setresuid"} {
		tm.noteMissingProgram(probe(name), nil)
	}
	if len(tm.probeFailures) != 0 || tm.probesAbsent != 3 {
		t.Fatalf("three absent maintenance programs: failures %v, absent %d", tm.probeFailures, tm.probesAbsent)
	}

	tm.noteMissingProgram(probe("sys_exit_setuid"), map[string]string{"trace_sys_exit_setuid": "rejected at load"})
	tm.noteMissingProgram(probe("sys_enter_kill"), nil)
	if tm.probeFailures["sys_exit_setuid"] != "rejected at load" || tm.probeFailures["sys_enter_kill"] != "program missing from BPF object" || tm.probesAbsent != 3 {
		t.Fatalf("a rejected program and a missing event program must fail: failures %v, absent %d", tm.probeFailures, tm.probesAbsent)
	}
}
