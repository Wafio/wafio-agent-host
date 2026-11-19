package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every tracepoint program of wafio_trace.c is attached by traceProbes under
// its own tracepoint, and every probe names a program the object has — a hook
// added in C but not here would never run (the legacy file syscalls added nine
// at once).
func TestTraceProbesMatchObjectSource(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("bpf", "wafio_trace.c"))
	if err != nil {
		t.Fatal(err)
	}
	sec := regexp.MustCompile(`SEC\("(tracepoint|raw_tracepoint)/([\w/]+)"\)\s*\nint (\w+)\(`)
	inSource := map[string]string{} // func → group/name
	for _, m := range sec.FindAllStringSubmatch(string(source), -1) {
		tp := m[2]
		if m[1] == "raw_tracepoint" {
			tp = "raw/" + tp
		}
		inSource[m[3]] = tp
	}
	if len(inSource) < 30 {
		t.Fatalf("parsed only %d tracepoint programs from wafio_trace.c", len(inSource))
	}
	seen := map[string]bool{}
	for _, p := range traceProbes {
		want := p.group + "/" + p.name
		if p.raw {
			want = "raw/" + p.name
		}
		got, ok := inSource[p.funcName]
		if !ok {
			t.Errorf("probe %s: no program %s in wafio_trace.c", p.name, p.funcName)
			continue
		}
		if got != want {
			t.Errorf("program %s is SEC %q, probe attaches it to %q", p.funcName, got, want)
		}
		if seen[p.funcName] {
			t.Errorf("program %s listed twice", p.funcName)
		}
		seen[p.funcName] = true
		if p.mayBeAbsent && !p.optional {
			t.Errorf("probe %s may be absent but its program is not optional", p.name)
		}
	}
	for fn := range inSource {
		if !seen[fn] {
			t.Errorf("program %s (SEC %s) is never attached", fn, inSource[fn])
		}
	}
}

// A program that the objects of an earlier release lack is not a capture gap
// only when it emits no event. The maintenance probes are exactly the
// optional programs of the protected set, and none of them submits one.
func TestMaintenanceProbesEmitNoEvent(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("bpf", "wafio_trace.c"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range traceProbes {
		if !p.maintenance {
			continue
		}
		got = append(got, p.name)
		if !p.optional {
			t.Errorf("maintenance probe %s is not optional", p.name)
		}
		body := regexp.MustCompile(`(?s)\bint ` + p.funcName + `\(.*?\n}\n`).FindString(string(source))
		if body == "" || strings.Contains(body, "new_event") || strings.Contains(body, "submit_event") {
			t.Errorf("maintenance probe %s: program %s is missing or emits an event", p.name, p.funcName)
		}
	}
	if want := []string{"sys_exit_setuid", "sys_exit_setreuid", "sys_exit_setresuid"}; !slices.Equal(got, want) {
		t.Errorf("maintenance probes %v, want %v", got, want)
	}
}

// The legacy and newer file syscalls are attached, optional at load
// (a verifier rejection drops only them), and those missing on some
// architectures or kernels are not reported as capture gaps.
func TestTraceProbesLegacySyscalls(t *testing.T) {
	optional := optionalTracePrograms()
	for _, name := range []string{"open", "creat", "openat2", "unlink", "rename", "renameat", "chmod", "fchmodat2"} {
		i := slices.IndexFunc(traceProbes, func(p traceProbe) bool { return p.name == "sys_enter_"+name })
		if i < 0 {
			t.Errorf("sys_enter_%s not attached", name)
			continue
		}
		p := traceProbes[i]
		if !slices.Contains(optional, p.funcName) {
			t.Errorf("%s is not optional at load", p.funcName)
		}
		if absent := name != "openat2"; p.mayBeAbsent != absent {
			t.Errorf("%s mayBeAbsent = %v, want %v", p.name, p.mayBeAbsent, absent)
		}
	}
	for _, core := range []string{"trace_sys_enter_openat", "trace_sys_enter_execve", "trace_sys_enter_connect"} {
		if slices.Contains(optional, core) {
			t.Errorf("%s must not be optional", core)
		}
	}
}
