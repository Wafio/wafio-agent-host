package ebpf

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ────────────────────────────────────────────────────────────────────────────
//  Kprobe twins of the user-string syscall hooks
//
//  Linux 6.19+/7.0 syscall tracepoints append the user strings a syscall
//  takes (paths, names, module parameters) to the event record: for every hit
//  with a perf event or BPF program attached, perf_syscall_enter copies them
//  from user memory (sys_fault_user -> trace_user_fault_read) before the
//  program runs. The trace hooks never use that copy. Its retry loop compares
//  a 32-bit copy of the CPU's 64-bit context-switch count, so once a CPU has
//  passed 2^32 switches every copy fails 100 times and
//  WARN_ONCE("Too many tries to read user space") fires (the demo host, one
//  vCPU, 21 days up on 7.0.0-14). On such a kernel the agent attaches the
//  hook's kprobe twin (trace_ksys_<syscall>, wafio_trace.c) to the syscall's
//  arch wrapper instead; it runs the same body over the same arguments.
// ────────────────────────────────────────────────────────────────────────────

// syscall is the syscall a sys_enter_* probe hooks ("sys_enter_openat" →
// "openat"; the tracepoint and SYSCALL_DEFINE names agree, umount included).
func (p traceProbe) syscall() string { return strings.TrimPrefix(p.name, "sys_enter_") }

// kprobeFuncName is the program name of the probe's kprobe twin
// (wafio_trace.c: SEC("kprobe/sys_<syscall>") trace_ksys_<syscall>).
func (p traceProbe) kprobeFuncName() string { return "trace_ksys_" + p.syscall() }

// syscallWrapperSymbol is the kernel symbol a kprobe twin attaches to: the
// arch syscall wrapper taking the user pt_regs. Only x86_64 twins are built
// (trace_ksyscall_args reads the x86_64 registers); "" elsewhere, where the
// tracepoint is kept.
func syscallWrapperSymbol(goarch, syscall string) string {
	if goarch == "amd64" {
		return "__x64_sys_" + syscall
	}
	return ""
}

// tracepointFormatCopiesUser reports whether a syscall tracepoint's format
// (tracefs events/syscalls/<name>/format) has a user-memory field, the
// "__data_loc char[] __<arg>_val" field Linux 6.19+ appends for path and
// name arguments.
func tracepointFormatCopiesUser(format string) bool {
	for _, line := range strings.Split(format, "\n") {
		f := strings.TrimSpace(line)
		if !strings.HasPrefix(f, "field:__data_loc") {
			continue
		}
		decl, _, _ := strings.Cut(f, ";")
		name := decl[strings.LastIndexAny(decl, " \t")+1:]
		if strings.HasPrefix(name, "__") && strings.HasSuffix(name, "_val") {
			return true
		}
	}
	return false
}

// tracefsRoots are where tracefs is looked for, in order.
var tracefsRoots = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

// tracepointCopiesUser reads the tracepoint's format from tracefs; false
// when it cannot be read (the tracepoint is kept, as before).
func tracepointCopiesUser(group, name string) bool {
	for _, root := range tracefsRoots {
		b, err := os.ReadFile(filepath.Join(root, "events", group, name, "format"))
		if err == nil {
			return tracepointFormatCopiesUser(string(b))
		}
	}
	return false
}

// selectKprobeTwins decides, per probe with a kprobe twin, whether the twin
// replaces the tracepoint: goarch has a wrapper symbol, the object has the
// twin and the tracepoint copies user memory. Every twin not selected is
// deleted from programs (the collection spec's program map), so a kernel
// whose tracepoints copy nothing loads exactly the tracepoint programs. The
// result maps probe name → wrapper symbol.
func selectKprobeTwins[P any](programs map[string]P, goarch string, copiesUser func(group, name string) bool) map[string]string {
	selected := make(map[string]string)
	keep := make(map[string]bool)
	for _, p := range traceProbes {
		if !p.kprobeTwin {
			continue
		}
		twin := p.kprobeFuncName()
		if _, ok := programs[twin]; !ok {
			continue
		}
		if sym := syscallWrapperSymbol(goarch, p.syscall()); sym != "" && copiesUser(p.group, p.name) {
			selected[p.name] = sym
			keep[twin] = true
		}
	}
	for name := range programs {
		if strings.HasPrefix(name, "trace_ksys_") && !keep[name] {
			delete(programs, name)
		}
	}
	return selected
}

// kprobeTwinPrograms lists the twin programs of the selected probes: optional
// at load, since a rejected twin falls back to its tracepoint.
func kprobeTwinPrograms(selected map[string]string) []string {
	var names []string
	for _, p := range traceProbes {
		if _, ok := selected[p.name]; ok && !slices.Contains(names, p.kprobeFuncName()) {
			names = append(names, p.kprobeFuncName())
		}
	}
	return names
}
