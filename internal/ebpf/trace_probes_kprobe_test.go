package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// Formats from the demo host (Ubuntu, 7.0.0-34-generic) and a 6.8 kernel.
const (
	fmtOpenat70 = `name: sys_enter_openat
ID: 712
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;
	field:umode_t mode;	offset:40;	size:8;	signed:0;
	field:__data_loc char[] __filename_val;	offset:48;	size:4;	signed:0;
`
	fmtRenameat2_70 = `	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int olddfd;	offset:16;	size:8;	signed:0;
	field:const char * oldname;	offset:24;	size:8;	signed:0;
	field:int newdfd;	offset:32;	size:8;	signed:0;
	field:const char * newname;	offset:40;	size:8;	signed:0;
	field:unsigned int flags;	offset:48;	size:8;	signed:0;
	field:__data_loc char[] __oldname_val;	offset:56;	size:4;	signed:0;
	field:__data_loc char[] __newname_val;	offset:60;	size:4;	signed:0;
`
	fmtOpenat68 = `	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;
	field:umode_t mode;	offset:40;	size:8;	signed:0;
`
	// sched_process_fork since 6.16: __data_loc comm, not a user copy.
	fmtFork616 = `	field:__data_loc char[] parent_comm;	offset:8;	size:4;	signed:0;
	field:pid_t parent_pid;	offset:12;	size:4;	signed:1;
`
)

func TestTracepointFormatCopiesUser(t *testing.T) {
	for name, c := range map[string]struct {
		format string
		want   bool
	}{
		"openat 7.0":    {fmtOpenat70, true},
		"renameat2 7.0": {fmtRenameat2_70, true},
		"openat 6.8":    {fmtOpenat68, false},
		"fork comm":     {fmtFork616, false},
		"empty":         {"", false},
	} {
		if got := tracepointFormatCopiesUser(c.format); got != c.want {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
}

// The demo host's 7.0 kernel copies user memory for exactly the probes with
// a kprobe twin (every sys_enter_* format with a __<arg>_val field), and for
// none of the others. Keep the twin list in step when hooks are added.
func TestKprobeTwinsAreTheUserStringSyscalls(t *testing.T) {
	copies70 := []string{"execve", "execveat", "openat", "openat2", "open", "creat", "unlinkat", "unlink",
		"renameat2", "renameat", "rename", "fchmodat", "fchmodat2", "chmod", "fchownat",
		"finit_module", "init_module", "mount", "umount", "memfd_create"}
	for _, p := range traceProbes {
		want := p.group == "syscalls" && slices.Contains(copies70, p.syscall())
		if p.kprobeTwin != want {
			t.Errorf("%s: kprobeTwin = %v, want %v", p.name, p.kprobeTwin, want)
		}
	}
}

func TestSelectKprobeTwins(t *testing.T) {
	newPrograms := func() map[string]int {
		m := map[string]int{"trace_ksys_stray": 1}
		for _, p := range traceProbes {
			m[p.funcName] = 1
			if p.kprobeTwin {
				m[p.kprobeFuncName()] = 1
			}
		}
		return m
	}
	countTwins := func(m map[string]int) int {
		n := 0
		for name := range m {
			if len(name) > 11 && name[:11] == "trace_ksys_" {
				n++
			}
		}
		return n
	}

	// 7.0 on amd64: every twin selected, tracepoint programs kept (fallback).
	progs := newPrograms()
	sel := selectKprobeTwins(progs, "amd64", func(_, name string) bool { return name != "sys_enter_openat2" })
	if len(sel) != 19 || sel["sys_enter_openat"] != "__x64_sys_openat" || sel["sys_enter_umount"] != "__x64_sys_umount" {
		t.Fatalf("selected %v", sel)
	}
	if _, ok := sel["sys_enter_openat2"]; ok {
		t.Fatal("openat2 selected though its tracepoint copies nothing")
	}
	if _, ok := progs["trace_ksys_openat2"]; ok {
		t.Fatal("unselected twin kept in the spec")
	}
	if _, ok := progs["trace_ksys_stray"]; ok {
		t.Fatal("twin of no probe kept in the spec")
	}
	if _, ok := progs["trace_sys_enter_openat"]; !ok {
		t.Fatal("tracepoint program of a selected probe removed (no fallback)")
	}
	if got := kprobeTwinPrograms(sel); len(got) != 19 || !slices.Contains(got, "trace_ksys_execve") {
		t.Fatalf("optional twins %v", got)
	}

	// Older kernel, or another arch: nothing selected, no twin loaded.
	for _, c := range []struct {
		arch   string
		copies bool
	}{{"amd64", false}, {"arm64", true}} {
		progs := newPrograms()
		sel := selectKprobeTwins(progs, c.arch, func(string, string) bool { return c.copies })
		if len(sel) != 0 || countTwins(progs) != 0 {
			t.Fatalf("%s copies=%v: selected %v, %d twins left", c.arch, c.copies, sel, countTwins(progs))
		}
	}

	// An object without twins (built before this change): tracepoints.
	progs = map[string]int{"trace_sys_enter_openat": 1}
	if sel := selectKprobeTwins(progs, "amd64", func(string, string) bool { return true }); len(sel) != 0 {
		t.Fatalf("selected twins the object lacks: %v", sel)
	}
}

// Every kprobe twin in wafio_trace.c belongs to a probe marked kprobeTwin,
// runs the same body as that probe's tracepoint program, and every marked
// probe has one.
func TestKprobeTwinsMatchObjectSource(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("bpf", "wafio_trace.c"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(source)
	// The open hooks pass the body a second argument (the kind of open, which
	// the twin lowers to 0 for an x32 task): the body must still be the same.
	twin := regexp.MustCompile(`SEC\("kprobe/sys_(\w+)"\)\s*\nint (\w+)\(struct pt_regs \*ctx\)\s*\{\s*TRACE_KSYSCALL_ARGS\(a, ctx\);\s*return (\w+)\(a[,)]`)
	tp := regexp.MustCompile(`SEC\("tracepoint/syscalls/sys_enter_(\w+)"\)\s*\nint \w+\(struct syscall_enter_ctx \*ctx\)\s*\{\s*TRACE_TP_ARGS\(a, ctx\);\s*return (\w+)\(a[,)]`)
	tpBody := map[string]string{}
	for _, m := range tp.FindAllStringSubmatch(src, -1) {
		tpBody[m[1]] = m[2]
	}
	found := map[string]bool{}
	for _, m := range twin.FindAllStringSubmatch(src, -1) {
		syscall, fn, body := m[1], m[2], m[3]
		i := slices.IndexFunc(traceProbes, func(p traceProbe) bool { return p.kprobeTwin && p.syscall() == syscall })
		if i < 0 {
			t.Errorf("kprobe twin %s has no probe marked kprobeTwin", fn)
			continue
		}
		if fn != traceProbes[i].kprobeFuncName() {
			t.Errorf("kprobe twin %s, probe expects %s", fn, traceProbes[i].kprobeFuncName())
		}
		if tpBody[syscall] != body {
			t.Errorf("twin %s runs %s, tracepoint runs %q", fn, body, tpBody[syscall])
		}
		found[syscall] = true
	}
	for _, p := range traceProbes {
		if p.kprobeTwin && !found[p.syscall()] {
			t.Errorf("probe %s marked kprobeTwin has no twin in wafio_trace.c", p.name)
		}
	}
	if !regexp.MustCompile(`(?m)^#if TRACE_KSYSCALL$`).MatchString(src) {
		t.Error("twins are not guarded by TRACE_KSYSCALL")
	}
}
