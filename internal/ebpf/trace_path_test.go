package ebpf

import (
	"errors"
	"testing"
)

// fakeProcFD makes procFDFn answer target for (pid, fd) and fail otherwise.
func fakeProcFD(t *testing.T, pid, fd uint32, target string) {
	t.Helper()
	prev := procFDFn
	procFDFn = func(p, f uint32) (string, error) {
		if p == pid && f == fd && target != "" {
			return target, nil
		}
		return "", errors.New("no such fd")
	}
	t.Cleanup(func() { procFDFn = prev })
}

// openat(open("/etc"), "shadow") used to be joined with the process
// CWD, producing a fabricated path at INFO. It resolves against the dirfd's
// directory, never the CWD.
func TestDirfdRelativeOpenResolvesAgainstTheFD(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	fakeProcFD(t, 4242, 3, "/etc")
	r := rawEvent(4242, TraceOpen, "shadow", "")
	r.Detail = 3 // an fd from open("/etc", O_PATH)
	te := r.ToTraceEvent(0)
	if te.Filename != "/etc/shadow" || te.Cwd != "/etc" || te.PathUnresolved || te.Severity != SevHigh {
		t.Fatalf("dirfd-relative shadow read: filename=%q cwd=%q unresolved=%v severity=%s", te.Filename, te.Cwd, te.PathUnresolved, te.SeverityName)
	}
}

// When the fd no longer names a directory path the file stays raw, flagged,
// and a sensitive basename is still at least MEDIUM (stored, not noise).
func TestDirfdRelativeOpenUnresolvedKeepsSensitiveBasename(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	for _, target := range []string{"", "socket:[4711]", "anon_inode:[eventfd]", "/etc (deleted)"} {
		fakeProcFD(t, 4242, 3, target)
		r := rawEvent(4242, TraceOpen, "shadow", "")
		r.Detail = 3
		te := r.ToTraceEvent(0)
		if te.Filename != "shadow" || te.Cwd != "" || !te.PathUnresolved || te.Severity != SevMedium {
			t.Errorf("fd target %q: filename=%q cwd=%q unresolved=%v severity=%s", target, te.Filename, te.Cwd, te.PathUnresolved, te.SeverityName)
		}
	}
	for _, evt := range []uint32{TraceUnlink, TraceChmod} {
		r := rawEvent(4242, evt, "shadow", "")
		r.Detail = 3
		if te := r.ToTraceEvent(0); te.Filename != "shadow" || !te.PathUnresolved {
			t.Errorf("event %d: dirfd-relative path resolved to %q", evt, te.Filename)
		}
	}
	// A non-sensitive unresolved read stays as the kernel graded it.
	r := rawEvent(4242, TraceOpen, "notes.txt", "")
	r.Detail = 3
	if te := r.ToTraceEvent(0); te.Severity != SevInfo {
		t.Errorf("unresolved notes.txt raised to %s", te.SeverityName)
	}
}

// The directory of a relative path is read after the fact: a chdir (or a
// reused fd number) before userspace reads /proc can move "shadow" to
// /tmp/shadow. The basename keeps it at MEDIUM.
func TestRelativeSensitiveBasenameFloor(t *testing.T) {
	prev := procCWDFn
	procCWDFn = func(uint32) (string, error) { return "/tmp", nil }
	t.Cleanup(func() { procCWDFn = prev })
	for raw, want := range map[string]uint32{"shadow": SevMedium, "./gshadow": SevMedium, "passwd": SevInfo, "notes": SevInfo} {
		r := rawEvent(7, TraceOpen, raw, "")
		if te := r.ToTraceEvent(0); te.Severity != want {
			t.Errorf("relative %q: severity %s, want %s", raw, te.SeverityName, severityName(want))
		}
	}
	w := rawEvent(7, TraceOpen, "passwd", "")
	w.Flags = 1
	if te := w.ToTraceEvent(0); te.Severity != SevMedium {
		t.Errorf("relative passwd write: severity %s", te.SeverityName)
	}
}

// "cat /etc//shadow" read below HIGH and slipped past filename eq
// "/etc/shadow" rules and kill policies. Absolute paths are cleaned, and the
// kernel's exact-path severity is re-derived on the cleaned path.
func TestAbsolutePathCleanedAndReclassified(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	cases := []struct {
		raw   string
		flags uint32
		want  string
		sev   uint32
	}{
		{"/etc//shadow", 0, "/etc/shadow", SevHigh},
		{"/etc/./shadow", 0, "/etc/shadow", SevHigh},
		{"//etc/shadow", 0, "/etc/shadow", SevHigh},
		{"/tmp/../etc/shadow", 0, "/etc/shadow", SevHigh},
		{"/etc//passwd", 0, "/etc/passwd", SevInfo},     // read stays as the kernel graded it
		{"/etc//passwd", 1, "/etc/passwd", SevHigh},     // write
		{"/etc//passwd", 01000, "/etc/passwd", SevHigh}, // O_TRUNC
		{"/etc//sudoers.d/admin", 2, "/etc/sudoers.d/admin", SevHigh},
		{"/etc//sudoers.bak", 1, "/etc/sudoers.bak", SevInfo},
		{"//proc/sys/kernel/core_pattern", 1, "/proc/sys/kernel/core_pattern", SevMedium},
		{"/srv//app/log", 1, "/srv/app/log", SevInfo},
	}
	for _, tc := range cases {
		r := rawEvent(4242, TraceOpen, tc.raw, "")
		r.Flags = tc.flags
		r.Severity = SevInfo
		te := r.ToTraceEvent(0)
		if te.Filename != tc.want || te.Severity != tc.sev || te.SeverityName != severityName(tc.sev) {
			t.Errorf("%q flags=%o: filename=%q severity=%s, want %q %s", tc.raw, tc.flags, te.Filename, te.SeverityName, tc.want, severityName(tc.sev))
		}
	}
}

// A relative path resolved against AT_FDCWD gets the same classification:
// "cd /etc && cat shadow" is a shadow read.
func TestResolvedRelativeShadowReadIsHigh(t *testing.T) {
	prev := procCWDFn
	procCWDFn = func(uint32) (string, error) { return "/etc", nil }
	t.Cleanup(func() { procCWDFn = prev })
	r := rawEvent(7, TraceOpen, "shadow", "")
	r.Severity = SevInfo
	te := r.ToTraceEvent(0)
	if te.Filename != "/etc/shadow" || te.Severity != SevHigh {
		t.Fatalf("relative shadow read: filename=%q severity=%s", te.Filename, te.SeverityName)
	}
}

// Re-derivation only ever raises: a kernel verdict above the path's class
// stays.
func TestPathReclassificationNeverLowers(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	r := rawEvent(4242, TraceOpen, "/srv//data", "")
	r.Severity = SevCritical
	if te := r.ToTraceEvent(0); te.Severity != SevCritical {
		t.Fatalf("severity lowered to %s", te.SeverityName)
	}
}

func TestExecAndRenamePathsCleaned(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	if te := rawEvent(4242, TraceExecve, "/usr/bin//nc", "-e /bin/sh").ToTraceEvent(0); te.Filename != "/usr/bin/nc" || te.Args != "-e /bin/sh" {
		t.Errorf("execve: filename=%q args=%q", te.Filename, te.Args)
	}
	if te := rawEvent(4242, TraceExecve, "./x//y", "").ToTraceEvent(0); te.Filename != "./x//y" {
		t.Errorf("relative exec path rewritten: %q", te.Filename)
	}
	if te := rawEvent(4242, TraceRename, "/tmp//a", "/etc/cron.d//job").ToTraceEvent(0); te.Filename != "/tmp/a" || te.Args != "/etc/cron.d/job" {
		t.Errorf("rename: %q -> %q", te.Filename, te.Args)
	}
}

// End to end: a kill policy on /dev/shm/ and a min-severity HIGH policy both
// see through a doubled slash.
func TestPolicyMatchesCleanedPath(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	pe := NewPolicyEngine()
	addPolicy(t, pe, EnforcementPolicy{Name: "shm exec", Enabled: true, Action: "kill", EventTypes: []string{"execve"}, MatchFilename: "/dev/shm/"})
	addPolicy(t, pe, EnforcementPolicy{Name: "shadow", Enabled: true, Action: "alert", EventTypes: []string{"openat"}, MinSeverity: "high", KillAcknowledged: true})

	exec := rawEvent(4242, TraceExecve, "/dev//shm/x", "").ToTraceEvent(0)
	if action, _ := pe.Evaluate(exec); action != ActionKill {
		t.Errorf("exec of /dev//shm/x escaped the /dev/shm/ kill policy (action %d)", action)
	}
	open := rawEvent(4242, TraceOpen, "/etc//shadow", "").ToTraceEvent(0)
	if action, _ := pe.Evaluate(open); action != ActionAlert {
		t.Errorf("/etc//shadow escaped the HIGH policy (action %d, severity %s)", action, open.SeverityName)
	}
}
