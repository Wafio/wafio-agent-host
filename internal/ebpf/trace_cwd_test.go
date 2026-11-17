package ebpf

import (
	"errors"
	"path/filepath"
	"testing"
)

const fakeCWD = "/expected/cwd"

// rawEvent builds an event the way the kernel reports it: openat, unlinkat
// and fchmodat carry their dirfd in detail, and libc's open() passes
// AT_FDCWD.
func rawEvent(pid, evt uint32, fn, args string) *RawTraceEvent {
	r := &RawTraceEvent{PID: pid, EventType: evt}
	if _, ok := fileEventDirfd(evt, 0); ok {
		r.Detail = atFDCWDDetail
	}
	copy(r.Filename[:], fn)
	copy(r.Args[:], args)
	return r
}

func fakeProcCWD(t *testing.T, pid uint32, wantErr error) {
	t.Helper()
	prev := procCWDFn
	procCWDFn = func(p uint32) (string, error) {
		if p == pid {
			return fakeCWD, wantErr
		}
		return "", errors.New("no such process")
	}
	t.Cleanup(func() { procCWDFn = prev })
}

// Relative file paths (openat(dfd, "shadow")) must resolve against the
// process CWD so filename rules like starts_with "/etc/" actually match.
func TestRelativeOpenPathResolvedAgainstProcCWD(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	te := rawEvent(4242, TraceOpen, "./shadow", "").ToTraceEvent(0)
	want := filepath.Clean(filepath.Join(fakeCWD, "shadow"))
	if te.Filename != want {
		t.Fatalf("resolved = %q, want %q", te.Filename, want)
	}
	if te.Cwd != fakeCWD {
		t.Fatalf("cwd = %q, want %q", te.Cwd, fakeCWD)
	}
	if te.PathUnresolved {
		t.Fatal("resolved path must not be flagged unresolved")
	}
}

func TestAbsoluteFilePathUntouched(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	te := rawEvent(4242, TraceOpen, "/etc/passwd", "").ToTraceEvent(0)
	if te.Filename != "/etc/passwd" {
		t.Fatalf("absolute path rewritten: %q", te.Filename)
	}
	if te.Cwd != "" {
		t.Fatalf("cwd must stay empty for absolute paths, got %q", te.Cwd)
	}
	if te.PathUnresolved {
		t.Fatal("absolute path must not be flagged unresolved")
	}
}

// Process already exited → /proc gone: keep the relative path and flag it so
// downstream consumers know the rule match ran on an unresolved path.
func TestExitedProcessFlagsPathUnresolved(t *testing.T) {
	fakeProcCWD(t, 4242, errors.New("no such process"))
	te := rawEvent(4242, TraceOpen, "shadow", "").ToTraceEvent(0)
	if te.Filename != "shadow" {
		t.Fatalf("relative path must be preserved on resolution failure, got %q", te.Filename)
	}
	if !te.PathUnresolved {
		t.Fatal("unresolved relative path must be flagged")
	}
}

func TestRenameBothPathsResolved(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	te := rawEvent(4242, TraceRename, "./old.txt", "./new.txt").ToTraceEvent(0)
	if want := filepath.Clean(filepath.Join(fakeCWD, "old.txt")); te.Filename != want {
		t.Fatalf("old path = %q, want %q", te.Filename, want)
	}
	if want := filepath.Clean(filepath.Join(fakeCWD, "new.txt")); te.Args != want {
		t.Fatalf("new path = %q, want %q", te.Args, want)
	}
}

func TestNonFileEventsUntouched(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	te := rawEvent(4242, TraceExecve, "relative-bin", "").ToTraceEvent(0)
	if te.Filename != "relative-bin" {
		t.Fatalf("non-file event path rewritten: %q", te.Filename)
	}
	if te.Cwd != "" || te.PathUnresolved {
		t.Fatal("non-file events must not gain cwd/unresolved metadata")
	}
}
