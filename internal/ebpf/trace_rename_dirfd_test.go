package ebpf

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProcFDs answers procFDFn from a table for one PID.
func fakeProcFDs(t *testing.T, pid uint32, fds map[uint32]string) {
	t.Helper()
	prev := procFDFn
	procFDFn = func(p, f uint32) (string, error) {
		if dir, ok := fds[f]; p == pid && ok {
			return dir, nil
		}
		return "", errors.New("no such fd")
	}
	t.Cleanup(func() { procFDFn = prev })
}

func renameEvent(oldDirfd uint32, oldName string, newDirfd uint32, newName string) *RawTraceEvent {
	r := &RawTraceEvent{PID: 4242, EventType: TraceRename, Detail: oldDirfd, Aux: newDirfd, ProcFlags: traceEvtDirfds}
	copy(r.Filename[:], oldName)
	copy(r.Args[:], newName)
	return r
}

// renameat/renameat2 record both dirfds; each relative path
// resolves against its own dirfd, never the CWD, and is flagged when the fd
// no longer names a directory — like openat/unlinkat/fchmodat.
func TestRenameResolvesEachPathAgainstItsDirfd(t *testing.T) {
	fakeProcCWD(t, 4242, nil)
	fakeProcFDs(t, 4242, map[uint32]string{5: "/etc", 6: "/tmp", 7: "socket:[1]"})

	te := renameEvent(5, "shadow", 6, "loot").ToTraceEvent(0)
	if te.Filename != "/etc/shadow" || te.Args != "/tmp/loot" || te.PathUnresolved {
		t.Fatalf("renameat(5, shadow, 6, loot): old=%q new=%q unresolved=%v", te.Filename, te.Args, te.PathUnresolved)
	}

	te = renameEvent(5, "shadow", atFDCWDDetail, "loot").ToTraceEvent(0)
	if te.Filename != "/etc/shadow" || te.Args != filepath.Join(fakeCWD, "loot") {
		t.Fatalf("new path relative to AT_FDCWD: old=%q new=%q", te.Filename, te.Args)
	}

	te = renameEvent(atFDCWDDetail, "a", 7, "b").ToTraceEvent(0)
	if te.Filename != filepath.Join(fakeCWD, "a") || te.Args != "b" || !te.PathUnresolved {
		t.Fatalf("new dirfd not a directory: old=%q new=%q unresolved=%v", te.Filename, te.Args, te.PathUnresolved)
	}

	// An older object records no dirfds (no marker): both join the CWD.
	old := renameEvent(5, "a", 6, "b")
	old.ProcFlags = 0
	te = old.ToTraceEvent(0)
	if te.Filename != filepath.Join(fakeCWD, "a") || te.Args != filepath.Join(fakeCWD, "b") {
		t.Fatalf("pre-marker rename: old=%q new=%q", te.Filename, te.Args)
	}
}

// The aux word follows proc_flags in a 1440-byte event.
func TestParseRawTraceEventAux(t *testing.T) {
	data := make([]byte, TraceEventSizeWithIdentity)
	binary.LittleEndian.PutUint32(data[1432:1436], traceEvtDirfds|traceProcProtected)
	binary.LittleEndian.PutUint32(data[1436:1440], 0xFFFFFF9C)
	r, err := ParseRawTraceEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Aux != atFDCWDDetail || r.ProcFlags&traceEvtDirfds == 0 {
		t.Fatalf("aux=%#x flags=%#x", r.Aux, r.ProcFlags)
	}
	short, err := ParseRawTraceEvent(data[:TraceEventSize])
	if err != nil || short.Aux != 0 || short.ProcFlags != 0 {
		t.Fatalf("1432-byte event: %+v %v", short, err)
	}
}

// An openat2 whose open_how the tracepoint could not read is
// recorded as O_RDWR and marked, so a write-sensitive path is classified as
// written and the event says why.
func TestUnreadableOpenHowIsMarked(t *testing.T) {
	r := &RawTraceEvent{PID: 4242, EventType: TraceOpen, Detail: atFDCWDDetail, Flags: 0o2, ProcFlags: traceEvtArgsUnreadable}
	copy(r.Filename[:], "/etc//passwd")
	te := r.ToTraceEvent(0)
	if !te.ArgsUnreadable || !strings.Contains(te.Description, "open_how unreadable") || te.Severity != SevHigh {
		t.Fatalf("unreadable open_how: marked=%v severity=%s description=%q", te.ArgsUnreadable, te.SeverityName, te.Description)
	}
	r.ProcFlags = 0
	if te := r.ToTraceEvent(0); te.ArgsUnreadable {
		t.Fatal("readable open_how marked")
	}
}
