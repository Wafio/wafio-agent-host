//go:build linux && amd64

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

// open, creat and openat2 report their result like openat does (x86_64 only:
// arm64 has no open and creat).
func TestTraceOpenResultLegacySyscalls(t *testing.T) {
	tm := openResultLab(t)
	dir := t.TempDir()
	created := filepath.Join(dir, "created")
	missing := filepath.Join(dir, "missing")
	cstr := func(s string) uintptr {
		p, err := unix.BytePtrFromString(s)
		if err != nil {
			t.Fatal(err)
		}
		return uintptr(unsafe.Pointer(p))
	}

	fd, _, errno := unix.Syscall(unix.SYS_CREAT, cstr(created), 0o600, 0)
	if errno != 0 {
		t.Fatalf("creat: %v", errno)
	}
	_ = unix.Close(int(fd))
	fd, _, errno = unix.Syscall(unix.SYS_OPEN, cstr(created), unix.O_RDONLY, 0)
	if errno != 0 {
		t.Fatalf("open: %v", errno)
	}
	_ = unix.Close(int(fd))
	if _, _, errno = unix.Syscall(unix.SYS_OPEN, cstr(missing), unix.O_RDONLY, 0); errno != unix.ENOENT {
		t.Fatalf("open of a missing file: %v", errno)
	}
	how := unix.OpenHow{Flags: unix.O_RDONLY}
	if fd2, err := unix.Openat2(unix.AT_FDCWD, created, &how); err != nil {
		t.Fatalf("openat2: %v", err)
	} else {
		_ = unix.Close(fd2)
	}
	if _, err := unix.Openat2(unix.AT_FDCWD, missing, &how); err != unix.ENOENT {
		t.Fatalf("openat2 of a missing file: %v", err)
	}

	self := map[uint32]bool{uint32(os.Getpid()): true} //nolint:gosec // G115: pids are small positive integers
	events := openEvents(tm, self, 5*time.Second, func(got []ebpf.TraceEvent) bool {
		return len(opensOf(got, created)) >= 3 && len(opensOf(got, missing)) >= 2
	})
	makes, misses := opensOf(events, created), opensOf(events, missing)
	// creat, open, openat2 on the created file; open and openat2 on the missing one.
	if len(makes) != 3 || len(misses) != 2 {
		t.Fatalf("one event per open wanted: created %d, missing %d (all: %+v)", len(makes), len(misses), events)
	}
	for _, e := range makes {
		if e.RetVal < 0 || e.ActivityOutcome != "success" {
			t.Errorf("open of the created file: ret_val %d, outcome %q", e.RetVal, e.ActivityOutcome)
		}
	}
	for _, e := range misses {
		if e.RetVal != -int64(unix.ENOENT) || e.ActivityOutcome != "failure" {
			t.Errorf("open of the missing file: ret_val %d, outcome %q", e.RetVal, e.ActivityOutcome)
		}
	}
}
