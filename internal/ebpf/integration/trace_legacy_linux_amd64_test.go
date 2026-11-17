//go:build linux && amd64

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

// Legacy file syscalls (kernel lab, x86_64: arm64 has no legacy file
// syscalls): open, creat, openat2, unlink, rename and chmod produce the same
// events as their *at forms, so file policies and detection rules see them.
// Observation probes only, on files in a temporary directory.
func TestTraceLegacyFileSyscalls(t *testing.T) {
	if os.Getenv("WAFIO_EBPF_INTEGRATION") != "1" {
		t.Skip("set WAFIO_EBPF_INTEGRATION=1 on an authorized Linux lab")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration requires root to load observation probes")
	}
	object := os.Getenv("WAFIO_TRACE_OBJECT")
	if object == "" {
		t.Fatal("WAFIO_TRACE_OBJECT is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tm := ebpf.NewTraceManager(ebpf.TraceManagerConfig{ObjectPath: object}, nil)
	if err := tm.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := tm.Stop(); err != nil {
			t.Errorf("detach: %v", err)
		}
	})
	if err := tm.UpdateConfig(ebpf.TraceConfigAPI{Enabled: true, MinSeverity: "info", FilterSelf: false}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	cstr := func(s string) uintptr {
		p, err := unix.BytePtrFromString(s)
		if err != nil {
			t.Fatal(err)
		}
		return uintptr(unsafe.Pointer(p))
	}
	closeFd := func(fd uintptr, errno unix.Errno, what string) {
		if errno != 0 {
			t.Fatalf("%s: %v", what, errno)
		}
		_ = unix.Close(int(fd))
	}
	fd, _, errno := unix.Syscall(unix.SYS_OPEN, cstr(path("open")), unix.O_CREAT|unix.O_WRONLY, 0o600)
	closeFd(fd, errno, "open")
	fd, _, errno = unix.Syscall(unix.SYS_CREAT, cstr(path("creat")), 0o600, 0)
	closeFd(fd, errno, "creat")
	how := unix.OpenHow{Flags: unix.O_RDONLY}
	if fd2, err := unix.Openat2(unix.AT_FDCWD, path("open"), &how); err != nil {
		t.Fatalf("openat2: %v", err)
	} else {
		_ = unix.Close(fd2)
	}
	if _, _, errno = unix.Syscall(unix.SYS_CHMOD, cstr(path("open")), 0o640, 0); errno != 0 {
		t.Fatalf("chmod: %v", errno)
	}
	if _, _, errno = unix.Syscall(unix.SYS_RENAME, cstr(path("open")), cstr(path("renamed")), 0); errno != 0 {
		t.Fatalf("rename: %v", errno)
	}
	if _, _, errno = unix.Syscall(unix.SYS_UNLINK, cstr(path("renamed")), 0, 0); errno != 0 {
		t.Fatalf("unlink: %v", errno)
	}

	want := map[string]bool{"open": false, "creat": false, "openat2": false, "chmod": false, "rename": false, "unlink": false}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range tm.DrainRecentTraceEvents(8192) {
			if e.PID != uint32(os.Getpid()) {
				continue
			}
			switch {
			case e.EventType == ebpf.TraceOpen && e.Filename == path("open") && e.Flags&unix.O_CREAT != 0:
				want["open"] = true
			case e.EventType == ebpf.TraceOpen && e.Filename == path("creat"):
				want["creat"] = e.Flags&unix.O_CREAT != 0 && e.Flags&unix.O_TRUNC != 0
			case e.EventType == ebpf.TraceOpen && e.Filename == path("open") && e.Flags&(unix.O_CREAT|unix.O_WRONLY) == 0:
				want["openat2"] = true
			case e.EventType == ebpf.TraceChmod && e.Filename == path("open"):
				want["chmod"] = true
			case e.EventType == ebpf.TraceRename && e.Filename == path("open"):
				want["rename"] = true
			case e.EventType == ebpf.TraceUnlink && e.Filename == path("renamed"):
				want["unlink"] = true
			}
		}
		done := true
		for _, ok := range want {
			done = done && ok
		}
		if done {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("legacy file syscalls not all traced: %v", want)
}
