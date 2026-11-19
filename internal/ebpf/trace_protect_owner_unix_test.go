//go:build unix

package ebpf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedOwnerMode(t *testing.T) {
	prev := trustedUID
	t.Cleanup(func() { trustedUID = prev })
	trustedUID = 0
	for _, tc := range []struct {
		uid, perm uint32
		want      bool
	}{
		{0, 0o755, true},
		{0, 0o700, true},
		{0, 0o4755, true}, // set-user-ID is not a write permission
		{0, 0o775, false},
		{0, 0o757, false},
		{0, 0o777, false},
		{0, 0o722, false},
		{0, 0o702, false},
		{1000, 0o755, false}, // an account's own file is its to replace
		{1000, 0o700, false},
		{1, 0o755, false},
	} {
		if got := trustedOwnerMode(tc.uid, tc.perm); got != tc.want {
			t.Errorf("trustedOwnerMode(%d, %o) = %t, want %t", tc.uid, tc.perm, got, tc.want)
		}
	}
}

// hostExeCheck says a running image is the host binary only when the file at
// its path, and the directory of that file, could only be written by root. A
// non-root account that owns the file, or the directory, can rename a copy of
// its own over a trusted path, and the image then equals the file at the path.
// The string it returns names what the account can write.
func TestHostExeCheckRefusesWhatOthersCanWrite(t *testing.T) {
	prev := trustedUID
	t.Cleanup(func() { trustedUID = prev })

	base := t.TempDir()
	hostRoot := filepath.Join(base, "host")
	exe := "/opt/acme/agentd"
	file := filepath.Join(hostRoot, exe)
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	set := func(path string, mode os.FileMode) {
		t.Helper()
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(file, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("y"), 0o755); err != nil {
		t.Fatal(err)
	}

	proc := filepath.Join(base, "proc")
	if err := os.MkdirAll(filepath.Join(proc, "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hostRoot, filepath.Join(proc, "1", "root")); err != nil {
		t.Fatal(err)
	}
	pidDir := filepath.Join(proc, "10")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// run points the process at the file it runs.
	run := func(image string) {
		t.Helper()
		_ = os.Remove(filepath.Join(pidDir, "exe"))
		if err := os.Symlink(image, filepath.Join(pidDir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	check := func(link string) (tri, string) { return hostExeCheck(proc, pidDir, link, nil) }
	run(file)

	trustedUID = uint32(os.Getuid())
	if got, path := check(exe); got != triYes || path != "" {
		t.Fatalf("a file and a directory only their owner can write: %v %q, want yes", got, path)
	}
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		set(file, mode)
		if got, path := check(exe); got != triNo || path != exe {
			t.Errorf("a file with mode %o: %v %q, want no naming %s", mode, got, path, exe)
		}
	}
	set(file, 0o755)
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		set(dir, mode)
		if got, path := check(exe); got != triNo || path != "/opt/acme" {
			t.Errorf("a directory with mode %o: %v %q, want no naming /opt/acme", mode, got, path)
		}
	}
	set(dir, 0o755)

	// The owner is the one the policy trusts, nobody else.
	trustedUID = uint32(os.Getuid()) + 1
	if got, path := check(exe); got != triNo || path != exe {
		t.Errorf("a file and directory of another owner than the trusted one: %v %q, want no naming %s", got, path, exe)
	}
	trustedUID = 0
	if os.Getuid() != 0 {
		if got, _ := check(exe); got != triNo {
			t.Errorf("a file of an unprivileged user under the real owner policy: %v, want no", got)
		}
	}

	// A different file at the path, a missing one and an unreadable image keep
	// their earlier answers, and none of them names a path: the image is not
	// the file the account can write.
	trustedUID = uint32(os.Getuid())
	run(other)
	set(file, 0o777)
	if got, path := check(exe); got != triNo || path != "" {
		t.Errorf("another file than the one at the path: %v %q, want no and silent", got, path)
	}
	set(file, 0o755)
	if got, _ := check("/opt/acme/missing"); got != triNo {
		t.Errorf("no file at the path: %v, want no", got)
	}
	if got, _ := hostExeCheck(proc, filepath.Join(proc, "11"), exe, nil); got != triUnknown {
		t.Errorf("no running image: %v, want unknown", got)
	}

	// A replaced image has no file at the path to compare with: it is the
	// running inode itself that must be root's alone, on the filesystem of the
	// directory its path names. The file now at the path is not looked at.
	deleted := exe + " (deleted)"
	run(other)
	if got, path := check(deleted); got != triYes || path != "" {
		t.Fatalf("a replaced image only its owner can write: %v %q, want yes", got, path)
	}
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		set(other, mode)
		if got, path := check(deleted); got != triNo || path != deleted {
			t.Errorf("a replaced image with mode %o: %v %q, want no naming %s", mode, got, path, deleted)
		}
	}
	set(other, 0o755)
	trustedUID = uint32(os.Getuid()) + 1
	if got, path := check(deleted); got != triNo || path != deleted {
		t.Errorf("a replaced image of another owner than the trusted one: %v %q, want no naming %s", got, path, deleted)
	}
	trustedUID = uint32(os.Getuid())
	set(dir, 0o777)
	if got, path := check(deleted); got != triNo || path != "/opt/acme" {
		t.Errorf("a replaced image in a directory with mode 777: %v %q, want no naming /opt/acme", got, path)
	}
	set(dir, 0o755)
	if got, _ := check("/opt/missing/agentd (deleted)"); got != triNo {
		t.Errorf("a replaced image whose directory is not on the host: %v, want no", got)
	}
	// An image on another filesystem than its directory is another file whatever
	// its owner: a copy a container or a mount put there.
	if st, err := os.Stat("/proc/self/status"); err == nil {
		here, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !sameDevice(st, here) {
			run("/proc/self/status")
			if got, path := check(deleted); got != triNo || path != "" {
				t.Errorf("a replaced image on another filesystem: %v %q, want no and silent", got, path)
			}
		}
	}
}
