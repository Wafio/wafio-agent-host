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
	if err := os.Symlink(file, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}

	trustedUID = uint32(os.Getuid())
	if got := hostExeCheck(proc, pidDir, exe); got != triYes {
		t.Fatalf("a file and a directory only their owner can write: %v, want yes", got)
	}
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		set(file, mode)
		if got := hostExeCheck(proc, pidDir, exe); got != triNo {
			t.Errorf("a file with mode %o: %v, want no", mode, got)
		}
	}
	set(file, 0o755)
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		set(dir, mode)
		if got := hostExeCheck(proc, pidDir, exe); got != triNo {
			t.Errorf("a directory with mode %o: %v, want no", mode, got)
		}
	}
	set(dir, 0o755)

	// The owner is the one the policy trusts, nobody else.
	trustedUID = uint32(os.Getuid()) + 1
	if got := hostExeCheck(proc, pidDir, exe); got != triNo {
		t.Errorf("a file and directory of another owner than the trusted one: %v, want no", got)
	}
	trustedUID = 0
	if os.Getuid() != 0 {
		if got := hostExeCheck(proc, pidDir, exe); got != triNo {
			t.Errorf("a file of an unprivileged user under the real owner policy: %v, want no", got)
		}
	}

	// A different file at the path, a missing one and an unreadable image keep
	// their earlier answers.
	trustedUID = uint32(os.Getuid())
	if err := os.Remove(filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
	if got := hostExeCheck(proc, pidDir, exe); got != triNo {
		t.Errorf("another file than the one at the path: %v, want no", got)
	}
	if got := hostExeCheck(proc, pidDir, "/opt/acme/missing"); got != triNo {
		t.Errorf("no file at the path: %v, want no", got)
	}
	if got := hostExeCheck(proc, filepath.Join(proc, "11"), exe); got != triUnknown {
		t.Errorf("no running image: %v, want unknown", got)
	}
}
