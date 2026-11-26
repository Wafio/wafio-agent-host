//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// mkdirExact makes a directory with exactly this mode, whatever the umask.
func mkdirExact(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// symlinkAt makes link, with the directories above it, a symlink to target.
func symlinkAt(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// openFDs is how many descriptors this process holds.
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// walkRoot builds the root the walk tests resolve in, owned by the test user,
// with directories only that user can write in unless a case says otherwise:
//
//	/releases/v1/agentd         the file the root-only paths lead to
//	/opt/app/current            symlink to /releases/v1 (absolute)
//	/opt/app/bin/agentd         symlink to ../current/agentd (relative, with "..")
//	/loose                      group-writable, holds a symlink to the file
//	/loose-dir                  writable by everyone, holds a symlink to /releases/v1
func walkRoot(t *testing.T) (int, string) {
	t.Helper()
	asTrustedOwner(t)
	base := imageTestDir(t)
	root := filepath.Join(base, "root")
	writeFile(t, filepath.Join(root, "releases", "v1", "agentd"), "x", 0o755)
	writeFile(t, filepath.Join(root, "releases", "v1", "open"), "x", 0o775)
	symlinkAt(t, "/releases/v1", filepath.Join(root, "opt", "app", "current"))
	symlinkAt(t, "../current/agentd", filepath.Join(root, "opt", "app", "bin", "agentd"))
	symlinkAt(t, "../../../../../../releases/v1/agentd", filepath.Join(root, "opt", "app", "bin", "high"))
	symlinkAt(t, "../../../../outside/agentd", filepath.Join(root, "opt", "app", "bin", "outside"))
	symlinkAt(t, "/loose", filepath.Join(root, "opt", "app", "shared"))
	writeFile(t, filepath.Join(base, "outside", "agentd"), "x", 0o755)

	mkdirExact(t, filepath.Join(root, "loose"), 0o775)
	symlinkAt(t, "/releases/v1/agentd", filepath.Join(root, "loose", "agentd"))
	writeFile(t, filepath.Join(root, "loose", "inner", "agentd"), "x", 0o755)
	mkdirExact(t, filepath.Join(root, "loose-dir"), 0o777)
	symlinkAt(t, "/releases/v1", filepath.Join(root, "loose-dir", "current"))

	symlinkAt(t, "b", filepath.Join(root, "loop", "a"))
	symlinkAt(t, "a", filepath.Join(root, "loop", "b"))
	// A chain of 40 links reaches the file, one of 41 does not.
	for _, n := range []int{40, 41} {
		for i := 1; i <= n; i++ {
			target := fmt.Sprintf("l%d", i+1)
			if i == n {
				target = "/releases/v1/agentd"
			}
			symlinkAt(t, target, filepath.Join(root, fmt.Sprintf("chain%d", n), fmt.Sprintf("l%d", i)))
		}
	}
	return rootFD(t, root), root
}

// The walk follows a symlink, to a file or to a directory, only out of a
// directory that only root can write in, and the file it ends at is held to the
// same rule.
func TestTrustedWalk(t *testing.T) {
	root, _ := walkRoot(t)
	before := openFDs(t)
	cases := []struct {
		path string
		// resolved is where a trusted path leads; untrusted names the directory
		// or file that stops the walk; otherwise err is the error.
		resolved, untrusted string
		err                 error
	}{
		{path: "/releases/v1/agentd", resolved: "/releases/v1/agentd"},
		{path: "releases/v1/agentd", resolved: "/releases/v1/agentd"},
		{path: "/opt/app/current/agentd", resolved: "/releases/v1/agentd"},
		{path: "/opt/app/bin/agentd", resolved: "/releases/v1/agentd"},              // both kinds, "..", an absolute target
		{path: "/opt/app/bin/high", resolved: "/releases/v1/agentd"},                // ".." stops at the root
		{path: "/opt/app/bin/outside", err: unix.ENOENT},                            // /outside is not in the root
		{path: "/opt/app/bin/../current/./agentd", resolved: "/releases/v1/agentd"}, // "." and ".." in the path itself
		{path: "/opt/app/current", resolved: "/releases/v1"},                        // a directory
		{path: "/", resolved: "/"},                                                  // the root
		{path: "/releases/v1/agentd/x", err: unix.ENOTDIR},                          // a file with something below it
		{path: "/releases/v1/missing", err: unix.ENOENT},                            // nothing at the end
		{path: "/loose/agentd", untrusted: "/loose"},                                // a writable directory holds a file symlink
		{path: "/loose-dir/current/agentd", untrusted: "/loose-dir"},                // a writable directory holds a directory symlink
		{path: "/opt/app/shared/agentd", untrusted: "/loose"},                       // a root-only symlink leads into a writable directory
		{path: "/loose/inner/agentd", untrusted: "/loose"},                          // a root-only directory below a writable one
		{path: "/releases/v1/open", untrusted: "/releases/v1/open"},                 // the file itself is writable
		{path: "/loose/missing", err: unix.ENOENT},                                  // a writable directory with no such entry names nothing
		{path: "/loose/inner/missing", err: unix.ENOENT},                            // nor does one with a directory in it, and nothing at the end
		{path: "/loop/a", err: unix.ELOOP},                                          // a loop
		{path: "/chain40/l1", resolved: "/releases/v1/agentd"},                      // 40 links are followed
		{path: "/chain41/l1", err: unix.ELOOP},                                      // the 41st is not
	}
	for _, tc := range cases {
		fd, resolved, err := trustedWalk(root, tc.path)
		if err == nil {
			_ = unix.Close(fd)
		}
		var u *untrustedError
		switch {
		case tc.untrusted != "":
			if !errors.As(err, &u) || u.path != tc.untrusted {
				t.Errorf("%s: %v, want the walk stopped at %s", tc.path, err, tc.untrusted)
			}
		case tc.err != nil:
			if !errors.Is(err, tc.err) || errors.As(err, &u) {
				t.Errorf("%s: %v, want %v", tc.path, err, tc.err)
			}
		case err != nil || resolved != tc.resolved:
			t.Errorf("%s: %q (%v), want %q", tc.path, resolved, err, tc.resolved)
		}
	}
	if after := openFDs(t); after != before {
		t.Errorf("the walks left %d descriptors open", after-before)
	}
}

// The image set and the lead of a configured path come from the same walk: a
// path that goes through a writable directory has no image and no lead, one
// through root's directories alone has both, and the system directories still
// refuse every symlink.
func TestTrustedWalkDecidesImageAndLead(t *testing.T) {
	root, _ := walkRoot(t)
	for path, protected := range map[string]bool{
		"/opt/app/bin/agentd":       true,
		"/opt/app/current/agentd":   true,
		"/loose/agentd":             false,
		"/loose-dir/current/agentd": false,
		"/opt/app/shared/agentd":    false,
		"/releases/v1/open":         false,
	} {
		_, imaged := imageAt(t, root, path, true)
		w := walkExe(root, path)
		if imaged != protected || (w.lead != "") != protected || (w.file != nil) != protected {
			t.Errorf("%s: image %t, lead %q, file %v, want protected %t", path, imaged, w.lead, w.file, protected)
		}
		if protected && w.lead != "/releases/v1/agentd" {
			t.Errorf("%s leads to %q, want /releases/v1/agentd", path, w.lead)
		}
		if _, ok := imageAt(t, root, path, false); ok {
			t.Errorf("%s: trusted with no symlink allowed", path)
		}
	}
	// No file at the path: the directory says where it was, but a writable
	// directory names nothing.
	if w := walkExe(root, "/opt/app/current/gone"); w.lead != "/releases/v1/gone" || w.file != nil || w.dir == nil {
		t.Errorf("a missing file in a root-only directory: %+v, want the lead /releases/v1/gone, no file and the directory", w)
	}
	if w := walkExe(root, "/loose/gone"); w.lead != "" || w.untrusted != "" || w.dir != nil || w.dirStop != "/loose" {
		t.Errorf("a missing file in a writable directory: %+v, want no lead, nothing named for the file and /loose for the directory", w)
	}
	if w := walkExe(root, "/loose/agentd"); w.lead != "" || w.untrusted != "/loose" {
		t.Errorf("a symlink in a writable directory: %+v, want /loose named", w)
	}
}

// An owner other than root makes a directory untrusted whatever its mode. Run
// as root, which only a privileged test can be, so no hook stands in for root.
func TestTrustedWalkOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to give a directory to another account")
	}
	root, rootPath := walkRoot(t)
	for _, path := range []string{filepath.Join(rootPath, "opt", "app"), filepath.Join(rootPath, "releases", "v1", "agentd")} {
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	var u *untrustedError
	// /opt/app belongs to an account now, and holds the symlink.
	if _, _, err := trustedWalk(root, "/opt/app/bin/agentd"); !errors.As(err, &u) || u.path != "/opt/app" {
		t.Errorf("a directory of another owner: %v, want /opt/app named", err)
	}
	if _, _, err := trustedWalk(root, "/releases/v1/agentd"); !errors.As(err, &u) || u.path != "/releases/v1/agentd" {
		t.Errorf("a file of another owner: %v, want the file named", err)
	}
}

// A process that runs a trusted file through a symlink in a directory others
// can write is not protected, whatever the file is: the symlink could lead any
// process to it. The scan names the directory, the kernel gets no image, and
// root making the directory its own protects the process again.
func TestSymlinkInWritableDirectoryProtectsNothing(t *testing.T) {
	asTrustedOwner(t)
	dir := imageTestDir(t)
	real := writeFile(t, filepath.Join(dir, "rel", "agentd"), sleepBinary(t), 0o755)
	loose := filepath.Join(dir, "bin")
	mkdirExact(t, loose, 0o775)
	configured := filepath.Join(loose, "agentd")
	if err := os.Symlink(real, configured); err != nil {
		t.Fatal(err)
	}

	child := exec.Command(real, "30")
	child.Env = []string{"PATH=" + os.Getenv("PATH")} // no loader variable of the test environment
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	proc := selfProc(t)
	pid := child.Process.Pid
	if err := os.Symlink(filepath.Join("/proc", strconv.Itoa(pid)), filepath.Join(proc, strconv.Itoa(pid))); err != nil {
		t.Fatal(err)
	}

	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{configured}, ReplaceDefaults: true})
	s.refreshExeLeads(proc)
	got, untrusted, err := s.scanProtectedTGIDs(proc, os.Getpid())
	if err != nil || len(got) != 0 || !slices.Equal(untrusted, []string{loose}) {
		t.Fatalf("scan with the symlink in a writable directory: %+v, untrusted %v (%v), want no process and %s named", got, untrusted, err, loose)
	}
	if reason := s.protectedPIDReason(proc, uint32(pid), os.Getpid(), ""); reason != "" {
		t.Fatalf("the guard says %q for a process behind a symlink in a writable directory", reason)
	}
	if images := s.kernelImages(proc, got); len(images) != 0 {
		t.Fatalf("%d kernel images for a path in a writable directory, want none: %v", len(images), images)
	}

	mkdirExact(t, loose, 0o755)
	s.refreshExeLeads(proc)
	got, untrusted, err = s.scanProtectedTGIDs(proc, os.Getpid())
	if err != nil || len(got) != 1 || len(untrusted) != 0 {
		t.Fatalf("scan after the directory was fixed: %+v, untrusted %v (%v), want the child protected", got, untrusted, err)
	}
	if images := s.kernelImages(proc, got); len(images) != 1 {
		t.Fatalf("%d kernel images after the fix, want 1: %v", len(images), images)
	}
}

// A process that runs the file at a configured path is protected only when the
// file and every directory on the way are root's alone, not only the last one: an
// account that owns a directory further up can show the agent a root-only view of
// the path (a user namespace with a bind mount or an overlay of its own) and run
// any program there. The scan, the guard and the kernel images follow the walk,
// which names that directory.
func TestConfiguredPathBehindWritableAncestorProtectsNothing(t *testing.T) {
	asTrustedOwner(t)
	dir := imageTestDir(t)
	svc := filepath.Join(dir, "svc")
	mkdirExact(t, svc, 0o777)
	configured := writeFile(t, filepath.Join(svc, "bin", "app"), sleepBinary(t), 0o755)

	child := exec.Command(configured, "30")
	child.Env = []string{"PATH=" + os.Getenv("PATH")} // no loader variable of the test environment
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	proc := selfProc(t)
	pid := child.Process.Pid
	if err := os.Symlink(filepath.Join("/proc", strconv.Itoa(pid)), filepath.Join(proc, strconv.Itoa(pid))); err != nil {
		t.Fatal(err)
	}

	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{configured}, ReplaceDefaults: true})
	s.refreshExeLeads(proc)
	got, untrusted, err := s.scanProtectedTGIDs(proc, os.Getpid())
	if err != nil || len(got) != 0 || !slices.Equal(untrusted, []string{svc}) {
		t.Fatalf("scan with a writable directory above the last: %+v, untrusted %v (%v), want no process and %s named", got, untrusted, err, svc)
	}
	if reason := s.protectedPIDReason(proc, uint32(pid), os.Getpid(), ""); reason != "" {
		t.Fatalf("the guard says %q for a process behind a writable directory", reason)
	}
	if images := s.kernelImages(proc, got); len(images) != 0 {
		t.Fatalf("%d kernel images for a path behind a writable directory, want none: %v", len(images), images)
	}

	// A set that has not walked its paths verifies no process.
	fresh := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{configured}, ReplaceDefaults: true})
	mkdirExact(t, svc, 0o755)
	if got, _, err := fresh.scanProtectedTGIDs(proc, os.Getpid()); err != nil || len(got) != 0 {
		t.Fatalf("scan before the first walk: %+v (%v), want no process", got, err)
	}

	s.refreshExeLeads(proc)
	got, untrusted, err = s.scanProtectedTGIDs(proc, os.Getpid())
	if err != nil || len(got) != 1 || len(untrusted) != 0 {
		t.Fatalf("scan after the directory was fixed: %+v, untrusted %v (%v), want the child protected", got, untrusted, err)
	}
	if images := s.kernelImages(proc, got); len(images) != 1 {
		t.Fatalf("%d kernel images after the fix, want 1: %v", len(images), images)
	}
}

// configuredExeCheck takes a running image for the file at a configured path
// only when it is the file the walk reached, and a replaced image only when it is
// root's alone and on the filesystem of the directory the walk reached.
func TestConfiguredExeCheck(t *testing.T) {
	asTrustedOwner(t)
	dir := imageTestDir(t)
	file := writeFile(t, filepath.Join(dir, "agentd"), "x", 0o755)
	other := writeFile(t, filepath.Join(dir, "other"), "y", 0o755)
	loose := writeFile(t, filepath.Join(dir, "loose"), "z", 0o777)
	stat := func(path string) fs.FileInfo {
		t.Helper()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return fi
	}
	walked := &exeWalk{lead: file, file: stat(file), dir: stat(dir)}
	deleted := file + " (deleted)"
	type want struct {
		got  tri
		name string
	}
	for _, tc := range []struct {
		desc    string
		running string
		link    string
		walk    *exeWalk
		want    want
	}{
		{"the file the walk reached", file, file, walked, want{triYes, ""}},
		{"another file under the name of the path", other, file, walked, want{triNo, ""}},
		{"a walk that found no file", file, file, &exeWalk{untrusted: "/svc"}, want{triNo, "/svc"}},
		{"a path that was not walked", file, file, &exeWalk{}, want{triNo, ""}},
		{"a replaced image of root", other, deleted, walked, want{triYes, ""}},
		{"a replaced image that others can write", loose, deleted, walked, want{triNo, deleted}},
		{"a replaced image whose directory the walk refused", other, deleted, &exeWalk{dirStop: "/svc"}, want{triNo, "/svc"}},
		{"a replaced image of a path that was not walked", other, deleted, &exeWalk{}, want{triNo, ""}},
	} {
		if got, name := configuredExeCheck(stat(tc.running), tc.link, strings.HasSuffix(tc.link, " (deleted)"), tc.walk); got != tc.want.got || name != tc.want.name {
			t.Errorf("%s: %v %q, want %v %q", tc.desc, got, name, tc.want.got, tc.want.name)
		}
	}
	// An image on another filesystem than the directory is another file whatever its owner.
	if st, err := os.Stat("/proc/self/status"); err == nil && !sameDevice(st, walked.dir) {
		if got, name := configuredExeCheck(st, deleted, true, walked); got != triNo || name != "" {
			t.Errorf("a replaced image on another filesystem: %v %q, want no and silent", got, name)
		}
	}
}
