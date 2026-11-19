//go:build linux

package ebpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// /proc/<pid>/exe shows the path the kernel resolved, never the symlink of a
// configured path. A process that runs the file such a path leads to is
// protected, for the scan and for the guard at kill time, and stops being so
// when the symlink leads somewhere else.
func TestConfiguredPathThroughSymlinkProtectsTheProcess(t *testing.T) {
	asTrustedOwner(t)
	dir := imageTestDir(t)
	for _, release := range []string{"rel2", "rel3"} {
		writeFile(t, filepath.Join(dir, release, "agentd"), sleepBinary(t), 0o755)
	}
	current := filepath.Join(dir, "current")
	if err := os.Symlink("rel2", current); err != nil {
		t.Fatal(err)
	}
	configured := filepath.Join(current, "agentd")

	child := exec.Command(filepath.Join(dir, "rel2", "agentd"), "30")
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
	protected := func() string {
		t.Helper()
		return s.protectedPIDReason(proc, uint32(pid), os.Getpid(), "")
	}
	if got, _, err := s.scanProtectedTGIDs(proc, os.Getpid()); err != nil || len(got) != 0 || protected() != "" {
		t.Fatalf("before the symlink is resolved: scan %v (%v), guard %q", got, err, protected())
	}

	s.refreshExeLeads(proc)
	got, _, err := s.scanProtectedTGIDs(proc, os.Getpid())
	if err != nil || len(got) != 1 || got[0].tgid != uint32(pid) || !got[0].configured {
		t.Fatalf("scan after the symlink was resolved: %+v (%v), want the child as a configured path", got, err)
	}
	if want := "protected executable " + configured; protected() != want {
		t.Fatalf("guard says %q, want %q", protected(), want)
	}

	// The symlink now leads to the other release, and the child still runs the old one.
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("rel3", current); err != nil {
		t.Fatal(err)
	}
	s.refreshExeLeads(proc)
	if got, _, err := s.scanProtectedTGIDs(proc, os.Getpid()); err != nil || len(got) != 0 || protected() != "" {
		t.Fatalf("after the symlink moved: scan %v (%v), guard %q", got, err, protected())
	}
}
