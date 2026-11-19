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
// when the symlink leads somewhere else. The symlink may be a directory of the
// path or the file itself.
func TestConfiguredPathThroughSymlinkProtectsTheProcess(t *testing.T) {
	cases := []struct {
		name string
		// path is the configured path; point makes it lead to the release rel.
		path  func(dir string) string
		point func(t *testing.T, dir, rel string)
	}{
		{
			name: "directory",
			path: func(dir string) string { return filepath.Join(dir, "current", "agentd") },
			point: func(t *testing.T, dir, rel string) {
				relink(t, rel, filepath.Join(dir, "current"))
			},
		},
		{
			name: "file",
			path: func(dir string) string { return filepath.Join(dir, "bin", "agentd") },
			point: func(t *testing.T, dir, rel string) {
				if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
					t.Fatal(err)
				}
				relink(t, filepath.Join(dir, rel, "agentd"), filepath.Join(dir, "bin", "agentd"))
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			asTrustedOwner(t)
			dir := imageTestDir(t)
			for _, release := range []string{"rel2", "rel3"} {
				writeFile(t, filepath.Join(dir, release, "agentd"), sleepBinary(t), 0o755)
			}
			c.point(t, dir, "rel2")
			configured := c.path(dir)

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
			c.point(t, dir, "rel3")
			s.refreshExeLeads(proc)
			if got, _, err := s.scanProtectedTGIDs(proc, os.Getpid()); err != nil || len(got) != 0 || protected() != "" {
				t.Fatalf("after the symlink moved: scan %v (%v), guard %q", got, err, protected())
			}
		})
	}
}

// relink makes link a symlink to target, replacing a symlink that is there.
func relink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
