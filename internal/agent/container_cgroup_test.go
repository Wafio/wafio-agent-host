//go:build unix

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

const testContainerID = "4f1c2a9b8e7d6c5b4a3928171615141312111009080706050403020100ffeedd"

// The container a process belongs to is decided by the cgroup its
// runtime created, not by the cgroup its init process happens to sit in.
func TestContainerCgroupRoot(t *testing.T) {
	id := testContainerID
	cases := []struct {
		name     string
		initPath string
		id       string
		want     string
	}{
		{"docker systemd driver", "/system.slice/docker-" + id + ".scope", id, "/system.slice/docker-" + id + ".scope"},
		{"systemd in the container moved init", "/system.slice/docker-" + id + ".scope/init.scope", id, "/system.slice/docker-" + id + ".scope"},
		{"docker cgroupfs driver", "/docker/" + id, id, "/docker/" + id},
		{"dind: outer init in a sub-cgroup", "/docker/" + id + "/docker/aaaa", id, "/docker/" + id},
		{"podman", "/machine.slice/libpod-" + id + ".scope/container", id, "/machine.slice/libpod-" + id + ".scope"},
		{"cri-containerd", "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-" + id + ".scope", id,
			"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-" + id + ".scope"},
		// Without a runtime-created directory naming the full ID there is no
		// ancestry: a privileged container could otherwise park its init in a
		// broad host cgroup and claim every host process below it.
		{"no id in the path: no ancestry root", "/custom/runtime/ctr7", id, ""},
		{"init moved to a host slice: no ancestry root", "/system.slice", id, ""},
		{"short id never matches a component", "/system.slice/docker-" + id[:12] + ".scope/sub", id[:12], ""},
		{"root cgroup is never a container root", "/", id, ""},
		{"empty path", "", id, ""},
		{"relative garbage", "system.slice/x", id, ""},
	}
	for _, tc := range cases {
		if got := containerCgroupRoot(tc.initPath, tc.id); got != tc.want {
			t.Errorf("%s: containerCgroupRoot(%q) = %q, want %q", tc.name, tc.initPath, got, tc.want)
		}
	}
}

func TestContainerForCgroupPath(t *testing.T) {
	outer := &ContainerInfo{ContainerID: "outer"}
	inner := &ContainerInfo{ContainerID: "inner"}
	roots := map[string]*ContainerInfo{
		"/system.slice/docker-a.scope":                outer,
		"/system.slice/docker-a.scope/nested/ctr-b":   inner,
		"/kubepods.slice/pod1/cri-containerd-c.scope": {ContainerID: "c"},
	}
	cases := []struct {
		path string
		want *ContainerInfo
	}{
		{"/system.slice/docker-a.scope", outer},
		{"/system.slice/docker-a.scope/init.scope", outer},
		{"/system.slice/docker-a.scope/system.slice/cron.service", outer},
		{"/system.slice/docker-a.scope/nested/ctr-b/sub", inner}, // deepest known root wins
		{"/system.slice/docker-a.scope-evil", nil},               // component-wise, never a string prefix
		{"/system.slice/docker-a.scopex/init.scope", nil},
		{"/system.slice", nil},
		{"/", nil},
		{"", nil},
		{"/user.slice/user-1000.slice/session-1.scope", nil},
	}
	for _, tc := range cases {
		if got := containerForCgroupPath(tc.path, roots); got != tc.want {
			t.Errorf("containerForCgroupPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// A privileged container can move its init into a host cgroup. The init's
// cgroup ID then names that host cgroup: it must not be mapped either, or
// host sshd would be labelled as the container.
func TestContainerCgroupIdentityNeedsTheContainerID(t *testing.T) {
	scope := "/system.slice/docker-" + testContainerID + ".scope"
	cases := []struct {
		name     string
		initPath string
		initID   uint64
		wantIDs  []uint64
		wantRoot string
	}{
		{"runtime cgroup", scope, 11, []uint64{11}, scope},
		{"init in a sub-cgroup", scope + "/init.scope", 12, []uint64{12}, scope},
		{"init moved into host sshd", "/system.slice/sshd.service", 13, nil, ""},
		{"init path unreadable", "", 0, nil, ""},
		{"path names the container, stat failed", scope, 0, nil, scope},
	}
	for _, tc := range cases {
		ids, root := containerCgroupIdentity(tc.initPath, testContainerID, tc.initID)
		if root != tc.wantRoot || len(ids) != len(tc.wantIDs) || (len(ids) == 1 && ids[0] != tc.wantIDs[0]) {
			t.Errorf("%s: got (%v, %q), want (%v, %q)", tc.name, ids, root, tc.wantIDs, tc.wantRoot)
		}
	}
}

func TestParseCgroupV2Path(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"unified", "0::/system.slice/docker-x.scope\n", "/system.slice/docker-x.scope"},
		{"hybrid", "12:memory:/docker/x\n11:cpu,cpuacct:/docker/x\n0::/docker/x\n", "/docker/x"},
		{"v1 only", "12:memory:/docker/x\n", ""},
		{"deleted cgroup", "0::/system.slice/docker-x.scope (deleted)\n", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		if got := parseCgroupV2Path(tc.content); got != tc.want {
			t.Errorf("%s: parseCgroupV2Path = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func dirIno(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no inode numbers on this platform")
	}
	return st.Ino
}

func mkdirs(t *testing.T, root string, rels ...string) {
	t.Helper()
	for _, rel := range rels {
		if err := os.MkdirAll(filepath.Join(root, rel), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWalkCgroupSubtree(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "sys/docker-a.scope/init.scope", "sys/docker-a.scope/system.slice/cron.service", "sys/other.service")
	if err := os.WriteFile(filepath.Join(root, "sys/docker-a.scope/cgroup.procs"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink out of the subtree is not followed (cgroupfs has none; a
	// test tree could).
	if err := os.Symlink(filepath.Join(root, "sys/other.service"), filepath.Join(root, "sys/docker-a.scope/escape")); err != nil {
		t.Fatal(err)
	}

	got, truncated := walkCgroupSubtree(root, "/sys/docker-a.scope", 100)
	if truncated {
		t.Fatal("walk reported truncation within budget")
	}
	want := map[uint64]string{
		dirIno(t, filepath.Join(root, "sys/docker-a.scope")):                           "/sys/docker-a.scope",
		dirIno(t, filepath.Join(root, "sys/docker-a.scope/init.scope")):                "/sys/docker-a.scope/init.scope",
		dirIno(t, filepath.Join(root, "sys/docker-a.scope/system.slice")):              "/sys/docker-a.scope/system.slice",
		dirIno(t, filepath.Join(root, "sys/docker-a.scope/system.slice/cron.service")): "/sys/docker-a.scope/system.slice/cron.service",
	}
	if len(got) != len(want) {
		t.Fatalf("walk = %v, want %v", got, want)
	}
	for ino, rel := range want {
		if got[ino] != rel {
			t.Errorf("inode %d = %q, want %q", ino, got[ino], rel)
		}
	}

	if got, truncated := walkCgroupSubtree(root, "/sys/docker-a.scope", 2); !truncated || len(got) != 2 {
		t.Errorf("budget 2: %d entries, truncated=%v", len(got), truncated)
	}
	if got, _ := walkCgroupSubtree(root, "/missing", 100); len(got) != 0 {
		t.Errorf("missing root walked: %v", got)
	}
	if got, _ := walkCgroupSubtree(root, "/", 100); len(got) != 0 {
		t.Errorf("the cgroup root itself must never be walked as a container: %v", got)
	}
}

// fakeCgroupEnricher builds an enricher over a temp "cgroupfs" with one
// running container whose init sits in init.scope below its runtime cgroup.
func fakeCgroupEnricher(t *testing.T) (*ContainerEnricher, string, *ContainerInfo) {
	t.Helper()
	fsRoot := t.TempDir()
	scope := "/system.slice/docker-" + testContainerID + ".scope"
	mkdirs(t, fsRoot, scope+"/init.scope", scope+"/system.slice/nginx.service", "/system.slice/sshd.service")
	e := NewContainerEnricher()
	e.cgroupFS = fsRoot
	info := &ContainerInfo{
		ContainerID: testContainerID,
		CgroupIDs:   []uint64{dirIno(t, filepath.Join(fsRoot, scope, "init.scope"))},
		CgroupRoot:  scope,
	}
	e.applySnapshot([]*ContainerInfo{info})
	return e, fsRoot, info
}

// Before the fix only the init process's own cgroup was mapped, so a
// process in a sibling sub-cgroup (systemd inside the container, DinD, a
// privileged container managing its own cgroups) was reported as a host
// process with is_container=false.
func TestEnrichMatchesSubCgroupsByAncestry(t *testing.T) {
	e, fsRoot, info := fakeCgroupEnricher(t)
	scope := info.CgroupRoot

	if got := e.Enrich(info.CgroupIDs[0]); got != info {
		t.Fatalf("init cgroup not mapped: %v", got)
	}
	sibling := dirIno(t, filepath.Join(fsRoot, scope, "system.slice/nginx.service"))
	if got := e.Enrich(sibling); got != info {
		t.Fatalf("sibling sub-cgroup of the container not mapped: %v", got)
	}
	host := dirIno(t, filepath.Join(fsRoot, "/system.slice/sshd.service"))
	if got := e.Enrich(host); got != nil {
		t.Fatalf("host service mapped to a container: %v", got)
	}
}

// A sub-cgroup created after the last refresh (DinD starting an inner
// container) is found by a rescan on the first miss; a host cgroup is
// remembered as unmatched so host events do not rescan every time.
func TestEnrichRescansOnMiss(t *testing.T) {
	e, fsRoot, info := fakeCgroupEnricher(t)
	var walks atomic.Int32
	e.walkHook = func() { walks.Add(1) }
	e.minRescanInterval = 0

	mkdirs(t, fsRoot, info.CgroupRoot+"/docker/inner-ctr")
	inner := dirIno(t, filepath.Join(fsRoot, info.CgroupRoot, "docker/inner-ctr"))
	if got := e.Enrich(inner); got != info {
		t.Fatalf("new nested cgroup not found by rescan: %v", got)
	}
	before := walks.Load()
	if before == 0 {
		t.Fatal("miss did not rescan")
	}
	if got := e.Enrich(inner); got != info || walks.Load() != before {
		t.Fatalf("hit rescanned again (walks %d → %d)", before, walks.Load())
	}

	host := dirIno(t, filepath.Join(fsRoot, "/system.slice/sshd.service"))
	if got := e.Enrich(host); got != nil {
		t.Fatalf("host cgroup mapped: %v", got)
	}
	afterHost := walks.Load()
	for range 5 {
		e.Enrich(host)
	}
	if walks.Load() != afterHost {
		t.Fatalf("unmatched host cgroup rescanned %d more times", walks.Load()-afterHost)
	}

	// Rescans are rate limited: a burst of unknown IDs costs one walk.
	e.minRescanInterval = 1 << 62
	mkdirs(t, fsRoot, info.CgroupRoot+"/late")
	late := dirIno(t, filepath.Join(fsRoot, info.CgroupRoot, "late"))
	pre := walks.Load()
	if got := e.Enrich(late); got != nil {
		t.Fatalf("rate-limited miss should not walk: %v", got)
	}
	if walks.Load() != pre {
		t.Fatal("rescan ignored the rate limit")
	}
}

// Evicting a container drops every cgroup ID mapped to it, including the
// sub-cgroups found by the walk.
func TestEvictDropsSubCgroups(t *testing.T) {
	e, fsRoot, info := fakeCgroupEnricher(t)
	sibling := dirIno(t, filepath.Join(fsRoot, info.CgroupRoot, "system.slice/nginx.service"))
	if e.Enrich(sibling) != info {
		t.Fatal("setup: sibling not mapped")
	}
	e.evictContainer(testContainerID)
	e.mu.RLock()
	defer e.mu.RUnlock()
	for id, c := range e.byCgroupID {
		if c == info {
			t.Fatalf("cgroup %d still maps to the evicted container", id)
		}
	}
}

// The walk never follows the subtree outside the cgroup mount and never
// descends into regular files.
func TestWalkCgroupSubtreeStaysInside(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "a/b")
	got, _ := walkCgroupSubtree(root, "/a/../..", 100)
	for _, rel := range got {
		if !strings.HasPrefix(rel, "/") || strings.Contains(rel, "..") {
			t.Fatalf("walk escaped: %q", rel)
		}
	}
	if len(got) != 0 {
		t.Fatalf("a path with .. was walked: %v", got)
	}
}
