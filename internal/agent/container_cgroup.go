package agent

import (
	"io/fs"
	"os"
	"path"
	"strings"
	"time"
)

// Container attribution by cgroup ancestry.
//
// A trace event carries the kernel cgroup ID of the process (the inode of its
// cgroup2 directory). The runtime creates one cgroup per container, named
// after the full container ID (docker-<id>.scope, /docker/<id>,
// libpod-<id>.scope, cri-containerd-<id>.scope, crio-<id>.scope); every
// process in that directory or below it belongs to the container, including
// sub-cgroups made inside it (systemd in the container moving itself to
// init.scope, Docker-in-Docker, a privileged container managing its own
// cgroups). Mapping only the init process's current cgroup reported all of
// those as host processes (is_container=false).

const (
	defaultCgroupFS = "/sys/fs/cgroup"
	// cgroupWalkBudget caps the directories walked below one container root.
	cgroupWalkBudget = 4096
	// defaultMinRescanInterval rate-limits the walk an unknown cgroup ID
	// triggers (a sub-cgroup created since the last refresh).
	defaultMinRescanInterval = 2 * time.Second
	// maxUnmatchedCgroups bounds the cache of IDs known to be outside every
	// container; it is cleared when full and on every refresh.
	maxUnmatchedCgroups = 8192
	// minAncestryIDLen: a component is the container's own cgroup only when
	// it names the full ID; a short ID could collide with another name.
	minAncestryIDLen = 32
)

// parseCgroupV2Path returns the unified-hierarchy path ("0::<path>") from the
// content of /proc/<pid>/cgroup, or "" when there is none or the cgroup was
// removed.
func parseCgroupV2Path(content string) string {
	for _, line := range strings.Split(content, "\n") {
		rest, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		if !strings.HasPrefix(rest, "/") || strings.HasSuffix(rest, " (deleted)") {
			return ""
		}
		return rest
	}
	return ""
}

// containerCgroupRoot returns the cgroup the runtime created for the
// container: the shallowest component of the init process's cgroup path
// that contains the full container ID. Without such a component there is no
// ancestry root (""): the init process's own cgroup ID still maps, but
// nothing below or beside it — otherwise a privileged container that moved
// its init into a broad host cgroup would claim every host process there.
func containerCgroupRoot(initPath, containerID string) string {
	if initPath == "" || initPath == "/" || !strings.HasPrefix(initPath, "/") ||
		path.Clean(initPath) != initPath || len(containerID) < minAncestryIDLen {
		return ""
	}
	parts := strings.Split(initPath[1:], "/")
	for i, part := range parts {
		if strings.Contains(part, containerID) {
			return "/" + strings.Join(parts[:i+1], "/")
		}
	}
	return ""
}

// containerCgroupIdentity returns what to map for a container whose init
// process sits in cgroup initPath with kernel cgroup ID initID: the init ID
// and the ancestry root, or nothing at all when the path names no container
// ID. A privileged container that moved its init into a host cgroup
// (sshd.service) would otherwise label that service's processes as the
// container through the init ID alone.
func containerCgroupIdentity(initPath, containerID string, initID uint64) ([]uint64, string) {
	root := containerCgroupRoot(initPath, containerID)
	if root == "" || initID == 0 {
		return nil, root
	}
	return []uint64{initID}, root
}

// containerForCgroupPath returns the container whose root is the deepest
// ancestor-or-self of cgroupPath, compared component by component (never as
// a string prefix: docker-a.scope-evil is not below docker-a.scope).
func containerForCgroupPath(cgroupPath string, roots map[string]*ContainerInfo) *ContainerInfo {
	if !strings.HasPrefix(cgroupPath, "/") {
		return nil
	}
	for cur := cgroupPath; cur != "/"; cur = path.Dir(cur) {
		if info := roots[cur]; info != nil {
			return info
		}
	}
	return nil
}

// walkCgroupSubtree maps the inode (= kernel cgroup ID) of every directory at
// or below rel, a clean absolute cgroup path, to its path. Symlinks and files
// are skipped; at most budget directories are returned (truncated reports
// the cut). The cgroup root itself is never walked.
func walkCgroupSubtree(fsRoot, rel string, budget int) (map[uint64]string, bool) {
	out := make(map[uint64]string)
	if rel == "/" || !strings.HasPrefix(rel, "/") || path.Clean(rel) != rel {
		return out, false
	}
	queue := []string{rel}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		fi, err := os.Lstat(fsRoot + cur)
		if err != nil || !fi.IsDir() {
			continue
		}
		ino, ok := fileInode(fi)
		if !ok {
			continue
		}
		if len(out) >= budget {
			return out, true
		}
		out[ino] = cur
		entries, err := os.ReadDir(fsRoot + cur)
		if err != nil {
			continue
		}
		for _, de := range entries {
			if de.Type()&fs.ModeType == fs.ModeDir {
				queue = append(queue, cur+"/"+de.Name())
			}
		}
	}
	return out, false
}

// walkRoots resolves every cgroup directory below the known container roots
// to the container owning it (deepest root wins for nested containers).
func (e *ContainerEnricher) walkRoots(roots map[string]*ContainerInfo) map[uint64]*ContainerInfo {
	out := make(map[uint64]*ContainerInfo)
	for root := range roots {
		found, _ := walkCgroupSubtree(e.cgroupFS, root, cgroupWalkBudget)
		for ino, rel := range found {
			if info := containerForCgroupPath(rel, roots); info != nil {
				out[ino] = info
			}
		}
	}
	return out
}

// rescanFor walks the container subtrees again for a cgroup ID no map knows
// (a sub-cgroup created since the last refresh), at most once per
// minRescanInterval. An ID still unknown afterwards is outside every
// container and cached as such, so host events do not trigger walks.
func (e *ContainerEnricher) rescanFor(cgroupID uint64) *ContainerInfo {
	e.rescanMu.Lock()
	defer e.rescanMu.Unlock()

	e.mu.RLock()
	info := e.byCgroupID[cgroupID]
	_, unmatched := e.unmatched[cgroupID]
	roots := make(map[string]*ContainerInfo, len(e.byRoot))
	for k, v := range e.byRoot {
		roots[k] = v
	}
	e.mu.RUnlock()
	if info != nil || unmatched || len(roots) == 0 {
		return info
	}
	if !e.lastRescan.IsZero() && time.Since(e.lastRescan) < e.minRescanInterval {
		return nil
	}
	e.lastRescan = time.Now()
	if e.walkHook != nil {
		e.walkHook()
	}
	found := e.walkRoots(roots)

	e.mu.Lock()
	defer e.mu.Unlock()
	for id, owner := range found {
		// Only for containers still running; never override an init ID.
		if e.byRoot[owner.CgroupRoot] != owner {
			continue
		}
		if _, exists := e.byCgroupID[id]; !exists {
			e.byCgroupID[id] = owner
		}
	}
	info = e.byCgroupID[cgroupID]
	if info == nil {
		if len(e.unmatched) >= maxUnmatchedCgroups {
			clear(e.unmatched)
		}
		e.unmatched[cgroupID] = struct{}{}
	}
	return info
}
