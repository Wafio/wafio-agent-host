//go:build linux

package agent

import (
	"fmt"
	"os"
	"syscall"
)

// readInitCgroup reads the unified-hierarchy (cgroup2) path of pid from
// /proc/<pid>/cgroup ("0::<path>") and resolves it to the kernel cgroup_id
// eBPF events carry: the inode of that cgroupfs directory. One read, so the
// ID and the path always describe the same cgroup. v1 hierarchies are not
// consulted: their inodes never equal bpf_get_current_cgroup_id().
func readInitCgroup(pid int) (string, uint64) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", 0
	}
	path := parseCgroupV2Path(string(data))
	if path == "" {
		return "", 0
	}
	return path, cgroupIDFromPath(cgroup2FS() + path)
}

// cgroupIDFromPath returns the inode number of a cgroupfs directory, which is
// the same value the kernel uses as cgroup_id in eBPF events.
func cgroupIDFromPath(path string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return st.Ino
}

// cgroup2FS returns where the cgroup2 hierarchy eBPF cgroup IDs refer to is
// mounted: /sys/fs/cgroup on a unified host, /sys/fs/cgroup/unified on a
// hybrid (v1 + v2) one.
func cgroup2FS() string {
	if _, err := os.Stat(defaultCgroupFS + "/cgroup.controllers"); err == nil {
		return defaultCgroupFS
	}
	if _, err := os.Stat(defaultCgroupFS + "/unified/cgroup.controllers"); err == nil {
		return defaultCgroupFS + "/unified"
	}
	return defaultCgroupFS
}
