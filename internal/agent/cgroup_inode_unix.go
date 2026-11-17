//go:build unix

package agent

import (
	"io/fs"
	"syscall"
)

// fileInode returns the inode number of fi; on cgroupfs it is the kernel
// cgroup ID eBPF events carry.
func fileInode(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true // Ino is not uint64 on every Unix
}
