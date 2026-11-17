//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// readSSHDPorts finds SSH daemon processes (comm and executable base name),
// collects their socket inodes and matches them against LISTEN sockets in
// the agent's network namespace (the host's, where XDP sees the traffic).
func readSSHDPorts() []uint16 {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	inodes := make(map[uint64]bool)
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		dir := filepath.Join("/proc", p.Name())
		comm, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil {
			continue
		}
		// comm is settable by any process; the executable name is not.
		exe, err := os.Readlink(filepath.Join(dir, "exe"))
		if err != nil || !isSSHDaemon(strings.TrimSpace(string(comm)), exe) {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil {
				continue
			}
			if inode, ok := socketInode(link); ok {
				inodes[inode] = true
			}
		}
	}
	if len(inodes) == 0 {
		return nil
	}
	var ports []uint16
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(table)
		if err != nil {
			continue
		}
		ports = append(ports, parseListenPorts(f, inodes)...)
		_ = f.Close()
	}
	return sortedUniquePorts(ports)
}
