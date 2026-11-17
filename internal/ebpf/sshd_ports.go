package ebpf

import (
	"bufio"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SSH listener detection for the firewall lockout guard: ingress
// Deny All must keep an ALLOW rule for the port the SSH daemon (OpenSSH
// sshd or dropbear) actually listens on, not just 22. The ports also travel
// in HostInfo (ssh_ports) so the control plane applies the same guard before
// it stores a desired state. Not detected: socket-activated sshd before its
// first connection (the listener belongs to systemd), a daemon in another
// PID namespace — the guard then assumes 22 and says so (SSH_PORT_ASSUMED).

const sshdPortsTTL = time.Minute

var sshdPortsCache struct {
	mu    sync.Mutex
	at    time.Time
	ports []uint16
}

// DetectSSHDPorts returns the TCP ports the SSH daemon listens on (sorted,
// unique), cached for a minute. Nil when none was found or the platform
// cannot tell; the guard then falls back to 22.
func DetectSSHDPorts() []uint16 {
	sshdPortsCache.mu.Lock()
	defer sshdPortsCache.mu.Unlock()
	if !sshdPortsCache.at.IsZero() && time.Since(sshdPortsCache.at) < sshdPortsTTL {
		return slices.Clone(sshdPortsCache.ports)
	}
	sshdPortsCache.ports = readSSHDPorts()
	sshdPortsCache.at = time.Now()
	return slices.Clone(sshdPortsCache.ports)
}

// sshDaemons are the process names (comm and executable base-name prefix)
// whose listening sockets count as SSH.
var sshDaemons = []string{"sshd", "dropbear"}

func isSSHDaemon(comm, exe string) bool {
	base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	for _, name := range sshDaemons {
		if comm == name && strings.HasPrefix(base, name) {
			return true
		}
	}
	return false
}

// parseListenPorts reads /proc/net/tcp or /proc/net/tcp6 content and returns
// the local ports of LISTEN sockets whose inode is in inodes.
func parseListenPorts(r io.Reader, inodes map[uint64]bool) []uint16 {
	var ports []uint16
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first { // header line
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		// sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
		if len(f) < 10 || f[3] != "0A" { // 0A = TCP_LISTEN
			continue
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil || !inodes[inode] {
			continue
		}
		_, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || port == 0 {
			continue
		}
		ports = append(ports, uint16(port))
	}
	return ports
}

// socketInode parses a /proc/<pid>/fd link target "socket:[12345]".
func socketInode(link string) (uint64, bool) {
	rest, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0, false
	}
	num, ok := strings.CutSuffix(rest, "]")
	if !ok {
		return 0, false
	}
	inode, err := strconv.ParseUint(num, 10, 64)
	return inode, err == nil
}

// sortedUniquePorts sorts and de-duplicates ports; nil for an empty input.
func sortedUniquePorts(ports []uint16) []uint16 {
	if len(ports) == 0 {
		return nil
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}
