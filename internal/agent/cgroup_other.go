//go:build !linux

package agent

// readInitCgroup returns nothing on non-Linux platforms. Container enrichment
// requires Linux cgroupfs and is a no-op on macOS/Windows.
func readInitCgroup(_ int) (string, uint64) { return "", 0 }

// cgroup2FS returns the default mount point; unused off Linux.
func cgroup2FS() string { return defaultCgroupFS }
