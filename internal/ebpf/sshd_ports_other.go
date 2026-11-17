//go:build !linux

package ebpf

// readSSHDPorts: listener detection needs /proc; the guard falls back to 22.
func readSSHDPorts() []uint16 { return nil }
