//go:build !linux

package ebpf

// isKeyNotExist: there are no BPF maps here, so no error is one.
func isKeyNotExist(error) bool { return false }
