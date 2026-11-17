//go:build linux

package ebpf

import (
	"errors"

	cebpf "github.com/cilium/ebpf"
)

// isKeyNotExist reports a map delete or lookup of an absent key.
func isKeyNotExist(err error) bool { return errors.Is(err, cebpf.ErrKeyNotExist) }
