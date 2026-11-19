//go:build unix

package ebpf

import (
	"io/fs"
	"syscall"
)

// trustedFile applies trustedOwnerMode to a stat result. Where the owner cannot
// be read the file is not trusted.
func trustedFile(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && trustedOwnerMode(st.Uid, uint32(fi.Mode().Perm()))
}
