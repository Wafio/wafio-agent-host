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

// sameDevice reports whether two files are on the same device (st_dev). Where
// the device cannot be read they are not.
func sameDevice(a, b fs.FileInfo) bool {
	sa, okA := a.Sys().(*syscall.Stat_t)
	sb, okB := b.Sys().(*syscall.Stat_t)
	return okA && okB && uint64(sa.Dev) == uint64(sb.Dev)
}
