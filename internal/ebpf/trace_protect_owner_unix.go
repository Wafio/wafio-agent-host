//go:build unix

package ebpf

import (
	"io/fs"
	"syscall"
)

// trustedUID is the owner a trusted file and its directory must have. It is 0;
// a test that builds its files as an unprivileged user sets its own UID.
var trustedUID uint32

// trustedOwnerMode reports whether a file with this owner and permission bits
// could only have been written by root: owned by trustedUID and writable by
// neither its group nor others. Anyone else who can write the file, or its
// directory, can replace a trusted binary with one of their own.
func trustedOwnerMode(uid uint32, perm uint32) bool {
	return uid == trustedUID && perm&0o022 == 0
}

// trustedFile applies trustedOwnerMode to a stat result. Where the owner cannot
// be read the file is not trusted.
func trustedFile(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && trustedOwnerMode(st.Uid, uint32(fi.Mode().Perm()))
}
