//go:build !unix

package ebpf

import "io/fs"

// trustedUID is the owner a trusted file must have; see trace_protect_owner_unix.go.
var trustedUID uint32

func trustedOwnerMode(uid uint32, perm uint32) bool {
	return uid == trustedUID && perm&0o022 == 0
}

// trustedFile: without a Unix stat the owner cannot be read, so no file is
// trusted.
func trustedFile(fs.FileInfo) bool { return false }
