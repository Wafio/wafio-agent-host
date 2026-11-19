//go:build !unix

package ebpf

import "io/fs"

// trustedFile: without a Unix stat the owner cannot be read, so no file is
// trusted.
func trustedFile(fs.FileInfo) bool { return false }
