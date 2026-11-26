//go:build !unix

package ebpf

import "io/fs"

// trustedFile: without a Unix stat the owner cannot be read, so no file is
// trusted.
func trustedFile(fs.FileInfo) bool { return false }

// sameDevice: without a Unix stat no two files are known to share a device.
func sameDevice(fs.FileInfo, fs.FileInfo) bool { return false }
