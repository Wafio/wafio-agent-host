//go:build !unix

package agent

import "io/fs"

// fileInode is unavailable without Unix stat; container ancestry is Linux-only.
func fileInode(fs.FileInfo) (uint64, bool) { return 0, false }
