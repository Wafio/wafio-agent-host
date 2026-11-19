//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// fsIocGetVersion is FS_IOC_GETVERSION, _IOR('v', 1, long): the request of
// FS_IOC_GETFLAGS, _IOR('f', 1, long), with 'f' (0x66) replaced by 'v' (0x76).
// x/sys/unix has no constant for it. ext4, XFS and btrfs answer it with
// i_generation; a filesystem that does not (tmpfs on older kernels, procfs)
// returns ENOTTY.
const fsIocGetVersion = unix.FS_IOC_GETFLAGS + 0x1000

// imageIdentity reads the identity the kernel has for the file at statPath: the
// device of its superblock, its inode number and its inode generation (the key
// of trace_protected_images). mountinfoPath is the mountinfo of the mount
// namespace the file is seen in: statx reports the mount ID of the file, and
// field 3 of that mount's line is sb->s_dev. stat's st_dev would be wrong on
// btrfs, where it is the subvolume's anonymous device.
//
// Any failure, a file that is not a regular file, a kernel without
// STATX_MNT_ID (before 5.8) and a filesystem that does not report a
// generation included, returns false: the file is not trusted. The file is
// opened once and every read goes through that descriptor, so the identity
// cannot mix two files. A variable so tests can substitute it.
var imageIdentity = func(statPath, mountinfoPath string) (protectedImageKey, bool) {
	// O_NONBLOCK: a FIFO put at a candidate path must not hang the refresh.
	fd, err := unix.Open(statPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return protectedImageKey{}, false
	}
	defer func() { _ = unix.Close(fd) }() // read-only descriptor
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_MNT_ID, &st); err != nil {
		return protectedImageKey{}, false
	}
	gen, err := unix.IoctlGetUint32(fd, fsIocGetVersion)
	if err != nil {
		return protectedImageKey{}, false
	}
	mountinfo, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return protectedImageKey{}, false
	}
	return imageKeyOf(&st, gen, mountDevices(string(mountinfo)))
}

// imageKeyOf builds the key from a statx result, the generation and the mount
// table, or reports that the file cannot be identified.
func imageKeyOf(st *unix.Statx_t, gen uint32, devs map[uint64]uint32) (protectedImageKey, bool) {
	if st.Mask&unix.STATX_INO == 0 || st.Mask&unix.STATX_MNT_ID == 0 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return protectedImageKey{}, false
	}
	dev, ok := devs[st.Mnt_id]
	if !ok {
		return protectedImageKey{}, false
	}
	return protectedImageKey{Ino: st.Ino, Dev: dev, Gen: gen}, true
}

// kernelImages is the content of trace_protected_images: the files the kernel
// may keep a protected entry for at exec. It merges three sources, and an
// image that appears in several keeps the lowest flag (a configured path
// needs no root):
//   - the files at the trusted paths (imagePaths), seen from PID 1's root;
//   - the images of the processes verified by the last scan, which may live in
//     their own mount namespace or run a binary that was replaced on disk (the
//     inode stays referenced while the process runs, so it cannot be reused);
//   - the files PID 1 holds open at a trusted path: systemd 255 and later keeps
//     systemd-executor open and runs it as /proc/self/fd/<n>, also after a
//     package upgrade replaced it and before daemon-reexec.
//
// A file that cannot be identified is left out, and an exec of it drops the
// entry.
func (s *ProtectedProcessSet) kernelImages(procRoot string, verified []protectedTGID) map[protectedImageKey]uint8 {
	out := make(map[protectedImageKey]uint8)
	if s == nil {
		return out
	}
	add := func(statPath, mountinfoPath string, flags uint8) {
		key, ok := imageIdentity(statPath, mountinfoPath)
		if !ok {
			return
		}
		if prev, seen := out[key]; !seen || flags < prev {
			out[key] = flags
		}
	}
	paths := s.imagePaths()
	hostMounts := filepath.Join(procRoot, "1", "mountinfo")
	for p, flags := range paths {
		add(filepath.Join(procRoot, "1", "root", p), hostMounts, flags)
	}
	for _, p := range verified {
		dir := procDir(procRoot, p.tgid)
		flags := protectedImageRootOnly
		if p.configured {
			flags = 0
		}
		add(filepath.Join(dir, "exe"), filepath.Join(dir, "mountinfo"), flags)
	}
	fdDir := filepath.Join(procRoot, "1", "fd")
	if fds, err := os.ReadDir(fdDir); err == nil {
		for _, fd := range fds {
			link := filepath.Join(fdDir, fd.Name())
			target, err := os.Readlink(link)
			if err != nil {
				continue
			}
			if flags, ok := paths[strings.TrimSuffix(target, " (deleted)")]; ok {
				add(link, hostMounts, flags)
			}
		}
	}
	return out
}
