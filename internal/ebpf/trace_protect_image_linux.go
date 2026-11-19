//go:build linux

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// fsIocGetVersion is FS_IOC_GETVERSION, _IOR('v', 1, long): the request of
// FS_IOC_GETFLAGS, _IOR('f', 1, long), with 'f' (0x66) replaced by 'v' (0x76).
// x/sys/unix has no constant for it. ext4, XFS and btrfs answer it with
// i_generation; a filesystem that does not (tmpfs on older kernels, overlayfs,
// squashfs, erofs, procfs) returns ENOTTY.
const fsIocGetVersion = unix.FS_IOC_GETFLAGS + 0x1000

// imageStatxMask is what the identity and the trust decision read: file type
// and permission bits, owner, inode number and the mount the file was found
// through (STATX_MNT_ID, Linux 5.8).
const imageStatxMask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_INO | unix.STATX_MNT_ID

// noOpenat2 makes the path walk take its fallback, which refuses every
// symlink. Tests set it; in production the fallback runs only where openat2 is
// missing (before Linux 5.6) or refused (a seccomp filter).
var noOpenat2 bool

// readMounts parses a mountinfo file. The mount IDs in it are those of the
// mount namespace the file belongs to, the ones statx reports for a file found
// in that namespace.
func readMounts(path string) (map[uint64]mountEntry, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return mountTable(string(data)), true
}

// fileImage reads the identity the kernel has for an open file: the device of
// its superblock, its inode number and its inode generation (the key of
// trace_protected_images), from the mount table of the namespace the file was
// found in. statx reports the mount ID of the file, and field 3 of that mount's
// line is sb->s_dev; stat's st_dev would be wrong on btrfs, where it is the
// subvolume's anonymous device.
//
// Any failure returns false, and the file is not trusted: a file that is not a
// regular file, a kernel without STATX_MNT_ID (before 5.8), an owner other than
// root, a file that its group or others can write, and a filesystem that does
// not report a generation unless its superblock is read-only (imageKeyOf). The
// descriptor is the only way the file is read, so the identity cannot mix two
// files.
func fileImage(fd int, mounts map[uint64]mountEntry) (protectedImageKey, bool) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, imageStatxMask, &st); err != nil {
		return protectedImageKey{}, false
	}
	gen, err := unix.IoctlGetUint32(fd, fsIocGetVersion)
	noGeneration := errors.Is(err, unix.ENOTTY)
	if err != nil && !noGeneration {
		return protectedImageKey{}, false
	}
	return imageKeyOf(&st, gen, noGeneration, mounts)
}

// imageKeyOf builds the key from a statx result, the generation and the mount
// table, or reports that the file cannot be trusted.
//
// A filesystem that answers FS_IOC_GETVERSION with ENOTTY gives no generation.
// Its files are accepted with generation 0 only when the superblock is
// read-only (squashfs, erofs and a composefs or overlay root mounted that way),
// where no file can be replaced under the key. The kernel reads
// inode->i_generation for the same file, and 0 is what a filesystem that never
// sets it leaves in the inode. A filesystem that sets one it does not expose
// has another value in the kernel, the key never matches and the exec drops the
// entry: the failure is toward not trusting.
func imageKeyOf(st *unix.Statx_t, gen uint32, noGeneration bool, mounts map[uint64]mountEntry) (protectedImageKey, bool) {
	if st.Mask&imageStatxMask != imageStatxMask || st.Mode&unix.S_IFMT != unix.S_IFREG ||
		!trustedOwnerMode(st.Uid, uint32(st.Mode)&0o7777) {
		return protectedImageKey{}, false
	}
	mount, ok := mounts[st.Mnt_id]
	if !ok {
		return protectedImageKey{}, false
	}
	if noGeneration {
		if !mount.readOnly {
			return protectedImageKey{}, false
		}
		gen = 0
	}
	return protectedImageKey{Ino: st.Ino, Dev: mount.dev, Gen: gen}, true
}

// openDirIn opens the directory at path as an O_PATH descriptor, resolved inside
// the root directory rootFD refers to: ".." and an absolute symlink target stop
// at that root, whatever the root of this process is (openat2 with
// RESOLVE_IN_ROOT). With followSymlinks false a symlink anywhere in the path is
// refused. Where openat2 is missing or refused, the walk refuses every symlink
// whatever followSymlinks says.
func openDirIn(rootFD int, path string, followSymlinks bool) (int, error) {
	if !noOpenat2 {
		resolve := uint64(unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS)
		if followSymlinks {
			resolve = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS
		}
		fd, err := unix.Openat2(rootFD, path, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: resolve,
		})
		if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EPERM) {
			return fd, err
		}
	}
	return walkWithoutSymlinks(rootFD, path)
}

// walkWithoutSymlinks opens path below the directory rootFD refers to one
// component at a time, without following any symlink.
func walkWithoutSymlinks(rootFD int, path string) (int, error) {
	fd, err := unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, name := range strings.Split(path, "/") {
		if name == "" {
			continue
		}
		if name == "." || name == ".." {
			_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
			return -1, unix.EINVAL
		}
		next, err := unix.Openat(fd, name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// trustedDir opens the directory at path inside the root rootFD refers to and
// checks that only root can write in it: it is a directory owned by trustedUID
// that its group and others cannot write. Anyone else who can write in the
// directory can rename a file of their own over a trusted one.
func trustedDir(rootFD int, path string, followSymlinks bool) (int, bool) {
	fd, err := openDirIn(rootFD, path, followSymlinks)
	if err != nil {
		return -1, false
	}
	const need = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, need, &st); err != nil ||
		st.Mask&need != need || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		!trustedOwnerMode(st.Uid, uint32(st.Mode)&0o7777) {
		_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
		return -1, false
	}
	return fd, true
}

// openTrusted opens the file at path inside the root rootFD refers to, for
// reading, when the file and its directory are trusted (trustedDir). The file
// itself must not be a symlink. followSymlinks says whether a symlink in the
// directory part may be followed, inside that root: a configured path may sit
// behind one (a release directory that a symlink points at), the system
// directories a protected name is searched in may not, so the file the key
// names really lives in the directory the path names. The open does not block
// on a FIFO put at the path.
func openTrusted(rootFD int, path string, followSymlinks bool) (int, bool) {
	dir, ok := trustedDir(rootFD, filepath.Dir(path), followSymlinks)
	if !ok {
		return -1, false
	}
	defer func() { _ = unix.Close(dir) }() // an O_PATH descriptor holds no data to flush
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, false
	}
	return fd, true
}

// openImage opens a descriptor path under /proc (the exe of a process, a file
// PID 1 holds open) for reading without blocking.
func openImage(path string) (int, bool) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	return fd, err == nil
}

// startTicksAt reads the start time of the process whose /proc directory is dir.
func startTicksAt(dir string) (uint64, bool) {
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return 0, false
	}
	ticks, err := parseProcStatStartTicks(stat)
	return ticks, err == nil
}

// afterImageRead runs between the read of a process image and the second check
// of its start time. Tests use it to change the process in between.
var afterImageRead func(dir string)

// systemDirOnly says that a path comes from a protected name searched in the
// system directories (imagePaths): symlinks are refused in its directory part.
func systemDirOnly(img protectedImage) bool {
	return img.Flags&^protectedImageKeepOnSetuid == protectedImageRoot
}

// refreshExeLeads records where each configured exe path that goes through a
// symlink leads inside PID 1's root (configuredLink matches a process by it).
// The directory is resolved with the same walk as the image set and the watch;
// it need not be trusted here, so a writable one is still reported as such by
// the scan. A root that cannot be opened leaves no entries.
func (s *ProtectedProcessSet) refreshExeLeads(procRoot string) {
	if s == nil {
		return
	}
	leads := make(map[string]string)
	if root, err := unix.Open(filepath.Join(procRoot, "1", "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		// d_path shows a file relative to the reader's root; the root descriptor
		// gives the part to cut off (nothing when the roots are the same).
		prefix, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(root))
		for p := range s.exes {
			dir, err := openDirIn(root, filepath.Dir(p), true)
			if err != nil {
				continue
			}
			resolved, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(dir))
			_ = unix.Close(dir) // an O_PATH descriptor holds no data to flush
			if err != nil {
				continue
			}
			target := filepath.Join("/", strings.TrimPrefix(resolved, prefix), filepath.Base(p))
			if _, listed := s.exes[target]; target != p && !listed {
				leads[target] = p
			}
		}
		_ = unix.Close(root) // an O_PATH descriptor holds no data to flush
	}
	s.leads.Store(&leads)
}

// kernelImages is the content of trace_protected_images: the files the kernel
// may keep a protected entry for at exec, with the condition of each. It merges
// three sources; a file that several list keeps what any of them says (merge):
//   - the files at the trusted paths (imagePaths), resolved inside PID 1's
//     root, whose directory and file only root can write;
//   - the images of the processes verified by the last scan, which may live in
//     their own mount namespace or run a binary that was replaced on disk (the
//     inode stays referenced while the process runs, so it cannot be reused).
//     A process is used only while its start time still equals the one the scan
//     recorded, before and after its image is read: the list may be seconds old
//     on a refresh started by a file change, and a PID that was reused since
//     would name another process's file;
//   - the files PID 1 holds open at a trusted path: systemd 255 and later keeps
//     systemd-executor open and runs it as /proc/self/fd/<n>, also after a
//     package upgrade replaced it and before daemon-reexec.
//
// A file that cannot be identified or trusted is left out, and an exec of it
// drops the entry. When PID 1's root or mount table cannot be read (the agent
// lacks CAP_SYS_PTRACE) the first and third sources are empty.
func (s *ProtectedProcessSet) kernelImages(procRoot string, verified []protectedTGID) map[protectedImageKey]protectedImage {
	out := make(map[protectedImageKey]protectedImage)
	if s == nil {
		return out
	}
	add := func(key protectedImageKey, img protectedImage) { out[key] = out[key].merge(img) }

	// A mount table is the same for every process of a mount namespace, so each
	// is read once per call. Mount IDs are global: a process that changes
	// namespace after its link was read can only miss a mount, which leaves its
	// image out.
	tables := make(map[string]map[uint64]mountEntry)
	hostMounts, hostMountsOK := readMounts(filepath.Join(procRoot, "1", "mountinfo"))
	if ns, err := os.Readlink(filepath.Join(procRoot, "1", "ns", "mnt")); hostMountsOK && err == nil {
		tables[ns] = hostMounts
	}
	mountsOf := func(dir string) (map[uint64]mountEntry, bool) {
		ns, err := os.Readlink(filepath.Join(dir, "ns", "mnt"))
		if err != nil {
			return readMounts(filepath.Join(dir, "mountinfo"))
		}
		if m, ok := tables[ns]; ok {
			return m, true
		}
		m, ok := readMounts(filepath.Join(dir, "mountinfo"))
		if ok {
			tables[ns] = m
		}
		return m, ok
	}

	for _, p := range verified {
		img, ok := p.image()
		if !ok {
			continue
		}
		dir := procDir(procRoot, p.tgid)
		if ticks, ok := startTicksAt(dir); !ok || ticks != p.startTicks {
			continue
		}
		fd, ok := openImage(filepath.Join(dir, "exe"))
		if !ok {
			continue
		}
		mounts, mountsOK := mountsOf(dir)
		key, keyOK := fileImage(fd, mounts)
		_ = unix.Close(fd) // read-only descriptor
		if afterImageRead != nil {
			afterImageRead(dir)
		}
		if ticks, ok := startTicksAt(dir); !mountsOK || !keyOK || !ok || ticks != p.startTicks {
			continue
		}
		add(key, img)
	}

	hostRoot, err := unix.Open(filepath.Join(procRoot, "1", "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err == nil {
		defer func() { _ = unix.Close(hostRoot) }() // an O_PATH descriptor holds no data to flush
		if hostMountsOK {
			paths := s.imagePaths()
			for p, img := range paths {
				fd, ok := openTrusted(hostRoot, p, !systemDirOnly(img))
				if !ok {
					continue
				}
				key, ok := fileImage(fd, hostMounts)
				_ = unix.Close(fd) // read-only descriptor
				if ok {
					add(key, img)
				}
			}
			s.addHeldImages(procRoot, hostRoot, hostMounts, paths, add)
		}
	}
	for key, img := range out {
		if img.Flags == 0 {
			delete(out, key)
		}
	}
	return out
}

// addHeldImages adds the files PID 1 holds open at one of the trusted paths.
func (s *ProtectedProcessSet) addHeldImages(procRoot string, hostRoot int, hostMounts map[uint64]mountEntry, paths map[string]protectedImage, add func(protectedImageKey, protectedImage)) {
	fdDir := filepath.Join(procRoot, "1", "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return
	}
	for _, e := range fds {
		link := filepath.Join(fdDir, e.Name())
		target, err := os.Readlink(link)
		if err != nil {
			continue
		}
		path := strings.TrimSuffix(target, " (deleted)")
		img, ok := paths[path]
		if !ok {
			continue
		}
		// The directory the file was opened in must still be root's.
		dir, ok := trustedDir(hostRoot, filepath.Dir(path), !systemDirOnly(img))
		if !ok {
			continue
		}
		_ = unix.Close(dir) // an O_PATH descriptor holds no data to flush
		fd, ok := openImage(link)
		if !ok {
			continue
		}
		key, ok := fileImage(fd, hostMounts)
		_ = unix.Close(fd) // read-only descriptor
		if ok {
			add(key, img)
		}
	}
}
