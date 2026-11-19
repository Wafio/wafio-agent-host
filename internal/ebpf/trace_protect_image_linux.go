//go:build linux

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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

// noOpenat2 makes the directory walk of the system paths take its fallback. Tests
// set it; in production the fallback runs only where openat2 is missing (before
// Linux 5.6) or refused (a seccomp filter). The trusted walk of a configured path
// never uses openat2.
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
// the root directory rootFD refers to, with no symlink anywhere in the path:
// ".." and an absolute target stop at that root, whatever the root of this
// process is (openat2 with RESOLVE_IN_ROOT). It serves the system directories a
// protected name is searched in. Where openat2 is missing or refused, the walk
// refuses every symlink the same way.
func openDirIn(rootFD int, path string) (int, error) {
	if !noOpenat2 {
		fd, err := unix.Openat2(rootFD, path, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS,
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

// maxTrustedLinks is how many symlinks one trusted walk follows before it fails
// with ELOOP, the limit of the kernel's own path walk.
const maxTrustedLinks = 40

// untrustedError says that the trusted walk met a directory or a file that an
// account other than root can write, and names it.
type untrustedError struct{ path string }

func (e *untrustedError) Error() string {
	return e.path + " can be written by an account other than root"
}

// assumeTrustedDirs lists directories, by their real path, that the trusted walk
// takes as root's without reading their owner and mode. Tests set it: they build
// their files below a directory they own, and the directories above it, /tmp
// among them, are writable by everyone.
var assumeTrustedDirs map[string]bool

// walkDir is a directory the trusted walk has entered.
type walkDir struct {
	fd   int
	name string // its name in the directory above; "" for the root
	ok   bool   // only root can write in it
}

// walkStatxMask is what the trusted walk reads of each entry: its type, mode
// and owner.
const walkStatxMask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID

// statxOf reads walkStatxMask of the file fd refers to.
func statxOf(fd int) (unix.Statx_t, error) {
	var st unix.Statx_t
	err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, walkStatxMask, &st)
	if err == nil && st.Mask&walkStatxMask != walkStatxMask {
		err = unix.ENOTSUP
	}
	return st, err
}

// readLinkOf reads the target of the symlink fd refers to, opened with O_PATH
// and O_NOFOLLOW.
func readLinkOf(fd int) (string, error) {
	var buf [unix.PathMax]byte
	n, err := unix.Readlinkat(fd, "", buf[:])
	switch {
	case err != nil:
		return "", err
	case n == 0:
		return "", unix.ENOENT
	case n == len(buf):
		return "", unix.ENAMETOOLONG
	}
	return string(buf[:n]), nil
}

// pathParts splits path into its components, without the empty and "." ones.
func pathParts(path string) []string {
	return slices.DeleteFunc(strings.Split(path, "/"), func(s string) bool { return s == "" || s == "." })
}

// walkPath is the path of the entry name in the innermost of dirs.
func walkPath(dirs []walkDir, name string) string {
	parts := make([]string, 0, len(dirs))
	for _, d := range dirs[1:] {
		parts = append(parts, d.name)
	}
	if name != "" {
		parts = append(parts, name)
	}
	return "/" + strings.Join(parts, "/")
}

// trustedWalk resolves path inside the root rootFD refers to, one component at a
// time, and returns an O_PATH descriptor of what it leads to, with where that is
// in the root (no symlink left in it). It succeeds only when every directory a
// component is looked up in is root's alone (trustedOwnerMode), the ones that
// hold a symlink included, and so is the file the path leads to. The target of a
// symlink is spliced in front of the rest of the path, an absolute one restarting
// at the root and ".." never climbing above it, at most maxTrustedLinks times. It
// reads with openat, readlinkat and statx only, so it needs no openat2.
//
// Past a directory or file that others can write the walk goes on, to find out
// whether the path leads anywhere, and cannot succeed any more: it gives an
// *untrustedError naming the first such directory or file. It reads only the text
// of symlinks and what exists, never a file's content. A path that leads nowhere
// gives the error of the walk (ENOENT) and names nothing.
func trustedWalk(rootFD int, path string) (int, string, error) {
	top, err := unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	st, err := statxOf(top)
	if err != nil {
		_ = unix.Close(top) // an O_PATH descriptor holds no data to flush
		return -1, "", err
	}
	dirs := []walkDir{{fd: top, ok: entryTrusted(top, &st)}}
	defer func() {
		for _, d := range dirs {
			_ = unix.Close(d.fd) // an O_PATH descriptor holds no data to flush
		}
	}()

	todo := pathParts(path)
	links := 0
	stop := "" // the first directory or file on the way that others can write
	for len(todo) > 0 {
		name := todo[0]
		todo = todo[1:]
		cur := dirs[len(dirs)-1]
		if name == ".." {
			if len(dirs) > 1 {
				_ = unix.Close(cur.fd) // an O_PATH descriptor holds no data to flush
				dirs = dirs[:len(dirs)-1]
			}
			continue
		}
		if !cur.ok && stop == "" {
			stop = walkPath(dirs, "")
		}
		fd, err := unix.Openat(cur.fd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, "", err
		}
		st, err := statxOf(fd)
		if err != nil {
			_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
			return -1, "", err
		}
		here := walkPath(dirs, name)
		switch {
		case st.Mode&unix.S_IFMT == unix.S_IFLNK:
			target, err := readLinkOf(fd)
			_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
			if err != nil {
				return -1, "", err
			}
			if links++; links > maxTrustedLinks {
				return -1, "", unix.ELOOP
			}
			if strings.HasPrefix(target, "/") {
				for _, d := range dirs[1:] {
					_ = unix.Close(d.fd) // an O_PATH descriptor holds no data to flush
				}
				dirs = dirs[:1]
			}
			todo = append(pathParts(target), todo...)
		case len(todo) > 0 && st.Mode&unix.S_IFMT == unix.S_IFDIR:
			dirs = append(dirs, walkDir{fd: fd, name: name, ok: entryTrusted(fd, &st)})
		case len(todo) > 0:
			_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
			return -1, "", unix.ENOTDIR
		default:
			if stop == "" && !entryTrusted(fd, &st) {
				stop = here
			}
			if stop != "" {
				_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
				return -1, "", &untrustedError{stop}
			}
			return fd, here, nil
		}
	}
	// The path named the root, or ended in "..": the directory it stands in.
	cur := dirs[len(dirs)-1]
	here := walkPath(dirs, "")
	if stop == "" && !cur.ok {
		stop = here
	}
	if stop != "" {
		return -1, "", &untrustedError{stop}
	}
	fd, err := unix.FcntlInt(uintptr(cur.fd), unix.F_DUPFD_CLOEXEC, 0)
	return fd, here, err
}

// entryTrusted reports whether the entry that st describes, open as fd, is owned
// by trustedUID and not writable by its group or others.
func entryTrusted(fd int, st *unix.Statx_t) bool {
	if assumeTrustedDirs != nil {
		if real, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); err == nil && assumeTrustedDirs[real] {
			return true
		}
	}
	return trustedOwnerMode(st.Uid, uint32(st.Mode)&0o7777)
}

// trustedDir opens the directory at path inside the root rootFD refers to and
// checks that only root can write in it: it is a directory owned by trustedUID
// that its group and others cannot write. Anyone else who can write in the
// directory can rename a file of their own over a trusted one. followSymlinks
// says how the path is resolved: through trustedWalk, which also asks root's
// alone of every directory above, or, for the system directories a protected
// name is searched in, with no symlink at all (openDirIn).
func trustedDir(rootFD int, path string, followSymlinks bool) (int, bool) {
	var fd int
	var err error
	if followSymlinks {
		fd, _, err = trustedWalk(rootFD, path)
	} else {
		fd, err = openDirIn(rootFD, path)
	}
	if err != nil {
		return -1, false
	}
	var st unix.Statx_t
	if st, err = statxOf(fd); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		!trustedOwnerMode(st.Uid, uint32(st.Mode)&0o7777) {
		_ = unix.Close(fd) // an O_PATH descriptor holds no data to flush
		return -1, false
	}
	return fd, true
}

// openTrusted opens the file at path inside the root rootFD refers to, for
// reading, when the file and every directory on the way are trusted. With
// followSymlinks the path is resolved by trustedWalk, which follows a symlink,
// the last part of the path included, only out of a directory root alone can
// write: a configured path may lead through one (a release directory or a file
// that a symlink points at). Without it, for the system directories a protected
// name is searched in, no symlink is allowed anywhere and the directory is
// trusted (trustedDir), so the file the key names really lives in the directory
// the path names. The open does not block on a FIFO put at the path.
func openTrusted(rootFD int, path string, followSymlinks bool) (int, bool) {
	if followSymlinks {
		file, _, err := trustedWalk(rootFD, path)
		if err != nil {
			return -1, false
		}
		defer func() { _ = unix.Close(file) }() // an O_PATH descriptor holds no data to flush
		return openImage("/proc/self/fd/" + strconv.Itoa(file))
	}
	dir, ok := trustedDir(rootFD, filepath.Dir(path), false)
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

// closeInfo reads the file info of the descriptor fd, an O_PATH one or one open
// for reading, and closes it. It returns nil when the descriptor cannot be
// read.
func closeInfo(fd int) os.FileInfo {
	f := os.NewFile(uintptr(fd), "")
	defer func() { _ = f.Close() }() // not open for writing: no data to flush
	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	return fi
}

// walkExe walks the configured path p inside the root rootFD refers to.
// trustedWalk follows its symlinks, in the directory part and in the file name,
// and stops at a directory or file that others can write. The result says where
// the path leads, the file there and the directory that holds it, each only when
// the walk to it passed, and what stopped the walks. A path with no file at its
// end (a replaced binary still runs from there) leads where its directory does.
func walkExe(root int, p string) exeWalk {
	var w exeWalk
	var stop *untrustedError
	fd, lead, err := trustedWalk(root, p)
	switch {
	case err == nil:
		w.lead, w.file = lead, closeInfo(fd)
	case errors.As(err, &stop):
		w.untrusted = stop.path
	}
	held := p
	if w.lead != "" {
		held = w.lead
	}
	fd, dir, err := trustedWalk(root, filepath.Dir(held))
	switch {
	case err == nil:
		w.dir = closeInfo(fd)
		if w.lead == "" && w.untrusted == "" {
			w.lead = filepath.Join(dir, filepath.Base(p))
		}
	case errors.As(err, &stop):
		w.dirStop = stop.path
	}
	return w
}

// refreshExeLeads walks each configured exe path inside PID 1's root. It records
// where a path that goes through a symlink, in its directory or as the file
// itself, leads (configuredLink matches a process by it), the directories and
// files that stopped a walk (scanProtectedTGIDs reports them), and the walk
// itself, which decides whether a running process is the file at the path
// (hostExeCheck). The walk is the one of the image set and the watch. A root that
// cannot be opened leaves no entries.
func (s *ProtectedProcessSet) refreshExeLeads(procRoot string) {
	if s == nil {
		return
	}
	found := &exeLeads{byTarget: make(map[string]string), walked: make(map[string]exeWalk)}
	if root, err := unix.Open(filepath.Join(procRoot, "1", "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		for p := range s.exes {
			w := walkExe(root, p)
			found.walked[p] = w
			if w.untrusted != "" {
				found.untrusted = append(found.untrusted, w.untrusted)
			}
			if _, listed := s.exes[w.lead]; w.lead != "" && w.lead != p && !listed {
				found.byTarget[w.lead] = p
			}
		}
		_ = unix.Close(root) // an O_PATH descriptor holds no data to flush
	}
	slices.Sort(found.untrusted)
	found.untrusted = slices.Compact(found.untrusted)
	s.leads.Store(found)
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
//     recorded, before and after its image is read, and its image is the file
//     the scan verified: the list may be seconds old on a refresh started by a
//     file change, a PID that was reused since would name another process's
//     file, and a process that ran exec since keeps its PID and start time;
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
		now := closeInfo(fd)
		if afterImageRead != nil {
			afterImageRead(dir)
		}
		if ticks, ok := startTicksAt(dir); !mountsOK || !keyOK || !ok || ticks != p.startTicks || !os.SameFile(now, p.file) {
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
