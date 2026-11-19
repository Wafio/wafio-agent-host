//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// asTrustedOwner lets the test use files it owns: the owner the trust decision
// asks for is root, which an unprivileged test run cannot be.
func asTrustedOwner(t *testing.T) {
	t.Helper()
	prev := trustedUID
	trustedUID = uint32(os.Getuid())
	t.Cleanup(func() { trustedUID = prev })
}

// requireGeneration fails the test when the filesystem of path reports no inode
// generation: no file on it can be identified, so a test of the identity would
// prove nothing there. A run on such a host must say so, not pass by skipping.
// WAFIO_ALLOW_IMAGE_TEST_SKIP turns the failure into a skip, for a developer's
// container; the gate does not set it.
func requireGeneration(t *testing.T, path string) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }() // read-only descriptor
	if _, err := unix.IoctlGetUint32(fd, fsIocGetVersion); err != nil {
		msg := fmt.Sprintf("the filesystem of %s reports no inode generation (%v), so no file on it can be identified; run on ext4, XFS or btrfs, or put WAFIO_TEST_IMAGE_DIR on one", path, err)
		if os.Getenv("WAFIO_ALLOW_IMAGE_TEST_SKIP") != "" {
			t.Skip(msg)
		}
		t.Fatal(msg)
	}
}

// imageTestDir is a directory only the test user can write, on a filesystem
// that reports inode generations: under WAFIO_TEST_IMAGE_DIR when set, else the
// test temporary directory (tmpfs on some hosts, which answers ENOTTY).
func imageTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if base := os.Getenv("WAFIO_TEST_IMAGE_DIR"); base != "" {
		var err error
		if dir, err = os.MkdirTemp(base, "image"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	requireGeneration(t, probe)
	return dir
}

// writeFile writes a file with exactly this mode, whatever the umask.
func writeFile(t *testing.T, path, content string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// selfProc is a /proc in which PID 1 is this process: its root, mount table and
// descriptors are the test's own, which the test can read and change.
func selfProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Symlink("/proc/self", filepath.Join(root, "1")); err != nil {
		t.Fatal(err)
	}
	return root
}

// rootFD opens dir as the root a path is resolved in.
func rootFD(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// imageAt is what kernelImages does for a trusted path: open it inside the root
// and identify it.
func imageAt(t *testing.T, root int, path string, followSymlinks bool) (protectedImageKey, bool) {
	t.Helper()
	fd, ok := openTrusted(root, path, followSymlinks)
	if !ok {
		return protectedImageKey{}, false
	}
	defer func() { _ = unix.Close(fd) }() // read-only descriptor
	mounts, ok := readMounts("/proc/self/mountinfo")
	if !ok {
		t.Fatal("no mount table")
	}
	return fileImage(fd, mounts)
}

// identityOf identifies the file at path against the mount table at mountinfo.
func identityOf(path, mountinfo string) (protectedImageKey, bool) {
	fd, ok := openImage(path)
	if !ok {
		return protectedImageKey{}, false
	}
	defer func() { _ = unix.Close(fd) }() // read-only descriptor
	mounts, ok := readMounts(mountinfo)
	if !ok {
		return protectedImageKey{}, false
	}
	return fileImage(fd, mounts)
}

// The identity userspace builds is the one the kernel sees: /proc/<pid>/maps
// prints inode->i_sb->s_dev and inode->i_ino of a mapped file, the very fields
// the exec program reads from mm->exe_file->f_inode. The test needs a
// filesystem that reports inode generations, and fails where there is none.
func TestImageIdentityMatchesKernelView(t *testing.T) {
	asTrustedOwner(t)
	path := writeFile(t, filepath.Join(imageTestDir(t), "image"), string(make([]byte, 4096)), 0o755)

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }() // read-only
	mapped, err := unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Munmap(mapped) }()

	selfMaps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	var wantIno, wantDev uint64
	for _, line := range strings.Split(string(selfMaps), "\n") {
		// address perms offset dev inode path, dev as hex major:minor
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[5] != path {
			continue
		}
		major, minor, ok := strings.Cut(fields[3], ":")
		if !ok {
			t.Fatalf("maps line %q has no device", line)
		}
		ma, err1 := strconv.ParseUint(major, 16, 32)
		mi, err2 := strconv.ParseUint(minor, 16, 32)
		ino, err3 := strconv.ParseUint(fields[4], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			t.Fatalf("maps line %q: %v %v %v", line, err1, err2, err3)
		}
		wantDev, wantIno = ma<<20|mi, ino
		break
	}
	if wantIno == 0 {
		t.Fatalf("%s not found in /proc/self/maps", path)
	}

	key, ok := identityOf(path, "/proc/self/mountinfo")
	if !ok {
		t.Fatal("no identity for a regular file")
	}
	if key.Ino != wantIno || uint64(key.Dev) != wantDev {
		t.Fatalf("identity dev=%#x ino=%d, the kernel shows dev=%#x ino=%d", key.Dev, key.Ino, wantDev, wantIno)
	}

	// The same file reached through another name has the same identity, a
	// copy has another.
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if again, ok := identityOf(link, "/proc/self/mountinfo"); !ok || again != key {
		t.Fatalf("hard link identity %v (ok %t), want %v", again, ok, key)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := writeFile(t, filepath.Join(filepath.Dir(path), "copy"), string(data), 0o755)
	if other, ok := identityOf(copyPath, "/proc/self/mountinfo"); !ok || other == key {
		t.Fatalf("copy identity %v (ok %t) equals the original", other, ok)
	}
}

// Every failure means no identity: the file is not trusted.
func TestImageIdentityFailures(t *testing.T) {
	asTrustedOwner(t)
	dir := imageTestDir(t)
	regular := writeFile(t, filepath.Join(dir, "regular"), "x", 0o755)
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o700); err != nil {
		t.Fatal(err)
	}
	mountinfo := "/proc/self/mountinfo"
	if _, ok := identityOf(regular, mountinfo); !ok {
		t.Fatal("the control file has no identity")
	}
	for name, tc := range map[string]struct{ path, mountinfo string }{
		"missing file":       {filepath.Join(dir, "missing"), mountinfo},
		"directory":          {dir, mountinfo},
		"fifo":               {fifo, mountinfo},
		"no generation":      {"/proc/self/status", mountinfo}, // ENOTTY from the ioctl, on a writable superblock
		"unreadable mounts":  {regular, filepath.Join(dir, "no-mountinfo")},
		"mount not in table": {regular, writeFile(t, filepath.Join(dir, "empty-mountinfo"), "", 0o600)},
	} {
		done := make(chan bool, 1)
		go func() { _, ok := identityOf(tc.path, tc.mountinfo); done <- ok }()
		select {
		case ok := <-done:
			if ok {
				t.Errorf("%s: an identity was returned", name)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s: the identity did not return", name)
		}
	}

	// The owner and the mode count: a file that its owner, when not root, its
	// group or others can write, or that another user owns, is not trusted.
	trustedUID = uint32(os.Getuid()) + 1
	if _, ok := identityOf(regular, mountinfo); ok {
		t.Error("a file owned by another user than the trusted one got an identity")
	}
	asTrustedOwner(t)
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777, 0o722, 0o702} {
		if err := os.Chmod(regular, mode); err != nil {
			t.Fatal(err)
		}
		if _, ok := identityOf(regular, mountinfo); ok {
			t.Errorf("a file with mode %o got an identity", mode)
		}
	}
	if err := os.Chmod(regular, 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		// The real policy: a file the test user owns is not root's.
		trustedUID = 0
		if _, ok := identityOf(regular, mountinfo); ok {
			t.Error("a file of an unprivileged user got an identity under the real owner policy")
		}
		asTrustedOwner(t)
	}

	// A statx result without the mount ID, the inode, the owner or the mode, or
	// for another file type, is refused before the mount table is consulted.
	good := unix.Statx_t{Mask: imageStatxMask, Mode: unix.S_IFREG | 0o755, Uid: uint32(os.Getuid()), Ino: 7, Mnt_id: 36}
	devs := map[uint64]mountEntry{36: {dev: 0x10300002}, 37: {dev: 0x10300003, readOnly: true}}
	if key, ok := imageKeyOf(&good, 5, false, devs); !ok || key != (protectedImageKey{Ino: 7, Dev: 0x10300002, Gen: 5}) {
		t.Fatalf("good statx: %v %t", key, ok)
	}
	for name, mutate := range map[string]func(*unix.Statx_t){
		"no mount ID in the mask": func(st *unix.Statx_t) { st.Mask &^= unix.STATX_MNT_ID },
		"no inode in the mask":    func(st *unix.Statx_t) { st.Mask &^= unix.STATX_INO },
		"no owner in the mask":    func(st *unix.Statx_t) { st.Mask &^= unix.STATX_UID },
		"no mode in the mask":     func(st *unix.Statx_t) { st.Mask &^= unix.STATX_MODE },
		"directory":               func(st *unix.Statx_t) { st.Mode = unix.S_IFDIR | 0o755 },
		"symlink":                 func(st *unix.Statx_t) { st.Mode = unix.S_IFLNK | 0o777 },
		"another owner":           func(st *unix.Statx_t) { st.Uid++ },
		"group writable":          func(st *unix.Statx_t) { st.Mode |= 0o020 },
		"world writable":          func(st *unix.Statx_t) { st.Mode |= 0o002 },
		"mount not listed":        func(st *unix.Statx_t) { st.Mnt_id = 99 },
	} {
		st := good
		mutate(&st)
		if key, ok := imageKeyOf(&st, 5, false, devs); ok {
			t.Errorf("%s: identity %v returned", name, key)
		}
	}

	// No generation: only a read-only superblock is accepted, with generation 0,
	// whatever value came back with the failed ioctl.
	rw, ro := good, good
	rw.Mnt_id, ro.Mnt_id = 36, 37
	if key, ok := imageKeyOf(&rw, 0, true, devs); ok {
		t.Errorf("a file without a generation on a writable superblock got identity %v", key)
	}
	if key, ok := imageKeyOf(&ro, 9, true, devs); !ok || key != (protectedImageKey{Ino: 7, Dev: 0x10300003, Gen: 0}) {
		t.Errorf("a file without a generation on a read-only superblock: %v %t, want generation 0", key, ok)
	}
	if key, ok := imageKeyOf(&ro, 9, false, devs); !ok || key.Gen != 9 {
		t.Errorf("a read-only superblock that reports a generation: %v %t, want the reported one", key, ok)
	}
}

// openTrusted resolves a path inside the root it is given and trusts only a
// file and a directory that root alone can write.
func TestOpenTrusted(t *testing.T) {
	asTrustedOwner(t)
	base := imageTestDir(t)
	root := filepath.Join(base, "root")
	good := writeFile(t, filepath.Join(root, "real", "agent"), "x", 0o755)
	if err := os.Chmod(filepath.Join(root, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "relative")); err != nil {
		t.Fatal(err)
	}
	// An absolute target means /real in the root it is read in, not in the
	// root of this process, where /real does not exist.
	if err := os.Symlink("/real", filepath.Join(root, "absolute")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("agent", filepath.Join(root, "real", "alias")); err != nil {
		t.Fatal(err)
	}
	// A symlink that climbs out of the root stays in it.
	writeFile(t, filepath.Join(base, "outside", "agent"), "x", 0o755)
	if err := os.Symlink("../outside", filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "outside"), filepath.Join(root, "escape-absolute")); err != nil {
		t.Fatal(err)
	}
	r := rootFD(t, root)

	type want struct{ follow, nosym bool }
	for path, tc := range map[string]want{
		"/real/agent":            {follow: true, nosym: true},
		"/relative/agent":        {follow: true},
		"/absolute/agent":        {follow: true},
		"real/agent":             {follow: true, nosym: true}, // a relative spelling means the same
		"/real/alias":            {},                          // the file itself is a symlink
		"/real/missing":          {},
		"/real":                  {}, // a directory
		"/escape/agent":          {}, // resolves to /outside inside the root: not there
		"/escape-absolute/agent": {},
	} {
		for _, follow := range []bool{true, false} {
			_, ok := imageAt(t, r, path, follow)
			expect := tc.follow
			if !follow {
				expect = tc.nosym
			}
			if ok != expect {
				t.Errorf("%s (follow symlinks %t): trusted %t, want %t", path, follow, ok, expect)
			}
		}
	}

	// Without openat2 the walk refuses every symlink.
	noOpenat2 = true
	t.Cleanup(func() { noOpenat2 = false })
	for path, expect := range map[string]bool{"/real/agent": true, "/relative/agent": false, "/absolute/agent": false} {
		if _, ok := imageAt(t, r, path, true); ok != expect {
			t.Errorf("%s with the fallback: trusted %t, want %t", path, ok, expect)
		}
	}
	noOpenat2 = false

	// A directory its group or others can write, or that another user owns,
	// lets them rename a file of their own over the trusted one.
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777, 0o722} {
		if err := os.Chmod(filepath.Join(root, "real"), mode); err != nil {
			t.Fatal(err)
		}
		if _, ok := imageAt(t, r, "/real/agent", true); ok {
			t.Errorf("a directory with mode %o is trusted", mode)
		}
	}
	if err := os.Chmod(filepath.Join(root, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := imageAt(t, r, "/real/agent", true); !ok {
		t.Fatal("the control file is not trusted")
	}
	// Each file mode that others can write, and the real owner policy.
	for _, mode := range []os.FileMode{0o775, 0o757} {
		if err := os.Chmod(good, mode); err != nil {
			t.Fatal(err)
		}
		if _, ok := imageAt(t, r, "/real/agent", true); ok {
			t.Errorf("a file with mode %o is trusted", mode)
		}
	}
	if err := os.Chmod(good, 0o755); err != nil {
		t.Fatal(err)
	}
	trustedUID = uint32(os.Getuid()) + 1
	if _, ok := imageAt(t, r, "/real/agent", true); ok {
		t.Error("a file in a directory of another owner than the trusted one is trusted")
	}
	asTrustedOwner(t)
	if os.Getuid() != 0 {
		trustedUID = 0
		if _, ok := imageAt(t, r, "/real/agent", true); ok {
			t.Error("a file of an unprivileged user is trusted under the real owner policy")
		}
		asTrustedOwner(t)
	}
}

// sleepBinary is the content of the sleep binary of this host, for a copy a test
// can own.
func sleepBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary to copy")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// startTicksOfPID reads the start time of a live process.
func startTicksOfPID(t *testing.T, pid int) uint64 {
	t.Helper()
	ticks, ok := startTicksAt(filepath.Join("/proc", strconv.Itoa(pid)))
	if !ok {
		t.Fatalf("no start time for pid %d", pid)
	}
	return ticks
}

// kernelImages merges the trusted paths, the images of verified processes and
// the files PID 1 holds open, with the identities and the checks of the real
// code (the root of PID 1 here is the test's own, through /proc/self).
func TestKernelImagesMergesSources(t *testing.T) {
	asTrustedOwner(t)
	dir := imageTestDir(t)
	agent := writeFile(t, filepath.Join(dir, "agent"), "agent", 0o755)
	wafd := writeFile(t, filepath.Join(dir, "wafd"), "wafd", 0o755)
	held := writeFile(t, filepath.Join(dir, "held"), "held", 0o755)
	loose := writeFile(t, filepath.Join(dir, "loose"), "loose", 0o755)
	writable := writeFile(t, filepath.Join(dir, "sub", "writable"), "writable", 0o755)
	if err := os.Chmod(filepath.Dir(writable), 0o775); err != nil {
		t.Fatal(err)
	}

	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{agent, wafd, held, writable}, ReplaceDefaults: true})
	s.units[wafd] = "waf.service"
	proc := selfProc(t)

	// PID 1 holds the executor open after a package upgrade replaced it, a
	// file nobody trusts, a socket, and a file of a trusted path whose
	// directory others can write.
	heldFile, err := os.Open(held)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = heldFile.Close() }() // read-only
	looseFile, err := os.Open(loose)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = looseFile.Close() }() // read-only
	writableFile, err := os.Open(writable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writableFile.Close() }() // read-only
	var sock [2]int
	if sock, err = unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(sock[0]); _ = unix.Close(sock[1]) }()
	if err := os.Remove(held); err != nil {
		t.Fatal(err)
	}

	mounts, _ := readMounts("/proc/self/mountinfo")
	keyOf := func(f *os.File) protectedImageKey {
		t.Helper()
		key, ok := fileImage(int(f.Fd()), mounts)
		if !ok {
			t.Fatalf("no identity for %s", f.Name())
		}
		return key
	}
	heldKey, looseKey, writableKey := keyOf(heldFile), keyOf(looseFile), keyOf(writableFile)

	// Two children with an image of their own: copies of sleep that the test user
	// owns (a test binary is built group-writable under some umasks).
	startChild := func(name string) (pid int, ticks uint64) {
		t.Helper()
		child := exec.Command(writeFile(t, filepath.Join(dir, name), sleepBinary(t), 0o755), "30")
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
		return child.Process.Pid, startTicksOfPID(t, child.Process.Pid)
	}
	childPID, ticks := startChild("child")
	otherPID, otherTicks := startChild("other-child")
	childProc := func(name string, pid int) { // procRoot/<name> is the process pid
		t.Helper()
		if err := os.Symlink(filepath.Join("/proc", strconv.Itoa(pid)), filepath.Join(proc, name)); err != nil {
			t.Fatal(err)
		}
	}
	childProc("500", childPID)
	childProc("501", otherPID)
	childKey, ok := identityOf(filepath.Join(proc, "500", "exe"), filepath.Join(proc, "500", "mountinfo"))
	if !ok {
		t.Fatal("no identity for the child's image")
	}
	selfKey, ok := identityOf(filepath.Join(proc, "501", "exe"), filepath.Join(proc, "501", "mountinfo"))
	if !ok {
		t.Fatal("no identity for the other child's image")
	}
	// The agent's own file is also the file a verified process by name runs: the
	// process source adds a root condition to the any-task one of the path.
	agentKey, ok := identityOf(agent, "/proc/self/mountinfo")
	if !ok {
		t.Fatal("no identity for the agent file")
	}

	root := protectedImage{Flags: protectedImageRoot}
	anyone := protectedImage{Flags: protectedImageAny}
	waf, _ := unitImage("waf.service")
	got := s.kernelImages(proc, []protectedTGID{
		{tgid: 500, startTicks: ticks},                                             // by name: root
		{tgid: 501, startTicks: otherTicks, configured: true, unit: "waf.service"}, // a configured path bound to a unit
	})
	wafKey, ok := identityOf(wafd, "/proc/self/mountinfo")
	if !ok {
		t.Fatal("no identity for the unit-bound file")
	}
	want := map[protectedImageKey]protectedImage{
		agentKey: anyone, // a configured path
		wafKey:   waf,    // a configured path bound to a unit
		heldKey:  anyone, // PID 1 holds a deleted file of a configured path open
		childKey: root,   // the image of a verified process
		selfKey:  waf,    // the image of a verified process in a unit
	}
	if len(got) != len(want) {
		t.Errorf("images:\n got %+v\nwant %+v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("image %+v: got %+v, want %+v", k, got[k], v)
		}
	}
	for name, k := range map[string]protectedImageKey{"a descriptor of an untrusted path": looseKey, "a file in a directory others can write": writableKey} {
		if v, ok := got[k]; ok {
			t.Errorf("%s was trusted: %+v", name, v)
		}
	}

	// A file listed by two sources keeps what both say: the same image by a
	// path that needs no root, and by a verified process of a name.
	got = s.kernelImages(proc, []protectedTGID{{tgid: 500, startTicks: ticks}, {tgid: 500, startTicks: ticks, unit: "waf.service"}})
	if v := got[childKey]; v != (protectedImage{Flags: protectedImageRoot | protectedImageUnit, Unit: waf.Unit}) {
		t.Errorf("the image of two verified processes: %+v, want root or the unit", v)
	}
	if got := (*ProtectedProcessSet)(nil).kernelImages(proc, nil); len(got) != 0 {
		t.Errorf("nil set returned %v", got)
	}
}

// A verified process lends its image only while it is the process the scan saw:
// a PID the kernel gave to another process since (the list may be seconds old
// when a file change starts the refresh) names another file.
func TestKernelImagesChecksProcessStartTime(t *testing.T) {
	asTrustedOwner(t)
	dir := imageTestDir(t)
	child := exec.Command(writeFile(t, filepath.Join(dir, "child"), sleepBinary(t), 0o755), "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	ticks := startTicksOfPID(t, child.Process.Pid)

	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{filepath.Join(dir, "no-such-file")}, ReplaceDefaults: true})
	proc := selfProc(t)
	// A /proc directory that is the child's, with a stat file the test can change.
	fake := filepath.Join(proc, "600")
	if err := os.MkdirAll(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"exe", "mountinfo"} {
		if err := os.Symlink(filepath.Join("/proc", strconv.Itoa(child.Process.Pid), name), filepath.Join(fake, name)); err != nil {
			t.Fatal(err)
		}
	}
	setStart := func(ticks uint64) { writeFile(t, filepath.Join(fake, "stat"), string(statLine("child", ticks)), 0o644) }
	childKey, ok := identityOf(filepath.Join(fake, "exe"), filepath.Join(fake, "mountinfo"))
	if !ok {
		t.Fatal("no identity for the child's image")
	}
	run := func(recorded uint64) bool {
		_, ok := s.kernelImages(proc, []protectedTGID{{tgid: 600, startTicks: recorded}})[childKey]
		return ok
	}

	setStart(ticks)
	if !run(ticks) {
		t.Fatal("the image of a process whose start time matches is not used")
	}
	// The PID belongs to another process now: another start time.
	if run(ticks - 1) {
		t.Error("the image of a process with another start time than the scan recorded was used")
	}
	setStart(ticks + 1)
	if run(ticks) {
		t.Error("the image of a process whose start time changed since the scan was used")
	}
	// The process is replaced while its image is read.
	setStart(ticks)
	afterImageRead = func(string) { setStart(ticks + 7) }
	t.Cleanup(func() { afterImageRead = nil })
	if run(ticks) {
		t.Error("the image of a process whose start time changed during the read was used")
	}
	afterImageRead = nil
	// No readable start time: not trusted.
	if err := os.Remove(filepath.Join(fake, "stat")); err != nil {
		t.Fatal(err)
	}
	if run(ticks) {
		t.Error("the image of a process with no readable start time was used")
	}
}

// A protected name is searched in the system directories, which stay out of the
// reach of every symlink and of any non-root writer. This runs on the real
// system files: /usr/bin/true is root's, in root's directory.
func TestKernelImagesNameDerivedPaths(t *testing.T) {
	const path = "/usr/bin/true"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no %s on this host", path)
	}
	requireGeneration(t, path)
	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{Names: []string{"true"}, ReplaceDefaults: true})
	proc := selfProc(t)
	key, ok := identityOf(path, "/proc/self/mountinfo")
	if !ok {
		t.Fatalf("no identity for %s (is it root's, in a directory only root can write?)", path)
	}
	got := s.kernelImages(proc, nil)
	if v := got[key]; v != (protectedImage{Flags: protectedImageRoot}) {
		t.Fatalf("%s: %+v, want root only; images %+v", path, v, got)
	}
	// /bin is a symlink to usr/bin on a merged-usr host: the name is not
	// searched through it, the file is listed once by its real directory.
	if link, err := os.Readlink("/bin"); err == nil {
		t.Logf("/bin is a symlink to %s: not followed for a protected name", link)
	}
}

// The watch signals for a file that could be a trusted image, however it
// arrives (a write, a rename into place, an attribute change, a removal), and
// not for any other file in the directory. It watches PID 1's view, and a
// directory that does not exist yet or was replaced is watched once rearm finds
// it.
func TestWatchProtectedImages(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agentd")
	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{exe}, ReplaceDefaults: true})
	w, err := watchProtectedImages(s, selfProc(t))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if n := w.armedDirs(); n != 1 {
		t.Fatalf("%d directories armed, want 1", n)
	}

	none := func(w *imageWatch, what string) {
		t.Helper()
		select {
		case <-w.changed:
			t.Errorf("%s signalled", what)
		case <-time.After(300 * time.Millisecond):
		}
	}
	signal := func(w *imageWatch, what string) {
		t.Helper()
		select {
		case <-w.changed:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not signal", what)
		}
	}
	write := func(dir, name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(dir, "other")
	none(w, "an unrelated file")
	write(dir, "agentd.new")
	none(w, "the staging name of an upgrade")
	if err := os.Rename(filepath.Join(dir, "agentd.new"), exe); err != nil {
		t.Fatal(err)
	}
	signal(w, "a rename into place")
	if err := os.Chmod(exe, 0o700); err != nil {
		t.Fatal(err)
	}
	signal(w, "an attribute change")
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	signal(w, "a removal")

	// The directory is moved away and a new one takes its name with a new binary
	// in it: the old watch follows the old directory, so it is dropped and the
	// new one watched.
	moved := dir + ".old"
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	signal(w, "the directory moving away")
	if n := w.armedDirs(); n != 0 {
		t.Fatalf("%d directories armed after the directory moved, want 0", n)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if n := w.rearm(); n != 1 {
		t.Fatalf("rearm armed %d directories, want 1", n)
	}
	// The kernel also reports the old watch gone, a moment later: let that
	// settle, so the signal below is the new directory's.
	time.Sleep(300 * time.Millisecond)
	select {
	case <-w.changed:
	default:
	}
	write(dir, "agentd")
	signal(w, "a file in the replaced directory")
	if n := w.rearm(); n != 0 {
		t.Errorf("rearm armed %d directories that were watched", n)
	}

	// A directory that does not exist when the watch starts is no reason to
	// refuse it: the first refresh after it appears watches it.
	late := filepath.Join(t.TempDir(), "later")
	lateExe := filepath.Join(late, "agentd")
	lateSet := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{lateExe}, ReplaceDefaults: true})
	w2, err := watchProtectedImages(lateSet, selfProc(t))
	if err != nil {
		t.Fatalf("a watch with no directory yet did not start: %v", err)
	}
	defer w2.Close()
	if n := w2.armedDirs(); n != 0 {
		t.Fatalf("%d directories armed, want 0", n)
	}
	if err := os.Mkdir(late, 0o755); err != nil {
		t.Fatal(err)
	}
	if n := w2.rearm(); n != 1 {
		t.Fatalf("rearm armed %d directories, want 1", n)
	}
	write(late, "agentd")
	signal(w2, "a file in a directory that appeared later")
}

// The watch looks at the directories of PID 1's root, not at the agent's own
// view of the same names.
func TestWatchProtectedImagesUsesPID1Root(t *testing.T) {
	fakeRoot := t.TempDir()
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fakeRoot, filepath.Join(proc, "1", "root")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fakeRoot, "opt", "acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The same names in the agent's own root do not exist.
	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{"/opt/acme/agentd"}, ReplaceDefaults: true})
	w, err := watchProtectedImages(s, proc)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if n := w.armedDirs(); n != 1 {
		t.Fatalf("%d directories armed in the root of PID 1, want 1", n)
	}
	if err := os.WriteFile(filepath.Join(fakeRoot, "opt", "acme", "agentd"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.changed:
	case <-time.After(5 * time.Second):
		t.Fatal("a file in the root of PID 1 did not signal")
	}

	// An unreadable root of PID 1 (the agent lacks CAP_SYS_PTRACE) is an error,
	// not a watch of something else.
	if _, err := watchProtectedImages(s, filepath.Join(proc, "missing")); err == nil {
		t.Fatal("a watch started without the root of PID 1")
	}
}

// retargetLink points link at target the way a release switch does: a new link
// renamed over the old one, in a directory nothing watches.
func retargetLink(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Symlink(target, link+".new"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(link+".new", link); err != nil {
		t.Fatal(err)
	}
}

// signalAfterWriting makes a file appear at path and waits for the watch to
// say so. It first drops the signals still pending, so only this write counts.
func signalAfterWriting(t *testing.T, w *imageWatch, path string) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	select {
	case <-w.changed:
	default:
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.changed:
	case <-time.After(5 * time.Second):
		t.Fatalf("a file written at %s did not signal", path)
	}
}

// A configured path that goes through a symlink is watched where the link leads
// now: the link moves in a directory nobody watches, so only rearm can see it.
func TestWatchFollowsRetargetedSymlink(t *testing.T) {
	base := t.TempDir()
	rel1, rel2 := filepath.Join(base, "rel1"), filepath.Join(base, "rel2")
	for _, d := range []string{rel1, rel2} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	current := filepath.Join(base, "current")
	if err := os.Symlink(rel1, current); err != nil {
		t.Fatal(err)
	}
	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{filepath.Join(current, "agentd")}, ReplaceDefaults: true})
	w, err := watchProtectedImages(s, selfProc(t))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if n := w.rearm(); n != 0 {
		t.Fatalf("rearm armed %d directories with nothing changed, want 0", n)
	}

	retargetLink(t, current, rel2)
	if n := w.rearm(); n != 1 {
		t.Fatalf("rearm armed %d directories after the link moved, want 1", n)
	}
	if n := w.armedDirs(); n != 1 {
		t.Fatalf("%d directories armed, want 1", n)
	}
	signalAfterWriting(t, w, filepath.Join(rel2, "agentd"))
	// The old release is not watched any more.
	time.Sleep(300 * time.Millisecond)
	select {
	case <-w.changed:
	default:
	}
	if err := os.WriteFile(filepath.Join(rel1, "agentd"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.changed:
		t.Error("the old release still signals")
	case <-time.After(300 * time.Millisecond):
	}
}

// Two names for one directory share a watch: moving one of them leaves the
// other watched.
func TestWatchRetargetKeepsSharedWatch(t *testing.T) {
	base := t.TempDir()
	rel1, rel2 := filepath.Join(base, "rel1"), filepath.Join(base, "rel2")
	for _, d := range []string{rel1, rel2} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	current, alias := filepath.Join(base, "current"), filepath.Join(base, "alias")
	for _, link := range []string{current, alias} {
		if err := os.Symlink(rel1, link); err != nil {
			t.Fatal(err)
		}
	}
	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{filepath.Join(current, "agentd"), filepath.Join(alias, "agentd")}, ReplaceDefaults: true})
	w, err := watchProtectedImages(s, selfProc(t))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if n := w.armedDirs(); n != 2 {
		t.Fatalf("%d directories armed, want 2", n)
	}
	retargetLink(t, current, rel2)
	if n := w.rearm(); n != 1 {
		t.Fatalf("rearm armed %d directories after one link moved, want 1", n)
	}
	signalAfterWriting(t, w, filepath.Join(rel1, "agentd"))
	signalAfterWriting(t, w, filepath.Join(rel2, "agentd"))
}

// TestTraceProtectedImagesMapMatchesAgent reads the compiled object, not the
// kernel: the key and the value the agent writes are the layouts the exec
// program looks up and reads, the budget array has the slots the agent writes,
// and the map holds what the agent may write. Needs the compiled objects but no
// privileges.
func TestTraceProtectedImagesMapMatchesAgent(t *testing.T) {
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if dir == "" {
		t.Skip("set WAFIO_TEST_BPF_DIR to the compiled objects")
	}
	spec, err := cebpf.LoadCollectionSpec(filepath.Join(dir, "wafio_trace.o"))
	if err != nil {
		t.Fatal(err)
	}
	ms := spec.Maps[traceMapProtectedImages]
	if ms == nil {
		t.Fatalf("wafio_trace.o has no %s", traceMapProtectedImages)
	}
	if ms.Type != cebpf.Hash || int(ms.KeySize) != binary.Size(protectedImageKey{}) || int(ms.ValueSize) != binary.Size(protectedImage{}) || ms.MaxEntries != maxProtectedImages || ms.Flags&bpfFNoPrealloc != 0 {
		t.Errorf("%s: %+v, want a preallocated hash with %d-byte keys, %d-byte values and %d entries", traceMapProtectedImages, ms, binary.Size(protectedImageKey{}), binary.Size(protectedImage{}), maxProtectedImages)
	}
	budget := spec.Maps[traceMapProtectedBudget]
	if budget == nil {
		t.Fatalf("wafio_trace.o has no %s", traceMapProtectedBudget)
	}
	if budget.Type != cebpf.Array || budget.KeySize != 4 || budget.ValueSize != 8 || budget.MaxEntries <= protectedLimitSlot || budget.MaxEntries <= protectedRefusedSlot || budget.MaxEntries <= protectedBudgetSlot {
		t.Errorf("%s: %+v, want an array of 8-byte values with the budget, refused and limit slots", traceMapProtectedBudget, budget)
	}
}

// The cgroup fields the exec program reads exist in the running kernel's BTF.
// A field it lacks makes the program fail closed (bpf_core_field_exists), and a
// program that fails closed loads, so only the BTF shows that a kernel can
// answer. Needs a kernel with BTF; no privileges.
func TestKernelBTFHasUnitCheckFields(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("no kernel BTF: %v", err)
	}
	for _, f := range []struct{ typ, field string }{
		{"task_struct", "cgroups"},
		{"css_set", "dfl_cgrp"},
		{"cgroup", "self"},
		{"cgroup", "level"},
		{"cgroup", "kn"},
		{"cgroup_subsys_state", "parent"},
		{"cgroup_subsys_state", "cgroup"},
		{"kernfs_node", "name"},
	} {
		if !btfStructHasField(t, spec, f.typ, f.field) {
			t.Errorf("the running kernel has no %s.%s: the exec program drops every unit-bound entry here", f.typ, f.field)
		}
	}
	// The parent of the cgroup comes from self.parent, which every kernel has;
	// kernfs_node.parent, which 6.17 calls __parent, is not read.
	t.Logf("kernfs_node.parent present: %t, kernfs_node.__parent present: %t",
		btfStructHasField(t, spec, "kernfs_node", "parent"), btfStructHasField(t, spec, "kernfs_node", "__parent"))
}

// btfStructHasField reports whether the struct typ of the kernel BTF has a
// member of that name.
func btfStructHasField(t *testing.T, spec *btf.Spec, typ, field string) bool {
	t.Helper()
	var st *btf.Struct
	if err := spec.TypeByName(typ, &st); err != nil {
		t.Errorf("the running kernel has no struct %s: %v", typ, err)
		return false
	}
	for _, m := range st.Members {
		if m.Name == field {
			return true
		}
	}
	return false
}
