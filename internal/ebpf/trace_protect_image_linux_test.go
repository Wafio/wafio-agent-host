//go:build linux

package ebpf

import (
	"encoding/binary"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// maybeSkipNoGeneration skips a test on a filesystem that does not report an
// inode generation: imageIdentity rightly refuses such a file (tmpfs before
// 6.x, procfs).
func maybeSkipNoGeneration(t *testing.T, path string) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }() // read-only descriptor
	if _, err := unix.IoctlGetUint32(fd, fsIocGetVersion); err != nil {
		t.Skipf("the filesystem of %s reports no inode generation: %v", path, err)
	}
}

// The identity userspace builds is the one the kernel sees: /proc/<pid>/maps
// prints inode->i_sb->s_dev and inode->i_ino of a mapped file, the very fields
// the exec program reads from mm->exe_file->f_inode.
func TestImageIdentityMatchesKernelView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	maybeSkipNoGeneration(t, path)

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

	key, ok := imageIdentity(path, "/proc/self/mountinfo")
	if !ok {
		t.Fatal("imageIdentity found no identity for a regular file")
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
	if again, ok := imageIdentity(link, "/proc/self/mountinfo"); !ok || again != key {
		t.Fatalf("hard link identity %v (ok %t), want %v", again, ok, key)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(filepath.Dir(path), "copy")
	if err := os.WriteFile(copyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if other, ok := imageIdentity(copyPath, "/proc/self/mountinfo"); !ok || other == key {
		t.Fatalf("copy identity %v (ok %t) equals the original", other, ok)
	}
}

// Every failure means no identity: the file is not trusted.
func TestImageIdentityFailures(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	mountinfo := "/proc/self/mountinfo"
	for name, tc := range map[string]struct{ path, mountinfo string }{
		"missing file":       {filepath.Join(dir, "missing"), mountinfo},
		"directory":          {dir, mountinfo},
		"fifo":               {fifo, mountinfo},
		"no generation":      {"/proc/self/status", mountinfo}, // ENOTTY from the ioctl
		"unreadable mounts":  {regular, filepath.Join(dir, "no-mountinfo")},
		"mount not in table": {regular, regularFile(t, dir, "empty-mountinfo", "")},
	} {
		done := make(chan bool, 1)
		go func() { _, ok := imageIdentity(tc.path, tc.mountinfo); done <- ok }()
		select {
		case ok := <-done:
			if ok {
				t.Errorf("%s: an identity was returned", name)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s: imageIdentity did not return", name)
		}
	}

	// A statx result without the mount ID or the inode, or for another file
	// type, is refused before the mount table is consulted.
	good := unix.Statx_t{Mask: unix.STATX_INO | unix.STATX_MNT_ID, Mode: unix.S_IFREG | 0o644, Ino: 7, Mnt_id: 36}
	devs := map[uint64]uint32{36: 0x10300002}
	if key, ok := imageKeyOf(&good, 5, devs); !ok || key != (protectedImageKey{Ino: 7, Dev: 0x10300002, Gen: 5}) {
		t.Fatalf("good statx: %v %t", key, ok)
	}
	for name, mutate := range map[string]func(*unix.Statx_t){
		"no mount ID in the mask": func(st *unix.Statx_t) { st.Mask &^= unix.STATX_MNT_ID },
		"no inode in the mask":    func(st *unix.Statx_t) { st.Mask &^= unix.STATX_INO },
		"directory":               func(st *unix.Statx_t) { st.Mode = unix.S_IFDIR | 0o755 },
		"symlink":                 func(st *unix.Statx_t) { st.Mode = unix.S_IFLNK | 0o777 },
		"mount not listed":        func(st *unix.Statx_t) { st.Mnt_id = 99 },
	} {
		st := good
		mutate(&st)
		if key, ok := imageKeyOf(&st, 5, devs); ok {
			t.Errorf("%s: identity %v returned", name, key)
		}
	}
}

func regularFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// kernelImages merges the trusted paths, the images of verified processes and
// the files PID 1 holds open, and gives an image seen twice the lower flag.
func TestKernelImagesMergesSources(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string, target string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if target == "" {
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	// PID 1 holds the executor open after a package upgrade replaced it, a
	// socket and a file nobody trusts.
	mk("1/fd/3", "/usr/lib/systemd/systemd-executor (deleted)")
	mk("1/fd/4", "socket:[12345]")
	mk("1/fd/5", "/tmp/not-trusted")

	sshd := protectedImageKey{Ino: 10, Dev: 1, Gen: 1}
	executorOld := protectedImageKey{Ino: 11, Dev: 1, Gen: 1}
	agent := protectedImageKey{Ino: 12, Dev: 1, Gen: 1}
	replaced := protectedImageKey{Ino: 13, Dev: 2, Gen: 4}
	known := map[string]protectedImageKey{
		"/1/root/usr/sbin/sshd":                    sshd,
		"/1/root/usr/lib/systemd/systemd-executor": {Ino: 14, Dev: 1, Gen: 1},
		"/1/root/opt/wafio/wafio-waf-agent":        agent,
		"/1/fd/3":                                  executorOld,
		"/500/exe":                                 replaced, // a sshd running a binary replaced on disk, another namespace
		"/501/exe":                                 agent,    // a verified process of the configured agent path
		"/502/exe":                                 sshd,     // a named process with the image of the path above
	}
	var asked []string
	orig := imageIdentity
	t.Cleanup(func() { imageIdentity = orig })
	imageIdentity = func(statPath, mountinfoPath string) (protectedImageKey, bool) {
		rel := strings.TrimPrefix(statPath, root)
		asked = append(asked, rel+" "+strings.TrimPrefix(mountinfoPath, root))
		if rel == "/500/exe" && mountinfoPath != filepath.Join(root, "500", "mountinfo") {
			t.Errorf("process image read against %s, not its own mountinfo", mountinfoPath)
		}
		k, ok := known[rel]
		return k, ok
	}

	s := NewProtectedProcessSet(nil, nil)
	got := s.kernelImages(root, []protectedTGID{{500, 1, false}, {501, 1, true}, {502, 1, false}, {503, 1, false}})
	want := map[protectedImageKey]uint8{
		sshd:                      protectedImageRootOnly,
		executorOld:               protectedImageRootOnly,
		{Ino: 14, Dev: 1, Gen: 1}: protectedImageRootOnly,
		agent:                     0,
		replaced:                  protectedImageRootOnly,
	}
	if !maps.Equal(got, want) {
		t.Fatalf("images:\n got %v\nwant %v", got, want)
	}
	for _, a := range asked {
		if strings.Contains(a, "not-trusted") || strings.Contains(a, "/1/fd/4") || strings.Contains(a, "/1/fd/5") {
			t.Errorf("an untrusted descriptor was identified: %s", a)
		}
	}

	// An image of a configured path seen again as a named one keeps no root
	// requirement, and an unidentifiable file leaves no key.
	known["/1/root/usr/sbin/sshd"] = agent
	got = s.kernelImages(root, nil)
	if got[agent] != 0 {
		t.Errorf("an image listed with and without the root flag has flags %d, want 0", got[agent])
	}
	if _, ok := got[sshd]; ok {
		t.Errorf("an image nobody lists was returned")
	}
	if got := (*ProtectedProcessSet)(nil).kernelImages(root, nil); len(got) != 0 {
		t.Errorf("nil set returned %v", got)
	}
}

// The watch signals for a file that could be a trusted image, however it
// arrives (a write, a rename into place, an attribute change, a removal), and
// not for any other file in the directory. It refuses to start when no
// directory can be watched.
func TestWatchProtectedImages(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agentd")
	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{exe}, ReplaceDefaults: true})
	w, err := watchProtectedImages(s)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	none := func(what string) {
		t.Helper()
		select {
		case <-w.changed:
			t.Errorf("%s signalled", what)
		case <-time.After(300 * time.Millisecond):
		}
	}
	signal := func(what string) {
		t.Helper()
		select {
		case <-w.changed:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not signal", what)
		}
	}
	write := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("other")
	none("an unrelated file")
	write("agentd.new")
	none("the staging name of an upgrade")
	if err := os.Rename(filepath.Join(dir, "agentd.new"), exe); err != nil {
		t.Fatal(err)
	}
	signal("a rename into place")
	if err := os.Chmod(exe, 0o700); err != nil {
		t.Fatal(err)
	}
	signal("an attribute change")
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	signal("a removal")

	missing := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{filepath.Join(dir, "no", "such", "agentd")}, ReplaceDefaults: true})
	if w2, err := watchProtectedImages(missing); err == nil {
		w2.Close()
		t.Fatal("a watch with no directory to watch started")
	}
}

// TestTraceProtectedImagesMapMatchesAgent reads the compiled object, not the
// kernel: the key the agent writes is the layout the exec program looks up, and
// the map holds what the agent may write. Needs the compiled objects but no
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
	if ms.Type != cebpf.Hash || int(ms.KeySize) != binary.Size(protectedImageKey{}) || ms.ValueSize != 1 || ms.MaxEntries != maxProtectedImages || ms.Flags&bpfFNoPrealloc != 0 {
		t.Errorf("%s: %+v, want a preallocated hash with %d-byte keys, 1-byte values and %d entries", traceMapProtectedImages, ms, binary.Size(protectedImageKey{}), maxProtectedImages)
	}
}
