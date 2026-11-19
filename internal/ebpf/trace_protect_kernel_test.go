package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// OpenSSH >= 9.8 runs each connection as sshd-session (and, from 10.0,
// the pre-auth phase as sshd-auth). Without them in the set a broad kill on
// openat/socket/setuid kills every new SSH session.
func TestDefaultProtectedNamesIncludeOpenSSHSplit(t *testing.T) {
	for _, name := range []string{"sshd", "sshd-session", "sshd-auth"} {
		if !slices.Contains(DefaultProtectedProcessNames, name) {
			t.Errorf("DefaultProtectedProcessNames lacks %q", name)
		}
	}
	s := NewProtectedProcessSet(nil, nil)
	for _, exe := range []string{"/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session", "/usr/lib/openssh/sshd-auth"} {
		if ok, _ := s.matchIdentity(hostRoot(exe, "sshd-session")); !ok {
			t.Errorf("verified root %s not protected", exe)
		}
	}
	// The same names outside a trusted directory, or not root, stay killable.
	if ok, _ := s.matchIdentity(hostRoot("/tmp/sshd-session", "sshd-session")); ok {
		t.Error("/tmp/sshd-session protected")
	}
	nonRoot := hostRoot("/usr/lib/openssh/sshd-auth", "sshd-auth")
	nonRoot.rootUIDs = triNo
	if ok, _ := s.matchIdentity(nonRoot); ok {
		t.Error("non-root sshd-auth protected")
	}
}

// The kernel keeps an inherited entry across exec only for a trusted file;
// names need root, configured exe paths do not (matchIdentity's rule), and a
// configured path never frees the same name in another directory.
func TestProtectedImagePaths(t *testing.T) {
	s := NewProtectedProcessSet([]string{"my-daemon"}, []string{"/opt/acme/bin/agentd", "/opt/other/sshd"})
	got := s.imagePaths()
	want := map[string]uint8{
		"/usr/sbin/sshd":                    protectedImageRootOnly,
		"/usr/lib/openssh/sshd-session":     protectedImageRootOnly, // Debian
		"/usr/libexec/openssh/sshd-auth":    protectedImageRootOnly, // Fedora
		"/usr/lib/ssh/sshd-session":         protectedImageRootOnly, // Arch
		"/usr/lib/systemd/systemd-executor": protectedImageRootOnly, // the systemd 255 helper
		"/lib/systemd/systemd-journald":     protectedImageRootOnly,
		"/usr/sbin/nginx":                   protectedImageRootOnly, // the master; a worker is not root
		"/usr/bin/containerd":               protectedImageRootOnly,
		"/usr/local/bin/kubelet":            protectedImageRootOnly,
		"/usr/bin/my-daemon":                protectedImageRootOnly,
		"/opt/acme/bin/agentd":              0,
		"/opt/other/sshd":                   0, // another file than /usr/sbin/sshd
		"/usr/local/bin/wafio-waf-agent":    0, // runs as a service account
		"/opt/wafio/wafio-waf-agent":        0,
		"/usr/lib/systemd/systemd-networkd": 0, // runs as its own user
		"/lib/systemd/systemd-networkd":     0,
	}
	for path, flags := range want {
		if v, ok := got[path]; !ok || v != flags {
			t.Errorf("image path %s: got %d (listed %t), want %d", path, v, ok, flags)
		}
	}
	// A name is searched in the system directories only.
	for _, path := range []string{"/tmp/sshd", "/opt/sshd", "/usr/lib/sshd", "/home/u/nginx"} {
		if _, ok := got[path]; ok {
			t.Errorf("image path %s is listed", path)
		}
	}
	if len(got) > maxProtectedImages {
		t.Fatalf("%d image paths exceed the map capacity %d", len(got), maxProtectedImages)
	}
	// The same path as a name and as a configured exe: the configured entry
	// lifts the root requirement, as in matchIdentity.
	if got := NewProtectedProcessSet(nil, []string{"/usr/sbin/nginx"}).imagePaths()["/usr/sbin/nginx"]; got != 0 {
		t.Errorf("configured /usr/sbin/nginx has flags %d, want 0", got)
	}
	if got := (*ProtectedProcessSet)(nil).imagePaths(); len(got) != 0 {
		t.Errorf("nil set lists %v", got)
	}
}

// Every directory the image set is searched in is a trusted executable
// directory, so an image path never trusts a place a name would not.
func TestProtectedImageDirsAreTrusted(t *testing.T) {
	for _, dir := range protectedImageDirs {
		if !strings.HasSuffix(dir, "/") || !inTrustedExeDir(dir) {
			t.Errorf("image directory %q is not a trusted directory with a trailing slash", dir)
		}
	}
}

// mountinfo field 3 is the superblock device the kernel prints as major:minor;
// BPF reads it as dev_t, MKDEV(major, minor).
func TestMountDevices(t *testing.T) {
	got := mountDevices("" +
		"36 35 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n" +
		"40 36 0:45 / /run rw,nosuid - tmpfs tmpfs rw\n" +
		"41 36 8:1 /sub /mnt rw - btrfs /dev/sda1 rw\n" +
		"malformed\n" +
		"x 36 8:1 / /x rw - ext4 /dev/sda1 rw\n" + // mount ID is not a number
		"42 36 8 / /y rw - ext4 /dev/sda1 rw\n" + // no colon
		"43 36 4096:1 / /z rw - ext4 /dev/sda1 rw\n" + // major beyond 12 bits
		"44 36 1:1048576 / /w rw - ext4 /dev/sda1 rw\n") // minor beyond 20 bits
	want := map[uint64]uint32{36: 0x10300002, 40: 45, 41: 8<<20 | 1}
	if !maps.Equal(got, want) {
		t.Fatalf("mount devices %v, want %v", got, want)
	}
	if _, ok := got[999]; ok {
		t.Fatal("an unknown mount ID has a device")
	}
}

// A refresh writes what is missing or changed before it deletes what is gone,
// so the trusted image of a service that restarts in between is never absent.
func TestApplyProtectedImagesAddsBeforeDeletes(t *testing.T) {
	gone, kept, flipped, added := protectedImageKey{1, 1, 1}, protectedImageKey{2, 1, 1}, protectedImageKey{3, 1, 1}, protectedImageKey{4, 1, 1}
	have := map[protectedImageKey]uint8{gone: 1, kept: 1, flipped: 1}
	want := map[protectedImageKey]uint8{kept: 1, flipped: 0, added: 1}
	var ops []string
	put := func(k protectedImageKey, v uint8) error {
		ops = append(ops, fmt.Sprintf("put %d=%d", k.Ino, v))
		return nil
	}
	del := func(k protectedImageKey) error {
		ops = append(ops, fmt.Sprintf("del %d", k.Ino))
		return nil
	}
	if err := applyProtectedImages(have, want, put, del); err != nil {
		t.Fatal(err)
	}
	if len(ops) != 3 || ops[2] != "del 1" {
		t.Fatalf("operations %v, want the two writes then del 1", ops)
	}
	slices.Sort(ops[:2])
	if ops[0] != "put 3=0" || ops[1] != "put 4=1" {
		t.Fatalf("operations %v: the unchanged key was written or a change is missing", ops)
	}

	// A failed write does not stop the others, and the failures are returned.
	ops = nil
	failing := func(protectedImageKey, uint8) error { return errors.New("full") }
	if err := applyProtectedImages(have, want, failing, del); err == nil || len(ops) != 1 {
		t.Fatalf("err %v, operations %v: the delete must still run after failed writes", err, ops)
	}
}

// The refresh reconciles against what the kernel map actually holds: the
// kernel adds children of protected processes itself, so userspace
// bookkeeping alone would leak those entries until the map is full.
func TestReconcileProtectedEntries(t *testing.T) {
	const scanStart = 1000 // USER_HZ ticks when the /proc scan began
	have := map[uint32]uint64{
		10: 500,  // verified again: keep
		11: 510,  // exited or failed verification before the scan: delete
		12: 1000, // forked by a protected parent as the scan began: keep for the next scan
		13: 1200, // forked after the scan began: keep for the next scan
		14: 600,  // PID reused by a new protected process: rewrite
	}
	want := map[uint32]uint64{
		10: 500,
		14: 900,
		15: 950, // newly verified
	}
	del, put := reconcileProtectedEntries(have, want, scanStart, true)
	slices.Sort(del)
	if !slices.Equal(del, []uint32{11}) {
		t.Errorf("deletes %v, want [11]", del)
	}
	if !maps.Equal(put, map[uint32]uint64{14: 900, 15: 950}) {
		t.Errorf("updates %v", put)
	}

	// Presence-flag objects (value 1) predate kernel inheritance: the scan is
	// the whole truth and no start time exists to guard with.
	del, put = reconcileProtectedEntries(map[uint32]uint64{20: 1, 21: 1}, map[uint32]uint64{20: 1, 22: 1}, scanStart, false)
	if !slices.Equal(del, []uint32{21}) || !maps.Equal(put, map[uint32]uint64{22: 1}) {
		t.Errorf("legacy reconcile: deletes %v updates %v", del, put)
	}
}

// Kernel fork inserts stop at 3/4 of the map so a fork burst
// cannot crowd out the refresh's verified entries.
func TestProtectedInheritBudget(t *testing.T) {
	for entries, want := range map[int]int64{0: 768, 10: 758, 767: 1, 768: 0, 1000: 0, maxProtectedTGIDs: 0} {
		if got := protectedInheritBudget(entries, true); got != want {
			t.Errorf("budget(%d) = %d, want %d", entries, got, want)
		}
		// Without the exec keep by image the kernel inherits nothing.
		if got := protectedInheritBudget(entries, false); got != 0 {
			t.Errorf("budget(%d) without exec keep = %d, want 0", entries, got)
		}
	}
	if maxInheritedFill >= maxProtectedTGIDs || maxInheritedFill <= 0 {
		t.Fatalf("maxInheritedFill %d leaves no headroom in %d", maxInheritedFill, maxProtectedTGIDs)
	}
}

// A non-root process renames every thread to "dockerd"
// (prctl(PR_SET_NAME)) and its leader calls SYS_exit. The zombie leader has
// no readable exe and no ns/mnt, only the chosen comm. It must never be
// protected, never enter the kernel set, and so never get exe_verified.
func TestZombieLeaderRenamedToDaemonIsNotProtected(t *testing.T) {
	const self = 4242
	root := fakeProc(t, map[uint32]fakeProcEntry{
		300: hostDaemon("/usr/bin/dockerd", "dockerd", 1300),
		// The zombie leader: comm, status and stat only.
		301: {comm: "dockerd", uid: "1000", start: 1301},
	})
	s := NewProtectedProcessSet(nil, nil)
	if reason := s.protectedPIDReason(root, 301, self, "dockerd"); reason != "" {
		t.Fatalf("zombie leader named dockerd protected: %s", reason)
	}
	got, err := s.scanProtectedTGIDs(root, self)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []protectedTGID{{300, 1300, false}}) {
		t.Fatalf("kernel set %v, want only the verified dockerd", got)
	}
}

// The kernel marks events of processes in the verified protected set
// (and PID 1). Objects without the field read as unverified.
func TestRawTraceEventExeVerifiedFlag(t *testing.T) {
	data := make([]byte, TraceEventSizeWithIdentity)
	binary.LittleEndian.PutUint32(data[36:40], TraceConnect)
	binary.LittleEndian.PutUint32(data[1432:1436], traceProcProtected)
	raw, err := ParseRawTraceEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if te := raw.ToTraceEvent(0); !te.ExeVerified {
		t.Fatal("protected-process flag not surfaced as exe_verified")
	}
	legacy, err := ParseRawTraceEvent(data[:TraceEventSize])
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ToTraceEvent(0).ExeVerified {
		t.Fatal("an event without the identity extension claimed a verified exe")
	}
}
