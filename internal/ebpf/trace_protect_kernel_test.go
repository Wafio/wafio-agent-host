package ebpf

import (
	"encoding/binary"
	"maps"
	"slices"
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

// The kernel keeps an inherited entry across exec only for a protected comm;
// names need root, configured exe paths do not (matchIdentity's rule).
func TestProtectedKernelComms(t *testing.T) {
	s := NewProtectedProcessSet([]string{"my-daemon"}, []string{"/opt/acme/bin/agentd", "/opt/other/sshd"})
	got := s.kernelComms()
	want := map[string]uint8{
		// A configured exe path lifts the root requirement for its basename;
		// the refresh still verifies the inode.
		"sshd":            0,
		"sshd-session":    protectedCommRootOnly,
		"sshd-auth":       protectedCommRootOnly,
		"systemd":         protectedCommRootOnly,
		"systemd-journal": protectedCommRootOnly, // truncated to TASK_COMM_LEN-1
		"systemd-executo": protectedCommRootOnly, // the systemd 255 helper, truncated
		"wafio-waf-agent": 0,                     // runs as a service account
		"containerd":      protectedCommRootOnly,
		"dockerd":         protectedCommRootOnly,
		"kubelet":         protectedCommRootOnly,
		"my-daemon":       protectedCommRootOnly,
		"agentd":          0,
	}
	plain := make(map[string]uint8, len(got))
	for k, v := range got {
		plain[commKeyString(k)] = v
	}
	if !maps.Equal(plain, want) {
		t.Fatalf("kernel comms:\n got %v\nwant %v", plain, want)
	}
	if len(got) > maxProtectedComms {
		t.Fatalf("%d comms exceed the map capacity %d", len(got), maxProtectedComms)
	}
}

func commKeyString(k [taskCommLen]byte) string {
	n := slices.Index(k[:], 0)
	if n < 0 {
		n = len(k)
	}
	return string(k[:n])
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
		if got := protectedInheritBudget(entries); got != want {
			t.Errorf("budget(%d) = %d, want %d", entries, got, want)
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
	if !slices.Equal(got, []protectedTGID{{300, 1300}}) {
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
