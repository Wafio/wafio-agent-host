package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// NewProtectedProcessSet merges DefaultProtectedProcessNames with the extra
// names and exact executable paths. Invalid entries (blank, a name containing
// '/', a relative or non-canonical exe path) are ignored.
func NewProtectedProcessSet(extraNames, exePaths []string) *ProtectedProcessSet {
	return NewProtectedProcessSetFromConfig(ProtectedProcessConfig{Names: extraNames, ExePaths: exePaths})
}

// ── Broad Kill policy validation ───────────────────────────────────────────

func TestBroadKillPolicyRequiresAcknowledgement(t *testing.T) {
	broad := []EnforcementPolicy{
		{Name: "no criteria", Action: "kill"},
		{Name: "event only", Action: "kill", EventTypes: []string{"memfd_create"}},
		{Name: "event+severity", Action: "KILL", EventTypes: []string{"connect"}, MinSeverity: "high"},
		{Name: "blank narrowing", Action: "kill", MatchComm: "  ", MatchFilename: " ", MatchDestPort: ""},
		// Present but weak criteria still match most of the host.
		{Name: "short comm", Action: "kill", MatchComm: "nc"},
		{Name: "root uid", Action: "kill", MatchUID: uidPtr(0)},
		{Name: "root path", Action: "kill", MatchFilename: "/"},
		{Name: "system dir", Action: "kill", MatchFilename: "/usr/"},
	}
	for _, p := range broad {
		if err := ValidateEnforcementPolicy(p); err == nil {
			t.Errorf("%s: broad kill policy accepted without acknowledgement", p.Name)
		}
		p.KillAcknowledged = true
		if err := ValidateEnforcementPolicy(p); err != nil {
			t.Errorf("%s: acknowledged broad kill rejected: %v", p.Name, err)
		}
	}

	narrowed := []EnforcementPolicy{
		{Name: "comm", Action: "kill", MatchComm: "ncat"},
		{Name: "filename", Action: "kill", MatchFilename: "/dev/shm/"},
		{Name: "uid", Action: "kill", MatchUID: uidPtr(1000)},
		{Name: "port", Action: "kill", EventTypes: []string{"connect"}, MatchDestPort: "4444"},
		{Name: "ip", Action: "kill", MatchDestIP: "192.0.2.1"},
	}
	for _, p := range narrowed {
		if err := ValidateEnforcementPolicy(p); err != nil {
			t.Errorf("%s: narrowed kill rejected: %v", p.Name, err)
		}
	}

	for _, action := range []string{"monitor", "alert", "simulate", ""} {
		if err := ValidateEnforcementPolicy(EnforcementPolicy{Name: "broad " + action, Action: action}); err != nil {
			t.Errorf("non-kill action %q needs no acknowledgement: %v", action, err)
		}
	}
}

func TestDowngradeUnacknowledgedBroadKill(t *testing.T) {
	p := EnforcementPolicy{Name: "broad", Action: "kill", EventTypes: []string{"execve"}}
	if !DowngradeUnacknowledgedBroadKill(&p) || p.Action != "alert" {
		t.Fatalf("broad unacknowledged kill not downgraded: %+v", p)
	}
	if err := ValidateEnforcementPolicy(p); err != nil {
		t.Fatalf("downgraded policy must validate: %v", err)
	}
	for _, keep := range []EnforcementPolicy{
		{Name: "acked", Action: "kill", KillAcknowledged: true},
		{Name: "narrow", Action: "kill", MatchComm: "ncat"},
		{Name: "alert", Action: "alert"},
	} {
		orig := keep.Action
		if DowngradeUnacknowledgedBroadKill(&keep) || keep.Action != orig {
			t.Errorf("%s: must be left unchanged, got %+v", keep.Name, keep)
		}
	}
}

// The authoritative snapshot path must apply the same rule as single CRUD.
func TestReplacePoliciesRejectsUnacknowledgedBroadKill(t *testing.T) {
	pe := NewPolicyEngine()
	err := pe.ReplacePolicies([]EnforcementPolicy{{ID: 5, Name: "broad", Enabled: true, Action: "kill", EventTypes: []string{"execve"}}})
	if err == nil {
		t.Fatal("snapshot with unacknowledged broad kill accepted")
	}
	if len(pe.ListPolicies()) != 0 {
		t.Fatal("rejected snapshot was partially applied")
	}
}

// ── Protected-process set ──────────────────────────────────────────────────

// hostRoot is a verified host binary running as root, the identity of a real
// system daemon.
func hostRoot(exe, comm string) procIdentity {
	return procIdentity{exe: exe, comm: comm, hostExe: triYes, hostMntNS: triYes, rootUIDs: triYes}
}

func TestProtectedSetMatchIdentity(t *testing.T) {
	s := NewProtectedProcessSet([]string{"my-daemon", "bad/name", " "}, []string{"/opt/acme/bin/agentd", "relative/exe"})
	with := func(id procIdentity, f func(*procIdentity)) procIdentity { f(&id); return id }
	// The WAF agent runs as a service account, so it is never root.
	const wafExe, wafUnit = "/usr/local/bin/wafio-waf-agent", "/system.slice/wafio-waf-agent.service"
	const wafBundleExe = "/opt/wafio/wafio-waf-agent" // where the WAF agent bundle installer puts it
	// systemd-networkd runs as its own user, in its own unit, from /usr/lib/systemd or /lib/systemd.
	const netExe, netLibExe, netUnit = "/usr/lib/systemd/systemd-networkd", "/lib/systemd/systemd-networkd", "/system.slice/systemd-networkd.service"
	networkd := func(exe, cgroup string) procIdentity {
		return with(hostRoot(exe, "systemd-network"), func(i *procIdentity) { i.rootUIDs = triNo; i.cgroup = cgroup })
	}
	waf := func(exe, cgroup string) procIdentity {
		// The shipped unit gives the agent its own mount namespace.
		return with(hostRoot(exe, "wafio-waf-agent"), func(i *procIdentity) { i.rootUIDs = triNo; i.hostMntNS = triNo; i.cgroup = cgroup })
	}
	for _, tc := range []struct {
		name string
		id   procIdentity
		want bool
	}{
		{"sshd", hostRoot("/usr/sbin/sshd", "sshd"), true},
		{"systemd", hostRoot("/usr/lib/systemd/systemd", "systemd"), true},
		{"journald", hostRoot("/usr/lib/systemd/systemd-journald", "systemd-journal"), true},
		{"containerd", hostRoot("/usr/bin/containerd", "containerd"), true},
		{"kubelet", hostRoot("/usr/local/bin/kubelet", "kubelet"), true},
		{"extra name", hostRoot("/usr/bin/my-daemon", "my-daemon"), true},
		{"configured exe", hostRoot("/opt/acme/bin/agentd", "agentd"), true},
		// Binary replaced by an upgrade: its inode is gone, the mount namespace decides.
		{"deleted host ns", hostRoot("/usr/sbin/sshd (deleted)", "sshd"), true},
		{"deleted other ns", with(hostRoot("/usr/sbin/sshd (deleted)", "sshd"), func(i *procIdentity) { i.hostMntNS = triNo }), false},
		{"deleted ns unknown", with(hostRoot("/usr/sbin/sshd (deleted)", "sshd"), func(i *procIdentity) { i.hostMntNS = triUnknown }), false},
		// Container image (or any other file) at a protected path: not the host binary.
		{"container sshd", with(hostRoot("/usr/sbin/sshd", "sshd"), func(i *procIdentity) { i.hostExe = triNo; i.hostMntNS = triNo }), false},
		{"host binary unverified", with(hostRoot("/usr/sbin/sshd", "sshd"), func(i *procIdentity) { i.hostExe = triUnknown }), false},
		// Genuine binary started by an unprivileged user, or with an injected library.
		{"non-root sshd", with(hostRoot("/usr/sbin/sshd", "sshd"), func(i *procIdentity) { i.rootUIDs = triNo }), false},
		{"uid unknown", with(hostRoot("/usr/sbin/sshd", "sshd"), func(i *procIdentity) { i.rootUIDs = triUnknown }), false},
		{"preloaded sshd", with(hostRoot("/usr/sbin/sshd", "sshd"), func(i *procIdentity) { i.preload = true }), false},
		{"preloaded configured exe", with(hostRoot("/opt/acme/bin/agentd", "agentd"), func(i *procIdentity) { i.preload = true }), false},
		// A configured exact path may run as a service user.
		{"configured exe non-root", with(hostRoot("/opt/acme/bin/agentd", "agentd"), func(i *procIdentity) { i.rootUIDs = triNo }), true},
		// A protected NAME outside a system directory is not trusted.
		{"tmp sshd", hostRoot("/tmp/sshd", "sshd"), false},
		{"cache dockerd", hostRoot("/home/user/.cache/dockerd", "dockerd"), false},
		// comm is attacker-settable: ignored whenever the exe is known.
		{"python as sshd", hostRoot("/usr/bin/python3", "sshd"), false},
		{"bash", hostRoot("/usr/bin/bash", "bash"), false},
		// exe unknown (unreadable link): comm is accepted only for a kernel
		// thread in the host mount namespace. A zombie leader whose threads
		// renamed themselves (prctl) has no exe and no ns/mnt either, and must
		// never be protected by its chosen name.
		{"comm sshd kernel thread", procIdentity{comm: "sshd", kthread: triYes, hostMntNS: triYes}, true},
		{"comm truncated journald kernel thread", procIdentity{comm: "systemd-journal", kthread: triYes, hostMntNS: triYes}, true},
		{"comm sshd zombie leader", procIdentity{comm: "sshd"}, false},
		{"comm dockerd not a kernel thread", procIdentity{comm: "dockerd", kthread: triNo, hostMntNS: triYes}, false},
		{"comm kernel thread ns unknown", procIdentity{comm: "sshd", kthread: triYes}, false},
		{"comm configured", procIdentity{comm: "agentd"}, false},
		{"comm sshd other ns", procIdentity{comm: "sshd", hostMntNS: triNo}, false},
		{"comm bash", procIdentity{comm: "bash"}, false},
		{"nothing", procIdentity{}, false},
		// The WAF agent counts only inside its own system unit: the path and the
		// inode are not enough, because any local user can run the genuine binary.
		{"waf agent in its unit", waf(wafExe, wafUnit), true},
		{"waf agent deleted image in its unit", waf(wafExe+" (deleted)", wafUnit), true},
		{"waf agent deleted image in a session scope", waf(wafExe+" (deleted)", "/user.slice/user-1000.slice/session-3.scope"), false},
		{"waf agent deleted image cgroup unreadable", waf(wafExe+" (deleted)", ""), false},
		{"waf agent in a session scope", waf(wafExe, "/user.slice/user-1000.slice/session-3.scope"), false},
		{"waf agent in a user unit of the same name", waf(wafExe, "/user.slice/user-1000.slice/user@1000.service/app.slice/wafio-waf-agent.service"), false},
		{"waf agent in a sub-cgroup", waf(wafExe, wafUnit+"/sub"), false},
		{"waf agent cgroup unreadable", waf(wafExe, ""), false},
		{"waf agent preloaded", with(waf(wafExe, wafUnit), func(i *procIdentity) { i.preload = true }), false},
		{"waf agent copy in tmp", waf("/tmp/wafio-waf-agent", wafUnit), false},
		{"bundle waf agent in its unit", waf(wafBundleExe, wafUnit), true},
		{"bundle waf agent deleted image in its unit", waf(wafBundleExe+" (deleted)", wafUnit), true},
		{"bundle waf agent in a session scope", waf(wafBundleExe, "/user.slice/user-1000.slice/session-3.scope"), false},
		{"bundle waf agent cgroup unreadable", waf(wafBundleExe, ""), false},
		{"other binary in /opt/wafio", waf("/opt/wafio/other", wafUnit), false},
		{"waf agent other image", with(waf(wafExe, wafUnit), func(i *procIdentity) { i.hostExe = triNo }), false},
		// systemd 255 and later: the helper between PID 1 and the service, as root.
		{"systemd-executor", hostRoot("/usr/lib/systemd/systemd-executor", "systemd-executo"), true},
		{"systemd-executor non-root", with(hostRoot("/usr/lib/systemd/systemd-executor", "systemd-executo"), func(i *procIdentity) { i.rootUIDs = triNo }), false},
		// nginx: the master runs as root, a worker as the configured user.
		{"nginx master", hostRoot("/usr/sbin/nginx", "nginx"), true},
		{"nginx worker", with(hostRoot("/usr/sbin/nginx", "nginx"), func(i *procIdentity) { i.rootUIDs = triNo }), false},
		{"nginx copy in tmp", hostRoot("/tmp/nginx", "nginx"), false},
		{"nginx container image", with(hostRoot("/usr/sbin/nginx", "nginx"), func(i *procIdentity) { i.hostExe = triNo; i.hostMntNS = triNo }), false},
		{"nginx preloaded", with(hostRoot("/usr/sbin/nginx", "nginx"), func(i *procIdentity) { i.preload = true }), false},
		{"python as nginx", hostRoot("/usr/bin/python3", "nginx"), false},
		// systemd-networkd counts only in its own unit, at either install path, as its own user.
		{"networkd in its unit", networkd(netExe, netUnit), true},
		{"networkd in its unit, unmerged /usr", networkd(netLibExe, netUnit), true},
		{"networkd deleted image in its unit", networkd(netExe+" (deleted)", netUnit), true},
		{"networkd in a session scope", networkd(netExe, "/user.slice/user-1000.slice/session-3.scope"), false},
		{"networkd in a user unit of the same name", networkd(netExe, "/user.slice/user-1000.slice/user@1000.service/app.slice/systemd-networkd.service"), false},
		{"networkd in a sub-cgroup", networkd(netExe, netUnit+"/sub"), false},
		{"networkd cgroup unreadable", networkd(netExe, ""), false},
		{"networkd deleted image in a session scope", networkd(netExe+" (deleted)", "/user.slice/user-1000.slice/session-3.scope"), false},
		{"networkd preloaded", with(networkd(netExe, netUnit), func(i *procIdentity) { i.preload = true }), false},
		{"networkd copy in tmp", networkd("/tmp/systemd-networkd", netUnit), false},
		{"networkd other image", with(networkd(netExe, netUnit), func(i *procIdentity) { i.hostExe = triNo }), false},
		{"other systemd binary in its unit", networkd("/usr/lib/systemd/systemd-resolved", netUnit), false},
		// Rejected configuration entries never match.
		{"bad name", hostRoot("/usr/bin/bad/name", "name"), false},
		{"relative exe", hostRoot("relative/exe", "exe"), false},
	} {
		if got, _ := s.matchIdentity(tc.id); got != tc.want {
			t.Errorf("%s: matchIdentity(%+v) = %v, want %v", tc.name, tc.id, got, tc.want)
		}
	}
	var nilSet *ProtectedProcessSet
	if got, _ := nilSet.matchIdentity(hostRoot("/usr/sbin/sshd", "sshd")); got {
		t.Error("nil set protected a process")
	}
}

// fakeProcEntry describes one fake /proc/<pid>.
type fakeProcEntry struct {
	exe, comm string
	uid       string // "0" = root in every Uid field; "" = no status file
	env       string // NUL-separated environ
	mntns     string // ns/mnt link text; "" = none
	hostExe   bool   // the fake host-binary check reports a match
	start     uint64 // stat starttime ticks; 0 = no stat file (unless kthread)
	kthread   bool   // stat flags carry PF_KTHREAD
	cgroup    string // /proc/<pid>/cgroup content; "" = no file
}

// fakeProc builds a /proc-like tree: <pid>/exe symlink (dangling is fine,
// only the link text is read), comm, status, environ, ns/mnt and stat. The
// host-binary check is replaced for the test's duration by a marker file,
// since a symlink in a temp dir cannot stand in for /proc's magic exe link.
func fakeProc(t *testing.T, entries map[uint32]fakeProcEntry) string {
	t.Helper()
	root := t.TempDir()
	write := func(p, data string) {
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for pid, e := range entries {
		dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))
		if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		if e.exe != "" {
			if err := os.Symlink(e.exe, filepath.Join(dir, "exe")); err != nil {
				t.Fatal(err)
			}
		}
		if e.comm != "" {
			write(filepath.Join(dir, "comm"), e.comm+"\n")
		}
		if e.uid != "" {
			write(filepath.Join(dir, "status"), "Name:\t"+e.comm+"\nUid:\t"+e.uid+"\t"+e.uid+"\t"+e.uid+"\t"+e.uid+"\nGid:\t0\t0\t0\t0\n")
		}
		write(filepath.Join(dir, "environ"), e.env)
		if e.cgroup != "" {
			write(filepath.Join(dir, "cgroup"), e.cgroup)
		}
		if e.mntns != "" {
			if err := os.Symlink(e.mntns, filepath.Join(dir, "ns", "mnt")); err != nil {
				t.Fatal(err)
			}
		}
		if e.hostExe {
			write(filepath.Join(dir, "fake_host_exe"), "")
		}
		if e.start != 0 || e.kthread {
			var flags uint64
			if e.kthread {
				flags = pfKthread
			}
			write(filepath.Join(dir, "stat"), string(statLineFlags(e.comm, e.start, flags)))
		}
	}
	orig := hostExeCheck
	hostExeCheck = func(_, dir, _ string) tri {
		_, err := os.Stat(filepath.Join(dir, "fake_host_exe"))
		return triOf(err == nil)
	}
	t.Cleanup(func() { hostExeCheck = orig })
	return root
}

const hostNS = "mnt:[4026531840]"

// hostDaemon is a verified root host process in the host mount namespace.
func hostDaemon(exe, comm string, start uint64) fakeProcEntry {
	return fakeProcEntry{exe: exe, comm: comm, uid: "0", mntns: hostNS, hostExe: true, start: start}
}

func TestProtectedPIDReasonGuards(t *testing.T) {
	root := fakeProc(t, map[uint32]fakeProcEntry{
		1:   hostDaemon("/usr/lib/systemd/systemd", "systemd", 1),
		200: hostDaemon("/usr/sbin/sshd", "sshd", 500),
		201: {exe: "/usr/bin/curl", comm: "curl", uid: "0", mntns: hostNS},
		// No exe, host namespace, not a kernel thread: a name alone is not enough.
		202: {comm: "dockerd", mntns: hostNS, start: 502},
		// Container process whose image carries /usr/sbin/sshd.
		203: {exe: "/usr/sbin/sshd", comm: "sshd", uid: "0", mntns: "mnt:[4026532999]"},
		// Genuine host sshd started by an unprivileged user with an injected library.
		204: {exe: "/usr/sbin/sshd", comm: "sshd", uid: "1000", mntns: hostNS, hostExe: true, env: "HOME=/home/u\x00LD_PRELOAD=/tmp/x.so\x00"},
		205: {exe: "/usr/sbin/sshd", comm: "sshd", uid: "0", mntns: hostNS, hostExe: true, env: "LD_PRELOAD=/tmp/x.so\x00"},
		// Kernel-thread-like entry (no exe) with a protected comm in another namespace.
		206: {comm: "sshd", mntns: "mnt:[4026532999]", kthread: true},
		// A real kernel thread named like a daemon, host namespace.
		207: {comm: "sshd", mntns: hostNS, kthread: true},
	})
	s := NewProtectedProcessSet(nil, nil)
	const self = 4242
	for _, pid := range []uint32{0, 1, self, 200, 207} {
		if s.protectedPIDReason(root, pid, self, "") == "" {
			t.Errorf("pid %d not protected", pid)
		}
	}
	for _, pid := range []uint32{201, 202, 203, 204, 205, 206} {
		if reason := s.protectedPIDReason(root, pid, self, "sshd"); reason != "" {
			t.Errorf("pid %d must be killable, refused: %s", pid, reason)
		}
	}
	// Process gone from /proc: nothing to verify and nothing left to kill —
	// the event comm alone never protects (pidfd_open then reports the exit).
	if reason := s.protectedPIDReason(root, 999, self, "sshd"); reason != "" {
		t.Errorf("vanished process protected by its event comm: %s", reason)
	}
	if reason := s.protectedPIDReason(root, 999, self, "curl"); reason != "" {
		t.Errorf("vanished unprotected process refused: %s", reason)
	}
}

func TestScanProtectedTGIDs(t *testing.T) {
	const self = 300
	root := fakeProc(t, map[uint32]fakeProcEntry{
		1:    hostDaemon("/usr/lib/systemd/systemd", "systemd", 1), // kernel guards pid 1 already
		100:  hostDaemon("/usr/sbin/sshd", "sshd", 1100),
		101:  {exe: "/tmp/sshd", comm: "sshd", uid: "0", mntns: hostNS, start: 1101},
		102:  {comm: "containerd", mntns: hostNS, start: 1102},          // no exe: never in the kernel set
		107:  {comm: "sshd", mntns: hostNS, kthread: true, start: 1107}, // kernel thread: cannot be signalled anyway
		103:  {exe: "/usr/bin/python3", comm: "sshd", uid: "0", mntns: hostNS, start: 1103},
		104:  hostDaemon("/usr/bin/dockerd", "dockerd", 1104),
		105:  {exe: "/usr/sbin/sshd", comm: "sshd", uid: "0", mntns: "mnt:[4026532999]", start: 1105},
		106:  {exe: "/usr/bin/kubelet", comm: "kubelet", uid: "0", mntns: hostNS, hostExe: true}, // no stat: no kernel entry
		self: hostDaemon("/usr/sbin/sshd", "sshd", 1300),                                         // the agent is guarded by agent_pid
		108:  {exe: "/usr/local/bin/wafio-waf-agent", comm: "wafio-waf-agent", uid: "999", mntns: hostNS, hostExe: true, start: 1108, cgroup: "0::/system.slice/wafio-waf-agent.service\n"},
		109:  {exe: "/usr/local/bin/wafio-waf-agent", comm: "wafio-waf-agent", uid: "1000", mntns: hostNS, hostExe: true, start: 1109, cgroup: "0::/user.slice/user-1000.slice/session-3.scope\n"},
		110:  {exe: "/usr/local/bin/wafio-waf-agent", comm: "wafio-waf-agent", uid: "1000", mntns: hostNS, hostExe: true, start: 1110},
		111:  {exe: "/usr/bin/cat", comm: "cat", uid: "1000", mntns: hostNS, hostExe: true, start: 1111},
		112:  {exe: "/usr/bin/python3", comm: "wafio-waf-agent", uid: "999", mntns: hostNS, hostExe: true, start: 1112, cgroup: "0::/system.slice/wafio-waf-agent.service\n"},
		113:  {exe: "/tmp/wafio-waf-agent", comm: "wafio-waf-agent", uid: "999", mntns: hostNS, hostExe: true, start: 1113, cgroup: "0::/system.slice/wafio-waf-agent.service\n"},
		114:  {exe: "/opt/wafio/wafio-waf-agent", comm: "wafio-waf-agent", uid: "999", mntns: hostNS, hostExe: true, start: 1114, cgroup: "0::/system.slice/wafio-waf-agent.service\n"},
		115:  {exe: "/opt/wafio/wafio-waf-agent", comm: "wafio-waf-agent", uid: "1000", mntns: hostNS, hostExe: true, start: 1115, cgroup: "0::/user.slice/user-1000.slice/session-3.scope\n"},
	})
	got, err := NewProtectedProcessSet(nil, nil).scanProtectedTGIDs(root, self)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(got, func(a, b protectedTGID) int { return int(a.tgid) - int(b.tgid) })
	// Only 108 and 114 get the kernel entry that marks their events verified:
	// the WAF agent in its unit as a service account, installed under
	// /usr/local/bin or /opt/wafio. 109 and 115 run it from a session scope,
	// 110 has no readable cgroup, 111 is another program, and 112 and 113 only
	// carry its name (an interpreter, a copy in /tmp) from inside the unit.
	const wafUnit = "wafio-waf-agent.service"
	want := []protectedTGID{
		{tgid: 100, startTicks: 1100},
		{tgid: 104, startTicks: 1104},
		{tgid: 108, startTicks: 1108, configured: true, unit: wafUnit},
		{tgid: 114, startTicks: 1114, configured: true, unit: wafUnit},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("protected tgids %v, want %v", got, want)
	}
	if _, err := NewProtectedProcessSet(nil, nil).scanProtectedTGIDs(filepath.Join(root, "missing"), self); err == nil {
		t.Fatal("missing proc root not reported")
	}
}

// A host agent confined to a capability subset without CAP_SYS_PTRACE gets
// EPERM on /proc/<pid>/exe of every root daemon (cap_ptrace_access_check):
// the scan then matches nothing, silently. procIdentityDenied detects that
// from pid 1's exe link; only a permission error counts.
func TestProcIdentityDenied(t *testing.T) {
	readable := fakeProc(t, map[uint32]fakeProcEntry{1: hostDaemon("/usr/lib/systemd/systemd", "systemd", 1)})
	if procIdentityDenied(readable) {
		t.Fatal("readable pid 1 exe reported as denied")
	}
	if procIdentityDenied(filepath.Join(readable, "missing")) {
		t.Fatal("a missing pid 1 is not a permission failure")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory permission used to simulate EPERM")
	}
	denied := fakeProc(t, map[uint32]fakeProcEntry{
		1:   hostDaemon("/usr/lib/systemd/systemd", "systemd", 1),
		200: hostDaemon("/usr/sbin/sshd", "sshd", 500),
	})
	s := NewProtectedProcessSet(nil, nil)
	if got, err := s.scanProtectedTGIDs(denied, 4242); err != nil || len(got) != 1 {
		t.Fatalf("readable scan = %v, %v; want sshd", got, err)
	}
	for _, pid := range []string{"1", "200"} {
		dir := filepath.Join(denied, pid)
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	}
	if !procIdentityDenied(denied) {
		t.Fatal("unreadable pid 1 exe not reported as denied")
	}
	// What the scan sees in that state: no identity, so no match — the
	// failure the self-check must name instead of reporting 0 as healthy.
	if got, err := s.scanProtectedTGIDs(denied, 4242); err != nil || len(got) != 0 {
		t.Fatalf("scan under denial = %v, %v", got, err)
	}
}

func TestSystemdCgroup(t *testing.T) {
	const unit = "/system.slice/wafio-waf-agent.service"
	dir := t.TempDir()
	file := filepath.Join(dir, "cgroup")
	for name, tc := range map[string]struct{ data, want string }{
		"cgroup v2":          {"0::" + unit + "\n", unit},
		"hybrid":             {"12:cpu,cpuacct:/system.slice/other.service\n1:name=systemd:" + unit + "\n0::" + unit + "\n", unit},
		"v1 only":            {"12:cpu,cpuacct:/user.slice\n1:name=systemd:" + unit + "\n", unit},
		"v1 without systemd": {"4:pids:/system.slice/x.service\n", ""},
		"v2 root":            {"0::/\n", "/"},
		"empty":              {"", ""},
		"malformed":          {"garbage\n::\n0:\n1:name=systemd\n", ""},
	} {
		if err := os.WriteFile(file, []byte(tc.data), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := systemdCgroup(file); got != tc.want {
			t.Errorf("%s: systemdCgroup(%q) = %q, want %q", name, tc.data, got, tc.want)
		}
	}
	if got := systemdCgroup(filepath.Join(dir, "missing")); got != "" {
		t.Errorf("missing file: got %q", got)
	}
}

func TestLoaderInjectionAndRootUIDs(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "environ")
	for data, want := range map[string]bool{
		"":                                      false,
		"PATH=/usr/bin\x00HOME=/root\x00":       false,
		"LD_PRELOAD=\x00":                       false, // empty value injects nothing
		"PATH=/usr/bin\x00LD_PRELOAD=/x.so\x00": true,
		"LD_AUDIT=/x.so":                        true,
		"LD_LIBRARY_PATH=/tmp\x00":              true,
	} {
		if err := os.WriteFile(env, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := loaderInjection(env); got != want {
			t.Errorf("loaderInjection(%q) = %v, want %v", data, got, want)
		}
	}
	status := filepath.Join(dir, "status")
	for data, want := range map[string]tri{
		"Uid:\t0\t0\t0\t0\n":    triYes,
		"Uid:\t1000\t0\t0\t0\n": triNo,
		"Uid:\t0\t0\t0\t1000\n": triNo,
		"Name:\tx\n":            triUnknown,
	} {
		if err := os.WriteFile(status, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := rootUIDs(status); got != want {
			t.Errorf("rootUIDs(%q) = %v, want %v", data, got, want)
		}
	}
	if rootUIDs(filepath.Join(dir, "missing")) != triUnknown {
		t.Error("unreadable status must be unknown")
	}
}

// ── /proc/<pid>/stat start time ────────────────────────────────────────────

// statLine builds a stat record whose field 22 is starttime; fields 3..21 are
// filler. comm may contain spaces and parentheses, as the kernel allows.
func statLine(comm string, starttime uint64) []byte {
	return statLineFlags(comm, starttime, 9)
}

// statLineFlags is statLine with field 9 (flags) set.
func statLineFlags(comm string, starttime, flags uint64) []byte {
	fields := []string{"S"}
	for i := 4; i <= 21; i++ {
		if i == 9 {
			fields = append(fields, strconv.FormatUint(flags, 10))
			continue
		}
		fields = append(fields, strconv.Itoa(i))
	}
	fields = append(fields, strconv.FormatUint(starttime, 10), "1000", "200")
	return []byte("4321 (" + comm + ") " + strings.Join(fields, " ") + "\n")
}

func TestParseProcStatStartTicks(t *testing.T) {
	for _, comm := range []string{"sleep", "a b", "x) S 1 2 (y", ")"} {
		got, err := parseProcStatStartTicks(statLine(comm, 98765))
		if err != nil || got != 98765 {
			t.Errorf("comm %q: got %d, %v", comm, got, err)
		}
	}
	for _, bad := range []string{"", "4321 sleep S 1", "4321 (sleep) S 1 2 3", "4321 (sleep) " + strings.Repeat("x ", 25)} {
		if _, err := parseProcStatStartTicks([]byte(bad)); err == nil {
			t.Errorf("malformed stat %q accepted", bad)
		}
	}
}

func TestVerifyStartTime(t *testing.T) {
	const ticks = 98765
	stat := statLine("victim", ticks)
	// start_boottime anywhere inside the same 10ms tick converts to the same
	// USER_HZ value (nsec_to_clock_t truncates).
	for _, ns := range []uint64{ticks * 10_000_000, ticks*10_000_000 + 9_999_999} {
		if err := verifyStartTime(stat, ns); err != nil {
			t.Errorf("ns %d: %v", ns, err)
		}
	}
	for _, ns := range []uint64{(ticks + 1) * 10_000_000, ticks*10_000_000 - 1} {
		if err := verifyStartTime(stat, ns); !errors.Is(err, errStartTimeMismatch) {
			t.Errorf("ns %d: want mismatch, got %v", ns, err)
		}
	}
	if err := verifyStartTime(stat, 0); err == nil {
		t.Error("missing event identity verified")
	}
	if err := verifyStartTime([]byte("garbage"), ticks*10_000_000); err == nil {
		t.Error("malformed stat verified")
	}
}
