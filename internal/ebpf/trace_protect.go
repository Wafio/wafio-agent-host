package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// ────────────────────────────────────────────────────────────────────────────
//  Protected-process set
//
//  A broad Kill policy must never take down the daemons that keep the host
//  reachable and manageable. Every userspace and deferred kill consults this
//  set first; the kernel kill paths consult the trace_protected_tgids map that
//  the TraceManager populates from the same set (when the loaded object has it).
// ────────────────────────────────────────────────────────────────────────────

// DefaultProtectedProcessNames are executable basenames that are never killed
// by enforcement. The agent itself is protected by PID (userspace self-check
// and trace_config.agent_pid in the kernel), not by name. OpenSSH >= 9.8 runs
// each connection as sshd-session and (10.0+) the pre-auth phase as
// sshd-auth. systemd-executor is the helper that systemd 255 and later runs
// as root between PID 1 and the service binary. nginx is the master process,
// which runs as root: its workers run as the configured user and a protected
// name needs root UIDs, so only the master counts, and the control plane can
// tell it loading its TLS key from a worker or another process reading it.
var DefaultProtectedProcessNames = []string{
	"sshd", "sshd-session", "sshd-auth", "systemd", "systemd-journald", "containerd", "dockerd", "kubelet",
	"systemd-executor", "nginx",
}

// DefaultProtectedUnitExes maps a built-in protected executable path to the
// systemd unit it must run in. The WAF agent runs as a service account and
// takes a key file and an engine library from its own configuration, so the
// path and the inode alone would let any local user run the genuine binary
// and be trusted. Only root can put a process into a system.slice cgroup.
// The unit installer puts the binary in /usr/local/bin; the installer in the
// WAF agent bundle puts it in /opt/wafio and points the unit there.
// systemd-networkd runs as its own user (systemd-network) from the same unit
// on every distribution that ships it; the distributions install the binary in
// /usr/lib/systemd or, without a merged /usr, in /lib/systemd. As for the WAF
// agent, the path alone would let any user who can run the binary be trusted.
var DefaultProtectedUnitExes = map[string]string{
	"/usr/local/bin/wafio-waf-agent":    "wafio-waf-agent.service",
	"/opt/wafio/wafio-waf-agent":        "wafio-waf-agent.service",
	"/usr/lib/systemd/systemd-networkd": "systemd-networkd.service",
	"/lib/systemd/systemd-networkd":     "systemd-networkd.service",
}

// trustedExeDirs: a protected NAME only counts when the executable lives in a
// root-owned system location. Otherwise any process could exempt itself from
// enforcement by being called "sshd" (comm is settable via prctl, and a
// basename is free to choose outside these directories). The path is only the
// first filter: matchIdentity also requires the running image to be that host
// file (inode, so a container image's /usr/sbin/sshd does not count), no
// loader injection, and root UIDs for the built-in names.
var trustedExeDirs = []string{
	"/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/",
	"/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/", "/usr/libexec/",
	"/usr/local/sbin/", "/usr/local/bin/", "/snap/",
}

// taskCommLen mirrors TASK_COMM_LEN: the kernel keeps 15 bytes + NUL.
const taskCommLen = 16

// maxProtectedTGIDs must match max_entries of trace_protected_tgids in
// wafio_trace.c. Extra matches are logged and left to the userspace guard.
const maxProtectedTGIDs = 1024

// maxProtectedComms must match max_entries of trace_protected_comms in
// wafio_trace.c. The configuration bounds (maxProtectedEntries names and exe
// paths plus the built-ins) stay well below it.
const maxProtectedComms = 1024

// protectedCommRootOnly mirrors TRACE_PROTECTED_COMM_ROOT: an exec keeps an
// inherited kernel entry for this comm only when the real UID is 0.
const protectedCommRootOnly uint8 = 1

// Slots of the trace_protected_budget array (TRACE_PROTECTED_BUDGET_SLOT and
// TRACE_PROTECTED_REFUSED_SLOT in wafio_trace.c).
const (
	protectedBudgetSlot  uint32 = 0
	protectedRefusedSlot uint32 = 1
)

// maxInheritedFill: the kernel stops inserting forked children once the map
// would hold this many entries (3/4 of maxProtectedTGIDs), so the refresh's
// verified inserts always fit.
const maxInheritedFill = maxProtectedTGIDs * 3 / 4

// protectedInheritBudget is how many fork inserts the kernel may make until
// the next refresh, when the map holds entries now. Deletes by the kernel in
// between are not credited back: the budget only shrinks until the refresh
// recomputes it.
func protectedInheritBudget(entries int) int64 {
	if entries >= maxInheritedFill {
		return 0
	}
	return int64(maxInheritedFill - entries)
}

// ProtectedProcessSet decides whether a process may be targeted by enforcement.
// Immutable after construction; safe for concurrent use.
type ProtectedProcessSet struct {
	names map[string]struct{} // executable basenames (full, untruncated)
	comms map[string]struct{} // same names truncated to TASK_COMM_LEN-1
	exes  map[string]struct{} // exact executable paths
	units map[string]string   // exe path -> system unit it must run in

	defaultsReplaced bool // DefaultProtectedProcessNames dropped by configuration
}

func truncateComm(name string) string {
	if len(name) > taskCommLen-1 {
		return name[:taskCommLen-1]
	}
	return name
}

// tri is a three-valued check result: a check that could not be performed is
// neither a pass nor a fail.
type tri int8

const (
	triUnknown tri = iota
	triYes
	triNo
)

func triOf(ok bool) tri {
	if ok {
		return triYes
	}
	return triNo
}

// procIdentity is what the protected-set decision needs to know about one
// process. exe and comm are always read; the verification fields are read only
// for a process whose exe names a protected binary (see readProcIdentity).
type procIdentity struct {
	exe  string // /proc/<pid>/exe link text; "" when unreadable
	comm string

	// hostExe: the running image is the very file at the same path in the
	// host's mount namespace (same device and inode). A path string alone is
	// not identity: in a container /usr/sbin/sshd is whatever the image put
	// there.
	hostExe tri
	// hostMntNS: the process shares pid 1's mount namespace. Used for a
	// replaced-on-disk image ("(deleted)"), whose inode no longer exists at
	// the path, unless the path is bound to a unit.
	hostMntNS tri
	// rootUIDs: real, effective, saved and filesystem UID are all 0. An
	// unprivileged user can run a genuine, non-setuid protected binary, but
	// never as root.
	rootUIDs tri
	// preload: the initial environment asks the dynamic loader to inject code
	// (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH), which makes a genuine binary run
	// foreign code in-process.
	preload bool
	// kthread: /proc/<pid>/stat flags carry PF_KTHREAD. Read only when exe is
	// unreadable: a kernel thread has no exe, but neither has a zombie leader
	// whose live threads renamed themselves.
	kthread tri

	// cgroup: the systemd cgroup path of the process (see systemdCgroup). Read
	// only for an exe that must run in a unit; "" when unreadable.
	cgroup string
}

// pfKthread is PF_KTHREAD (include/linux/sched.h), field 9 of /proc/<pid>/stat.
const pfKthread = 0x00200000

// kernelThread reports whether the stat record at statPath is a kernel
// thread's.
func kernelThread(statPath string) tri {
	stat, err := os.ReadFile(statPath)
	if err != nil {
		return triUnknown
	}
	flags, err := parseProcStatField(stat, 9)
	if err != nil {
		return triUnknown
	}
	return triOf(flags&pfKthread != 0)
}

// matchIdentity reports whether a process is protected, plus a short reason
// for the enforcement log.
//
// exe is authoritative when known: comm is ignored then, because it is
// attacker-controlled. A protected exe path counts only when the process is
// verifiably that host binary (hostExe, or hostMntNS for a replaced image),
// runs without a loader injection, runs in its own unit when the set names one
// for that path (units, which also stands in for the mount namespace check on a
// replaced image), and, for the built-in name list, runs as root. Any
// failed or impossible verification means NOT protected: the protection exists
// to keep host daemons alive, and must not become a way for the processes a
// Kill policy targets to exempt themselves.
//
// When exe is unknown (unreadable link) comm decides only for a kernel thread
// in the host mount namespace (both verified). Anything else without an exe —
// an exited or zombie leader whose live threads renamed themselves with
// prctl(PR_SET_NAME), a vanished process — is NOT protected: the name is the
// process's own choice, and trusting it would let any user join the set (and,
// through the kernel map, get exe_verified on its events).
func (s *ProtectedProcessSet) matchIdentity(id procIdentity) (bool, string) {
	if s == nil {
		return false, ""
	}
	if id.exe == "" {
		comm := strings.TrimRight(id.comm, "\x00")
		if _, ok := s.comms[comm]; ok && comm != "" && id.kthread == triYes && id.hostMntNS == triYes {
			return true, "protected kernel thread " + comm
		}
		return false, ""
	}
	exe, deleted := protectedExeCandidate(id.exe)
	_, configured := s.exes[exe]
	_, named := s.names[filepath.Base(exe)]
	named = named && inTrustedExeDir(exe)
	if !configured && !named {
		return false, ""
	}
	if id.preload {
		return false, ""
	}
	if deleted {
		// A unit-bound path needs no host mount namespace: its unit may give the
		// process its own, and the cgroup check below decides.
		if _, bound := s.units[exe]; !bound && id.hostMntNS != triYes {
			return false, ""
		}
	} else if id.hostExe != triYes {
		return false, ""
	}
	if unit, ok := s.units[exe]; ok && id.cgroup != "/system.slice/"+unit {
		return false, ""
	}
	if configured {
		return true, "protected executable " + exe
	}
	if id.rootUIDs != triYes {
		return false, ""
	}
	return true, "protected system process " + exe
}

// protectedExeCandidate normalizes an exe link text. A replaced-on-disk binary
// (package upgrade) reads "<path> (deleted)".
func protectedExeCandidate(link string) (exe string, deleted bool) {
	trimmed := strings.TrimSuffix(link, " (deleted)")
	return filepath.Clean(trimmed), trimmed != link
}

// isCandidate reports whether an exe link names a protected binary at all, so
// the costlier verification reads are skipped for every other process.
func (s *ProtectedProcessSet) isCandidate(link string) bool {
	exe, _ := protectedExeCandidate(link)
	if _, ok := s.exes[exe]; ok {
		return true
	}
	_, ok := s.names[filepath.Base(exe)]
	return ok && inTrustedExeDir(exe)
}

func inTrustedExeDir(exe string) bool {
	for _, dir := range trustedExeDirs {
		if strings.HasPrefix(exe, dir) {
			return true
		}
	}
	return false
}

// protectedPIDReason applies the unconditional guards (pid<=1, the agent
// itself) and then the protected set against /proc under procRoot. Returns ""
// when the process may be targeted. fallbackComm is used only when the live
// comm cannot be read.
func (s *ProtectedProcessSet) protectedPIDReason(procRoot string, pid uint32, selfPID int, fallbackComm string) string {
	// pid<=1 covers init and the kill(2) broadcast / process-group sentinels.
	if pid <= 1 {
		return fmt.Sprintf("pid %d", pid)
	}
	if int64(pid) == int64(selfPID) {
		return "the agent itself"
	}
	id := s.readProcIdentity(procRoot, pid)
	if id.comm == "" {
		id.comm = fallbackComm
	}
	if ok, reason := s.matchIdentity(id); ok {
		return reason
	}
	return ""
}

// procDir is procRoot/<pid>.
func procDir(procRoot string, pid uint32) string {
	return filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10))
}

// readProcIdentity reads a process's identity under procRoot. The verification
// fields are filled only for protected-binary candidates.
func (s *ProtectedProcessSet) readProcIdentity(procRoot string, pid uint32) procIdentity {
	var id procIdentity
	dir := procDir(procRoot, pid)
	if target, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		id.exe = target
	}
	if data, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		id.comm = strings.TrimRight(string(data), "\n\x00")
	}
	if s == nil {
		return id
	}
	if id.exe == "" {
		// Kernel threads and exiting processes: only a protected comm is worth
		// the namespace and stat reads.
		if _, ok := s.comms[id.comm]; ok && id.comm != "" {
			id.hostMntNS = sameHostMountNS(procRoot, dir)
			id.kthread = kernelThread(filepath.Join(dir, "stat"))
		}
		return id
	}
	if !s.isCandidate(id.exe) {
		return id
	}
	id.hostMntNS = sameHostMountNS(procRoot, dir)
	if exe, deleted := protectedExeCandidate(id.exe); !deleted {
		id.hostExe = hostExeCheck(procRoot, dir, exe)
	}
	id.rootUIDs = rootUIDs(filepath.Join(dir, "status"))
	id.preload = loaderInjection(filepath.Join(dir, "environ"))
	if exe, _ := protectedExeCandidate(id.exe); s.units[exe] != "" {
		id.cgroup = systemdCgroup(filepath.Join(dir, "cgroup"))
	}
	return id
}

// systemdCgroup returns the cgroup path from a /proc/<pid>/cgroup file: the
// unified "0::<path>" line, or else the cgroup v1 "name=systemd" line. "" when
// the file is unreadable or has neither.
func systemdCgroup(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var v1 string
	for _, line := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p
		}
		// "<id>:<controllers>:<path>"; the path may hold colons.
		if f := strings.SplitN(line, ":", 3); len(f) == 3 && slices.Contains(strings.Split(f[1], ","), "name=systemd") {
			v1 = f[2]
		}
	}
	return v1
}

// procIdentityDenied reports whether this process is refused the identity
// links of processes more privileged than itself. /proc/<pid>/exe, ns/mnt,
// root and environ are gated by ptrace_may_access(PTRACE_MODE_READ_FSCREDS):
// a root agent confined to a capability subset (systemd
// CapabilityBoundingSet) passes cap_ptrace_access_check only for targets whose
// permitted set is within its own, unless it holds CAP_SYS_PTRACE. pid 1
// always holds the full set, so its exe link is the probe. When denied, no
// host daemon can be verified: the kernel set stays empty and the userspace
// guard protects only pid<=1 and the agent itself.
func procIdentityDenied(procRoot string) bool {
	_, err := os.Readlink(filepath.Join(procRoot, "1", "exe"))
	return errors.Is(err, fs.ErrPermission)
}

// sameHostMountNS compares the process's mount namespace with pid 1's.
func sameHostMountNS(procRoot, dir string) tri {
	host, err := os.Readlink(filepath.Join(procRoot, "1", "ns", "mnt"))
	if err != nil {
		return triUnknown
	}
	own, err := os.Readlink(filepath.Join(dir, "ns", "mnt"))
	if err != nil {
		return triUnknown
	}
	return triOf(own == host)
}

// hostExeCheck reports whether the running image of the process in dir is the
// file at exe in the host's filesystem (procRoot/1/root, so an agent running
// in a container with the host PID namespace compares against the host view).
// /proc/<pid>/exe is a magic link: stat follows it to the real inode whatever
// mount namespace the process lives in. A variable so tests can substitute it.
var hostExeCheck = func(procRoot, dir, exe string) tri {
	running, err := os.Stat(filepath.Join(dir, "exe"))
	if err != nil {
		return triUnknown
	}
	host, err := os.Stat(filepath.Join(procRoot, "1", "root", exe))
	if err != nil {
		return triNo // no such host file: the image is not a host binary
	}
	return triOf(os.SameFile(running, host))
}

// rootUIDs parses the "Uid:" line of /proc/<pid>/status (real, effective,
// saved, filesystem) and reports whether all four are 0.
func rootUIDs(statusPath string) tri {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return triUnknown
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return triUnknown
		}
		for _, f := range fields {
			if f != "0" {
				return triNo
			}
		}
		return triYes
	}
	return triUnknown
}

// loaderInjectionVars are dynamic-loader variables that make a binary run
// code it did not ship with.
var loaderInjectionVars = []string{"LD_PRELOAD=", "LD_AUDIT=", "LD_LIBRARY_PATH="}

// loaderInjection reports whether the process's initial environment carries a
// non-empty loader injection variable. An unreadable environ reads as none: the
// root-UID and host-binary checks remain. (A process can overwrite its own
// environ block after start, so this is defense in depth, not proof.)
func loaderInjection(environPath string) bool {
	data, err := os.ReadFile(environPath)
	if err != nil {
		return false
	}
	for _, kv := range bytes.Split(data, []byte{0}) {
		for _, v := range loaderInjectionVars {
			if len(kv) > len(v) && bytes.HasPrefix(kv, []byte(v)) {
				return true
			}
		}
	}
	return false
}

// protectedTGID is one kernel-map entry: a protected process and its start
// time in USER_HZ ticks (the /proc/<pid>/stat unit), so a PID reused by an
// unrelated process never inherits the protection.
type protectedTGID struct {
	tgid       uint32
	startTicks uint64
}

// scanProtectedTGIDs walks procRoot and returns the protected processes
// (excluding pid<=1 and selfPID, which the kernel guards already) with their
// start times. Unreadable entries are skipped: a process we cannot identify
// here is still covered by the userspace guard at kill time, and one whose
// start time cannot be read gets no kernel entry.
func (s *ProtectedProcessSet) scanProtectedTGIDs(procRoot string, selfPID int) ([]protectedTGID, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	var out []protectedTGID
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil || pid <= 1 || int64(pid) == int64(selfPID) {
			continue
		}
		id := s.readProcIdentity(procRoot, uint32(pid))
		if id.exe == "" {
			// Only a verified host binary enters the kernel set: its entries
			// also mark events exe_verified. Kernel threads cannot be
			// signalled anyway.
			continue
		}
		if ok, _ := s.matchIdentity(id); !ok {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(procDir(procRoot, uint32(pid)), "stat"))
		if err != nil {
			continue
		}
		ticks, err := parseProcStatStartTicks(stat)
		if err != nil {
			continue
		}
		out = append(out, protectedTGID{tgid: uint32(pid), startTicks: ticks})
	}
	return out, nil
}

// kernelComms is the content of the trace_protected_comms map: every
// protected name and configured exe basename, truncated to TASK_COMM_LEN-1
// and NUL-padded as bpf_get_current_comm returns it. The kernel consults it
// when a process in trace_protected_tgids calls exec: the entry is kept
// only for a listed comm, and for a name (not an exe path) only as root —
// matchIdentity's rule, which the next refresh then verifies by inode.
func (s *ProtectedProcessSet) kernelComms() map[[taskCommLen]byte]uint8 {
	out := make(map[[taskCommLen]byte]uint8)
	if s == nil {
		return out
	}
	key := func(name string) [taskCommLen]byte {
		var k [taskCommLen]byte
		copy(k[:], truncateComm(name))
		return k
	}
	for n := range s.names {
		if _, seen := out[key(n)]; !seen {
			out[key(n)] = protectedCommRootOnly
		}
	}
	for p := range s.exes {
		out[key(filepath.Base(p))] = 0 // exe paths need no root (matchIdentity)
	}
	return out
}

// reconcileProtectedEntries computes the kernel map changes for one refresh.
// have is the map's current content (including entries the kernel added for
// children of protected processes), want the verified scan result, and
// scanStartTicks the boot time in USER_HZ ticks taken before the /proc scan
// began. An entry the scan did not confirm is deleted unless its process
// started at or after scanStartTicks: such a process may have been forked
// after its /proc directory was read, and the next refresh decides. Objects
// with the 1-byte presence value (withStart false) never add entries
// themselves, so the scan is the whole truth there.
func reconcileProtectedEntries(have, want map[uint32]uint64, scanStartTicks uint64, withStart bool) (del []uint32, put map[uint32]uint64) {
	put = make(map[uint32]uint64)
	for tgid, v := range have {
		if w, ok := want[tgid]; ok {
			if w != v {
				put[tgid] = w
			}
			continue
		}
		if withStart && v >= scanStartTicks {
			continue
		}
		del = append(del, tgid)
	}
	for tgid, w := range want {
		if _, ok := have[tgid]; !ok {
			put[tgid] = w
		}
	}
	return del, put
}

// ────────────────────────────────────────────────────────────────────────────
//  Process start-time verification
// ────────────────────────────────────────────────────────────────────────────

// userHZ is USER_HZ, the unit of /proc/<pid>/stat starttime. It is part of the
// Linux userspace ABI and 100 on every architecture the agent ships for
// (amd64, arm64); the kernel converts with nsec_to_clock_t (truncating).
const userHZ = 100

var errProcStatMalformed = errors.New("malformed /proc/<pid>/stat")

// parseProcStatStartTicks extracts field 22 (starttime, clock ticks since
// boot) from a /proc/<pid>/stat line.
func parseProcStatStartTicks(stat []byte) (uint64, error) {
	return parseProcStatField(stat, 22)
}

// parseProcStatField extracts numeric field n (1-based, n >= 3) from a
// /proc/<pid>/stat line. comm (field 2) may contain spaces and parentheses,
// so fields are counted from the LAST ')'.
func parseProcStatField(stat []byte, n int) (uint64, error) {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 || n < 3 {
		return 0, errProcStatMalformed
	}
	// Remaining fields start at field 3 (state).
	fields := strings.Fields(string(stat[end+1:]))
	idx := n - 3
	if len(fields) <= idx {
		return 0, errProcStatMalformed
	}
	v, err := strconv.ParseUint(fields[idx], 10, 64)
	if err != nil {
		return 0, errProcStatMalformed
	}
	return v, nil
}

// startNsToTicks converts a task start_boottime in ns (the event's
// process_start_ns) to the USER_HZ ticks /proc/<pid>/stat reports.
func startNsToTicks(ns uint64) uint64 {
	return ns / (1_000_000_000 / userHZ)
}

// errStartTimeMismatch: the PID now belongs to a different process than the
// one that produced the event (PID reuse) — never signal it by number.
var errStartTimeMismatch = errors.New("process start time mismatch (pid reused or process exited)")

// verifyStartTime compares the /proc stat starttime with the event identity.
func verifyStartTime(stat []byte, eventStartNs uint64) error {
	if eventStartNs == 0 {
		return errors.New("event carries no process start time")
	}
	ticks, err := parseProcStatStartTicks(stat)
	if err != nil {
		return err
	}
	if ticks != startNsToTicks(eventStartNs) {
		return errStartTimeMismatch
	}
	return nil
}
