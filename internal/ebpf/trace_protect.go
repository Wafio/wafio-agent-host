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
	"sync/atomic"
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
// file (inode, so a container image's /usr/sbin/sshd does not count) in a place
// only root can write, no loader injection, and root UIDs for the built-in
// names.
var trustedExeDirs = []string{
	"/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/",
	"/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/", "/usr/libexec/",
	"/usr/local/sbin/", "/usr/local/bin/", "/snap/",
}

// trustedUID is the owner a trusted file and its directory must have. It is 0;
// a test that builds its files as an unprivileged user sets its own UID.
var trustedUID uint32

// trustedOwnerMode reports whether a file with this owner and permission bits
// could only have been written by root: owned by trustedUID and writable by
// neither its group nor others. Anyone else who can write the file, or its
// directory, can replace a trusted binary with one of their own.
func trustedOwnerMode(uid uint32, perm uint32) bool {
	return uid == trustedUID && perm&0o022 == 0
}

// taskCommLen mirrors TASK_COMM_LEN: the kernel keeps 15 bytes + NUL.
const taskCommLen = 16

// maxProtectedTGIDs must match max_entries of trace_protected_tgids in
// wafio_trace.c. Extra matches are logged and left to the userspace guard.
const maxProtectedTGIDs = 1024

// maxProtectedImages must match max_entries of trace_protected_images in
// wafio_trace.c. A refresh writes one key per trusted file that exists: the
// configuration bounds (maxProtectedEntries names and exe paths plus the
// built-ins, times protectedImageDirs) stay below it on a host with few files.
const maxProtectedImages = 1024

// Flags of a trace_protected_images value (TRACE_PROTECTED_IMAGE_* in
// wafio_trace.c). Any, Root and Unit are alternatives: an exec keeps the entry
// when any one holds, and a value with none keeps nothing.
const (
	// protectedImageAny keeps the entry for any task: a configured exe path,
	// which needs no root.
	protectedImageAny uint64 = 1 << iota
	// protectedImageRoot keeps it when the real UID is 0: the built-in names.
	protectedImageRoot
	// protectedImageUnit keeps it when the task runs in the systemd unit named
	// in the value: the WAF agent and systemd-networkd.
	protectedImageUnit
	// protectedImageKeepOnSetuid keeps it through the exit of setuid, setreuid
	// and setresuid, whoever the task is then. Exec ignores it.
	protectedImageKeepOnSetuid
)

// userSwitchNames are the OpenSSH programs that drop root themselves and then
// call setgid(0) and setuid(0) to check that root cannot come back. The control
// plane downgrades those two events only for a verified process, so these
// images keep the mark through their own switch of user.
var userSwitchNames = map[string]struct{}{"sshd": {}, "sshd-session": {}, "sshd-auth": {}}

// rootImage is the value for a protected name found in a system directory: the
// entry survives an exec for root, and a switch of user too for the OpenSSH
// names.
func rootImage(name string) protectedImage {
	img := protectedImage{Flags: protectedImageRoot}
	if _, ok := userSwitchNames[name]; ok {
		img.Flags |= protectedImageKeepOnSetuid
	}
	return img
}

// protectedUnitLen mirrors TRACE_UNIT_NAME_LEN. The kernel reads a cgroup name
// into a buffer that long and cuts a longer one to protectedUnitLen-1 bytes, so
// a stored name of at most protectedUnitLen-2 bytes never equals a cut one.
const protectedUnitLen = 48

// protectedImageKey is the key of trace_protected_images (struct
// protected_image_key): the file as the kernel sees it. Dev is the encoding of
// sb->s_dev (major<<20 | minor), Gen is i_generation. The layout has no
// padding, so cilium/ebpf marshals it byte for byte.
type protectedImageKey struct {
	Ino uint64
	Dev uint32
	Gen uint32
}

// protectedImage is the value of trace_protected_images (struct
// protected_image): when an exec of the file keeps the entry. Unit is the
// NUL padded unit name, set with protectedImageUnit.
type protectedImage struct {
	Flags uint64
	Unit  [protectedUnitLen]byte
}

// unitImage is the value for a file that keeps the entry only inside the
// systemd unit of that name. A name the kernel could not compare exactly (empty
// or too long) has no value: the file is not trusted.
func unitImage(unit string) (protectedImage, bool) {
	if unit == "" || len(unit) > protectedUnitLen-2 || strings.IndexByte(unit, 0) >= 0 {
		return protectedImage{}, false
	}
	img := protectedImage{Flags: protectedImageUnit}
	copy(img.Unit[:], unit)
	return img, true
}

// merge combines what two sources know about one file: it keeps the entry when
// either says so. Two different units for one file leave neither, the safe
// direction.
func (a protectedImage) merge(b protectedImage) protectedImage {
	switch {
	case a.Flags == 0:
		return b
	case b.Flags == 0:
		return a
	case (a.Flags|b.Flags)&protectedImageAny != 0:
		return protectedImage{Flags: protectedImageAny}
	}
	out := protectedImage{Flags: a.Flags | b.Flags}
	switch {
	case a.Flags&protectedImageUnit == 0:
		out.Unit = b.Unit
	case b.Flags&protectedImageUnit == 0 || a.Unit == b.Unit:
		out.Unit = a.Unit
	default:
		out.Flags &^= protectedImageUnit
	}
	return out
}

// Slots of the trace_protected_budget array (TRACE_PROTECTED_BUDGET_SLOT,
// TRACE_PROTECTED_REFUSED_SLOT and TRACE_PROTECTED_LIMIT_SLOT in
// wafio_trace.c).
const (
	protectedBudgetSlot  uint32 = 0
	protectedRefusedSlot uint32 = 1
	protectedLimitSlot   uint32 = 2
)

// maxInheritedFill: the kernel stops inserting forked children once the map
// would hold this many entries (3/4 of maxProtectedTGIDs), so the refresh's
// verified inserts always fit.
const maxInheritedFill = maxProtectedTGIDs * 3 / 4

// protectedInheritBudget is how many fork inserts the kernel may make with the
// map holding entries now: the room below maxInheritedFill. The refresh writes
// it to the budget slot and to the limit slot. Between refreshes the kernel
// takes a unit at each insert and gives one back at each delete it makes (exec
// drop, exit), never above the limit, so the budget follows the entries in the
// map and a flood of short-lived children does not use it up. It is 0 when the
// kernel cannot keep an entry through exec by image (execKeep false: the exec
// program is not attached, or the object has no trace_protected_images): an
// inherited entry would then follow whatever the child runs, and with the limit
// at 0 no unit comes back to raise it.
func protectedInheritBudget(entries int, execKeep bool) int64 {
	if !execKeep || entries >= maxInheritedFill {
		return 0
	}
	return int64(maxInheritedFill - entries)
}

// ProtectedProcessSet decides whether a process may be targeted by enforcement.
// Immutable after construction except leads; safe for concurrent use.
type ProtectedProcessSet struct {
	names map[string]struct{} // executable basenames (full, untruncated)
	comms map[string]struct{} // same names truncated to TASK_COMM_LEN-1
	exes  map[string]struct{} // exact executable paths
	units map[string]string   // exe path -> system unit it must run in

	// leads maps the path a configured exe path leads to now, inside PID 1's
	// root, to that configured path, for each one that goes through a symlink:
	// /proc/<pid>/exe shows the resolved path, never the configured one.
	// Replaced by refreshExeLeads.
	leads atomic.Pointer[map[string]string]

	defaultsReplaced bool // DefaultProtectedProcessNames dropped by configuration
}

func truncateComm(name string) string {
	if len(name) > taskCommLen-1 {
		return name[:taskCommLen-1]
	}
	return name
}

// configuredLink maps an exe link that is the file a configured symlinked path
// leads to onto that path. Any other link is returned as it is.
func (s *ProtectedProcessSet) configuredLink(link string) string {
	if s == nil {
		return link
	}
	leads := s.leads.Load()
	if leads == nil {
		return link
	}
	exe, deleted := protectedExeCandidate(link)
	configured, ok := (*leads)[exe]
	switch {
	case !ok:
		return link
	case deleted:
		return configured + " (deleted)"
	}
	return configured
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
	exe  string // /proc/<pid>/exe link text, or the configured path it is the target of (configuredLink); "" when unreadable
	comm string

	// hostExe: the running image is the very file at the same path in the
	// host's mount namespace (same device and inode), or, for a replaced image,
	// a file on the filesystem of the directory the path names, and that file
	// and its directory belong to root and are writable by no one else. A path
	// string alone is not identity: in a container /usr/sbin/sshd is whatever
	// the image put there, and an account that can write the file or its
	// directory can put its own copy at a trusted path.
	hostExe tri
	// hostMntNS: the process shares pid 1's mount namespace. A replaced-on-disk
	// image ("(deleted)") at a path that is bound to no unit needs it on top of
	// hostExe: nothing is at the path to compare the inode with.
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

	// cgroup: the cgroup path of the process in the form matchIdentity compares
	// (see unitCgroup). Read only for an exe that must run in a unit; "" when
	// unreadable or not in that unit.
	cgroup string

	// untrusted: the file or directory an account other than root can write
	// while the process runs that file (hostExeCheck); hostExe is triNo then.
	untrusted string
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
// verifiably that host binary (hostExe, and hostMntNS too for a replaced image
// at a path bound to no unit), runs without a loader injection, runs in its own
// unit when the set names one for that path (units, which also stands in for
// the mount namespace check on a replaced image), and, for the built-in name
// list, runs as root. Any
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
	}
	if id.hostExe != triYes {
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
	var link string // what /proc/<pid>/exe says; id.exe may name the configured path instead
	if target, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		link = target
		id.exe = s.configuredLink(target)
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
	id.hostExe, id.untrusted = hostExeCheck(procRoot, dir, link)
	id.rootUIDs = rootUIDs(filepath.Join(dir, "status"))
	id.preload = loaderInjection(filepath.Join(dir, "environ"))
	if exe, _ := protectedExeCandidate(id.exe); s.units[exe] != "" {
		id.cgroup = unitCgroup(procRoot, dir, pid, s.units[exe])
	}
	return id
}

// hostCgroupRoots are the places, inside PID 1's root, where the hierarchy
// that systemd places its units in is mounted: the unified one, or the named
// systemd hierarchy of a hybrid or v1 host.
var hostCgroupRoots = []string{"sys/fs/cgroup", "sys/fs/cgroup/unified", "sys/fs/cgroup/systemd"}

// sharesHostCgroupNS reports whether this process is in the cgroup namespace of
// PID 1. /proc/<pid>/cgroup is rendered relative to the reader's namespace root,
// so from a private one a unit outside it reads "/../../system.slice/<unit>".
// A link that cannot be read counts as shared: PID 1's links are gated like its
// exe link, and procIdentityDenied reports that case.
func sharesHostCgroupNS(procRoot string) bool {
	own, err := os.Readlink(filepath.Join(procRoot, "self", "ns", "cgroup"))
	if err != nil {
		return true
	}
	host, err := os.Readlink(filepath.Join(procRoot, "1", "ns", "cgroup"))
	if err != nil {
		return true
	}
	return own == host
}

// unitCgroup returns the cgroup of the process in the form matchIdentity
// compares. In the namespace of PID 1 that is the path in /proc/<pid>/cgroup.
// In a private one it is "/system.slice/<unit>" when the cgroup.procs of that
// unit under PID 1's root lists the process (a direct member, which the exact
// path says too) and "" when it does not: that file does not depend on the
// reader's namespace.
func unitCgroup(procRoot, dir string, pid uint32, unit string) string {
	if sharesHostCgroupNS(procRoot) {
		return systemdCgroup(filepath.Join(dir, "cgroup"))
	}
	for _, root := range hostCgroupRoots {
		data, err := os.ReadFile(filepath.Join(procRoot, "1", "root", root, "system.slice", unit, "cgroup.procs"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil && slices.Contains(strings.Fields(string(data)), strconv.FormatUint(uint64(pid), 10)) {
			return "/system.slice/" + unit
		}
		return ""
	}
	return ""
}

// unitCheckAvailable reports whether the unit of a protected path can be told:
// the agent shares PID 1's cgroup namespace, or PID 1's root shows a
// system.slice directory the agent can read.
func unitCheckAvailable(procRoot string) bool {
	if sharesHostCgroupNS(procRoot) {
		return true
	}
	for _, root := range hostCgroupRoots {
		if _, err := os.Stat(filepath.Join(procRoot, "1", "root", root, "system.slice")); err == nil {
			return true
		}
	}
	return false
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
// host's file for the exe link text (procRoot/1/root, so an agent running in a
// container with the host PID namespace compares against the host view), and
// whether that file and its directory could only have been put there by root
// (trustedFile): a file an unprivileged account owns, or can replace through
// its directory, is not a host binary however it got its name.
// /proc/<pid>/exe is a magic link: stat follows it to the real inode whatever
// mount namespace the process lives in, a replaced one included. A replaced
// image has no file at the path to compare with, so it passes when it is on the
// filesystem of the directory the path names. The string is the path that an
// account other than root can write, set only when the running image is that
// file (or, for a replaced image, on that filesystem). A variable so tests can
// substitute it.
var hostExeCheck = func(procRoot, dir, link string) (tri, string) {
	exe, deleted := protectedExeCandidate(link)
	running, err := os.Stat(filepath.Join(dir, "exe"))
	if err != nil {
		return triUnknown, ""
	}
	hostPath := filepath.Join(procRoot, "1", "root", exe)
	parent, err := os.Stat(filepath.Dir(hostPath))
	if err != nil {
		return triNo, "" // no such host directory: the image is not a host binary
	}
	if deleted {
		if !sameDevice(running, parent) {
			return triNo, ""
		}
	} else {
		host, err := os.Stat(hostPath)
		if err != nil || !os.SameFile(running, host) {
			return triNo, ""
		}
	}
	switch {
	case !trustedFile(running):
		return triNo, link
	case !trustedFile(parent):
		return triNo, filepath.Dir(exe)
	}
	return triYes, ""
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
	// configured: matched by an exe path of the set, which needs no root; a
	// match by name needs root UIDs (matchIdentity).
	configured bool
	// unit: the systemd unit the exe path is bound to ("" when it is not), so
	// the image this process runs keeps the entry only inside that unit.
	unit string
	// name: the basename of the executable of a process matched by name; ""
	// for one matched by a configured path.
	name string
}

// image is the trace_protected_images value for the file the process runs: the
// same condition matchIdentity applied to it. ok is false for a unit name the
// kernel cannot compare, which leaves the file untrusted.
func (p protectedTGID) image() (protectedImage, bool) {
	switch {
	case p.unit != "":
		return unitImage(p.unit)
	case p.configured:
		return protectedImage{Flags: protectedImageAny}, true
	}
	return rootImage(p.name), true
}

// scanProtectedTGIDs walks procRoot and returns the protected processes
// (excluding pid<=1 and selfPID, which the kernel guards already) with their
// start times. Unreadable entries are skipped: a process we cannot identify
// here is still covered by the userspace guard at kill time, and one whose
// start time cannot be read gets no kernel entry. The second result lists the
// paths an account other than root can write, for the processes that would be
// protected if that were not so (hostExeCheck): they are left out of the first.
func (s *ProtectedProcessSet) scanProtectedTGIDs(procRoot string, selfPID int) ([]protectedTGID, []string, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, nil, err
	}
	var out []protectedTGID
	var untrusted []string
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
			if id.untrusted != "" {
				id.hostExe = triYes
				if ok, _ := s.matchIdentity(id); ok {
					untrusted = append(untrusted, id.untrusted)
				}
			}
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
		exe, _ := protectedExeCandidate(id.exe)
		_, configured := s.exes[exe]
		p := protectedTGID{tgid: uint32(pid), startTicks: ticks, configured: configured, unit: s.units[exe]}
		if !configured {
			p.name = filepath.Base(exe)
		}
		out = append(out, p)
	}
	slices.Sort(untrusted)
	return out, slices.Compact(untrusted), nil
}

// protectedImageDirs are the directories searched for the built-in and extra
// protected names when the kernel's image set is built. They are system
// locations of root-owned binaries, a subset of trustedExeDirs (the OpenSSH
// helpers live in /usr/lib/openssh on Debian, /usr/libexec/openssh on Fedora
// and /usr/lib/ssh on Arch). A name in a nested directory is not found here:
// list its path in WAFIO_PROTECTED_EXE_PATHS.
var protectedImageDirs = []string{
	"/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/usr/local/sbin/", "/usr/local/bin/",
	"/usr/libexec/", "/usr/lib/openssh/", "/usr/libexec/openssh/", "/usr/lib/ssh/", "/usr/libexec/ssh/",
	"/usr/lib/systemd/", "/lib/systemd/",
}

// imagePaths is the set of files the kernel may trust at exec, with the
// trace_protected_images value of each: every protected name in every
// protectedImageDirs entry needs root, a configured exe path does not, and the
// latter wins when both name the same path (matchIdentity's rule). A path bound
// to a unit keeps the entry only inside that unit, whichever way it is listed:
// as a name it would need the unit and root together, which the value cannot
// say, so a bound path is trusted only as a configured one. The next refresh
// still verifies a running process by inode.
func (s *ProtectedProcessSet) imagePaths() map[string]protectedImage {
	out := make(map[string]protectedImage)
	if s == nil {
		return out
	}
	for n := range s.names {
		for _, dir := range protectedImageDirs {
			if _, bound := s.units[dir+n]; !bound {
				out[dir+n] = rootImage(n)
			}
		}
	}
	for p := range s.exes {
		img, ok := protectedImage{Flags: protectedImageAny}, true
		if unit, bound := s.units[p]; bound {
			img, ok = unitImage(unit)
		}
		if ok {
			out[p] = img
		} else {
			delete(out, p)
		}
	}
	return out
}

// mountEntry is what a mountinfo line says about the superblock of a mount.
type mountEntry struct {
	dev      uint32 // sb->s_dev, MKDEV(major, minor)
	readOnly bool   // "ro" among the super options, the last field
}

// mountTable maps mount IDs to the superblock of the mount, from the text of a
// mountinfo file: field 1 is the mount ID, field 3 the "major:minor" the kernel
// prints from sb->s_dev, and the super options follow the filesystem type and
// source after " - ". The device is dev_t as BPF reads s_dev, MKDEV(major,
// minor) = major<<20 | minor. The mount's own options (field 6) are not the
// superblock's: a read-only bind mount of a writable filesystem does not make
// the files unwritable. A malformed line is skipped.
func mountTable(mountinfo string) map[uint64]mountEntry {
	out := make(map[uint64]mountEntry)
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		id, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		majorText, minorText, ok := strings.Cut(f[2], ":")
		if !ok {
			continue
		}
		major, err1 := strconv.ParseUint(majorText, 10, 12)
		minor, err2 := strconv.ParseUint(minorText, 10, 20)
		if err1 != nil || err2 != nil {
			continue
		}
		entry := mountEntry{dev: uint32(major<<20 | minor)}
		if i := slices.Index(f, "-"); i >= 0 && len(f) > i+3 {
			entry.readOnly = slices.Contains(strings.Split(f[i+3], ","), "ro")
		}
		out[id] = entry
	}
	return out
}

// applyProtectedImages brings trace_protected_images to want: every key that
// is missing or changed is written before any stale key is deleted, so a
// trusted image is never absent while the map is swapped. Failures are
// returned together; the work goes on.
func applyProtectedImages(have, want map[protectedImageKey]protectedImage, put func(protectedImageKey, protectedImage) error, del func(protectedImageKey) error) error {
	var errs []error
	for k, v := range want {
		if hv, ok := have[k]; ok && hv == v {
			continue
		}
		if err := put(k, v); err != nil {
			errs = append(errs, err)
		}
	}
	for k := range have {
		if _, ok := want[k]; ok {
			continue
		}
		if err := del(k); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
