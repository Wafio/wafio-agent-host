package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// procCWDFn reads the current working directory of a PID via /proc. Variadic
// override keeps the syscall boundary testable on non-Linux hosts.
var procCWDFn = func(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
}

// procFDFn reads what a PID's file descriptor points to via /proc (the
// directory of a dirfd). Replaced in tests.
var procFDFn = func(pid, fd uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
}

// atFDCWDDetail is AT_FDCWD (-100) as the trace hooks store a dirfd: the
// syscall argument truncated to the event's u32 detail field.
const atFDCWDDetail = uint32(0xFFFFFF9C)

// isFileEventType reports whether the event carries a filesystem path in
// Filename (and, for rename, the destination in Args).
func isFileEventType(t uint32) bool {
	switch t {
	case TraceOpen, TraceUnlink, TraceRename, TraceChmod, TraceChown:
		return true
	}
	return false
}

// fileEventDirfd returns the directory fd a relative Filename is relative
// to, for the hooks that record it (openat, unlinkat and fchmodat keep it in
// detail). fchownat does not record its: known is false. Rename events
// record both of theirs only with traceEvtDirfds (renameDirfds).
func fileEventDirfd(eventType, detail uint32) (dirfd uint32, known bool) {
	switch eventType {
	case TraceOpen, TraceUnlink, TraceChmod:
		return detail, true
	}
	return 0, false
}

// renameDirfds returns the directory fds of a rename event's old path
// (Filename) and new path (Args) when the object recorded them;
// older objects did not, and their relative paths join the CWD.
func renameDirfds(r *RawTraceEvent) (oldDirfd, newDirfd uint32, known bool) {
	if r.EventType != TraceRename || r.ProcFlags&traceEvtDirfds == 0 {
		return 0, 0, false
	}
	return r.Detail, r.Aux, true
}

// normalizeEventPaths makes the path fields of an event match what the
// kernel acted on, before policy matching, rule evaluation and persistence:
// absolute paths are cleaned lexically, relative paths are resolved
// against the process CWD (AT_FDCWD) or the dirfd's directory, and the
// kernel's exact-path severity for openat is re-derived on the result. The
// raw path stays in Description.
func normalizeEventPaths(r *RawTraceEvent, te *TraceEvent) {
	cleanAbsolutePaths(r.EventType, te)
	raw := te.Filename
	resolveRelativeFileEvent(r, te)
	if r.EventType == TraceOpen {
		sev := sensitiveOpenSeverity(te.Filename, te.Flags)
		if raw != "" && !filepath.IsAbs(raw) {
			sev = max(sev, relativeSensitiveSeverity(raw, te.Flags))
		}
		if sev > te.Severity {
			te.Severity = sev
			te.SeverityName = severityName(sev)
		}
	}
}

// relativeSensitiveSeverity is the floor for an openat whose path was
// relative. Its directory is read from /proc when userspace sees the event
// (CWD or dirfd), after the fact: chdir or a re-used fd number can make it
// resolve somewhere harmless, and it may not resolve at all. A sensitive
// basename therefore keeps at least MEDIUM wherever it resolved.
func relativeSensitiveSeverity(raw string, flags uint32) uint32 {
	modifies := flags&3 != 0 || flags&0o1000 != 0
	switch filepath.Base(raw) {
	case "shadow", "gshadow", "master.passwd":
		return SevMedium
	case "passwd", "sudoers":
		if modifies {
			return SevMedium
		}
	}
	return SevInfo
}

// cleanAbsolutePaths applies filepath.Clean to absolute paths of file and
// exec events: "/etc//shadow", "/etc/./shadow" and "/tmp/../etc/shadow" all
// open /etc/shadow, and a byte-exact rule or policy on the raw string misses
// them. Relative paths are left for resolveRelativeFileEvent; exec argv
// (Args) is never touched.
func cleanAbsolutePaths(eventType uint32, te *TraceEvent) {
	if !isFileEventType(eventType) && eventType != TraceExecve && eventType != TraceExecveat {
		return
	}
	if filepath.IsAbs(te.Filename) {
		te.Filename = filepath.Clean(te.Filename)
	}
	if eventType == TraceRename && filepath.IsAbs(te.Args) {
		te.Args = filepath.Clean(te.Args)
	}
}

// resolveRelativeFileEvent rewrites relative paths on file syscalls against
// the process CWD read from /proc/<pid>/cwd at event time. The
// kernel only sees the raw relative string (openat(AT_FDCWD, "shadow")), so
// rules like starts_with "/etc/" never matched; resolving here restores
// absolute context before rule evaluation. When the process already exited
// and /proc is gone, the relative path is preserved and flagged
// PathUnresolved instead of dropped.
//
// A path relative to a directory fd other than AT_FDCWD
// (openat(open("/etc"), "shadow")) is never joined with the CWD, which would
// fabricate a path: it is resolved against /proc/<pid>/fd/<dirfd> (best
// effort, Cwd then names that directory), or kept as-is and flagged
// PathUnresolved when the fd no longer names a directory path.
func resolveRelativeFileEvent(r *RawTraceEvent, te *TraceEvent) {
	if !isFileEventType(r.EventType) {
		return
	}
	relFn := te.Filename != "" && !filepath.IsAbs(te.Filename)
	relArgs := r.EventType == TraceRename && te.Args != "" && !filepath.IsAbs(te.Args)
	fnDirfd, fnKnown := fileEventDirfd(r.EventType, r.Detail)
	oldDirfd, newDirfd, renameKnown := renameDirfds(r)
	if renameKnown {
		fnDirfd, fnKnown = oldDirfd, true
	}
	if relFn && fnKnown && fnDirfd != atFDCWDDetail {
		relFn = false
		if dir, ok := dirfdPath(r.PID, fnDirfd); ok {
			te.Filename = filepath.Clean(filepath.Join(dir, te.Filename))
			te.Cwd = dir
		} else {
			te.PathUnresolved = true
		}
	}
	if relArgs && renameKnown && newDirfd != atFDCWDDetail {
		relArgs = false
		if dir, ok := dirfdPath(r.PID, newDirfd); ok {
			te.Args = filepath.Clean(filepath.Join(dir, te.Args))
		} else {
			te.PathUnresolved = true
		}
	}
	if !relFn && !relArgs {
		return
	}
	cwd, err := procCWDFn(r.PID)
	if err != nil {
		te.PathUnresolved = true
		return
	}
	if relFn {
		te.Filename = filepath.Clean(filepath.Join(cwd, te.Filename))
	}
	if relArgs {
		te.Args = filepath.Clean(filepath.Join(cwd, te.Args))
	}
	te.Cwd = cwd
}

// dirfdPath is the directory a dirfd names, read from /proc when the event is
// processed. Anything that is not a live absolute path (a socket, an
// anonymous inode, a deleted directory, a closed fd) is no answer.
func dirfdPath(pid, fd uint32) (string, bool) {
	dir, err := procFDFn(pid, fd)
	if err != nil || !filepath.IsAbs(dir) || strings.HasSuffix(dir, " (deleted)") {
		return "", false
	}
	return filepath.Clean(dir), true
}

// sensitiveOpenSeverity mirrors the exact-path classification of the openat
// hook in wafio_trace.c (trace_sys_enter_openat) for a cleaned or resolved
// path: any /etc/shadow access and a write or truncate of /etc/passwd,
// /etc/sudoers or /etc/sudoers.d/* are HIGH; a write under /proc/ or /sys/ is
// MEDIUM. The kernel compares the raw argument byte for byte, so this is
// where a non-canonical spelling gets the same verdict.
func sensitiveOpenSeverity(filename string, flags uint32) uint32 {
	accMode := flags & 3                          // O_RDONLY=0, O_WRONLY=1, O_RDWR=2
	modifies := accMode != 0 || flags&0o1000 != 0 // or O_TRUNC
	switch {
	case filename == "/etc/shadow":
		return SevHigh
	case modifies && (filename == "/etc/passwd" || filename == "/etc/sudoers" || strings.HasPrefix(filename, "/etc/sudoers.d/")):
		return SevHigh
	case accMode != 0 && (strings.HasPrefix(filename, "/proc/") || strings.HasPrefix(filename, "/sys/")):
		return SevMedium
	}
	return SevInfo
}
