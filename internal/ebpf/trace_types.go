package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
//  TraceManager Config (platform-independent)
// ────────────────────────────────────────────────────────────────────────────

type TraceManagerConfig struct {
	ObjectPath string // path to compiled wafio_trace.o

	// Protected processes are never killed by enforcement. Names are added to
	// DefaultProtectedProcessNames and match the executable basename in a
	// system directory; exe paths match /proc/<pid>/exe exactly.
	// ProtectedReplaceDefaults drops the built-in names instead (see
	// ProtectedProcessConfig).
	ProtectedProcessNames    []string
	ProtectedExePaths        []string
	ProtectedReplaceDefaults bool

	// MapSizes sizes trace_events and trace_open_pending at load (see
	// ComputeMapSizes). The zero value leaves them at the sizes the object
	// declares.
	MapSizes MapSizes
}

// ProtectedConfig returns the protected-process part of the configuration.
func (c TraceManagerConfig) ProtectedConfig() ProtectedProcessConfig {
	return ProtectedProcessConfig{
		Names:           c.ProtectedProcessNames,
		ExePaths:        c.ProtectedExePaths,
		ReplaceDefaults: c.ProtectedReplaceDefaults,
	}
}

// ────────────────────────────────────────────────────────────────────────────
//  Raw BPF Trace Event (matches struct wafio_event in wafio_trace.h)
//  Total: 1440 bytes (1408 core + 8 signal + 8 exact process identity +
//  8 identity flags); objects before the identity flags emit the first 1432.
// ────────────────────────────────────────────────────────────────────────────

const TraceEventSize = 1432

// TraceEventSizeWithIdentity is an event from an object that appends the
// process identity flags (proc_flags + reserved u32). Shorter events
// come from older objects and carry no flags.
const TraceEventSizeWithIdentity = 1440

// traceProcProtected mirrors TRACE_PROC_PROTECTED: when the kernel produced
// the event, the process was PID 1 or in trace_protected_tgids — the
// agent-verified protected set (host binary by inode, root, no loader
// injection) or a child forked by such a process that has not exec'd since.
const traceProcProtected uint32 = 1

// proc_flags bits 8+ describe the event (zero from older
// objects, which also leave Aux zero):
//   - traceEvtArgsUnreadable (TRACE_EVT_ARGS_UNREADABLE): openat2's open_how
//     could not be read at the tracepoint; the kernel recorded O_RDWR.
//   - traceEvtDirfds (TRACE_EVT_DIRFDS): a rename event carries its old
//     dirfd in Detail and its new dirfd in Aux.
//   - traceEvtOpenResult (TRACE_EVT_OPEN_RESULT): an open event whose RetVal
//     is the result of the open (a descriptor or a negative errno). Without
//     it the result was not recorded: an older object, an exit probe that is
//     not attached, a kill candidate or an event with a kernel Kill (both
//     leave at entry), a restarted open, or the open left the kernel before
//     it returned.
const (
	traceEvtArgsUnreadable uint32 = 1 << 8
	traceEvtDirfds         uint32 = 1 << 9
	traceEvtOpenResult     uint32 = 1 << 10
)

type RawTraceEvent struct {
	ProcessStartNs  uint64
	SignalResult    int32
	SignalAttempted bool
	TimestampNs     uint64
	CgroupID        uint64
	PID             uint32
	TID             uint32
	PPID            uint32
	UID             uint32
	GID             uint32
	EventType       uint32
	Severity        uint32
	Flags           uint32
	RetVal          int64
	Detail          uint32
	Port            uint16
	AddrFamily      uint16
	Addr            [16]byte
	Comm            [16]byte
	Filename        [256]byte
	Args            [1024]byte
	ParentComm      [16]byte // real_parent->comm (process lineage)
	GrandparentComm [16]byte // real_parent->real_parent->comm
	Action          uint32   // TRACE_ACTION_* — enforcement action taken
	PolicyID        uint32   // which policy matched (0 = none)
	ProcFlags       uint32   // TRACE_PROC_* identity flags | TRACE_EVT_* event bits (0 for older objects)
	Aux             uint32   // event-specific (rename: new dirfd with traceEvtDirfds); 0 for older objects
}

// ParseRawTraceEvent decodes a raw wafio_event from the ringbuf.
func ParseRawTraceEvent(data []byte) (*RawTraceEvent, error) {
	if len(data) < TraceEventSize {
		return nil, fmt.Errorf("trace event too short: %d < %d", len(data), TraceEventSize)
	}

	e := &RawTraceEvent{}
	e.TimestampNs = binary.LittleEndian.Uint64(data[0:8])
	e.CgroupID = binary.LittleEndian.Uint64(data[8:16])
	e.PID = binary.LittleEndian.Uint32(data[16:20])
	e.TID = binary.LittleEndian.Uint32(data[20:24])
	e.PPID = binary.LittleEndian.Uint32(data[24:28])
	e.UID = binary.LittleEndian.Uint32(data[28:32])
	e.GID = binary.LittleEndian.Uint32(data[32:36])
	e.EventType = binary.LittleEndian.Uint32(data[36:40])
	e.Severity = binary.LittleEndian.Uint32(data[40:44])
	e.Flags = binary.LittleEndian.Uint32(data[44:48])
	e.RetVal = int64(binary.LittleEndian.Uint64(data[48:56])) //nolint:gosec // G115: the kernel field is an s64 (syscall return); two's-complement reinterpretation is intended
	e.Detail = binary.LittleEndian.Uint32(data[56:60])
	e.Port = binary.LittleEndian.Uint16(data[60:62])
	e.AddrFamily = binary.LittleEndian.Uint16(data[62:64])
	copy(e.Addr[:], data[64:80])
	copy(e.Comm[:], data[80:96])
	copy(e.Filename[:], data[96:352])
	copy(e.Args[:], data[352:1376])
	copy(e.ParentComm[:], data[1376:1392])
	copy(e.GrandparentComm[:], data[1392:1408])
	e.Action = binary.LittleEndian.Uint32(data[1408:1412])
	e.PolicyID = binary.LittleEndian.Uint32(data[1412:1416])
	e.SignalResult = int32(binary.LittleEndian.Uint32(data[1416:1420])) //nolint:gosec // G115: the kernel field is an s32 (-errno or 0); two's-complement reinterpretation is intended
	e.SignalAttempted = binary.LittleEndian.Uint32(data[1420:1424]) != 0
	e.ProcessStartNs = binary.LittleEndian.Uint64(data[1424:1432])
	if len(data) >= TraceEventSizeWithIdentity {
		e.ProcFlags = binary.LittleEndian.Uint32(data[1432:1436])
		e.Aux = binary.LittleEndian.Uint32(data[1436:1440])
	}
	return e, nil
}

// cString extracts a C-style null-terminated string from a byte array.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// argsString renders the kernel argv region: NUL-separated C strings are
// joined with single spaces so multi-argument commands stay readable.
func argsString(b []byte) string {
	// One pass, one allocation: the region is 1 KiB of mostly NUL padding,
	// and bytes.Split allocated a slice header per NUL (~24 KiB per event,
	// the largest cost of the trace ring reader).
	out := make([]byte, 0, len(b))
	sep := false
	for _, c := range b {
		if c == 0 {
			sep = len(out) > 0
			continue
		}
		if sep {
			out = append(out, ' ')
			sep = false
		}
		out = append(out, c)
	}
	return string(out)
}

func severityName(s uint32) string {
	switch s {
	case SevInfo:
		return "info"
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	case SevCritical:
		return "critical"
	}
	return "unknown"
}

func actionName(a uint32) string {
	switch a {
	case ActionMonitor:
		return "monitor"
	case ActionAlert:
		return "alert"
	case ActionKill:
		return "kill"
	case ActionSimulate:
		return "simulate"
	}
	return "monitor"
}

func categoryName(cat uint32) string {
	var parts []string
	if cat&CatProcess != 0 {
		parts = append(parts, "process")
	}
	if cat&CatFile != 0 {
		parts = append(parts, "file")
	}
	if cat&CatNetwork != 0 {
		parts = append(parts, "network")
	}
	if cat&CatSecurity != 0 {
		parts = append(parts, "security")
	}
	if cat&CatContainer != 0 {
		parts = append(parts, "container")
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ",")
}

func formatAddr(addr [16]byte, family uint16) string {
	switch family {
	case 2: // AF_INET
		return net.IP(addr[:4]).String()
	case 10: // AF_INET6
		ip := net.IP(addr[:])
		if ip.IsUnspecified() {
			return ""
		}
		return ip.String()
	}
	return ""
}

// ToTraceEvent converts a raw BPF event to a user-facing TraceEvent.
func (r *RawTraceEvent) ToTraceEvent(bootOffset time.Duration) TraceEvent {
	wallTime := time.Unix(0, i64FromU64(r.TimestampNs)+int64(bootOffset))

	info := TraceEventTypes[r.EventType]

	te := TraceEvent{
		Timestamp:       wallTime.Format(time.RFC3339Nano),
		TimestampNs:     wallTime.UnixNano(),
		CgroupID:        r.CgroupID,
		PID:             r.PID,
		TID:             r.TID,
		PPID:            r.PPID,
		UID:             r.UID,
		GID:             r.GID,
		EventType:       r.EventType,
		EventName:       info.Name,
		Category:        categoryName(info.Category),
		Severity:        r.Severity,
		SeverityName:    severityName(r.Severity),
		Comm:            cString(r.Comm[:]),
		Filename:        cString(r.Filename[:]),
		Args:            argsString(r.Args[:]),
		Flags:           r.Flags,
		RetVal:          r.RetVal,
		Detail:          r.Detail,
		Port:            r.Port,
		AddrFamily:      r.AddrFamily,
		Addr:            formatAddr(r.Addr, r.AddrFamily),
		Description:     info.Description,
		Action:          r.Action,
		ActionName:      actionName(r.Action),
		PolicyID:        r.PolicyID,
		ProcessStartNs:  r.ProcessStartNs,
		MonotonicNs:     r.TimestampNs,
		ParentComm:      cString(r.ParentComm[:]),
		GrandparentComm: cString(r.GrandparentComm[:]),
		ExeVerified:     r.ProcFlags&traceProcProtected != 0,
	}

	if !eventCarriesFilename(r.EventType) {
		// Older objects left the per-CPU scratch filename of
		// the previous event in every event that writes none.
		te.Filename = ""
	}

	te.ActivityOutcome = "attempt"
	if r.EventType == TraceExecExit || r.EventType == TraceConnExit ||
		(r.EventType == TraceOpen && r.ProcFlags&traceEvtOpenResult != 0) {
		te.ActivityOutcome = "success"
		if r.RetVal < 0 {
			te.ActivityOutcome = "failure"
		}
	}
	if r.Action == ActionKill {
		te.SignalOutcome = "unknown"
		if r.SignalAttempted {
			te.SignalOutcome = "accepted"
			if r.SignalResult != 0 {
				te.SignalOutcome = "failed"
				te.SignalError = r.SignalResult
			}
		}
	}
	// Build richer description based on event type
	te.Description = buildDescription(te)
	if r.EventType == TraceOpen && r.ProcFlags&traceEvtArgsUnreadable != 0 {
		te.ArgsUnreadable = true
		te.Description += " [open_how unreadable: treated as read-write]"
	}

	// Clean absolute paths, materialize relative file paths
	// against the process CWD (AT_FDCWD only) and re-derive the exact-path
	// severity before the event reaches policy matching, rule evaluation and
	// persistence.
	normalizeEventPaths(r, &te)

	return te
}

// eventCarriesFilename reports whether the trace program writes the
// filename field for this event type: file events (path), exec (binary),
// clone (child comm), mount (device), umount (target) and memfd_create
// (name). Every other event's filename is meaningless: until the trace
// object cleared it in new_event, it held whatever path the previous event
// on the same CPU had read, so a sendto or setuid could "name"
// /etc/shadow. TestEventCarriesFilenameMatchesBPF checks this list against
// wafio_trace.c.
func eventCarriesFilename(eventType uint32) bool {
	switch eventType {
	case TraceExecve, TraceExecveat, TraceClone, TraceOpen, TraceUnlink, TraceRename,
		TraceChmod, TraceChown, TraceMount, TraceUmount, TraceMemfd:
		return true
	}
	return false
}

// openFailure names the errno of a failed open result (-ENOENT and so on).
// The kernel side never reports its restart codes (-512 to -516) as a result.
func openFailure(ret int64) string {
	if ret >= 0 || ret < -4095 {
		return fmt.Sprintf("result %d", ret)
	}
	return syscall.Errno(-ret).Error()
}

func buildDescription(e TraceEvent) string {
	switch e.EventType {
	case TraceExecve, TraceExecveat:
		if e.Args != "" {
			return fmt.Sprintf("Executed: %s %s", e.Filename, e.Args)
		}
		return fmt.Sprintf("Executed: %s", e.Filename)

	case TraceOpen:
		mode := "read"
		if e.Flags&3 == 1 {
			mode = "write"
		} else if e.Flags&3 == 2 {
			mode = "read/write"
		}
		if e.ActivityOutcome == "failure" {
			return fmt.Sprintf("Open of %s failed: %s (%s)", e.Filename, openFailure(e.RetVal), mode)
		}
		return fmt.Sprintf("Opened %s (%s)", e.Filename, mode)

	case TraceConnect:
		if e.Addr != "" && e.Port > 0 {
			proto := "TCP"
			if e.Port == 53 {
				proto = "DNS"
			}
			return fmt.Sprintf("%s connect to %s:%d", proto, e.Addr, e.Port)
		}
		return "Outbound connection"

	case TraceAccept:
		return fmt.Sprintf("Accepted connection on fd %d", e.Detail)

	case TraceClone:
		return fmt.Sprintf("Forked child PID %d", e.Detail)

	case TraceExit:
		return fmt.Sprintf("Process exited (code=%d)", e.RetVal)

	case TraceKill:
		return fmt.Sprintf("Sent signal %d to PID %d", e.Detail, e.Flags)

	case TraceUnlink:
		return fmt.Sprintf("Deleted: %s", e.Filename)

	case TraceRename:
		return fmt.Sprintf("Renamed: %s → %s", e.Filename, e.Args)

	case TraceChmod:
		return fmt.Sprintf("Changed permissions of %s to %04o", e.Filename, e.Flags)

	case TraceChown:
		return fmt.Sprintf("Changed owner of %s to uid=%d", e.Filename, e.Detail)

	case TraceSetuid:
		return fmt.Sprintf("setuid(%d) requested", e.Detail)

	case TraceSetgid:
		return fmt.Sprintf("setgid(%d) requested", e.Detail)

	case TracePtrace:
		reqName := fmt.Sprintf("request=%d", e.Detail)
		switch e.Detail {
		case 0:
			reqName = "PTRACE_TRACEME"
		case 4:
			reqName = "PTRACE_POKETEXT"
		case 5:
			reqName = "PTRACE_POKEDATA"
		case 16:
			reqName = "PTRACE_ATTACH"
		case 0x4206:
			reqName = "PTRACE_SEIZE"
		}
		return fmt.Sprintf("ptrace(%s) on PID %d", reqName, e.Flags)

	case TraceMount:
		return fmt.Sprintf("Mounted %s on %s", e.Filename, e.Args)

	case TraceUmount:
		return fmt.Sprintf("Unmounted %s", e.Filename)

	case TraceModuleLoad, TraceInitModule:
		return fmt.Sprintf("Kernel module loaded (fd=%d, params=%s)", e.Detail, e.Args)

	case TraceMprotect:
		protStr := ""
		if e.Flags&1 != 0 {
			protStr += "R"
		}
		if e.Flags&2 != 0 {
			protStr += "W"
		}
		if e.Flags&4 != 0 {
			protStr += "X"
		}
		return fmt.Sprintf("mprotect(%s) — %s", protStr, func() string {
			if e.Flags&6 == 6 {
				return "W^X violation (JIT runtimes do this; shellcode indicator otherwise)"
			}
			return "memory made executable"
		}())

	case TraceBind:
		if e.Addr != "" && e.Port > 0 {
			return fmt.Sprintf("Bound to %s:%d", e.Addr, e.Port)
		}
		return fmt.Sprintf("Bound port %d", e.Port)

	case TraceSocket:
		domainStr := fmt.Sprintf("domain=%d", e.AddrFamily)
		switch e.AddrFamily {
		case 1:
			domainStr = "AF_UNIX"
		case 2:
			domainStr = "AF_INET"
		case 10:
			domainStr = "AF_INET6"
		case 16:
			domainStr = "AF_NETLINK"
		case 33:
			domainStr = "AF_RXRPC"
		}
		typeStr := fmt.Sprintf("type=%d", e.Detail&0xff)
		switch e.Detail & 0xff {
		case 1:
			typeStr = "SOCK_STREAM"
		case 2:
			typeStr = "SOCK_DGRAM"
		case 3:
			typeStr = "SOCK_RAW"
		}
		if e.Detail&0xff == 3 && e.Flags == 50 {
			return fmt.Sprintf("Socket creation requested (%s, %s, IPPROTO_ESP=50)", domainStr, typeStr)
		}
		return fmt.Sprintf("Socket creation requested (%s, %s)", domainStr, typeStr)

	case TraceListen:
		return fmt.Sprintf("Listening on fd %d (backlog=%d)", e.Detail, e.Flags)

	case TraceDup:
		fdName := fmt.Sprintf("fd %d", e.Flags)
		switch e.Flags {
		case 0:
			fdName = "stdin"
		case 1:
			fdName = "stdout"
		case 2:
			fdName = "stderr"
		}
		return fmt.Sprintf("Duplicated fd %d → %s", e.Detail, fdName)

	case TracePipe:
		return "Pipe created"

	case TracePrctl:
		optName := fmt.Sprintf("option=%d", e.Detail)
		switch e.Detail {
		case 4:
			optName = "PR_SET_DUMPABLE"
		case 15:
			optName = "PR_SET_NAME"
		case 22:
			optName = "PR_SET_SECCOMP"
		case 24:
			optName = "PR_CAPBSET_DROP"
		case 38:
			optName = "PR_SET_NO_NEW_PRIVS"
		case 47:
			optName = "PR_CAP_AMBIENT"
		}
		return fmt.Sprintf("prctl(%s)", optName)

	case TraceMemfd:
		return fmt.Sprintf("memfd_create(%s) requested", e.Filename)
	}

	return TraceEventTypes[e.EventType].Description
}

// ────────────────────────────────────────────────────────────────────────────
//  Trace Config Types (API)
// ────────────────────────────────────────────────────────────────────────────

// BPF-level config (matches struct trace_config)
type TraceConfigBPF struct {
	Enabled      uint32
	EventMaskLo  uint32
	MinSeverity  uint32
	FilterOwnPid uint32
	AgentPid     uint32
	Pad          [3]uint32
}

func traceConfigToBPF(c TraceConfigAPI, agentPid uint32) TraceConfigBPF {
	bpf := TraceConfigBPF{}
	if c.Enabled {
		bpf.Enabled = 1
	}

	// Convert event names to bitmask
	nameToType := make(map[string]uint32)
	for k, v := range TraceEventTypes {
		nameToType[v.Name] = k
	}

	if len(c.EventTypes) == 0 {
		// Enable all events by default
		bpf.EventMaskLo = 0xFFFFFFFF
	} else {
		for _, name := range c.EventTypes {
			if t, ok := nameToType[strings.ToLower(name)]; ok && t <= 32 {
				bpf.EventMaskLo |= (1 << (t - 1))
			}
		}
	}

	bpf.MinSeverity = ParseSeverityName(c.MinSeverity)

	bpf.AgentPid = agentPid
	if c.FilterSelf {
		bpf.FilterOwnPid = 1
	}

	return bpf
}

func TraceConfigFromBPF(bpf TraceConfigBPF) TraceConfigAPI {
	api := TraceConfigAPI{
		Enabled:    bpf.Enabled != 0,
		FilterSelf: bpf.FilterOwnPid != 0,
	}

	// Convert bitmask to event names
	for i := uint32(1); i <= TraceEventMax; i++ {
		if bpf.EventMaskLo&(1<<(i-1)) != 0 {
			if info, ok := TraceEventTypes[i]; ok {
				api.EventTypes = append(api.EventTypes, info.Name)
			}
		}
	}

	api.MinSeverity = severityName(bpf.MinSeverity)

	return api
}

// ────────────────────────────────────────────────────────────────────────────
//  Trace Statistics (API)
// ────────────────────────────────────────────────────────────────────────────

type TraceStats struct {
	KernelEventsDropped uint64 `json:"kernel_events_dropped"`
	// EventsShed: per event name, low-severity events the kernel shed to
	// keep shared-ring headroom (trace_shed_wanted, wafio_trace.h TRACE_SHED_*).
	EventsShed  map[string]uint64 `json:"events_shed,omitempty"`
	TotalEvents uint64            `json:"total_events"`
	EventCounts map[string]uint64 `json:"event_counts"` // per event name
	BySeverity  map[string]uint64 `json:"by_severity"`  // per severity
	ByCategory  map[string]uint64 `json:"by_category"`  // per category
	BufferUsed  uint64            `json:"buffer_used"`  // estimated events in ring
	BufferTotal uint64            `json:"buffer_total"` // ring buffer size
	UptimeMs    int64             `json:"uptime_ms"`
}

// ────────────────────────────────────────────────────────────────────────────
//  Trace Status (API)
// ────────────────────────────────────────────────────────────────────────────

type TraceStatus struct {
	EnforcementDropped     uint64            `json:"enforcement_dropped"`
	TerminationMode        string            `json:"termination_mode"`
	UserspaceKillSupported bool              `json:"userspace_kill_supported"`
	ExpectedProbes         int               `json:"expected_probes"`
	MissingProbes          map[string]string `json:"missing_probes"`
	KernelEventsDropped    uint64            `json:"kernel_events_dropped"`
	QueueDropped           uint64            `json:"queue_dropped"` // sum of the QueueDropped* classes
	QueueDepth             int               `json:"queue_depth"`
	// Loss accounting by push-queue class (TraceClass): noise
	// (observed file/network events below MEDIUM) is dropped first, then
	// watched (such openat events of sensitive or policy files, kept by the
	// shed exemption), then significant (everything ingest always stores:
	// process, security, MEDIUM+, enforced). Delivery* = trace events in
	// telemetry batches discarded without a control plane receipt.
	QueueDroppedNoise       uint64 `json:"queue_dropped_noise"`
	QueueDroppedWatched     uint64 `json:"queue_dropped_watched"`
	QueueDroppedSignificant uint64 `json:"queue_dropped_significant"`
	DeliveryLostNoise       uint64 `json:"delivery_lost_noise"`
	DeliveryLostWatched     uint64 `json:"delivery_lost_watched"`
	DeliveryLostSignificant uint64 `json:"delivery_lost_significant"`
	// Loss in the last LossWindowSec seconds per class (queue + delivery;
	// kernel loss, which has no class, counts as significant); LastLossAt is
	// the last time any loss was observed (RFC 3339, "" = none since the
	// agent started). The dashboard warns on these, not on the totals.
	LossWindowSec         int      `json:"loss_window_sec"`
	RecentLostNoise       uint64   `json:"recent_lost_noise"`
	RecentLostWatched     uint64   `json:"recent_lost_watched"`
	RecentLostSignificant uint64   `json:"recent_lost_significant"`
	LastLossAt            string   `json:"last_loss_at"`
	Running               bool     `json:"running"`
	Probes                int      `json:"probes"`         // attached tracepoints
	ProbeNames            []string `json:"probe_names"`    // attached probe names
	EventsTotal           uint64   `json:"events_total"`   // total events received
	EventsDropped         uint64   `json:"events_dropped"` // ringbuf drops
	UptimeMs              int64    `json:"uptime_ms"`
	RingbufSizeMB         int      `json:"ringbuf_size_mb"` // ring buffer size in MB
	Enforcement           bool     `json:"enforcement"`     // enforcement engine active
	PoliciesTotal         int      `json:"policies_total"`  // number of loaded policies
	// MapSizing: the scale the trace maps were sized with and how full each
	// one is. Absent when the maps were not sized.
	MapSizing *MapSizing `json:"map_sizing,omitempty"`
	// ProtectedKernelSet: the loaded object has trace_protected_tgids, so the
	// kernel kill paths also skip protected processes (not only pid<=1/agent).
	ProtectedKernelSet bool `json:"protected_kernel_set"`
	// ProtectedTGIDs: processes currently in trace_protected_tgids (0 when
	// the object lacks the map).
	ProtectedTGIDs int `json:"protected_tgids"`
	// ProtectedForkRefused: forked children of protected processes the
	// kernel did not insert since load (fork budget spent or map full); they
	// are protected from the next refresh on.
	ProtectedForkRefused uint64 `json:"protected_fork_refused,omitempty"`
	// PriorityRing: the kill-candidate ring is read. The counters sum
	// trace_priority_stats: events it carried, candidates that found it full,
	// and candidates lost with both rings full.
	PriorityRing         bool   `json:"priority_ring"`
	PriorityEventsRouted uint64 `json:"priority_events_routed"`
	PriorityEventsFull   uint64 `json:"priority_events_full"`
	PriorityEventsLost   uint64 `json:"priority_events_lost"`
	// KernelEventsShed: events below MEDIUM the kernel did not export
	// because the shared ring was at least 6/8 full (file/network types) or
	// 7/8 full (any type); deliberate, unlike kernel_events_dropped. 0 with
	// an object without trace_shed_stats.
	KernelEventsShed uint64 `json:"kernel_events_shed"`
	// Forwarding filter, set by the host agent's telemetry
	// stream. ForwardFilter: "off" (no filter on the current stream: every
	// event is sent), "active", "revision_mismatch" (built for other ingest
	// semantics than this agent's: every event is sent), "too_large" (the
	// control plane's filter for this host is over 1 MiB and was not sent:
	// every event is sent) or "invalid" (every event is sent);
	// ForwardFilterDigest names the filter received.
	// ForwardFiltered* count the events not sent since the agent started
	// because the control plane would discard them: a suppress rule matched
	// (Suppressed), or ingest would neither store nor correlate them
	// (Unstored). Not loss — the rule hits they carry are reported.
	ForwardFilter             string `json:"forward_filter,omitempty"`
	ForwardFilterDigest       string `json:"forward_filter_digest,omitempty"`
	ForwardFilteredSuppressed uint64 `json:"forward_filtered_suppressed"`
	ForwardFilteredUnstored   uint64 `json:"forward_filtered_unstored"`
	// KprobeProbes: probes attached as a kprobe on the syscall wrapper
	// instead of the syscall tracepoint, because this kernel's tracepoint
	// copies user strings before the program runs (Linux 6.19+/7.0).
	KprobeProbes []string `json:"kprobe_probes,omitempty"`
	// OpenResult: file open events leave the kernel with the result of the
	// open (the exit probes of openat, openat2, open and creat are attached
	// and armed), so a failed open reads as failure and a successful one as
	// success. False: every open is an attempt. OpenResultKnown counts open
	// events exported with their result since load; OpenResultUnknown those
	// that waited for one and left without it (the open was restarted, the
	// thread went on or exited before the exit probe ran, or the pending map
	// was full). Kill candidates and events with a kernel Kill leave at entry,
	// without waiting, and count in neither.
	OpenResult        bool   `json:"open_result"`
	OpenResultKnown   uint64 `json:"open_result_known"`
	OpenResultUnknown uint64 `json:"open_result_unknown"`
}

// ────────────────────────────────────────────────────────────────────────────
//  Enforcement Policy (API)
// ────────────────────────────────────────────────────────────────────────────

// ActionPriority returns the ordering used to pick the "best" matching policy
// action when multiple policies fire on the same event: kill trumps alert
// trumps simulate trumps monitor. The raw uint32 constants cannot be used
// directly because ActionSimulate=3 must not outrank ActionKill=2 (the numeric
// values are constrained to match the BPF ABI where alert=1/kill=2).
func ActionPriority(a uint32) int {
	switch a {
	case ActionKill:
		return 3
	case ActionAlert:
		return 2
	case ActionSimulate:
		return 1
	}
	return 0
}

func ParseSeverityName(s string) uint32 {
	switch strings.ToLower(s) {
	case "low":
		return SevLow
	case "medium":
		return SevMedium
	case "high":
		return SevHigh
	case "critical":
		return SevCritical
	default:
		return SevInfo
	}
}

// BPF enforcement rule (matches struct trace_enforce_rule in wafio_trace.h, 16 bytes)
type TraceEnforceRuleBPF struct {
	Enabled     uint32
	Action      uint32
	MinSeverity uint32
	PolicyID    uint32
}

// ────────────────────────────────────────────────────────────────────────────
//  Enforcement Log Entry (audit trail)
// ────────────────────────────────────────────────────────────────────────────

type EnforcementLogEntry struct {
	Timestamp     string     `json:"timestamp"`
	PolicyID      uint32     `json:"policy_id"`
	PolicyName    string     `json:"policy_name"`
	Action        string     `json:"action"` // alert / kill / simulate
	Success       bool       `json:"success"`
	FailureReason string     `json:"failure_reason,omitempty"` // populated when Success==false
	Mode          string     `json:"mode"`                     // "kernel" | "userspace"
	Event         TraceEvent `json:"event"`

	// MITRE ATT&CK attribution — copied off the matching policy at log time.
	// Stored on every entry (denormalized) so downstream SIEM ingestion does
	// not need to round-trip back to the policy store. `omitempty` keeps the
	// wire format compatible with old servers that don't know these fields.
	MITRETechniqueID   string   `json:"mitre_technique_id,omitempty"`
	MITRETechniqueName string   `json:"mitre_technique_name,omitempty"`
	MITRETactic        string   `json:"mitre_tactic,omitempty"`
	Severity           string   `json:"severity,omitempty"`
	Tags               []string `json:"tags,omitempty"`
}
