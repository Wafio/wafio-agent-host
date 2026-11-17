package ebpf

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
//  Kill-candidate routing
//
//  Every traced syscall used to share one 16 MB ring buffer. A process that
//  floods cheap events (openat at INFO) could fill it, and the event that
//  should trigger its userspace kill was then dropped like any other — only
//  counted. The trace object now has a small second ring,
//  trace_priority_events: submit_event routes an event there when
//  trace_priority_rules says some enabled Kill policy evaluated in userspace
//  could select it (event type, minimum severity), or when the kernel already
//  killed for it. A full priority ring falls back to the shared ring; the
//  per-CPU trace_priority_stats count routed / full / lost, and a rise in the
//  drop counters becomes an alert event.
// ────────────────────────────────────────────────────────────────────────────

// killCandidateRoutes returns, per trace event type, the lowest severity at
// which an enabled Kill policy could select an event of that type. Only
// connect and sendto carry a destination, so a policy with match_dest_ip
// selects nothing else. A connect the BPF-LSM blocklist denies in the kernel
// needs no userspace kill: with an object that has the marker (mapped) every
// connect that reaches the policy's IPv4 address is denied there, so the
// blocklist's policies leave connect out — and sendto too while the
// socket_sendmsg hook is wired (sendWired) and the policy selects it.
func killCandidateRoutes(policies map[uint32]*EnforcementPolicy, connectAvail, mapped, sendWired bool) map[uint32]uint32 {
	nameToType := make(map[string]uint32, len(TraceEventTypes))
	for et, info := range TraceEventTypes {
		nameToType[info.Name] = et
	}
	routes := make(map[uint32]uint32)
	for _, p := range policies {
		if !p.Enabled || ParseActionName(p.Action) != ActionKill {
			continue
		}
		var types []uint32
		if len(p.EventTypes) == 0 {
			for et := uint32(1); et <= TraceEventMax; et++ {
				types = append(types, et)
			}
		} else {
			for _, name := range p.EventTypes {
				if et, ok := nameToType[strings.ToLower(strings.TrimSpace(name))]; ok {
					types = append(types, et)
				}
			}
		}
		destIP := strings.TrimSpace(p.MatchDestIP) != ""
		onBlocklist := p.KernelEnforce && connectBlockEnforces(p, connectAvail)
		blocklisted := mapped && onBlocklist
		sendDenied := sendWired && onBlocklist && policySelectsSend(p)
		sev := ParseSeverityName(p.MinSeverity)
		for _, et := range types {
			if destIP && et != TraceConnect && et != TraceSendto {
				continue
			}
			if (blocklisted && et == TraceConnect) || (sendDenied && et == TraceSendto) {
				continue
			}
			if cur, ok := routes[et]; !ok || sev < cur {
				routes[et] = sev
			}
		}
	}
	return routes
}

// killRoutes is what the kernel needs to route kill candidates: per event
// type the lowest severity (absent = not a candidate), and the openat
// final-component names (killCandidateOpenNames); plus the openat path
// components it must not shed for ring headroom (shedKeepNames).
type killRoutes struct {
	Types     map[uint32]uint32
	OpenNames map[string]struct{}
	KeepNames map[string]uint8
}

// killCandidateOpenNames returns the path component names that make an
// openat a kill candidate at any kernel severity. The kernel raises openat
// severity on an exact path only; the agent cleans and resolves the path
// first (/etc/./shadow, "shadow" opened from /etc, /etc/./sudoers.d/x) and
// may raise it to what a Kill policy waits for. So for every enabled Kill
// policy that selects openat above INFO (at INFO every openat is routed by
// type already) with a match_filename, the last component of each term is
// listed. The kernel routes an openat whose final component is listed, or,
// opened for writing, any of whose components is (a directory term:
// /etc/sudoers.d/, /proc/ — raised by the agent only for a write).
func killCandidateOpenNames(policies map[uint32]*EnforcementPolicy) map[string]struct{} {
	names := make(map[string]struct{})
	for _, p := range policies {
		if !p.Enabled || ParseActionName(p.Action) != ActionKill || p.MatchFilename == "" ||
			strings.TrimSpace(p.MatchDestIP) != "" || ParseSeverityName(p.MinSeverity) == SevInfo {
			continue
		}
		if len(p.EventTypes) > 0 && !slices.ContainsFunc(p.EventTypes, func(n string) bool {
			return strings.EqualFold(strings.TrimSpace(n), TraceEventTypes[TraceOpen].Name)
		}) {
			continue
		}
		for _, term := range strings.Split(p.MatchFilename, ",") {
			if name := finalPathComponent(term); name != "" {
				names[name] = struct{}{}
			}
		}
	}
	return names
}

// finalPathComponent returns the lowercased last component of a filename
// term ("/etc/shadow" → "shadow", "/etc/sudoers.d/" → "sudoers.d"), or "".
func finalPathComponent(term string) string {
	t := strings.TrimRight(strings.ToLower(strings.TrimSpace(term)), "/")
	if i := strings.LastIndexByte(t, '/'); i >= 0 {
		t = t[i+1:]
	}
	if t == "." || t == ".." {
		return ""
	}
	return t
}

// traceNameHash is the key of trace_priority_names: FNV-1a 64 of name with
// ASCII A-Z lowercased, exactly as trace_final_name_hash computes it in the
// kernel over an event's final path component.
func traceNameHash(name string) uint64 {
	const (
		offset = 0xcbf29ce484222325
		prime  = 0x100000001b3
	)
	h := uint64(offset)
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c |= 0x20
		}
		h = (h ^ uint64(c)) * prime
	}
	return h
}

// SetKillCandidateRouting wires the kernel priority-rule map writer. It is
// called at once and after every policy change with the full route set
// (absent types are not candidates). A nil fn disables routing updates.
func (pe *PolicyEngine) SetKillCandidateRouting(fn func(routes killRoutes)) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.killRouting = fn
	pe.syncKillRoutingLocked()
}

// syncKillRoutingLocked pushes the current routes. Best effort: a failed map
// write only costs the priority lane (events still reach the shared ring),
// so it never rolls back a policy change; the writer logs it.
// Must be called with pe.mu held.
func (pe *PolicyEngine) syncKillRoutingLocked() {
	if pe.killRouting == nil {
		return
	}
	pe.killRouting(killRoutes{
		Types:     killCandidateRoutes(pe.policies, pe.connectBlockAvailableLocked(), pe.connectMapped, pe.pushConnectSend != nil),
		OpenNames: killCandidateOpenNames(pe.policies),
		KeepNames: shedKeepNames(pe.policies),
	})
}

// syncDerivedMapsLocked reconciles what follows from the policy set after the
// kernel rules: the connect blocklist, then kill-candidate routing.
// Must be called with pe.mu held.
func (pe *PolicyEngine) syncDerivedMapsLocked() error {
	err := pe.syncConnectBlocksLocked()
	pe.syncKillRoutingLocked()
	return err
}

// traceLossCounters are the kernel drop counters of the trace object:
// trace_stats[0] (shared ring full) and trace_priority_stats (priority ring
// full, kill candidate lost with both rings full).
type traceLossCounters struct {
	BulkLost     uint64
	PriorityFull uint64
	PriorityLost uint64
}

// traceLossDelta is cur-prev for a monotonic counter; a counter that went
// backwards restarted (new trace object), so cur itself is the delta.
func traceLossDelta(prev, cur uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// traceLossAlert builds the alert event for drops since the previous check,
// or false when nothing new was dropped. A lost kill candidate is HIGH (a
// userspace kill policy may not have fired), a shared-ring drop MEDIUM, and
// a priority-ring overflow that the shared ring still took LOW.
func traceLossAlert(prev, cur traceLossCounters, now time.Time) (TraceEvent, bool) {
	bulk := traceLossDelta(prev.BulkLost, cur.BulkLost)
	full := traceLossDelta(prev.PriorityFull, cur.PriorityFull)
	lost := traceLossDelta(prev.PriorityLost, cur.PriorityLost)
	if bulk == 0 && full == 0 && lost == 0 {
		return TraceEvent{}, false
	}
	sev := SevLow
	if bulk > 0 {
		sev = SevMedium
	}
	if lost > 0 {
		sev = SevHigh
	}
	var parts []string
	if lost > 0 {
		parts = append(parts, fmt.Sprintf("%d kill-candidate events lost with both rings full; a userspace kill policy may not have fired", lost))
	}
	if full > 0 {
		parts = append(parts, fmt.Sprintf("%d kill-candidate events overflowed the priority ring", full))
	}
	if bulk > 0 {
		parts = append(parts, fmt.Sprintf("%d events dropped from the shared ring", bulk))
	}
	return TraceEvent{
		EventName:    traceLossEventName,
		Category:     "security",
		Severity:     sev,
		SeverityName: severityName(sev),
		Timestamp:    now.UTC().Format(time.RFC3339),
		Description:  "trace event loss since the last check: " + strings.Join(parts, "; "),
	}, true
}

const (
	// traceShedHighStreak: consecutive checks with shedding (one check per
	// traceLossCheckInterval, so 60 s) after which the shed event is HIGH: a
	// burst (package install, build) ends within seconds, a flood kept up to
	// hide activity does not.
	traceShedHighStreak = 6
	// traceShedHighCount: events shed in one check that make the event HIGH
	// at once (10,000/s over 10 s, about the ring's whole capacity per
	// second).
	traceShedHighCount = 100_000
)

// traceShedAlert builds the security event for events the kernel shed for
// shared-ring headroom since the previous check (trace_shed_stats), or false
// when none were. Shedding keeps the ring for MEDIUM+ events, kill
// candidates and the events the agent or ingest would raise (trace_open_keep)
// while the reader is behind, but what it sheds is gone: an escalate rule, a
// correlation stage or an Alert policy without a filename can no longer see
// it. A flood of cheap events is how an attacker would push the ring there,
// so the shed is reported like a loss (≤ 1 event per check): MEDIUM, HIGH
// once it has lasted traceShedHighStreak checks (streak counts consecutive
// checks with shedding, this one included) or reached traceShedHighCount.
func traceShedAlert(prev, cur map[uint32]uint64, streak int, now time.Time) (TraceEvent, bool) {
	var total uint64
	types := make([]uint32, 0, len(cur))
	for et := range cur {
		types = append(types, et)
	}
	slices.Sort(types)
	var parts []string
	for _, et := range types {
		d := traceLossDelta(prev[et], cur[et])
		if d == 0 {
			continue
		}
		total += d
		parts = append(parts, fmt.Sprintf("%s=%d", TraceEventTypes[et].Name, d))
	}
	if total == 0 {
		return TraceEvent{}, false
	}
	sev := SevMedium
	if streak >= traceShedHighStreak || total >= traceShedHighCount {
		sev = SevHigh
	}
	desc := fmt.Sprintf("trace ring headroom: %d low-severity events shed since the last check (%s)", total, strings.Join(parts, " "))
	if streak > 1 {
		desc += fmt.Sprintf(", shedding for %d consecutive checks", streak)
	}
	desc += "; the trace reader is behind - a flood of low-severity events can hide activity. MEDIUM and higher events, kill candidates, credential changes and events the agent or ingest may raise are kept"
	return TraceEvent{
		EventName:    traceShedEventName,
		Category:     "security",
		Severity:     sev,
		SeverityName: severityName(sev),
		Timestamp:    now.UTC().Format(time.RFC3339),
		Description:  desc,
	}, true
}

// shedKeepNames is what the agent writes to trace_keep_names: the built-in
// names plus the last component of each narrowing filename term
// (filenameTermNarrows) of an enabled Kill, Alert or Simulate policy that may
// select openat (those act in userspace on the exported event; a term ending
// in "/" names a directory, kept for any file below it). Policies with
// match_dest_ip select no openat.
func shedKeepNames(policies map[uint32]*EnforcementPolicy) map[string]uint8 {
	names := maps.Clone(traceKeepBuiltin)
	for _, p := range policies {
		if !p.Enabled || p.MatchFilename == "" || strings.TrimSpace(p.MatchDestIP) != "" {
			continue
		}
		switch ParseActionName(p.Action) {
		case ActionKill, ActionAlert, ActionSimulate:
		default:
			continue
		}
		if len(p.EventTypes) > 0 && !slices.ContainsFunc(p.EventTypes, func(n string) bool {
			return strings.EqualFold(strings.TrimSpace(n), TraceEventTypes[TraceOpen].Name)
		}) {
			continue
		}
		for _, term := range strings.Split(p.MatchFilename, ",") {
			// A term that does not narrow (e.g. "/usr/", "lib", "/tmp/")
			// would exempt nearly every path from shedding and fill the
			// push queue's watched class.
			if !filenameTermNarrows(strings.TrimSpace(term)) {
				continue
			}
			name := finalPathComponent(term)
			if name == "" {
				continue
			}
			flag := traceKeepName
			if strings.HasSuffix(strings.TrimSpace(term), "/") {
				flag = traceKeepDir
			}
			names[name] |= flag
		}
	}
	return names
}

// traceKeepNameKeys hashes shedKeepNames into trace_keep_names entries; two
// names with one hash share their bits.
func traceKeepNameKeys(names map[string]uint8) map[uint64]uint8 {
	keys := make(map[uint64]uint8, len(names))
	for name, flag := range names {
		keys[traceNameHash(name)] |= flag
	}
	return keys
}
