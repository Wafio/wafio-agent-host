package ebpf

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// afInet is AF_INET as the trace program stores it in TraceEvent.AddrFamily.
const afInet uint16 = 2

// ────────────────────────────────────────────────────────────────────────────
//  PolicyEngine — runtime security enforcement policy evaluation & storage
//
//  Supports two enforcement layers:
//   1. Kernel (BPF): Fast-path per-event-type rules pushed to trace_enforce_map.
//      Used for "kill on any module_load" type rules. Instant, no userspace delay.
//   2. Userspace (Go): Rich matching on comm, filename, UID, severity.
//      Used for regex/substring policies. Slight latency but more flexible.
//      Kill is delivered by the TraceManager: pidfd_send_signal(SIGKILL) after
//      verifying the process start time, else a deferred in-kernel request
//      fired at the process's next traced syscall. Protected processes are
//      never targeted (trace_protect.go).
// ────────────────────────────────────────────────────────────────────────────

type PolicyEngine struct {
	mu                sync.RWMutex
	policies          map[uint32]*EnforcementPolicy
	nextID            uint32
	enforcementLog    []EnforcementLogEntry
	maxLogEntries     int
	droppedLogEntries uint64
	lastLogTime       time.Time

	// Callback to push kernel-level rules to BPF map
	pushKernelRule   func(eventType uint32, rule TraceEnforceRuleBPF) error
	removeKernelRule func(eventType uint32) error

	// BPF-LSM connect blocklist callbacks: destination IPs denied
	// synchronously at socket_connect (-EPERM before any packet leaves).
	pushConnectBlock   func(ip string, policyID uint32) error
	removeConnectBlock func(ip string) error
	// activeConnectBlocks tracks what was last pushed so sync can remove
	// IPs that no longer have an enforcing policy.
	activeConnectBlocks map[string]uint32
	// connectMapped: the loaded LSM object also denies an AF_INET6 connect to
	// the IPv4-mapped form of a blocklisted address (see lsm_connect.go).
	connectMapped bool
	// pushConnectSend replaces pushConnectBlock while the socket_sendmsg
	// hook is attached and denying: it also carries whether
	// addressed sends to the IP are denied. activeConnectSend is the send
	// flag last pushed per IP.
	pushConnectSend   func(ip string, policyID uint32, send bool) error
	activeConnectSend map[string]bool

	// killRouting writes the kernel kill-candidate routes (see
	// trace_priority.go) after every policy change.
	killRouting func(routes killRoutes)
}

// SetConnectCallbacks wires the BPF-LSM connect blocklist sync. Passing nil
// for push disables the kernel path: dest-IP-only policies then downgrade to
// userspace like any other complex match.
func (pe *PolicyEngine) SetConnectCallbacks(
	push func(ip string, policyID uint32) error,
	remove func(ip string) error,
) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.pushConnectBlock = push
	pe.removeConnectBlock = remove
	pe.markConnectAvailabilityLocked()
	pe.syncKillRoutingLocked()
}

// SetSendBlocklist wires the BPF-LSM socket_sendmsg hook:
// with push set, connect-blocklist entries are written through it with a
// send flag — set when an enforcing policy for the IP selects sendto — and
// Evaluate skips userspace action on a sendto the hook denied, as it does
// for connects. nil unwires it (addressed sends back to userspace). Call
// after SetConnectCallbacks; entries whose flag changes are rewritten.
func (pe *PolicyEngine) SetSendBlocklist(push func(ip string, policyID uint32, send bool) error) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.pushConnectSend = push
	err := pe.syncConnectBlocksLocked()
	pe.syncKillRoutingLocked()
	return err
}

// connectBlocklistDenies decides whether the host agent may wire the BPF-LSM
// connect blocklist into the engine. Once wired, Evaluate skips userspace
// action on connects it believes the blocklist denied, so the kernel
// must really deny them: blocklist map loaded, socket_connect program
// attached, LSM config written, block_connect on. Otherwise dest-IP policies
// stay in userspace; reason says why, for the agent log.
func connectBlocklistDenies(mapLoaded, hookAttached, blockConnect bool, configErr error) (bool, string) {
	switch {
	case !mapLoaded:
		return false, "connect blocklist map missing"
	case !hookAttached:
		return false, "socket_connect hook not attached"
	case configErr != nil:
		return false, "LSM config write failed: " + configErr.Error()
	case !blockConnect:
		return false, "report-only (lsm-block-connect off)"
	}
	return true, ""
}

// connectBlockAvailableLocked reports whether the LSM connect path is wired.
func (pe *PolicyEngine) connectBlockAvailableLocked() bool {
	return pe.pushConnectBlock != nil
}

func (pe *PolicyEngine) markConnectAvailabilityLocked() {
	avail := pe.connectBlockAvailableLocked()
	for _, p := range pe.policies {
		if p.ConnectBlockAvailable != avail {
			np := *p
			np.ConnectBlockAvailable = avail
			pe.policies[p.ID] = &np
		}
	}
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		policies:            make(map[uint32]*EnforcementPolicy),
		activeConnectBlocks: make(map[string]uint32),
		activeConnectSend:   make(map[string]bool),
		nextID:              1,
		maxLogEntries:       2000,
	}
}

// SetKernelCallbacks sets the functions used to push/remove enforcement rules
// to/from the BPF trace_enforce_map.
func (pe *PolicyEngine) SetKernelCallbacks(
	push func(eventType uint32, rule TraceEnforceRuleBPF) error,
	remove func(eventType uint32) error,
) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.pushKernelRule = push
	pe.removeKernelRule = remove
}

// ────────────────────────────────────────────────────────────────────────────
//  Policy CRUD
// ────────────────────────────────────────────────────────────────────────────

// policyHasComplexMatch returns true if the policy uses match criteria that
// kernel BPF cannot evaluate (comm/filename substring, UID). Such policies
// must be evaluated in userspace only.
func policyHasComplexMatch(p *EnforcementPolicy) bool {
	return p.MatchComm != "" || p.MatchFilename != "" || p.MatchUID != nil || p.MatchDestPort != "" ||
		p.MatchDestIP != ""
}

// destIPOnly reports a policy whose ONLY match criterion is MatchDestIP: the
// BPF-LSM socket_connect hook evaluates the destination IP synchronously in
// the kernel, so such a policy can still be kernel-enforced (via the connect
// blocklist) even though the per-event rule path cannot express it.
func destIPOnly(p *EnforcementPolicy) bool {
	return p.MatchDestIP != "" && p.MatchComm == "" && p.MatchFilename == "" &&
		p.MatchUID == nil && p.MatchDestPort == ""
}

// connectBlockEnforces reports whether the BPF-LSM connect blocklist can carry
// p: a dest-IP-only Block or Kill policy that selects every connect to its IP
// (event types empty or including connect, minimum severity the lowest),
// while the blocklist is wired (avail). The hook denies every connect to the
// IP with -EPERM, whatever the event type or severity, and has no alert mode:
// any narrower policy would deny connects it never selects, so it stays in
// userspace.
func connectBlockEnforces(p *EnforcementPolicy, avail bool) bool {
	if !avail || !destIPOnly(p) || ParseSeverityName(p.MinSeverity) != SevInfo {
		return false
	}
	if len(p.EventTypes) > 0 && !slices.ContainsFunc(p.EventTypes, func(name string) bool {
		return strings.EqualFold(name, "connect")
	}) {
		return false
	}
	switch ParseActionName(p.Action) {
	case ActionBlock, ActionKill:
		return true
	}
	return false
}

// policyDestIP parses MatchDestIP as validation accepts it (trimmed, IPv4 or
// IPv4-mapped IPv6) into its plain IPv4 form, which is also the connect
// blocklist key. ok is false when the field is empty or does not parse.
func policyDestIP(matchDestIP string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(matchDestIP))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// eventDestIP returns the destination address of an event that has one:
// connect and sendto name the peer they send to. bind carries a local address
// and other events none, so they never match a destination-IP policy. An
// IPv4-mapped IPv6 destination (a dual-stack socket reaching an IPv4 peer)
// comes back in its IPv4 form; any other IPv6 address never equals an IPv4
// policy address.
func eventDestIP(evt TraceEvent) (netip.Addr, bool) {
	if !strings.EqualFold(evt.EventName, "connect") && !strings.EqualFold(evt.EventName, "sendto") {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(evt.Addr)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// normalizeEnforcementMode sets KernelEnforceRequested, AutoDowngraded,
// EnforcementMode, and (if needed) clears KernelEnforce on policies that
// cannot actually run in the kernel. Call this before inserting into the
// map so the stored record reflects the effective state.
func normalizeEnforcementMode(p *EnforcementPolicy) {
	// Remember what the user originally asked for
	p.KernelEnforceRequested = p.KernelEnforce

	// Simulate (dry-run) is a pure userspace concept — the kernel only knows
	// alert/kill. Force userspace mode for simulate so we can log "would-have"
	// without ever firing bpf_send_signal.
	isSimulate := strings.EqualFold(p.Action, "simulate") ||
		strings.EqualFold(p.Action, "dryrun") || strings.EqualFold(p.Action, "dry-run") ||
		strings.EqualFold(p.Action, "shadow")

	// Auto-downgrade: kernel can only match on event_type + severity.
	// Anything using comm/filename/uid must run in userspace. Same for simulate.
	// Exception: a dest-IP-only Block/Kill policy is enforced synchronously by
	// the BPF-LSM socket_connect hook (the connect blocklist), so it keeps
	// kernel mode — but only when that path is actually wired (engine connect
	// callbacks).
	if p.KernelEnforce && isSimulate {
		p.KernelEnforce = false
		p.AutoDowngraded = true
	} else if p.KernelEnforce && policyHasComplexMatch(p) && !connectBlockEnforces(p, p.ConnectBlockAvailable) {
		p.KernelEnforce = false
		p.AutoDowngraded = true
	} else {
		p.AutoDowngraded = false
	}

	switch {
	case p.KernelEnforce:
		p.EnforcementMode = "kernel"
	case p.AutoDowngraded:
		p.EnforcementMode = "downgraded"
	default:
		p.EnforcementMode = "userspace"
	}
}

// clonePolicy isolates mutable criteria so callers cannot change enforcement
// without validation and kernel synchronization under the engine lock.
func clonePolicy(p EnforcementPolicy) EnforcementPolicy {
	p.EventTypes = append([]string(nil), p.EventTypes...)
	p.Tags = append([]string(nil), p.Tags...)
	if p.MatchUID != nil {
		uid := *p.MatchUID
		p.MatchUID = &uid
	}
	return p
}

// ReplacePolicies applies an authoritative snapshot while preserving server IDs.
// Userspace replacement is atomic. Kernel maps are updated entry by entry;
// an error restores the previous desired snapshot and reports rollback errors.
func (pe *PolicyEngine) ReplacePolicies(policies []EnforcementPolicy) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	next := make(map[uint32]*EnforcementPolicy, len(policies))
	nextID := pe.nextID
	for _, p := range policies {
		if err := ValidateEnforcementPolicy(p); err != nil {
			return err
		}
		// A snapshot without match_comm_mode comes from a control plane that
		// predates it: those policies were written for substring matching.
		if p.MatchCommMode == "" {
			p.MatchCommMode = CommMatchSubstring
		}
		p.ConnectBlockAvailable = pe.connectBlockAvailableLocked()
		if p.ID == 0 || p.ID == ^uint32(0) || p.Name == "" {
			return fmt.Errorf("invalid policy identity or name")
		}
		if _, exists := next[p.ID]; exists {
			return fmt.Errorf("duplicate policy ID %d", p.ID)
		}
		normalizeEnforcementMode(&p)
		p = clonePolicy(p)
		if old := pe.policies[p.ID]; old != nil {
			p.HitCount = old.HitCount
		}
		next[p.ID] = &p
		if p.ID >= nextID {
			nextID = p.ID + 1
		}
	}
	previous := pe.policies
	pe.policies = next
	if err := pe.syncKernelRulesLocked(); err != nil {
		pe.policies = previous
		if rollback := pe.syncKernelRulesLocked(); rollback != nil {
			return fmt.Errorf("apply policies: %w; rollback: %v", err, rollback)
		}
		return err
	}
	pe.nextID = nextID
	return nil
}

func (pe *PolicyEngine) AddPolicy(p EnforcementPolicy) (*EnforcementPolicy, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if err := ValidateEnforcementPolicy(p); err != nil {
		return nil, err
	}
	if p.Action == "" {
		p.Action = "monitor"
	}
	DefaultCommMatchMode(&p, "") // new policies compare whole words
	p.ConnectBlockAvailable = pe.connectBlockAvailableLocked()

	// Normalize enforcement mode (may auto-downgrade kernel → userspace)
	normalizeEnforcementMode(&p)

	now := time.Now().UTC().Format(time.RFC3339)
	p.ID = pe.nextID
	pe.nextID++
	p.CreatedAt = now
	p.UpdatedAt = now
	p.HitCount = 0

	p = clonePolicy(p)
	pe.policies[p.ID] = &p

	if err := pe.syncKernelRulesLocked(); err != nil {
		delete(pe.policies, p.ID)
		return nil, errors.Join(err, pe.syncKernelRulesLocked())
	}

	cp := clonePolicy(p)
	return &cp, nil
}

func (pe *PolicyEngine) UpdatePolicy(id uint32, p EnforcementPolicy) (*EnforcementPolicy, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if err := ValidateEnforcementPolicy(p); err != nil {
		return nil, err
	}

	existing, ok := pe.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy %d not found", id)
	}
	DefaultCommMatchMode(&p, existing.MatchCommMode) // an update without a mode keeps it

	p.ConnectBlockAvailable = pe.connectBlockAvailableLocked()
	// Normalize enforcement mode (may auto-downgrade kernel → userspace)
	normalizeEnforcementMode(&p)

	p.ID = id
	p.CreatedAt = existing.CreatedAt
	p.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	p.HitCount = existing.HitCount

	p = clonePolicy(p)
	pe.policies[id] = &p

	if err := pe.syncKernelRulesLocked(); err != nil {
		pe.policies[id] = existing
		return nil, errors.Join(err, pe.syncKernelRulesLocked())
	}

	cp := clonePolicy(p)
	return &cp, nil
}

func (pe *PolicyEngine) DeletePolicy(id uint32) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if _, ok := pe.policies[id]; !ok {
		return fmt.Errorf("policy %d not found", id)
	}

	previous := pe.policies[id]
	delete(pe.policies, id)
	if err := pe.syncKernelRulesLocked(); err != nil {
		pe.policies[id] = previous
		return errors.Join(err, pe.syncKernelRulesLocked())
	}

	return nil
}

func (pe *PolicyEngine) GetPolicy(id uint32) (*EnforcementPolicy, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	p, ok := pe.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy %d not found", id)
	}

	cp := clonePolicy(*p)
	return &cp, nil
}

func (pe *PolicyEngine) ListPolicies() []EnforcementPolicy {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	result := make([]EnforcementPolicy, 0, len(pe.policies))
	for _, p := range pe.policies {
		result = append(result, clonePolicy(*p))
	}
	return result
}

// ────────────────────────────────────────────────────────────────────────────
//  Enforcement Evaluation
// ────────────────────────────────────────────────────────────────────────────

// Evaluate checks an event against all userspace policies and returns
// the highest-priority action to take. Also logs enforcement actions.
func (pe *PolicyEngine) Evaluate(evt TraceEvent) (action uint32, policyID uint32) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	var bestAction uint32 = evt.Action
	var bestPolicyID uint32
	bestPri := ActionPriority(bestAction)

	for _, p := range pe.policies {
		if !p.Enabled || (evt.Action != ActionMonitor && p.ID == evt.PolicyID) {
			continue
		}

		if !pe.matchPolicy(p, evt) {
			continue
		}
		if pe.connectDeniedByBlocklistLocked(p, evt) {
			// Denied in the kernel before the connect happened: a hit, but
			// no second action from userspace.
			p.HitCount++
			continue
		}

		pAction := ParseActionName(p.Action)
		if pri := ActionPriority(pAction); pri > bestPri || (pri == bestPri && pri > 0 && (bestPolicyID != 0 && p.ID < bestPolicyID)) {
			bestAction = pAction
			bestPolicyID = p.ID
			bestPri = pri
		}

		// Increment hit count
		p.HitCount++
	}

	// Log any non-monitor enforcement (simulate/alert/kill all produce audit entries)
	if bestAction != ActionMonitor && bestPolicyID > 0 {
		policyName := ""
		var mitreID, mitreName, tactic, severity string
		var tags []string
		if p, ok := pe.policies[bestPolicyID]; ok {
			policyName = p.Name
			// Copy MITRE attribution onto the log entry. This denormalization
			// ensures the entry can be rendered in the UI / SIEM later even
			// if the policy is subsequently edited or deleted.
			mitreID = p.MITRETechniqueID
			mitreName = p.MITRETechniqueName
			tactic = p.MITRETactic
			severity = p.Severity
			tags = p.Tags
		}

		entry := EnforcementLogEntry{
			Timestamp:          pe.nextLogTimestampLocked(),
			PolicyID:           bestPolicyID,
			PolicyName:         policyName,
			Action:             actionName(bestAction),
			Success:            bestAction != ActionKill,
			Mode:               "userspace",
			Event:              evt,
			MITRETechniqueID:   mitreID,
			MITRETechniqueName: mitreName,
			MITRETactic:        tactic,
			Severity:           severity,
			Tags:               tags,
		}

		pe.enforcementLog = append(pe.enforcementLog, entry)
		if len(pe.enforcementLog) > pe.maxLogEntries {
			drop := len(pe.enforcementLog) - pe.maxLogEntries
			pe.droppedLogEntries += u64FromInt(drop)
			pe.enforcementLog = pe.enforcementLog[drop:]
		}
	}

	return bestAction, bestPolicyID
}

// RecordKernelEnforcement appends an audit entry for a kernel-enforced event
// (action was decided and applied by bpf_send_signal before the event reached
// userspace). Called from trace_manager when evt.Action was already set by
// the kernel. Does NOT alter hit counts (those are incremented when the
// userspace Evaluate path runs on the same event).
func (pe *PolicyEngine) RecordKernelEnforcement(evt TraceEvent) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	policyID := evt.PolicyID
	policyName := ""
	var mitreID, mitreName, tactic, severity string
	var tags []string
	if p, ok := pe.policies[policyID]; ok {
		policyName = p.Name
		// Also denormalize MITRE metadata for kernel-enforced matches so
		// the audit log has consistent attribution regardless of whether
		// the kill came from kernel (bpf_send_signal) or userspace path.
		mitreID = p.MITRETechniqueID
		mitreName = p.MITRETechniqueName
		tactic = p.MITRETactic
		severity = p.Severity
		tags = p.Tags
		// Count the kernel hit too so UI reflects reality
		p.HitCount++
	}

	entry := EnforcementLogEntry{
		Timestamp:          pe.nextLogTimestampLocked(),
		PolicyID:           policyID,
		PolicyName:         policyName,
		Action:             actionName(evt.Action),
		Success:            evt.Action != ActionKill || evt.SignalOutcome == "accepted",
		Mode:               "kernel",
		Event:              evt,
		MITRETechniqueID:   mitreID,
		MITRETechniqueName: mitreName,
		MITRETactic:        tactic,
		Severity:           severity,
		Tags:               tags,
	}
	if evt.Action == ActionKill && !entry.Success {
		entry.FailureReason = "signal outcome unknown (legacy trace object)"
		if evt.SignalOutcome == "failed" {
			entry.FailureReason = fmt.Sprintf("kernel signal helper failed: %d", evt.SignalError)
			if evt.SignalError == -1 {
				// enforce_check reports its own refusals (pid<=1, the agent,
				// trace_protected_tgids) as -1; the helper's EPERM is -1 too.
				entry.FailureReason = "kernel refused signal (-1): protected process or not permitted"
			}
		}
	}

	pe.enforcementLog = append(pe.enforcementLog, entry)
	if len(pe.enforcementLog) > pe.maxLogEntries {
		drop := len(pe.enforcementLog) - pe.maxLogEntries
		pe.droppedLogEntries += u64FromInt(drop)
		pe.enforcementLog = pe.enforcementLog[drop:]
	}
}

// matchPolicy checks if an event matches a policy's criteria.
func (pe *PolicyEngine) matchPolicy(p *EnforcementPolicy, evt TraceEvent) bool {
	// Check event type
	if len(p.EventTypes) > 0 {
		matched := false
		for _, et := range p.EventTypes {
			if strings.EqualFold(et, evt.EventName) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check minimum severity
	if p.MinSeverity != "" {
		minSev := ParseSeverityName(p.MinSeverity)
		if evt.Severity < minSev {
			return false
		}
	}

	// Check comm (process name), case-insensitive, under MatchCommMode
	// (exact / word / substring). Supports a comma-separated list of
	// terms (OR logic): "nc, ncat, socat".
	// For execve/execveat events, bpf_get_current_comm() returns the calling
	// process's comm (e.g. "sh"), not the new program name. In that case also
	// compare against the basename of the executed filename (e.g. "dig" from
	// "/usr/bin/dig") so that policies like match_comm:"dig" work correctly.
	if p.MatchComm != "" {
		mode := effectiveCommMatchMode(p.MatchCommMode)
		commLower := strings.ToLower(evt.Comm)
		execveEvent := strings.EqualFold(evt.EventName, "execve") || strings.EqualFold(evt.EventName, "execveat")
		fileBaseLower := strings.ToLower(path.Base(evt.Filename))
		anyCommMatch := false
		for _, t := range matchTerms(p.MatchComm) {
			if commTermMatches(mode, t, commLower) || (execveEvent && evt.Filename != "" && commTermMatches(mode, t, fileBaseLower)) {
				anyCommMatch = true
				break
			}
		}
		if !anyCommMatch {
			return false
		}
	}

	// Check filename — case-insensitive substring match.
	// Supports comma-separated list of terms (OR logic): "/tmp/, /dev/shm/"
	if p.MatchFilename != "" {
		filenameLower := strings.ToLower(evt.Filename)
		anyFilenameMatch := false
		for _, term := range strings.Split(p.MatchFilename, ",") {
			t := strings.TrimSpace(strings.ToLower(term))
			if t == "" {
				continue
			}
			if strings.Contains(filenameLower, t) {
				anyFilenameMatch = true
				break
			}
		}
		if !anyFilenameMatch {
			return false
		}
	}

	// Check UID
	if p.MatchUID != nil {
		if evt.UID != *p.MatchUID {
			return false
		}
	}

	// Check destination port (for connect / bind / listen events)
	// Supports comma-separated list of ports (OR logic): "4444, 1337, 443"
	if p.MatchDestPort != "" {
		eventPort := evt.Port
		anyPortMatch := false
		for _, term := range strings.Split(p.MatchDestPort, ",") {
			t := strings.TrimSpace(term)
			if t == "" {
				continue
			}
			if parsed, err := strconv.ParseUint(t, 10, 16); err == nil && uint16(parsed) == eventPort {
				anyPortMatch = true
				break
			}
		}
		if !anyPortMatch {
			return false
		}
	}

	// Check destination IP. Only an event whose destination parses and
	// equals the policy address matches; an event without one never does.
	if strings.TrimSpace(p.MatchDestIP) != "" {
		want, ok := policyDestIP(p.MatchDestIP)
		if !ok {
			return false
		}
		got, ok := eventDestIP(evt)
		if !ok || got != want {
			return false
		}
	}

	return true
}

// connectDeniedByBlocklistLocked reports whether the BPF-LSM connect blocklist
// already enforced p on evt. sys_enter_connect traces a connect before
// security_socket_connect denies it, so the event still reaches Evaluate;
// acting on it again would kill a process whose connect never happened. The
// hook sees AF_INET connects and, with an object that has the marker, AF_INET6
// connects to an IPv4-mapped address. sys_enter_sendto likewise precedes
// security_socket_sendmsg: with that hook wired, a sendto to an IPv4 (or
// IPv4-mapped) destination whose entry carries the send flag was denied too.
// Anything else the hooks never saw (an AF_INET6 connect with an older object,
// a sendto without the sendmsg hook) is still enforced from userspace. Must be
// called with pe.mu held.
func (pe *PolicyEngine) connectDeniedByBlocklistLocked(p *EnforcementPolicy, evt TraceEvent) bool {
	if !p.KernelEnforce || !connectBlockEnforces(p, pe.connectBlockAvailableLocked()) {
		return false
	}
	viaConnect := connectHookCoversEvent(evt, pe.connectMapped)
	viaSend := pe.pushConnectSend != nil && policySelectsSend(p) && sendHookCoversEvent(evt)
	if !viaConnect && !viaSend {
		return false
	}
	ip, ok := policyDestIP(p.MatchDestIP)
	if !ok {
		return false
	}
	_, onBlocklist := pe.activeConnectBlocks[ip.String()]
	if viaSend {
		return onBlocklist && pe.activeConnectSend[ip.String()]
	}
	return onBlocklist
}

// ────────────────────────────────────────────────────────────────────────────
//  Kernel Rule Sync (push policies to BPF map)
// ────────────────────────────────────────────────────────────────────────────

// syncKernelRulesLocked pushes kernel enforcement rules to the BPF map.
// For each event type, we find the highest-action enabled kernel-enforce policy.
// Must be called with pe.mu held.
func (pe *PolicyEngine) syncKernelRulesLocked() error {
	if pe.pushKernelRule == nil || pe.removeKernelRule == nil {
		for _, p := range pe.policies {
			// Dest-IP-only policies ride the LSM connect blocklist, which can
			// be wired even when the per-event enforce map is not — keep them.
			if p.KernelEnforce && !connectBlockEnforces(p, pe.connectBlockAvailableLocked()) {
				p.KernelEnforce = false
				p.AutoDowngraded = true
				p.EnforcementMode = "downgraded"
			}
		}
		return pe.syncDerivedMapsLocked()
	}

	// A single BPF slot cannot represent overlapping severity thresholds.
	// Keep those policies in userspace rather than silently dropping predicates.
	candidates := make(map[uint32][]*EnforcementPolicy)
	for _, p := range pe.policies {
		if !p.Enabled || !p.KernelEnforce {
			continue
		}
		for et, info := range TraceEventTypes {
			if len(p.EventTypes) == 0 {
				candidates[et] = append(candidates[et], p)
				continue
			}
			for _, name := range p.EventTypes {
				if strings.EqualFold(name, info.Name) {
					candidates[et] = append(candidates[et], p)
					break
				}
			}
		}
	}
	for _, group := range candidates {
		if len(group) < 2 {
			continue
		}
		different := false
		for _, p := range group[1:] {
			if ParseSeverityName(p.MinSeverity) != ParseSeverityName(group[0].MinSeverity) {
				different = true
			}
		}
		if different {
			for _, p := range group {
				p.KernelEnforce = false
				p.AutoDowngraded = true
				p.EnforcementMode = "downgraded"
			}
		}
	}

	// Build map of event_type → best rule
	nameToType := make(map[string]uint32)
	for k, v := range TraceEventTypes {
		nameToType[v.Name] = k
	}

	bestRules := make(map[uint32]TraceEnforceRuleBPF)

	for _, p := range pe.policies {
		if !p.Enabled || !p.KernelEnforce {
			continue
		}
		// Safety: skip policies with complex match criteria the kernel can't evaluate
		if policyHasComplexMatch(p) {
			continue
		}

		pAction := ParseActionName(p.Action)
		pSev := ParseSeverityName(p.MinSeverity)

		if len(p.EventTypes) == 0 {
			// Apply to ALL event types
			for et := uint32(1); et <= TraceEventMax; et++ {
				existing, ok := bestRules[et]
				if !ok || ActionPriority(pAction) > ActionPriority(existing.Action) || (pAction == existing.Action && p.ID < existing.PolicyID) {
					bestRules[et] = TraceEnforceRuleBPF{
						Enabled:     1,
						Action:      pAction,
						MinSeverity: pSev,
						PolicyID:    p.ID,
					}
				}
			}
		} else {
			for _, name := range p.EventTypes {
				et, ok := nameToType[strings.ToLower(name)]
				if !ok {
					continue
				}
				existing, has := bestRules[et]
				if !has || ActionPriority(pAction) > ActionPriority(existing.Action) || (pAction == existing.Action && p.ID < existing.PolicyID) {
					bestRules[et] = TraceEnforceRuleBPF{
						Enabled:     1,
						Action:      pAction,
						MinSeverity: pSev,
						PolicyID:    p.ID,
					}
				}
			}
		}
	}

	// Clear all existing rules for event types not in bestRules
	for et := uint32(1); et <= TraceEventMax; et++ {
		if _, ok := bestRules[et]; !ok {
			if err := pe.removeKernelRule(et); err != nil {
				return fmt.Errorf("remove kernel policy %d: %w", et, err)
			}
		}
	}

	// Push the best rules
	for et, rule := range bestRules {
		if err := pe.pushKernelRule(et, rule); err != nil {
			return fmt.Errorf("push kernel policy %d: %w", et, err)
		}
	}

	return pe.syncDerivedMapsLocked()
}

// syncConnectBlocksLocked reconciles the BPF-LSM connect blocklist with the
// current policy snapshot: the highest-priority enabled kernel-enforce policy
// wins per destination IP, and IPs without an enforcing policy are removed.
// Keys are the canonical IPv4 form, as in the kernel map, so two spellings of
// one address share one entry. With the socket_sendmsg hook wired, an entry
// carries the send flag when any of its enforcing policies selects sendto.
// Must be called with pe.mu held.
func (pe *PolicyEngine) syncConnectBlocksLocked() error {
	if pe.removeConnectBlock == nil {
		return nil
	}

	best := make(map[string]uint32) // ip → policyID
	bestAction := make(map[string]uint32)
	send := make(map[string]bool) // ip → an enforcing policy selects sendto
	for _, p := range pe.policies {
		if !p.Enabled || !p.KernelEnforce || !connectBlockEnforces(p, true) {
			continue
		}
		addr, ok := policyDestIP(p.MatchDestIP)
		if !ok {
			continue
		}
		ip := addr.String()
		if policySelectsSend(p) {
			send[ip] = true
		}
		action := ParseActionName(p.Action)
		if prev, ok := bestAction[ip]; !ok || ActionPriority(action) > ActionPriority(prev) ||
			(action == prev && p.ID < best[ip]) {
			best[ip] = p.ID
			bestAction[ip] = action
		}
	}

	for ip := range pe.activeConnectBlocks {
		if _, ok := best[ip]; !ok {
			if err := pe.removeConnectBlock(ip); err != nil {
				return fmt.Errorf("remove connect block %s: %w", ip, err)
			}
			delete(pe.activeConnectBlocks, ip)
			delete(pe.activeConnectSend, ip)
		}
	}
	for ip, policyID := range best {
		// The kernel entry's send flag: only written through the sendmsg
		// pusher; pushConnectBlock leaves it clear.
		wantSend := send[ip] && pe.pushConnectSend != nil
		prev, ok := pe.activeConnectBlocks[ip]
		prevSend, sendKnown := pe.activeConnectSend[ip]
		if ok && prev == policyID && sendKnown && prevSend == wantSend {
			continue
		}
		var err error
		if pe.pushConnectSend != nil {
			err = pe.pushConnectSend(ip, policyID, wantSend)
		} else {
			err = pe.pushConnectBlock(ip, policyID)
		}
		if err != nil {
			return fmt.Errorf("push connect block %s: %w", ip, err)
		}
		pe.activeConnectBlocks[ip] = policyID
		pe.activeConnectSend[ip] = wantSend
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
//  Enforcement Log
// ────────────────────────────────────────────────────────────────────────────

func (pe *PolicyEngine) GetEnforcementLog(limit int) []EnforcementLogEntry {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	n := len(pe.enforcementLog)
	if n == 0 {
		return []EnforcementLogEntry{}
	}
	if limit <= 0 || limit > n {
		limit = n
	}

	// Return newest first
	start := n - limit
	result := make([]EnforcementLogEntry, limit)
	copy(result, pe.enforcementLog[start:])

	// Reverse for newest-first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

// DrainEnforcementLog returns up to `limit` oldest entries (FIFO) and removes
// them from the buffer. Used by the push client so the same entries are not
// re-pushed (and re-inserted) on every flush tick. Caller pushes the returned
// slice; on push failure the entries are dropped (server-side ON CONFLICT
// keeps duplicates harmless even if a retry path is added later).
func (pe *PolicyEngine) DrainEnforcementLog(limit int) []EnforcementLogEntry {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	n := len(pe.enforcementLog)
	if n == 0 {
		return nil
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]EnforcementLogEntry, limit)
	copy(out, pe.enforcementLog[:limit])
	// Shift remaining entries to the front so future appends start fresh.
	pe.enforcementLog = append(pe.enforcementLog[:0], pe.enforcementLog[limit:]...)
	return out
}

// EnforcementLogPending reports whether an enforcement entry waits for
// DrainEnforcementLog.
func (pe *PolicyEngine) EnforcementLogPending() bool {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	return len(pe.enforcementLog) > 0
}

func (pe *PolicyEngine) ClearEnforcementLog() {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.enforcementLog = nil
}

// RecordSignalOutcome records helper acceptance, never proof of process exit.
func (pe *PolicyEngine) RecordSignalOutcome(policyID uint32, evt TraceEvent, err error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	for i := len(pe.enforcementLog) - 1; i >= 0; i-- {
		e := &pe.enforcementLog[i]
		if e.PolicyID != policyID || e.Event.TimestampNs != evt.TimestampNs || e.Event.PID != evt.PID {
			continue
		}
		e.Success = err == nil
		e.Event.SignalOutcome = "accepted"
		if err != nil {
			e.Event.SignalOutcome = evt.SignalOutcome
			if e.Event.SignalOutcome == "" {
				e.Event.SignalOutcome = "failed"
			}
			e.FailureReason = err.Error()
		}
		return
	}
	// The requested record may already have been drained for telemetry. Emit
	// a distinct outcome record while retaining the original event identity.
	outcome := evt.SignalOutcome
	evt.SignalOutcome = "accepted"
	entry := EnforcementLogEntry{Timestamp: pe.nextLogTimestampLocked(), PolicyID: policyID, Action: "kill", Mode: "deferred_outcome", Success: err == nil, Event: evt}
	if err != nil {
		entry.Event.SignalOutcome = "failed"
		if outcome != "" {
			entry.Event.SignalOutcome = outcome
		}
		entry.FailureReason = err.Error()
	}
	if p := pe.policies[policyID]; p != nil {
		entry.PolicyName = p.Name
		entry.MITRETechniqueID = p.MITRETechniqueID
		entry.MITRETechniqueName = p.MITRETechniqueName
		entry.MITRETactic = p.MITRETactic
		entry.Severity = p.Severity
		entry.Tags = append([]string(nil), p.Tags...)
	}
	pe.enforcementLog = append(pe.enforcementLog, entry)
	if len(pe.enforcementLog) > pe.maxLogEntries {
		pe.droppedLogEntries += u64FromInt(len(pe.enforcementLog) - pe.maxLogEntries)
		pe.enforcementLog = pe.enforcementLog[len(pe.enforcementLog)-pe.maxLogEntries:]
	}
}

func (pe *PolicyEngine) RecordSignalRequested(policyID uint32, evt TraceEvent) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	for i := len(pe.enforcementLog) - 1; i >= 0; i-- {
		e := &pe.enforcementLog[i]
		if e.PolicyID == policyID && e.Event.TimestampNs == evt.TimestampNs && e.Event.PID == evt.PID {
			e.Mode = "deferred"
			e.Event.SignalOutcome = "requested"
			e.Success = false
			return
		}
	}
}

func (pe *PolicyEngine) RecordSignalCoalesced(policyID uint32, evt TraceEvent) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	// Repeated events from an already-requested process are not new signal attempts.
	for i := len(pe.enforcementLog) - 1; i >= 0; i-- {
		e := pe.enforcementLog[i]
		if e.PolicyID == policyID && e.Event.TimestampNs == evt.TimestampNs && e.Event.PID == evt.PID {
			pe.enforcementLog = append(pe.enforcementLog[:i], pe.enforcementLog[i+1:]...)
			return
		}
	}
}

func (pe *PolicyEngine) EnforcementDropped() uint64 {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.droppedLogEntries
}

// PostgreSQL event_time dedup uses microsecond precision. Keep distinct records
// distinct even when requested and outcome are collected in the same clock tick.
func (pe *PolicyEngine) nextLogTimestampLocked() string {
	now := time.Now().UTC().Truncate(time.Microsecond)
	if !now.After(pe.lastLogTime) {
		now = pe.lastLogTime.Add(time.Microsecond)
	}
	pe.lastLogTime = now
	return now.Format(time.RFC3339Nano)
}
