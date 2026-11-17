//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// ────────────────────────────────────────────────────────────────────────────
//  BPF Map Names (must match SEC(".maps") in wafio_trace.c / wafio_lsm.c)
// ────────────────────────────────────────────────────────────────────────────

const (
	traceMapEvents    = "trace_events"
	traceMapConfig    = "trace_config_map"
	traceMapStats     = "trace_stats"
	traceMapEnforce   = "trace_enforce_map"
	traceMapDeferred  = "trace_deferred_signals"
	traceMapProtected = traceProtectedMapName // optional: objects built before the protected set lack it
	// optional: objects built before kernel-side protected-set upkeep lack it
	// (exec then keeps no inherited protection; the refresh restores verified
	// processes).
	traceMapProtectedComms = "trace_protected_comms"
	// optional: objects built before the fork-insert budget lack it (no fork
	// inheritance budget; such objects are not shipped with this agent).
	traceMapProtectedBudget = "trace_protected_budget"

	lsmMapConfig      = "wafio_lsm_config"
	lsmMapBlocklist   = "wafio_lsm_blocklist"
	lsmMapIPBlocklist = "wafio_lsm_ip_blocklist"
	lsmMapEvents      = "wafio_lsm_events"
)

// ────────────────────────────────────────────────────────────────────────────
//  TraceManager — lifecycle controller for runtime security tracing
// ────────────────────────────────────────────────────────────────────────────

type TraceManager struct {
	mu sync.RWMutex

	eventPrefix string
	cfg         TraceManagerConfig
	log         *log.Logger

	// BPF objects
	coll *ebpf.Collection

	// map references
	eventsMap      *ebpf.Map
	configMap      *ebpf.Map
	statsMap       *ebpf.Map
	enforceMap     *ebpf.Map
	deferredMap    *ebpf.Map
	deferredMu     sync.Mutex
	deferredEvents map[uint32]TraceEvent

	// Protected-process set: consulted before every userspace or
	// deferred kill; mirrored into protectedMap for the kernel kill paths
	// when the loaded object provides it. protectedTGIDs and
	// protectedOverflowLogged are owned by protectedRefreshLoop.
	protected               *ProtectedProcessSet
	protectedMap            *ebpf.Map
	protectedTGIDs          map[uint32]uint64 // tgid → value written to protectedMap
	protectedOverflowLogged bool
	protectedCount          atomic.Int32 // len(protectedTGIDs), readable by Status
	// protectedBudgetMap bounds the kernel's fork inserts; refused
	// inserts since load, readable by Status.
	protectedBudgetMap *ebpf.Map
	protectedRefused   atomic.Uint64
	// pidfdOK: pidfd_open + pidfd_send_signal usable → immediate verified kill.
	pidfdOK bool

	// attached links
	links         []link.Link
	linkNames     []string
	probeFailures map[string]string
	// probesAbsent: mayBeAbsent probes whose tracepoint this kernel lacks
	// (not expected, not failures).
	probesAbsent int

	// ringbuf reader
	reader *ringbuf.Reader

	// Kill-candidate priority ring (trace_priority_linux.go); unset with
	// objects that predate it. priorityMaps is written by the PolicyEngine's
	// routing callback under the engine lock: atomic, so Stop detaches it
	// without taking that lock (policy sync already takes tm.mu through the
	// connect blocklist). priorityNameKeys is owned by that callback.
	priorityReader   *ringbuf.Reader
	priorityMaps     atomic.Pointer[priorityMaps]
	priorityNameKeys map[uint64]struct{}
	// keepNameKeys: trace_keep_names as last written (key → TRACE_KEEP_*
	// bits); owned by the same callback. keepMap is trace_keep_names itself,
	// written whether or not the priority ring is read (the kernel's shed
	// exemption does not depend on it); nil with objects without the map.
	keepNameKeys     map[uint64]uint8
	keepMap          atomic.Pointer[ebpf.Map]
	priorityStatsMap *ebpf.Map
	// shedStatsMap: per event type, events the kernel shed for shared-ring
	// headroom (trace_shed_stats; nil for older objects).
	shedStatsMap *ebpf.Map
	// kprobeNames: probes attached through their kprobe twin
	// (trace_probes_kprobe.go) instead of the tracepoint.
	kprobeNames []string
	// Open results (trace_open_result_linux.go): openCtlMap arms the kernel to
	// hold open events for their result, openStatsMap counts how they left;
	// both nil with objects that predate it. openResultArmed: armed.
	openCtlMap      *ebpf.Map
	openStatsMap    *ebpf.Map
	openResultArmed bool

	// BPF-LSM proactive blocking
	lsmColl       *ebpf.Collection
	lsmLink       link.Link
	lsmExtraLinks []link.Link // socket_connect / socket_sendmsg hook links
	lsmConfigMap  *ebpf.Map
	lsmBlockMap   *ebpf.Map
	lsmIPBlockMap *ebpf.Map
	lsmEventsMap  *ebpf.Map
	// lsmSuppressedMap: per-CPU count of network deny reports the object
	// rate-limited (nil for older objects).
	lsmSuppressedMap *ebpf.Map
	lsmReader        *ringbuf.Reader
	lsmActive        bool
	lsmState         string // LSMState* value reported in the trace status

	// events: the newest-5000 query ring, per-category rings (1000 each, so
	// low-frequency categories are not drowned out by file/openat) and the
	// destructive push queue consumed by the telemetry push loop. The query
	// ring used to double as the push source: the pusher copied the newest
	// 500 every tick, so events were re-sent many times over (inflated
	// server-side hit counts) and, past 500 ev/s, silently aged out unsent.
	events *traceEventStore

	// boot time offset
	bootTimeOffset time.Duration

	// counters
	totalEvents   atomic.Uint64
	droppedEvents atomic.Uint64
	// Trace events in telemetry batches the agent discarded unconfirmed
	// (NoteDeliveryLoss), and the per-minute loss history behind the
	// RecentLost* status fields.
	deliveryLost [traceClassCount]atomic.Uint64
	lossHistory  traceLossHistory

	// enforcement
	policyEngine *PolicyEngine

	// state
	running   bool
	startedAt time.Time
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewTraceManager creates a new trace manager (does not start).
func NewTraceManager(cfg TraceManagerConfig, logger *log.Logger) *TraceManager {
	if logger == nil {
		logger = log.New(os.Stderr, "[trace] ", log.LstdFlags|log.Lmsgprefix)
	}
	return &TraceManager{
		cfg:          cfg,
		log:          logger,
		events:       newTraceEventStore(5000, 1000, tracePushQueueCap),
		policyEngine: NewPolicyEngine(),
		protected:    NewProtectedProcessSetFromConfig(cfg.ProtectedConfig()),
	}
}

// ────────────────────────────────────────────────────────────────────────────
//  Lifecycle: Start / Stop / Status
// ────────────────────────────────────────────────────────────────────────────

func (tm *TraceManager) Start(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.running {
		return fmt.Errorf("trace manager already running")
	}

	tm.eventPrefix = rand.Text()
	if bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil && len(strings.TrimSpace(string(bootID))) > 0 {
		tm.eventPrefix = strings.TrimSpace(string(bootID))
	}

	// Compute boot-time offset for wall-clock conversion
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return fmt.Errorf("clock_gettime: %w", err)
	}
	monoNow := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)*time.Nanosecond
	tm.bootTimeOffset = time.Duration(time.Now().UnixNano()) - monoNow

	// Load BPF object file
	spec, err := ebpf.LoadCollectionSpec(tm.cfg.ObjectPath)
	if err != nil {
		return fmt.Errorf("load trace BPF object %s: %w", tm.cfg.ObjectPath, err)
	}

	// User-string syscall hooks on a kernel whose tracepoints copy user
	// memory (6.19+/7.0) attach as kprobes (trace_probes_kprobe.go); the
	// twins of every other probe are not loaded.
	kprobeSyms := selectKprobeTwins(spec.Programs, runtime.GOARCH, tracepointCopiesUser)

	// The legacy file syscall hooks are optional: a kernel that rejects one
	// keeps the rest. So are the kprobe twins: a rejected twin falls back to
	// its tracepoint.
	optional := append(optionalTracePrograms(), kprobeTwinPrograms(kprobeSyms)...)
	coll, dropped, err := createDroppingOptional(spec.Programs, optional,
		func() (*ebpf.Collection, error) { return ebpf.NewCollection(spec) })
	if err != nil {
		return fmt.Errorf("create trace BPF collection: %w", err)
	}
	droppedReason := make(map[string]string, len(dropped))
	for name, why := range dropped {
		droppedReason[name] = fmt.Sprintf("rejected at load, object loaded without it: %v", why)
		tm.log.Printf("trace program %s not loaded: %v", name, why)
	}
	tm.coll = coll

	// Get map references
	tm.eventsMap = coll.Maps[traceMapEvents]
	if tm.eventsMap == nil {
		coll.Close()
		return fmt.Errorf("map %q not found in BPF object", traceMapEvents)
	}
	tm.configMap = coll.Maps[traceMapConfig]
	tm.statsMap = coll.Maps[traceMapStats]
	tm.enforceMap = coll.Maps[traceMapEnforce]
	tm.deferredMap = coll.Maps[traceMapDeferred]
	tm.deferredEvents = make(map[uint32]TraceEvent)
	tm.protectedMap = coll.Maps[traceMapProtected]
	tm.protectedTGIDs = make(map[uint32]uint64)
	tm.protectedCount.Store(0)
	tm.protectedBudgetMap = coll.Maps[traceMapProtectedBudget]
	tm.protectedRefused.Store(0)
	// Before any probe attaches: exec consults this set for inherited entries.
	if commsMap := coll.Maps[traceMapProtectedComms]; commsMap != nil {
		if n, err := writeProtectedComms(commsMap, tm.protected.kernelComms()); err != nil {
			tm.log.Printf("protected comm map: wrote %d names: %v", n, err)
		}
	}
	// Also before any probe attaches: the protected processes already running
	// (sshd, sshd-session, systemd, ...), so the first events after attach — a
	// login that starts while the agent restarts — are exe_verified like any
	// later one instead of unverified look-alikes. The fork-insert budget is
	// set here too, so a child a protected process forks right after attach (a
	// new SSH session) is inserted; sched_process_exec and _exit attach before
	// _fork (traceProbes), so no inherited entry outlives an exec into another
	// image. The sync after attach (runProtectedSelfCheck) adds the processes
	// that started in between.
	if tm.protectedMap != nil {
		if _, err := tm.syncProtectedTGIDs(); err != nil {
			tm.log.Printf("protected-process scan before attach failed: %v (the scan after attach still runs)", err)
		}
	}
	tm.pidfdOK = pidfdSupported()
	if coll.Maps["trace_scratch"] == nil {
		tm.enforceMap = nil
		tm.log.Printf("kernel enforcement unavailable: trace object lacks independent enforcement ABI")
	}

	// Wire up kernel enforcement callbacks
	if tm.enforceMap != nil {
		tm.policyEngine.SetKernelCallbacks(tm.pushKernelRule, tm.removeKernelRule)
		tm.log.Printf("enforcement map loaded — kernel-side enforcement available")
	} else {
		tm.log.Printf("warning: enforcement map not found — kernel-side enforcement unavailable")
	}

	// Set default config: enable all probes, filter own PID
	defaultCfg := TraceConfigAPI{
		Enabled:     true,
		EventTypes:  nil, // all
		MinSeverity: "info",
		FilterSelf:  true,
	}
	bpfCfg := traceConfigToBPF(defaultCfg, agentPID())
	if tm.configMap != nil {
		if err := tm.writeConfig(bpfCfg); err != nil {
			tm.log.Printf("warning: failed to write default trace config: %v", err)
		}
	}

	// Attach tracepoints
	tm.probeFailures = make(map[string]string)
	tm.probesAbsent = 0
	tm.kprobeNames = nil
	for _, probe := range traceProbes {
		if sym, ok := kprobeSyms[probe.name]; ok {
			if kl, ok := tm.attachKprobeTwin(coll, probe, sym, droppedReason); ok {
				tm.links = append(tm.links, kl)
				tm.linkNames = append(tm.linkNames, probe.name)
				tm.kprobeNames = append(tm.kprobeNames, probe.name)
				continue
			}
		}
		prog := coll.Programs[probe.funcName]
		if prog == nil {
			reason := "program missing from BPF object"
			if r, ok := droppedReason[probe.funcName]; ok {
				reason = r
			}
			tm.probeFailures[probe.name] = reason
			tm.log.Printf("trace program %q not available (%s), skipping", probe.funcName, reason)
			continue
		}

		var tp link.Link
		var err error
		if probe.raw {
			tp, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: probe.name, Program: prog})
		} else {
			tp, err = link.Tracepoint(probe.group, probe.name, prog, nil)
		}
		if err != nil {
			if probe.mayBeAbsent && errors.Is(err, os.ErrNotExist) {
				// A legacy syscall this architecture/kernel does not have
				// (open/creat/... on arm64, fchmodat2 before 6.6): nothing
				// to trace, not a capture gap.
				tm.probesAbsent++
				tm.log.Printf("tracepoint %s/%s absent on this kernel, skipping", probe.group, probe.name)
				continue
			}
			tm.probeFailures[probe.name] = err.Error()
			tm.log.Printf("attach %s/%s failed: %v, skipping", probe.group, probe.name, err)
			continue
		}
		tm.links = append(tm.links, tp)
		tm.linkNames = append(tm.linkNames, probe.name)
	}

	if len(tm.links) == 0 {
		coll.Close()
		return fmt.Errorf("no tracepoints could be attached")
	}

	tm.log.Printf("attached %d/%d tracepoints", len(tm.links), len(traceProbes)-tm.probesAbsent)
	if len(tm.kprobeNames) > 0 {
		tm.log.Printf("%d user-string syscall hooks attached as kprobes (this kernel's syscall tracepoints copy user memory): %v", len(tm.kprobeNames), tm.kprobeNames)
	}

	// Start ringbuf reader
	reader, err := ringbuf.NewReader(tm.eventsMap)
	if err != nil {
		tm.closeLinks()
		coll.Close()
		return fmt.Errorf("create ringbuf reader: %w", err)
	}
	tm.reader = reader

	// After every probe (an open held for its result needs its exit probe) and
	// after the last step that can return an error, so a failed Start never
	// reports open results.
	tm.openCtlMap = coll.Maps[traceMapOpenCtl]
	tm.openStatsMap = coll.Maps[traceMapOpenStats]
	tm.armOpenResult()

	// Kill-candidate priority ring: read by its own goroutine, so a
	// backlog on the shared ring never delays a kill candidate. Routes follow
	// the policy set from here on.
	tm.priorityStatsMap = coll.Maps[traceMapPriorityStats]
	tm.shedStatsMap = coll.Maps[traceMapShedStats]
	tm.priorityReader = nil
	tm.priorityNameKeys = make(map[uint64]struct{})
	tm.keepNameKeys = make(map[uint64]uint8)
	tm.keepMap.Store(coll.Maps[traceMapKeepNames])
	pm := &priorityMaps{
		rules: coll.Maps[traceMapPriorityRules],
		ctl:   coll.Maps[traceMapPriorityCtl],
		names: coll.Maps[traceMapPriorityNames],
	}
	if prioMap := coll.Maps[traceMapPriorityEvents]; prioMap != nil && pm.rules != nil && pm.ctl != nil && pm.names != nil {
		// The kernel routes nothing to the ring until writeKillRoutes sets
		// the attach flag, so a failed reader leaves every event on the
		// main ring.
		if pr, err := ringbuf.NewReader(prioMap); err != nil {
			tm.log.Printf("kill-candidate priority ring unavailable: %v (attach flag left unset: every event stays on the main ring)", err)
			// priorityMaps stays nil, so only the push queue's names are set.
			tm.policyEngine.SetKillCandidateRouting(tm.writeKillRoutes)
		} else {
			tm.priorityReader = pr
			tm.priorityMaps.Store(pm)
			tm.policyEngine.SetKillCandidateRouting(tm.writeKillRoutes)
			tm.log.Printf("kill-candidate priority ring attached (shed exemption names: %t)", tm.keepMap.Load() != nil)
		}
	} else {
		tm.log.Printf("kill-candidate priority ring absent (trace object predates the priority ring); kill candidates share the main ring")
		// Still wired: the push queue takes the shed-exemption names from
		// the same policy sync (writeKillRoutes skips the absent maps).
		tm.policyEngine.SetKillCandidateRouting(tm.writeKillRoutes)
	}

	// Protected-process set: the effective configuration, then the
	// first kernel-map sync as a self-check line deploy verification greps
	// for. Runs before protectedRefreshLoop starts (it owns that state).
	tm.log.Printf("protected-process set: %s", tm.protected.Summary())
	if w := tm.protected.RiskyWarning(); w != "" {
		tm.log.Print(w)
	}
	selfCheck := tm.runProtectedSelfCheck()
	tm.log.Print(selfCheck.String())
	if w := selfCheck.Warning(); w != "" {
		tm.log.Print(w)
	}

	childCtx, cancel := context.WithCancel(ctx)
	tm.cancel = cancel
	tm.running = true
	tm.startedAt = time.Now()

	tm.wg.Add(1)
	go tm.ringbufLoop(childCtx, tm.reader)
	if tm.priorityReader != nil {
		tm.wg.Add(1)
		go tm.ringbufLoop(childCtx, tm.priorityReader)
	}
	tm.wg.Add(1)
	go tm.traceLossLoop(childCtx)
	if tm.deferredMap != nil {
		tm.wg.Add(1)
		go tm.deferredSignalLoop(childCtx)
	}
	if tm.protectedMap != nil {
		tm.wg.Add(1)
		go tm.protectedRefreshLoop(childCtx.Done())
	}

	tm.startLSM(childCtx, kernelLSMListPath)

	return nil
}

// startLSM attaches the proactive BPF-LSM blocking programs when the kernel
// runs them. A kernel without bpf in its LSM list (read from listPath)
// accepts the attach and never calls the programs, so nothing is attached
// there. A failure is logged, never returned: the agent works without LSM.
func (tm *TraceManager) startLSM(ctx context.Context, listPath string) {
	plan := planLSM(tm.cfg.LSMEnabled, listPath)
	tm.lsmState = plan.State
	switch {
	case !plan.Attach && plan.Note != "":
		tm.log.Printf("INFO: %s; enforcement is reactive only: kernel-rule kills via bpf_send_signal at the traced syscall, userspace-matched kills via %s", plan.Note, tm.terminationMode())
	case plan.Attach:
		if plan.Note != "" {
			tm.log.Printf("INFO: %s", plan.Note)
		}
		if err := tm.loadLSM(ctx); err != nil {
			tm.lsmState = LSMStateFailed
			tm.log.Printf("INFO: BPF-LSM unavailable or not active (%v); enforcement is reactive only: kernel-rule kills via bpf_send_signal at the traced syscall, userspace-matched kills via %s", err, tm.terminationMode())
		} else if plan.State == LSMStateUnverified {
			tm.log.Printf("INFO: BPF-LSM hooks attached; the kernel LSM list was unreadable, so whether they run is unverified")
		} else {
			tm.log.Printf("INFO: BPF-LSM proactive blocking enabled (-EPERM on bprm_check_security)")
		}
	}
}

func (tm *TraceManager) Stop() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if !tm.running {
		return nil
	}

	tm.cancel()
	if tm.reader != nil {
		_ = tm.reader.Close() // unblocks the reader loop; nothing to report on shutdown
	}
	if tm.priorityReader != nil {
		_ = tm.priorityReader.Close() // its loop holds its own reference; unblocks the reader loop; nothing to report on shutdown
		tm.priorityReader = nil
	}
	tm.priorityMaps.Store(nil) // not SetKillCandidateRouting: never pe.mu under tm.mu here
	tm.keepMap.Store(nil)
	if tm.lsmReader != nil {
		_ = tm.lsmReader.Close() // unblocks the reader loop; nothing to report on shutdown
		tm.lsmReader = nil
	}
	tm.wg.Wait()

	tm.closeLinks()

	if tm.lsmLink != nil {
		_ = tm.lsmLink.Close() // detach on shutdown; the kernel drops the link with its fd
		tm.lsmLink = nil
	}
	for _, l := range tm.lsmExtraLinks {
		_ = l.Close() // detach on shutdown; the kernel drops the link with its fd
	}
	tm.lsmExtraLinks = nil
	if tm.lsmColl != nil {
		tm.lsmColl.Close()
		tm.lsmColl = nil
	}
	tm.lsmActive = false
	tm.lsmState = ""

	if tm.coll != nil {
		tm.coll.Close()
		tm.coll = nil
	}
	tm.openCtlMap, tm.openStatsMap, tm.openResultArmed = nil, nil, false

	tm.running = false
	tm.log.Printf("trace manager stopped (processed %d events)", tm.totalEvents.Load())
	return nil
}

func (tm *TraceManager) resolveLSMPath() string {
	if tm.cfg.LSMObjectPath != "" {
		return tm.cfg.LSMObjectPath
	}
	if tm.cfg.ObjectPath != "" {
		candidate := filepath.Join(filepath.Dir(tm.cfg.ObjectPath), "wafio_lsm.o")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func (tm *TraceManager) loadLSM(ctx context.Context) error {
	lsmPath := tm.resolveLSMPath()
	if lsmPath == "" {
		return fmt.Errorf("wafio_lsm.o not found")
	}

	spec, err := ebpf.LoadCollectionSpec(lsmPath)
	if err != nil {
		return fmt.Errorf("load LSM spec from %s: %w", lsmPath, err)
	}

	// socket_sendmsg is optional: a kernel that rejects it keeps exec and
	// connect blocking.
	coll, dropped, err := createDroppingOptional(spec.Programs, []string{lsmProgSendmsg},
		func() (*ebpf.Collection, error) { return ebpf.NewCollection(spec) })
	if err != nil {
		return fmt.Errorf("create LSM collection: %w", err)
	}
	if why, ok := dropped[lsmProgSendmsg]; ok {
		tm.log.Printf("LSM program %s not loaded (%v) — addressed sends to blocklisted IPs enforced from userspace", lsmProgSendmsg, why)
	}
	tm.lsmColl = coll
	tm.lsmConfigMap = coll.Maps[lsmMapConfig]
	tm.lsmBlockMap = coll.Maps[lsmMapBlocklist]
	tm.lsmIPBlockMap = coll.Maps[lsmMapIPBlocklist]
	tm.lsmEventsMap = coll.Maps[lsmMapEvents]
	tm.lsmSuppressedMap = coll.Maps["wafio_lsm_reports_suppressed"]

	// Attach every LSM program present in the object; the bprm hook is the
	// historical minimum, socket_connect is newer, socket_sendmsg newer still.
	progNames := []string{"wafio_bprm_check_security", "wafio_socket_connect", lsmProgSendmsg}
	var attached []string
	for _, name := range progNames {
		prog := coll.Programs[name]
		if prog == nil {
			continue
		}
		lsmLink, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			// socket_connect needs kernel ≥ 5.7 hook support —
			// non-fatal when the kernel lacks the hook.
			tm.log.Printf("LSM attach %s skipped: %v", name, err)
			continue
		}
		if tm.lsmLink == nil {
			tm.lsmLink = lsmLink
		} else {
			tm.lsmExtraLinks = append(tm.lsmExtraLinks, lsmLink)
		}
		attached = append(attached, name)
	}
	if tm.lsmLink == nil {
		coll.Close()
		return fmt.Errorf("no LSM program could be attached")
	}
	tm.log.Printf("BPF-LSM hooks attached: %v", attached)

	// Set initial LSM config. Without it lsm_gate() allows everything, so a
	// failed write must keep dest-IP policies out of the connect blocklist.
	configErr := fmt.Errorf("LSM config map %s missing", lsmMapConfig)
	if tm.lsmConfigMap != nil {
		zero := uint32(0)
		cfg := LSMConfig{
			Enabled:      1,
			BlockExec:    1,
			BlockConnect: boolToU32(tm.cfg.LSMBlockConnect),
			AgentPID:     agentPID(),
		}
		configErr = tm.lsmConfigMap.Update(zero, &cfg, ebpf.UpdateAny)
	}
	if configErr != nil {
		tm.log.Printf("LSM config write failed — LSM hooks allow everything: %v", configErr)
	}

	// Start ringbuf reader for LSM blocked events
	if tm.lsmEventsMap != nil {
		reader, err := ringbuf.NewReader(tm.lsmEventsMap)
		if err == nil {
			tm.lsmReader = reader
			tm.wg.Add(1)
			go tm.lsmRingbufLoop(ctx, reader)
		}
	}

	tm.lsmActive = true

	// Wire the policy engine's dest-IP path here, not in Start (map may exist
	// while attach failed), and only when the kernel really denies: the engine
	// skips userspace action for connects it believes the blocklist enforced,
	// so report-only mode, a failed socket_connect attach or a failed
	// config write would turn a kill policy into a no-op. Any of those keeps
	// dest-IP policies in userspace.
	denies, reason := connectBlocklistDenies(tm.lsmIPBlockMap != nil,
		slices.Contains(attached, "wafio_socket_connect"), tm.cfg.LSMBlockConnect, configErr)
	// Only an object with the marker denies IPv4-mapped AF_INET6
	// connects; with an older one userspace keeps enforcing them.
	mapped := coll.Maps[lsmMapConnectV4Mapped] != nil
	tm.policyEngine.SetConnectBlocklistIPv4Mapped(denies && mapped)
	if denies && !mapped {
		tm.log.Printf("LSM object predates the IPv4-mapped connect check: IPv4-mapped IPv6 connects to blocklisted addresses are enforced in userspace")
	}
	if denies {
		tm.policyEngine.SetConnectCallbacks(tm.pushConnectBlock, tm.removeConnectBlock)
		tm.log.Printf("LSM connect blocklist loaded — dest-IP policies kernel-enforceable")
		// Addressed sends (unconnected UDP sendto, sendmsg
		// with a destination, MSG_FASTOPEN) meet the same blocklist.
		if slices.Contains(attached, lsmProgSendmsg) {
			if err := tm.policyEngine.SetSendBlocklist(tm.pushConnectBlockSend); err != nil {
				tm.log.Printf("LSM send blocklist sync: %v", err)
			}
			tm.log.Printf("LSM socket_sendmsg hook attached — addressed sends to blocklisted IPs denied in the kernel")
		} else {
			tm.log.Printf("LSM socket_sendmsg hook not attached — addressed sends to blocklisted IPs enforced from userspace")
		}
	} else {
		tm.log.Printf("LSM connect blocklist not used (%s) — dest-IP policies enforced in userspace", reason)
	}
	return nil
}

func (tm *TraceManager) lsmRingbufLoop(ctx context.Context, reader *ringbuf.Reader) {
	defer tm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		if len(rec.RawSample) < 344 {
			continue
		}

		var evt WafioLSMEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &evt); err != nil {
			continue
		}

		pathStr := strings.TrimRight(string(evt.Path[:]), "\x00")
		commStr := strings.TrimRight(string(evt.Comm[:]), "\x00")

		// Hook-specific presentation: exec carries a path, connect and send an IP.
		eventType, eventName, category := TraceExecve, "execve", "process"
		subject := pathStr
		description := "blocked unauthorized execution"
		switch evt.Hook {
		case LSMHookConnect:
			eventType, eventName, category = TraceConnect, "socket_connect", "network"
			subject = net.IP(evt.Addr[:4]).String()
			description = "BPF-LSM blocked outbound connect"
		case LSMHookSendmsg:
			eventType, eventName, category = TraceSendto, "socket_sendmsg", "network"
			subject = net.IP(evt.Addr[:4]).String()
			description = "BPF-LSM blocked outbound send"
		}
		addrFamily, familyNote := lsmConnectFamily(evt)
		description += familyNote
		if evt.Port != 0 {
			subject = fmt.Sprintf("%s:%d", subject, evt.Port)
		}

		traceEvt := TraceEvent{
			EventID:         fmt.Sprintf("%s-lsm-%d", tm.eventPrefix, evt.TimestampNs),
			EventType:       eventType,
			EventName:       eventName,
			Category:        category,
			Severity:        SevCritical,
			SeverityName:    severityName(SevCritical),
			PID:             evt.PID,
			UID:             evt.UID,
			GID:             evt.GID,
			Comm:            commStr,
			Filename:        pathStr,
			Addr:            net.IP(evt.Addr[:4]).String(),
			AddrFamily:      addrFamily,
			Port:            evt.Port,
			RetVal:          int64(evt.RetCode),
			Action:          ActionBlock,
			ActionName:      actionName(ActionBlock),
			PolicyID:        evt.PolicyID,
			Timestamp:       time.Unix(0, i64FromU64(evt.TimestampNs)+int64(tm.bootTimeOffset)).UTC().Format(time.RFC3339),
			TimestampNs:     i64FromU64(evt.TimestampNs),
			ActivityOutcome: "blocked",
			Description:     fmt.Sprintf("%s: %s (PID %d, comm %s)", description, subject, evt.PID, commStr),
		}

		// Store in the recent and category rings and the push queue
		tm.events.record(traceEvt, category)
	}
}

// BlockConnectIP adds a destination IPv4 to the BPF-LSM socket_connect
// blocklist: outbound connects are denied synchronously in-kernel (-EPERM)
// before any packet leaves the host.
func (tm *TraceManager) BlockConnectIP(ipStr string, policyID uint32) error {
	return tm.blockConnectIP(ipStr, policyID, false)
}

// blockConnectIP writes the blocklist entry; send also marks it for the
// socket_sendmsg hook (LSMRuleSend).
func (tm *TraceManager) blockConnectIP(ipStr string, policyID uint32, send bool) error {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	if !tm.lsmActive || tm.lsmIPBlockMap == nil {
		return fmt.Errorf("BPF-LSM is not active")
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("connect blocklist requires an IPv4 address, got %q", ipStr)
	}
	var key [4]byte
	copy(key[:], ip.To4())
	rule := LSMRule{Action: ActionBlock, PolicyID: policyID, Enabled: 1}
	if send {
		rule.Flags |= LSMRuleSend
	}
	return tm.lsmIPBlockMap.Update(key, &rule, ebpf.UpdateAny)
}

// UnblockConnectIP removes a destination IPv4 from the connect blocklist.
func (tm *TraceManager) UnblockConnectIP(ipStr string) error {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	if !tm.lsmActive || tm.lsmIPBlockMap == nil {
		return fmt.Errorf("BPF-LSM is not active")
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("connect blocklist requires an IPv4 address, got %q", ipStr)
	}
	var key [4]byte
	copy(key[:], ip.To4())
	return tm.lsmIPBlockMap.Delete(key)
}

func (tm *TraceManager) closeLinks() {
	for _, l := range tm.links {
		_ = l.Close() // detach on shutdown; the kernel drops the link with its fd
	}
	tm.links = nil
	tm.linkNames = nil
}

func (tm *TraceManager) IsRunning() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.running
}

// ────────────────────────────────────────────────────────────────────────────
//  Ring Buffer Reader Loop
// ────────────────────────────────────────────────────────────────────────────

// ringbufLoop reads one trace ring: the shared trace_events ring, or the
// kill-candidate priority ring in its own goroutine.
func (tm *TraceManager) ringbufLoop(ctx context.Context, reader *ringbuf.Reader) {
	defer tm.wg.Done()
	usEffects := userspaceActionEffects{kill: tm.userspaceKill, logf: tm.log.Printf}
	// One record buffer for the reader's lifetime (ReadInto): Read allocated
	// a fresh 1.4 KiB sample per event.
	var record ringbuf.Record

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := reader.ReadInto(&record); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			tm.log.Printf("ringbuf read error: %v", err)
			continue
		}

		evt, err := decodeTraceRecord(record.RawSample, tm.bootTimeOffset, tm.eventPrefix)
		if err != nil {
			tm.droppedEvents.Add(1)
			continue
		}
		tm.totalEvents.Add(1)

		// Userspace policy evaluation (for policies without kernel_enforce)
		// Note: kernel-side enforcement (bpf_send_signal) already happened
		// before the event reached userspace. This catches complex userspace-only
		// policies with substring matching on comm/filename/uid.
		if evt.Action != ActionMonitor {
			tm.policyEngine.RecordKernelEnforcement(evt)
		}
		// Not already enforced by the kernel — check userspace policies.
		// Userspace kill: protected-process guard, then an immediate
		// identity-verified pidfd SIGKILL, else a deferred kernel request; the
		// outcome lands in the enforcement log. Simulate never delivers a
		// signal — it's a dry run (trace_userspace_action.go).
		applyUserspacePolicy(&evt, tm.policyEngine, usEffects)

		// Recent and per-category rings, and the at-most-once push queue
		// (overflow and send failure can lose data).
		tm.events.record(evt, traceEventCategory(evt.EventType))
	}
}

// ────────────────────────────────────────────────────────────────────────────
//  Event Queries
// ────────────────────────────────────────────────────────────────────────────

// DrainRecentTraceEvents removes and returns up to limit pending events,
// oldest first — exactly-once delivery for the push loop. Snapshot/query
// readers use the non-destructive ring (FilterRecentEvents).
func (tm *TraceManager) DrainRecentTraceEvents(limit int) []TraceEvent {
	return tm.events.push.drain(limit)
}

// QueuedEvents is the number of trace events waiting in the push queue.
func (tm *TraceManager) QueuedEvents() int { return tm.events.push.len() }

// TelemetryUrgent reports whether the telemetry loop should send at its next
// tick rather than with the next one-second batch: an urgent
// trace event is queued (traceEventUrgent) or an enforcement entry waits.
func (tm *TraceManager) TelemetryUrgent() bool {
	return tm.events.push.hasUrgent() || tm.policyEngine.EnforcementLogPending()
}

// FilterRecentEvents returns recent events matching the given category filter.
// For specific categories it reads from the per-category ring buffer so that
// high-frequency events (openat/file) cannot drown out low-frequency ones.
func (tm *TraceManager) FilterRecentEvents(category string, minSeverity uint32, limit int) []TraceEvent {
	return tm.events.filter(category, minSeverity, limit)
}

// ────────────────────────────────────────────────────────────────────────────
//  Config Read/Write
// ────────────────────────────────────────────────────────────────────────────

func (tm *TraceManager) GetConfig() (*TraceConfigAPI, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if tm.configMap == nil {
		return nil, fmt.Errorf("trace config map not available")
	}

	var key uint32 = 0
	var val [32]byte // struct trace_config is 32 bytes
	if err := tm.configMap.Lookup(key, &val); err != nil {
		return nil, fmt.Errorf("read trace config: %w", err)
	}

	bpfCfg := TraceConfigBPF{
		Enabled:      binary.LittleEndian.Uint32(val[0:4]),
		EventMaskLo:  binary.LittleEndian.Uint32(val[4:8]),
		MinSeverity:  binary.LittleEndian.Uint32(val[8:12]),
		FilterOwnPid: binary.LittleEndian.Uint32(val[12:16]),
		AgentPid:     binary.LittleEndian.Uint32(val[16:20]),
	}

	api := TraceConfigFromBPF(bpfCfg)
	return &api, nil
}

func (tm *TraceManager) UpdateConfig(cfg TraceConfigAPI) error {
	if err := ValidateTraceConfig(cfg); err != nil {
		return err
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.configMap == nil {
		return fmt.Errorf("trace config map not available")
	}

	bpfCfg := traceConfigToBPF(cfg, agentPID())
	return tm.writeConfig(bpfCfg)
}

func (tm *TraceManager) writeConfig(bpfCfg TraceConfigBPF) error {
	var key uint32 = 0
	var val [32]byte
	binary.LittleEndian.PutUint32(val[0:4], bpfCfg.Enabled)
	binary.LittleEndian.PutUint32(val[4:8], bpfCfg.EventMaskLo)
	binary.LittleEndian.PutUint32(val[8:12], bpfCfg.MinSeverity)
	binary.LittleEndian.PutUint32(val[12:16], bpfCfg.FilterOwnPid)
	binary.LittleEndian.PutUint32(val[16:20], bpfCfg.AgentPid)
	return tm.configMap.Update(key, val, ebpf.UpdateAny)
}

// ────────────────────────────────────────────────────────────────────────────
//  Statistics
// ────────────────────────────────────────────────────────────────────────────

func (tm *TraceManager) GetStats() (*TraceStats, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	stats := &TraceStats{
		TotalEvents: tm.totalEvents.Load(),
		EventCounts: make(map[string]uint64),
		BySeverity:  make(map[string]uint64),
		ByCategory:  make(map[string]uint64),
		BufferTotal: 1 << 24, // 16MB
	}

	if !tm.running {
		return stats, nil
	}
	stats.UptimeMs = time.Since(tm.startedAt).Milliseconds()

	// Read per-CPU stats from BPF map
	if tm.statsMap != nil {
		for i := uint32(0); i <= TraceEventMax; i++ {
			var vals []uint64
			if err := tm.statsMap.Lookup(i, &vals); err != nil {
				continue
			}
			var total uint64
			for _, v := range vals {
				total += v
			}
			if i == 0 {
				stats.KernelEventsDropped = total
				continue
			}
			if total > 0 {
				info := TraceEventTypes[i]
				stats.EventCounts[info.Name] = total
			}
		}
	}

	for et, n := range tm.readShedCounters() {
		if n == 0 {
			continue
		}
		if stats.EventsShed == nil {
			stats.EventsShed = make(map[string]uint64)
		}
		stats.EventsShed[TraceEventTypes[et].Name] = n
	}

	// Compute severity/category breakdown from recent events
	stats.BufferUsed = u64FromInt(tm.events.breakdown(stats.BySeverity, stats.ByCategory))

	return stats, nil
}

// ────────────────────────────────────────────────────────────────────────────
//  Enforcement: BPF Map Operations
// ────────────────────────────────────────────────────────────────────────────

func (tm *TraceManager) pushKernelRule(eventType uint32, rule TraceEnforceRuleBPF) error {
	if tm.enforceMap == nil {
		return fmt.Errorf("enforcement map not available")
	}
	var val [16]byte
	binary.LittleEndian.PutUint32(val[0:4], rule.Enabled)
	binary.LittleEndian.PutUint32(val[4:8], rule.Action)
	binary.LittleEndian.PutUint32(val[8:12], rule.MinSeverity)
	binary.LittleEndian.PutUint32(val[12:16], rule.PolicyID)
	return tm.enforceMap.Update(eventType, val, ebpf.UpdateAny)
}

// pushConnectBlock reconciles the LSM ip blocklist on behalf of the policy
// engine (dest-IP-only kernel-enforce policies).
func (tm *TraceManager) pushConnectBlock(ip string, policyID uint32) error {
	return tm.BlockConnectIP(ip, policyID)
}

func (tm *TraceManager) pushConnectBlockSend(ip string, policyID uint32, send bool) error {
	return tm.blockConnectIP(ip, policyID, send)
}

func (tm *TraceManager) removeConnectBlock(ip string) error {
	return tm.UnblockConnectIP(ip)
}

func (tm *TraceManager) removeKernelRule(eventType uint32) error {
	if tm.enforceMap == nil {
		return nil
	}
	err := tm.enforceMap.Delete(eventType)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
//  Enforcement: Policy CRUD (delegates to PolicyEngine)
// ────────────────────────────────────────────────────────────────────────────

func (tm *TraceManager) AddPolicy(p EnforcementPolicy) (*EnforcementPolicy, error) {
	return tm.policyEngine.AddPolicy(p)
}

func (tm *TraceManager) UpdatePolicy(id uint32, p EnforcementPolicy) (*EnforcementPolicy, error) {
	return tm.policyEngine.UpdatePolicy(id, p)
}

func (tm *TraceManager) DeletePolicy(id uint32) error {
	return tm.policyEngine.DeletePolicy(id)
}

func (tm *TraceManager) GetPolicy(id uint32) (*EnforcementPolicy, error) {
	return tm.policyEngine.GetPolicy(id)
}

func (tm *TraceManager) ListPolicies() []EnforcementPolicy {
	return tm.policyEngine.ListPolicies()
}

func (tm *TraceManager) GetEnforcementLog(limit int) []EnforcementLogEntry {
	return tm.policyEngine.GetEnforcementLog(limit)
}

func (tm *TraceManager) DrainEnforcementLog(limit int) []EnforcementLogEntry {
	return tm.policyEngine.DrainEnforcementLog(limit)
}

func (tm *TraceManager) ClearEnforcementLog() {
	tm.policyEngine.ClearEnforcementLog()
}

// ────────────────────────────────────────────────────────────────────────────
//  Status
// ────────────────────────────────────────────────────────────────────────────

func (tm *TraceManager) Status() TraceStatus {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	s := TraceStatus{
		EnforcementDropped:     tm.policyEngine.EnforcementDropped(),
		Running:                tm.running,
		ExpectedProbes:         len(traceProbes) - tm.probesAbsent,
		MissingProbes:          make(map[string]string, len(tm.probeFailures)),
		QueueDepth:             tm.events.push.len(),
		Probes:                 len(tm.links),
		ProbeNames:             make([]string, len(tm.linkNames)),
		EventsTotal:            tm.totalEvents.Load(),
		EventsDropped:          tm.droppedEvents.Load(),
		RingbufSizeMB:          16,
		Enforcement:            tm.enforceMap != nil,
		UserspaceKillSupported: tm.pidfdOK || tm.deferredMap != nil,
		TerminationMode:        tm.terminationMode(),
		ProtectedKernelSet:     tm.protectedMap != nil,
		ProtectedTGIDs:         int(tm.protectedCount.Load()),
		ProtectedForkRefused:   tm.protectedRefused.Load(),
		PoliciesTotal:          len(tm.policyEngine.ListPolicies()),
		PriorityRing:           tm.priorityReader != nil,
		PriorityEventsRouted:   sumPerCPU(tm.priorityStatsMap, tracePrioRouted),
		PriorityEventsFull:     sumPerCPU(tm.priorityStatsMap, tracePrioFull),
		PriorityEventsLost:     sumPerCPU(tm.priorityStatsMap, tracePrioLost),
		LSMReportsSuppressed:   sumPerCPU(tm.lsmSuppressedMap, 0),
		LSMActive:              tm.lsmActive,
		LSMState:               tm.lsmState,
		KprobeProbes:           slices.Clone(tm.kprobeNames),
		OpenResult:             tm.openResultArmed,
	}
	s.OpenResultKnown, s.OpenResultUnknown = readOpenResultCounters(tm.openStatsMap)
	for _, n := range tm.readShedCounters() {
		s.KernelEventsShed += n
	}
	copy(s.ProbeNames, tm.linkNames)
	for name, reason := range tm.probeFailures {
		s.MissingProbes[name] = reason
	}
	if tm.statsMap != nil {
		var vals []uint64
		if err := tm.statsMap.Lookup(uint32(0), &vals); err == nil {
			for _, v := range vals {
				s.KernelEventsDropped += v
			}
		}
	}
	tm.fillLossStatus(&s, time.Now())

	if tm.running {
		s.UptimeMs = time.Since(tm.startedAt).Milliseconds()
	}

	return s
}

// terminationMode describes how a userspace-matched Kill is delivered.
func (tm *TraceManager) terminationMode() string {
	switch {
	case tm.pidfdOK && tm.deferredMap != nil:
		return "pidfd_verified_start_time+deferred_exact_identity_next_hook_1s"
	case tm.pidfdOK:
		return "pidfd_verified_start_time"
	case tm.deferredMap != nil:
		return "deferred_exact_identity_next_hook_1s"
	}
	return "unsupported"
}

func (tm *TraceManager) ReplacePolicies(policies []EnforcementPolicy) error {
	return tm.policyEngine.ReplacePolicies(policies)
}

// attachKprobeTwin attaches the probe's kprobe twin to the syscall wrapper
// sym. false (logged) means the caller attaches the tracepoint instead: the
// twin was rejected at load or the kprobe could not be created.
func (tm *TraceManager) attachKprobeTwin(coll *ebpf.Collection, probe traceProbe, sym string, droppedReason map[string]string) (link.Link, bool) {
	twin := probe.kprobeFuncName()
	prog := coll.Programs[twin]
	if prog == nil {
		reason := "program missing from BPF object"
		if r, ok := droppedReason[twin]; ok {
			reason = r
		}
		tm.log.Printf("kprobe twin %s not available (%s); attaching tracepoint %s", twin, reason, probe.name)
		return nil, false
	}
	kl, err := link.Kprobe(sym, prog, nil)
	if err != nil {
		tm.log.Printf("kprobe %s for %s failed: %v; attaching tracepoint %s", sym, twin, err, probe.name)
		return nil, false
	}
	return kl, true
}
