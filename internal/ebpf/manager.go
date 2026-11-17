//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ────────────────────────────────────────────────────────────────────────────
//  Map names (must match SEC(".maps") names in C)
// ────────────────────────────────────────────────────────────────────────────

const (
	mapConfig           = "wafio_config"
	mapAllow4           = "wafio_allow4" // ingress lists, LPM tries
	mapAllow6           = "wafio_allow6"
	mapAllowScopes      = "wafio_allow_scopes" // marker: the walk matches port scopes
	mapBlock4           = "wafio_block4"
	mapBlock6           = "wafio_block6"
	mapJail             = "wafio_jail" // WAF-agent jail
	mapRateConfig       = "wafio_rate_config"
	mapRateState        = "wafio_rate_state"
	mapSynState         = "wafio_syn_state"
	mapConntrack        = "wafio_conntrack"
	mapGeoIP            = "wafio_geoip"
	mapGeoBlocked       = "wafio_geo_blocked"
	mapGeoCIDR4         = "wafio_geo_cidr4"
	mapGeoCIDR6         = "wafio_geo_cidr6"
	mapGeoConfig        = "wafio_geo_config"
	mapGeoLocal4        = "wafio_geo_local4"
	mapGeoLocal6        = "wafio_geo_local6"
	mapMetrics          = "wafio_metrics"
	mapEvents           = "wafio_events"
	mapPortscan         = "wafio_portscan"
	mapPortscanCfg      = "wafio_portscan_config"
	mapBandwidth        = "wafio_bandwidth"
	mapAnomalyConfig    = "wafio_anomaly_config"
	mapPortPolicy       = "wafio_port_policy"
	mapPortPolicyConfig = "wafio_port_policy_config"
	mapEgressBlocklist  = "wafio_egress_blocklist"
	mapEgressSubnetV4   = "wafio_egress_subnet_v4"
	mapEgressSubnetV6   = "wafio_egress_subnet_v6"
	mapCPEndpoints      = "wafio_cp_endpoints"
	mapDHCPPending      = "wafio_dhcp_pending"
	mapDHCPServers      = "wafio_dhcp_servers"
)

// ────────────────────────────────────────────────────────────────────────────
//  Manager — enterprise lifecycle controller for XDP + TC programs
// ────────────────────────────────────────────────────────────────────────────

// Manager loads, attaches, and manages all Wafio eBPF programs and maps.
type Manager struct {
	perfLostSamples atomic.Uint64
	decodeFailures  atomic.Uint64
	mu              sync.RWMutex

	// ── loaded BPF objects ──
	xdpColl *ebpf.Collection
	tcColl  *ebpf.Collection

	// ── attached links ──
	xdpLink       link.Link
	tcIngressLink link.Link
	tcEgressLink  link.Link
	legacyTC      *legacyTCAttachment

	// ── shortcut map references (from xdpColl / tcColl) ──
	configMap          *ebpf.Map
	allow4Map          *ebpf.Map // nil on objects without the prefix IP lists
	allow6Map          *ebpf.Map
	allowScopesMap     *ebpf.Map // marker: nil on objects that do not match allowlist ports
	block4Map          *ebpf.Map
	block6Map          *ebpf.Map
	jailMap            *ebpf.Map // WAF-agent jail, apart from the operator lists
	rateConfigMap      *ebpf.Map
	rateStateMap       *ebpf.Map
	synStateMap        *ebpf.Map
	conntrackMap       *ebpf.Map
	geoipMap           *ebpf.Map
	geoBlockedMap      *ebpf.Map
	geoCIDR4Map        *ebpf.Map
	geoCIDR6Map        *ebpf.Map
	geoConfigMap       *ebpf.Map // nil on objects older than geo allow mode
	geoLocal4Map       *ebpf.Map // the XDP interface's subnets (allow mode, UDP)
	geoLocal6Map       *ebpf.Map
	metricsMap         *ebpf.Map
	eventsMap          *ebpf.Map
	portscanMap        *ebpf.Map
	portscanCfgMap     *ebpf.Map
	bandwidthMap       *ebpf.Map
	anomalyConfigMap   *ebpf.Map
	portPolicyMap      *ebpf.Map
	portPolicyCfgMap   *ebpf.Map
	egressBlocklistMap *ebpf.Map
	egressSubnetV4Map  *ebpf.Map
	egressSubnetV6Map  *ebpf.Map
	cpEndpointsMap     *ebpf.Map // nil on objects without the exemptions

	// lockoutExemptions: both objects carry the reply and control-plane
	// exemptions (the shared wafio_cp_endpoints map is their ABI marker).
	lockoutExemptions bool
	// cpPort: control-plane port from the last SetControlPlaneEndpoints.
	cpPort uint16
	// cpExpected: the agent has a control plane configured.
	cpExpected bool
	// geoState: what the last ApplyGeoRanges left in the geo maps.
	geoState GeoRangeState
	// geoDegraded*: why the desired geo policy is not enforced and what the
	// dataplane holds instead (SetGeoDegraded).
	geoDegradedCode    string
	geoDegradedState   string
	geoDegradedMessage string
	// allowlistScopedSkipped: port-scoped allowlist entries of the last
	// applied desired state this object could not enforce (not written).
	allowlistScopedSkipped int

	// ── perf reader ──
	perfReader *perf.Reader

	// ── config ──
	cfg ManagerConfig
	log *log.Logger

	// ── state ──
	running   bool
	startedAt time.Time
	ifIndex   int
	ifName    string

	// ── event channel ──
	events chan Event

	// ── recent events ring buffer (survives multiple reads) ──
	recentEvents    []Event
	recentEventsMu  sync.Mutex
	maxRecentEvents int

	// pushQueue is the destructive FIFO for the telemetry push loop; the ring
	// above stays non-destructive for snapshot APIs.
	pushQueue *drainQueue[Event]

	// ── boot-time offset for converting bpf_ktime_get_ns → wall clock ──
	bootTimeOffset time.Duration

	// ── metrics snapshot (updated by poller) ──
	lastMetrics   *Metrics
	lastMetricsMu sync.RWMutex
	prevMetrics   *MetricsVal
	prevMetricsAt time.Time

	// ── background goroutines ──
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// bpfTimeToWall converts a bpf_ktime_get_ns() value to wall-clock time.
func (m *Manager) bpfTimeToWall(ns uint64) time.Time {
	return time.Unix(0, i64FromU64(ns)+int64(m.bootTimeOffset))
}

// wallToKtime converts a wall-clock UnixNano timestamp to the equivalent
// bpf_ktime_get_ns() monotonic nanoseconds, as required by the XDP program.
func (m *Manager) wallToKtime(wallNs int64) uint64 {
	ktime := wallNs - int64(m.bootTimeOffset)
	if ktime < 0 {
		ktime = 0
	}
	return uint64(ktime)
}

// ktimeNow returns the current time as bpf_ktime_get_ns() monotonic nanoseconds.
func (m *Manager) ktimeNow() uint64 {
	return m.wallToKtime(time.Now().UnixNano())
}

// NewManager creates (but does not start) an eBPF manager.
func NewManager(cfg ManagerConfig, logger *log.Logger) *Manager {
	if cfg.PinPath == "" {
		cfg.PinPath = "/sys/fs/bpf/wafio"
	}
	if cfg.EventBufferSize <= 0 {
		cfg.EventBufferSize = 128 // pages → 128×4KB = 512KB ring
	}
	if cfg.EventChanSize <= 0 {
		cfg.EventChanSize = 4096
	}
	if cfg.MetricsPollMs <= 0 {
		cfg.MetricsPollMs = 1000
	}
	if logger == nil {
		logger = log.New(os.Stderr, "[ebpf] ", log.LstdFlags|log.Lmsgprefix)
	}
	return &Manager{
		cfg:             cfg,
		log:             logger,
		events:          make(chan Event, cfg.EventChanSize),
		maxRecentEvents: 1000,
		pushQueue:       newDrainQueue[Event](4096),
	}
}

// ────────────────────────────────────────────────────────────────────────────
//  Lifecycle: Start / Stop / Status
// ────────────────────────────────────────────────────────────────────────────

// Start loads both XDP and TC programs, attaches them to the interface,
// and starts background perf-event and metrics pollers.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("ebpf manager already running on %s", m.ifName)
	}

	iface, err := net.InterfaceByName(m.cfg.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", m.cfg.Interface, err)
	}
	m.ifIndex = iface.Index
	m.ifName = iface.Name

	// Ensure pin directory exists.
	if err := os.MkdirAll(m.cfg.PinPath, 0700); err != nil {
		return fmt.Errorf("create pin path %s: %w", m.cfg.PinPath, err)
	}

	// ── Load XDP ──
	if err := m.loadXDP(); err != nil {
		m.cleanup()
		return fmt.Errorf("load XDP: %w", err)
	}

	// ── Load TC (reuse shared maps from XDP) ──
	if err := m.loadTC(); err != nil {
		m.cleanup()
		return fmt.Errorf("load TC: %w", err)
	}

	// ── Attach XDP ──
	if err := m.attachXDP(); err != nil {
		m.cleanup()
		return fmt.Errorf("attach XDP: %w", err)
	}

	// ── Attach TC ──
	if err := m.attachTC(); err != nil {
		m.cleanup()
		return fmt.Errorf("attach TC: %w", err)
	}

	// ── Write default config ──
	if err := m.writeDefaultConfig(); err != nil {
		m.log.Printf("WARN: write default config: %v", err)
	}

	// ── Start perf reader ──
	if err := m.startPerfReader(); err != nil {
		m.log.Printf("WARN: start perf reader: %v", err)
	}

	// ── Compute boot-time offset for bpf_ktime_get_ns → wall-clock conversion ──
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
		monoNow := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)*time.Nanosecond
		m.bootTimeOffset = time.Duration(time.Now().UnixNano()) - monoNow
	}

	// ── Start background goroutines ──
	bgCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.running = true
	m.startedAt = time.Now()

	m.wg.Add(2)
	go m.perfReaderLoop(bgCtx)
	go m.metricsPollerLoop(bgCtx)

	m.log.Printf("eBPF started: iface=%s (idx %d) xdp=%s pin=%s",
		m.ifName, m.ifIndex, m.cfg.XDPMode, m.cfg.PinPath)
	return nil
}

// Stop detaches programs, closes all objects, and drains background goroutines.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.log.Printf("stopping eBPF on %s …", m.ifName)
	m.running = false

	if m.cancel != nil {
		m.cancel()
	}

	// Close perf reader (unblocks perfReaderLoop).
	if m.perfReader != nil {
		_ = m.perfReader.Close() // unblocks the reader loop; nothing to report on shutdown
	}

	m.mu.Unlock()
	m.wg.Wait() // wait for goroutines outside lock
	m.mu.Lock()

	m.cleanup()
	m.log.Printf("eBPF stopped")
	return nil
}

// IsRunning reports whether the manager is running.
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// Status returns the current runtime status.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := Status{
		PerfLostSamples: m.perfLostSamples.Load(),
		DecodeFailures:  m.decodeFailures.Load(),
		QueueDropped:    m.pushQueue.dropped(),
		QueueDepth:      m.pushQueue.len(),
		Running:         m.running,
		Interface:       m.ifName,
		InterfaceIdx:    m.ifIndex,
		XDPAttached:     m.xdpLink != nil,
		TCIngress:       m.tcIngressLink != nil || m.legacyTC != nil && m.legacyTC.attached(netlink.HANDLE_MIN_INGRESS),
		TCEgress:        m.tcEgressLink != nil || m.legacyTC != nil && m.legacyTC.attached(netlink.HANDLE_MIN_EGRESS),
		XDPMode:         m.cfg.XDPMode.String(),
		PinPath:         m.cfg.PinPath,
	}
	s.EgressIPv6Supported = s.TCEgress && m.tcColl != nil && m.tcColl.Maps["wafio_packet_abi"] != nil
	s.GeoAllowSupported = m.geoConfigMap != nil && m.geoCIDR4Map != nil && m.geoCIDR6Map != nil
	s.AllowlistPortsSupported = m.allowlistPortsSupportedLocked()
	s.AllowlistScopedSkipped = m.allowlistScopedSkipped
	if m.running {
		s.GeoMode = m.liveGeoMode()
		s.GeoRangesV4, s.GeoRangesV6 = m.geoState.RangesV4, m.geoState.RangesV6
		s.GeoDegradedCode, s.GeoDegradedState, s.GeoDegradedMessage = m.geoDegradedCode, m.geoDegradedState, m.geoDegradedMessage
	}
	s.LockoutExemptions = m.lockoutExemptions && s.XDPAttached && s.TCEgress
	s.CoverageWarnings = append([]string(nil), BaselineCoverageNotes...)
	if !s.EgressIPv6Supported {
		s.CoverageWarnings = append(s.CoverageWarnings, "IPv6 egress filtering unavailable on attached object")
	}
	if !s.LockoutExemptions {
		s.CoverageWarnings = append(s.CoverageWarnings, "attached objects lack the reply and control-plane exemptions; egress Deny All and wildcard blocklists are refused")
	}
	if m.xdpColl != nil && (m.allow4Map == nil || m.block4Map == nil) {
		s.CoverageWarnings = append(s.CoverageWarnings, "attached XDP object predates prefix IP lists; allowlist and blocklist changes are refused until the eBPF objects are updated")
	}
	if m.allowlistScopedSkipped > 0 {
		s.CoverageWarnings = append(s.CoverageWarnings, fmt.Sprintf("%d port-scoped allowlist entries are not enforced: the attached XDP object predates allowlist port scopes; update the eBPF objects with the agent", m.allowlistScopedSkipped))
	}
	if !s.TCIngress {
		s.CoverageWarnings = append(s.CoverageWarnings, "TC ingress is not attached")
	}
	if !s.TCEgress {
		s.CoverageWarnings = append(s.CoverageWarnings, "TC egress is not attached")
	}

	if m.running {
		s.StartedAt = m.startedAt
		s.UptimeSeconds = time.Since(m.startedAt).Seconds()
	}
	if kver, err := kernelVersion(); err == nil {
		s.KernelVersion = kver
	}
	// Include live config from BPF maps (read without lock since we already hold RLock)
	if m.running {
		cfg := &FullConfigAPI{}
		if m.configMap != nil {
			var key uint32
			var val GlobalConfig
			if err := m.configMap.Lookup(key, &val); err == nil {
				cfg.Global = val.ToAPI()
			}
		}
		if m.rateConfigMap != nil {
			var key uint32
			var val RateConfig
			if err := m.rateConfigMap.Lookup(key, &val); err == nil {
				cfg.Rate = val.ToAPI()
			}
		}
		if m.anomalyConfigMap != nil {
			var key uint32
			var val AnomalyConfig
			if err := m.anomalyConfigMap.Lookup(key, &val); err == nil {
				cfg.Anomaly = val.ToAPI()
			}
		}
		s.Config = cfg
	}
	// Include port policy snapshot
	if m.running {
		ppSnap := &PortPoliciesSnapshot{}
		if m.portPolicyCfgMap != nil {
			var key uint32
			var val PortPolicyConfig
			if err := m.portPolicyCfgMap.Lookup(key, &val); err == nil {
				ppSnap.Config = PortPolicyConfigAPI{
					Enabled:        val.Enabled != 0,
					DefaultIngress: "allow",
					DefaultEgress:  "allow",
				}
				if val.DefaultIngress == 1 {
					ppSnap.Config.DefaultIngress = "deny"
				}
				if val.DefaultEgress == 1 {
					ppSnap.Config.DefaultEgress = "deny"
				}
			}
		}
		if m.portPolicyMap != nil {
			var pkey PortPolicyKey
			var pval PortPolicyVal
			iter := m.portPolicyMap.Iterate()
			for iter.Next(&pkey, &pval) && len(ppSnap.Policies) < 500 {
				actionStr := "drop"
				switch pval.Action {
				case 0:
					actionStr = "allow"
				case 2:
					actionStr = "log"
				}
				ppSnap.Policies = append(ppSnap.Policies, PortPolicyAPI{
					Port:      pkey.Port,
					Proto:     protoNumToString(pkey.Proto),
					Direction: directionNumToString(pkey.Direction),
					Action:    actionStr,
					HitCount:  pval.HitCount,
				})
			}
		}
		if ppSnap.Policies == nil {
			ppSnap.Policies = []PortPolicyAPI{}
		}
		ppSnap.Count = len(ppSnap.Policies)
		s.PortPolicies = ppSnap
	}
	// Jailed addresses, read-only for the dashboard.
	if m.running && m.jailMap != nil {
		if jail, total, err := m.listJailLocked(statusJailEntries); err == nil {
			s.Jail = jail
			s.JailCount = total
		}
	}
	return s
}

// Events returns a read-only channel of decoded perf events.
func (m *Manager) Events() <-chan Event {
	return m.events
}

// ────────────────────────────────────────────────────────────────────────────
//  Internal: load BPF objects
// ────────────────────────────────────────────────────────────────────────────

func (m *Manager) loadXDP() error {
	spec, err := m.loadSpec(m.cfg.XDPObjectPath)
	if err != nil {
		return err
	}

	// The tail-call PROG_ARRAY must never be pinned: a reused pin would
	// hold program FDs from the previous load (stale after reload).
	if pa := spec.Maps["wafio_xdp_progs"]; pa != nil {
		pa.Pinning = ebpf.PinNone
	}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: m.cfg.PinPath,
		},
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("new XDP collection: %w", err)
	}
	m.xdpColl = coll

	// Cache map references.
	m.configMap = coll.Maps[mapConfig]
	m.allow4Map = coll.Maps[mapAllow4]
	m.allow6Map = coll.Maps[mapAllow6]
	m.allowScopesMap = coll.Maps[mapAllowScopes]
	m.block4Map = coll.Maps[mapBlock4]
	m.block6Map = coll.Maps[mapBlock6]
	m.jailMap = coll.Maps[mapJail]
	m.rateConfigMap = coll.Maps[mapRateConfig]
	m.rateStateMap = coll.Maps[mapRateState]
	m.synStateMap = coll.Maps[mapSynState]
	m.conntrackMap = coll.Maps[mapConntrack]
	m.geoipMap = coll.Maps[mapGeoIP]
	m.geoBlockedMap = coll.Maps[mapGeoBlocked]
	m.geoCIDR4Map = coll.Maps[mapGeoCIDR4]
	m.geoCIDR6Map = coll.Maps[mapGeoCIDR6]
	m.geoConfigMap = coll.Maps[mapGeoConfig]
	m.geoLocal4Map = coll.Maps[mapGeoLocal4]
	m.geoLocal6Map = coll.Maps[mapGeoLocal6]
	m.geoState = GeoRangeState{Mode: GeoModeBlock}
	m.geoDegradedCode, m.geoDegradedState, m.geoDegradedMessage = "", "", ""
	m.metricsMap = coll.Maps[mapMetrics]
	m.eventsMap = coll.Maps[mapEvents]
	m.portscanMap = coll.Maps[mapPortscan]
	m.portscanCfgMap = coll.Maps[mapPortscanCfg]
	m.portPolicyMap = coll.Maps[mapPortPolicy]
	m.portPolicyCfgMap = coll.Maps[mapPortPolicyConfig]
	m.egressBlocklistMap = coll.Maps[mapEgressBlocklist]
	m.cpEndpointsMap = coll.Maps[mapCPEndpoints]

	// Populate the tail-call PROG_ARRAY: entry dispatches to per-family
	// sub-programs. Each gets its own verifier budget (kernel 5.15).
	if progArray := coll.Maps["wafio_xdp_progs"]; progArray != nil {
		if v4 := coll.Programs["wafio_xdp_v4"]; v4 != nil {
			_ = progArray.Update(uint32(0), u32FromInt(v4.FD()), ebpf.UpdateAny)
		}
		if v6 := coll.Programs["wafio_xdp_v6"]; v6 != nil {
			_ = progArray.Update(uint32(1), u32FromInt(v6.FD()), ebpf.UpdateAny)
		}
		m.log.Printf("XDP tail-call dispatch armed (v4=idx0, v6=idx1)")
	}

	return nil
}

func (m *Manager) loadTC() error {
	spec, err := m.loadSpec(m.cfg.TCObjectPath)
	if err != nil {
		return err
	}

	// Reuse shared maps from XDP collection. A replacement must exist in the
	// TC spec (cilium/ebpf rejects unknown names), so a TC object older than
	// the XDP object still loads — without the maps it does not know.
	replacements := make(map[string]*ebpf.Map)
	shared := []string{mapConfig, mapConntrack, mapEvents, mapMetrics,
		mapPortPolicy, mapPortPolicyConfig, mapEgressBlocklist, mapCPEndpoints,
		mapDHCPPending, mapDHCPServers}
	for _, name := range shared {
		if xm := m.xdpColl.Maps[name]; xm != nil && spec.Maps[name] != nil {
			replacements[name] = xm
		}
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: replacements,
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("new TC collection: %w", err)
	}
	m.tcColl = coll

	// TC-specific maps.
	m.bandwidthMap = coll.Maps[mapBandwidth]
	m.anomalyConfigMap = coll.Maps[mapAnomalyConfig]
	m.egressSubnetV4Map = coll.Maps[mapEgressSubnetV4]
	m.egressSubnetV6Map = coll.Maps[mapEgressSubnetV6]
	m.lockoutExemptions = m.cpEndpointsMap != nil && replacements[mapCPEndpoints] != nil

	return nil
}

func (m *Manager) loadSpec(path string) (*ebpf.CollectionSpec, error) {
	if path == "" {
		return nil, fmt.Errorf("BPF object path not configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return spec, nil
}

// ────────────────────────────────────────────────────────────────────────────
//  Internal: attach / detach programs
// ────────────────────────────────────────────────────────────────────────────

func (m *Manager) attachXDP() error {
	prog := m.xdpColl.Programs["wafio_xdp_firewall"]
	if prog == nil {
		return fmt.Errorf("XDP program 'wafio_xdp_firewall' not found in collection")
	}

	opts := link.XDPOptions{
		Program:   prog,
		Interface: m.ifIndex,
	}
	switch m.cfg.XDPMode {
	case XDPModeSKB:
		opts.Flags = link.XDPGenericMode
	case XDPModeDriver:
		opts.Flags = link.XDPDriverMode
	case XDPModeHW:
		opts.Flags = link.XDPOffloadMode
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		return fmt.Errorf("attach XDP to %s: %w", m.ifName, err)
	}
	m.xdpLink = l
	return nil
}

func (m *Manager) attachTC() error {
	for _, hook := range []struct {
		name   string
		attach ebpf.AttachType
		parent uint32
		link   *link.Link
	}{
		{"wafio_tc_ingress", ebpf.AttachTCXIngress, netlink.HANDLE_MIN_INGRESS, &m.tcIngressLink},
		{"wafio_tc_egress", ebpf.AttachTCXEgress, netlink.HANDLE_MIN_EGRESS, &m.tcEgressLink},
	} {
		prog := m.tcColl.Programs[hook.name]
		if prog == nil {
			return fmt.Errorf("TC program %q missing", hook.name)
		}
		attached, err := link.AttachTCX(link.TCXOptions{Program: prog, Attach: hook.attach, Interface: m.ifIndex})
		if err == nil {
			*hook.link = attached
			continue
		}
		m.log.Printf("TCX %s unavailable: %v; trying legacy clsact", hook.name, err)
		if m.legacyTC == nil {
			m.legacyTC = &legacyTCAttachment{ifIndex: m.ifIndex}
		}
		if legacyErr := m.legacyTC.attach(hook.parent, prog); legacyErr != nil {
			return fmt.Errorf("attach %s: TCX: %v; clsact: %w", hook.name, err, legacyErr)
		}
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
//  Internal: perf reader
// ────────────────────────────────────────────────────────────────────────────

func (m *Manager) startPerfReader() error {
	if m.eventsMap == nil {
		return fmt.Errorf("events map not loaded")
	}
	rd, err := perf.NewReader(m.eventsMap, m.cfg.EventBufferSize*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("perf reader: %w", err)
	}
	m.perfReader = rd
	return nil
}

func (m *Manager) perfReaderLoop(ctx context.Context) {
	defer m.wg.Done()
	if m.perfReader == nil {
		return
	}
	for {
		record, err := m.perfReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				m.log.Printf("perf read error: %v", err)
				continue
			}
		}
		if record.LostSamples > 0 {
			m.perfLostSamples.Add(record.LostSamples)
			m.log.Printf("perf lost %d samples", record.LostSamples)
			continue
		}
		ev, err := ParsePerfEvent(record.RawSample)
		if err != nil {
			m.decodeFailures.Add(1)
			continue
		}
		event := ev.ToEvent()

		// Convert bpf_ktime_get_ns (monotonic) to wall-clock time.
		event.Timestamp = m.bpfTimeToWall(ev.TimestampNs)

		// Store in ring buffer for API reads.
		m.recentEventsMu.Lock()
		m.recentEvents = append(m.recentEvents, event)
		if len(m.recentEvents) > m.maxRecentEvents {
			m.recentEvents = m.recentEvents[len(m.recentEvents)-m.maxRecentEvents:]
		}
		m.recentEventsMu.Unlock()
		// Queue for the destructive push drain (exactly-once delivery).
		m.pushQueue.push(event)

		// Non-blocking send to channel (for streaming consumers).
		select {
		case m.events <- event:
		default:
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
//  Internal: metrics poller
// ────────────────────────────────────────────────────────────────────────────

func (m *Manager) metricsPollerLoop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(time.Duration(m.cfg.MetricsPollMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.pruneDetectionState()
			snap, err := m.readRawMetrics()
			if err != nil {
				continue
			}
			now := time.Now()
			metrics := &Metrics{
				RxPackets:           snap.RxPackets,
				RxBytes:             snap.RxBytes,
				TxPackets:           snap.TxPackets,
				TxBytes:             snap.TxBytes,
				DroppedPackets:      snap.DroppedPackets,
				DroppedBytes:        snap.DroppedBytes,
				RatelimitedPackets:  snap.RatelimitedPackets,
				SynfloodDrops:       snap.SynfloodDrops,
				BlocklistDrops:      snap.BlocklistDrops,
				AllowlistPasses:     snap.AllowlistPasses,
				GeoblockDrops:       snap.GeoblockDrops,
				ConntrackEntries:    snap.ConntrackEntries,
				PortScanDrops:       snap.PortScanDrops,
				PortPolicyDrops:     snap.PortPolicyDrops,
				EgressIPDrops:       snap.EgressIPDrops,
				WouldDropPackets:    snap.WouldDropPackets,
				WouldDropBytes:      snap.WouldDropBytes,
				StateTableFull:      snap.StateTableFull,
				PacketParseFailures: snap.PacketParseFailures,
				SynPressureDrops:    snap.SynPressureDrops,
				Timestamp:           now,
			}

			// Calculate rates from delta.
			if m.prevMetrics != nil && !m.prevMetricsAt.IsZero() {
				dt := now.Sub(m.prevMetricsAt).Seconds()
				if dt > 0 {
					dp := float64(snap.RxPackets - m.prevMetrics.RxPackets)
					db := float64(snap.RxBytes - m.prevMetrics.RxBytes)
					metrics.PPS = dp / dt
					metrics.BPS = db / dt
				}
			}
			total := snap.RxPackets + snap.TxPackets
			if total > 0 {
				metrics.DropRate = float64(snap.DroppedPackets) / float64(total) * 100
			}

			m.prevMetrics = snap
			m.prevMetricsAt = now

			m.lastMetricsMu.Lock()
			m.lastMetrics = metrics
			m.lastMetricsMu.Unlock()
		}
	}
}

// readRawMetrics reads per-CPU metrics and sums them.
func (m *Manager) readRawMetrics() (*MetricsVal, error) {
	if m.metricsMap == nil {
		return nil, fmt.Errorf("metrics map not loaded")
	}
	var key uint32
	var perCPU []MetricsVal
	if err := m.metricsMap.Lookup(key, &perCPU); err != nil {
		return nil, fmt.Errorf("metrics lookup: %w", err)
	}
	var sum MetricsVal
	for _, v := range perCPU {
		sum.RxPackets += v.RxPackets
		sum.RxBytes += v.RxBytes
		sum.TxPackets += v.TxPackets
		sum.TxBytes += v.TxBytes
		sum.DroppedPackets += v.DroppedPackets
		sum.DroppedBytes += v.DroppedBytes
		sum.RatelimitedPackets += v.RatelimitedPackets
		sum.SynfloodDrops += v.SynfloodDrops
		sum.BlocklistDrops += v.BlocklistDrops
		sum.AllowlistPasses += v.AllowlistPasses
		sum.GeoblockDrops += v.GeoblockDrops
		sum.ConntrackEntries += v.ConntrackEntries
		sum.PortScanDrops += v.PortScanDrops
		sum.PortPolicyDrops += v.PortPolicyDrops
		sum.EgressIPDrops += v.EgressIPDrops
		sum.WouldDropPackets += v.WouldDropPackets
		sum.WouldDropBytes += v.WouldDropBytes
		sum.StateTableFull += v.StateTableFull
		sum.PacketParseFailures += v.PacketParseFailures
		sum.SynPressureDrops += v.SynPressureDrops
	}
	return &sum, nil
}

// ReadMetrics returns the latest aggregated metrics snapshot.
func (m *Manager) ReadMetrics() (*Metrics, error) {
	m.lastMetricsMu.RLock()
	defer m.lastMetricsMu.RUnlock()
	if m.lastMetrics == nil {
		// Compute on demand if poller hasn't run yet.
		raw, err := m.readRawMetrics()
		if err != nil {
			return nil, err
		}
		return &Metrics{
			RxPackets:           raw.RxPackets,
			RxBytes:             raw.RxBytes,
			TxPackets:           raw.TxPackets,
			TxBytes:             raw.TxBytes,
			DroppedPackets:      raw.DroppedPackets,
			DroppedBytes:        raw.DroppedBytes,
			RatelimitedPackets:  raw.RatelimitedPackets,
			SynfloodDrops:       raw.SynfloodDrops,
			BlocklistDrops:      raw.BlocklistDrops,
			AllowlistPasses:     raw.AllowlistPasses,
			GeoblockDrops:       raw.GeoblockDrops,
			ConntrackEntries:    raw.ConntrackEntries,
			PortScanDrops:       raw.PortScanDrops,
			PortPolicyDrops:     raw.PortPolicyDrops,
			EgressIPDrops:       raw.EgressIPDrops,
			WouldDropPackets:    raw.WouldDropPackets,
			WouldDropBytes:      raw.WouldDropBytes,
			StateTableFull:      raw.StateTableFull,
			PacketParseFailures: raw.PacketParseFailures,
			SynPressureDrops:    raw.SynPressureDrops,
			Timestamp:           time.Now(),
		}, nil
	}
	snap := *m.lastMetrics
	return &snap, nil
}

// ────────────────────────────────────────────────────────────────────────────
//  Config operations
// ────────────────────────────────────────────────────────────────────────────

// GetGlobalConfig reads the current global config from BPF map.
func (m *Manager) GetGlobalConfig() (*GlobalConfigAPI, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.configMap == nil {
		return nil, fmt.Errorf("config map not loaded")
	}
	var key uint32
	var val GlobalConfig
	if err := m.configMap.Lookup(key, &val); err != nil {
		return nil, fmt.Errorf("config lookup: %w", err)
	}
	api := val.ToAPI()
	return &api, nil
}

// UpdateGlobalConfig writes a new global config to the BPF map.
func (m *Manager) UpdateGlobalConfig(api GlobalConfigAPI) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.configMap == nil {
		return fmt.Errorf("config map not loaded")
	}
	var bpf GlobalConfig
	bpf.FromAPI(api)
	var key uint32
	return m.configMap.Update(key, &bpf, ebpf.UpdateAny)
}

// GetRateConfig reads the current rate config from BPF map.
func (m *Manager) GetRateConfig() (*RateConfigAPI, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.rateConfigMap == nil {
		return nil, fmt.Errorf("rate config map not loaded")
	}
	var key uint32
	var val RateConfig
	if err := m.rateConfigMap.Lookup(key, &val); err != nil {
		return nil, fmt.Errorf("rate config lookup: %w", err)
	}
	api := val.ToAPI()
	return &api, nil
}

// UpdateRateConfig writes a new rate config to the BPF map.
func (m *Manager) UpdateRateConfig(api RateConfigAPI) error {
	if err := ValidateRateConfig(api); err != nil {
		return err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.rateConfigMap == nil {
		return fmt.Errorf("rate config map not loaded")
	}
	var bpf RateConfig
	bpf.FromAPI(api)
	var key uint32
	return m.rateConfigMap.Update(key, &bpf, ebpf.UpdateAny)
}

// GetPortScanConfig reads the current port scan config from BPF map.
func (m *Manager) GetPortScanConfig() (*PortScanConfigAPI, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.portscanCfgMap == nil {
		return nil, fmt.Errorf("portscan config map not loaded")
	}
	var key uint32
	var val PortScanConfig
	if err := m.portscanCfgMap.Lookup(key, &val); err != nil {
		return nil, fmt.Errorf("portscan config lookup: %w", err)
	}
	api := val.ToAPI()
	return &api, nil
}

// UpdatePortScanConfig writes a new port scan config to the BPF map.
func (m *Manager) UpdatePortScanConfig(api PortScanConfigAPI) error {
	if err := ValidatePortScanConfig(api); err != nil {
		return err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.portscanCfgMap == nil {
		return fmt.Errorf("portscan config map not loaded")
	}
	var bpf PortScanConfig
	bpf.FromAPI(api)
	var key uint32
	return m.portscanCfgMap.Update(key, &bpf, ebpf.UpdateAny)
}

// GetAnomalyConfig reads the current anomaly config from BPF map.
func (m *Manager) GetAnomalyConfig() (*AnomalyConfigAPI, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.anomalyConfigMap == nil {
		return nil, fmt.Errorf("anomaly config map not loaded")
	}
	var key uint32
	var val AnomalyConfig
	if err := m.anomalyConfigMap.Lookup(key, &val); err != nil {
		return nil, fmt.Errorf("anomaly config lookup: %w", err)
	}
	api := val.ToAPI()
	return &api, nil
}

// UpdateAnomalyConfig writes a new anomaly config to the BPF map.
func (m *Manager) UpdateAnomalyConfig(api AnomalyConfigAPI) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.anomalyConfigMap == nil {
		return fmt.Errorf("anomaly config map not loaded")
	}
	var bpf AnomalyConfig
	bpf.FromAPI(api)
	var key uint32
	return m.anomalyConfigMap.Update(key, &bpf, ebpf.UpdateAny)
}

// GetFullConfig reads all sub-configs and returns them as a single struct.
func (m *Manager) GetFullConfig() (*FullConfigAPI, error) {
	global, err := m.GetGlobalConfig()
	if err != nil {
		return nil, err
	}
	rate, err := m.GetRateConfig()
	if err != nil {
		rate = &RateConfigAPI{}
	}
	anomaly, err := m.GetAnomalyConfig()
	if err != nil {
		anomaly = &AnomalyConfigAPI{}
	}
	portScan, err := m.GetPortScanConfig()
	if err != nil {
		portScan = &PortScanConfigAPI{}
	}
	return &FullConfigAPI{
		Global:   *global,
		Rate:     *rate,
		Anomaly:  *anomaly,
		PortScan: *portScan,
	}, nil
}

// UpdateFullConfig writes all sub-configs from a single struct.
func (m *Manager) UpdateFullConfig(cfg FullConfigAPI) error {
	if err := ValidateRateConfig(cfg.Rate); err != nil {
		return err
	}
	if err := ValidatePortScanConfig(cfg.PortScan); err != nil {
		return err
	}
	if err := m.UpdateGlobalConfig(cfg.Global); err != nil {
		return fmt.Errorf("global: %w", err)
	}
	if err := m.UpdateRateConfig(cfg.Rate); err != nil {
		return fmt.Errorf("rate: %w", err)
	}
	if err := m.UpdateAnomalyConfig(cfg.Anomaly); err != nil {
		return fmt.Errorf("anomaly: %w", err)
	}
	if err := m.UpdatePortScanConfig(cfg.PortScan); err != nil {
		return fmt.Errorf("port_scan: %w", err)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
//  Blocklist / Allowlist operations
// ────────────────────────────────────────────────────────────────────────────

// The ingress allowlist and blocklist operations (prefixes in LPM tries)
// live in ip_lists_linux.go.

// ────────────────────────────────────────────────────────────────────────────
//  Geo-blocking operations
// ────────────────────────────────────────────────────────────────────────────

// BlockCountry marks a country code as blocked in the geo_blocked map.
func (m *Manager) BlockCountry(code string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.geoBlockedMap == nil {
		return fmt.Errorf("geo_blocked map not loaded")
	}
	if len(code) != 2 {
		return fmt.Errorf("invalid country code: %s (must be 2 chars)", code)
	}
	key := PackCountry(code[0], code[1])
	val := GeoCountryVal{Blocked: 1}
	return m.geoBlockedMap.Update(key, &val, ebpf.UpdateAny)
}

// UnblockCountry removes a country from the geo_blocked map.
func (m *Manager) UnblockCountry(code string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.geoBlockedMap == nil {
		return fmt.Errorf("geo_blocked map not loaded")
	}
	if len(code) != 2 {
		return fmt.Errorf("invalid country code: %s", code)
	}
	key := PackCountry(code[0], code[1])
	return m.geoBlockedMap.Delete(key)
}

// ListBlockedCountries returns all currently blocked country codes.
func (m *Manager) ListBlockedCountries() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.geoBlockedMap == nil {
		return nil, fmt.Errorf("geo_blocked map not loaded")
	}
	var countries []string
	var key uint16
	var val GeoCountryVal
	iter := m.geoBlockedMap.Iterate()
	for iter.Next(&key, &val) {
		if val.Blocked == 1 {
			countries = append(countries, UnpackCountry(key))
		}
	}
	return countries, iter.Err()
}

// ────────────────────────────────────────────────────────────────────────────
//  Connection tracking
// ────────────────────────────────────────────────────────────────────────────

// ListConnections iterates the conntrack table and returns decoded entries.
func (m *Manager) ListConnections(limit int) ([]Connection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.conntrackMap == nil {
		return nil, fmt.Errorf("conntrack map not loaded")
	}
	if limit <= 0 {
		limit = 100
	}
	var conns []Connection
	var key ConnKey
	var val ConnVal
	now := m.ktimeNow()
	iter := m.conntrackMap.Iterate()
	for iter.Next(&key, &val) && len(conns) < limit {
		if !connectionFresh(key.Proto, val.LastSeenNs, now) {
			continue
		}
		conns = append(conns, Connection{
			SrcIP:     key.Src.ToIP().String(),
			DstIP:     key.Dst.ToIP().String(),
			SrcPort:   ntohs(key.Sport),
			DstPort:   ntohs(key.Dport),
			Proto:     protoString(key.Proto),
			State:     tcpStateString(val.TCPState),
			FirstSeen: m.bpfTimeToWall(val.FirstSeenNs),
			LastSeen:  m.bpfTimeToWall(val.LastSeenNs),
			Packets:   val.Packets,
			Bytes:     val.Bytes,
		})
	}
	return conns, iter.Err()
}

// ────────────────────────────────────────────────────────────────────────────
//  Bandwidth (TC)
// ────────────────────────────────────────────────────────────────────────────

// ListBandwidth reads per-IP bandwidth accounting from TC map.
func (m *Manager) ListBandwidth(limit int) ([]BandwidthEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.bandwidthMap == nil {
		return nil, fmt.Errorf("bandwidth map not loaded")
	}
	if limit <= 0 {
		limit = 100
	}
	var entries []BandwidthEntry
	var key IPKey
	var val BwState
	iter := m.bandwidthMap.Iterate()
	for iter.Next(&key, &val) && len(entries) < limit {
		entries = append(entries, BandwidthEntry{
			IP:             key.ToIP().String(),
			IngressBytes:   val.IngressBytes,
			EgressBytes:    val.EgressBytes,
			IngressPackets: val.IngressPackets,
			EgressPackets:  val.EgressPackets,
		})
	}
	return entries, iter.Err()
}

// ────────────────────────────────────────────────────────────────────────────
//  Recent events snapshot (for polling APIs)
// ────────────────────────────────────────────────────────────────────────────

// DrainRecentEvents removes and returns up to limit pending events, oldest
// first — exactly-once delivery for the push loop.
// PendingEvents is the number of firewall events waiting for
// DrainRecentEvents (the telemetry loop sends early once a batch is full).
func (m *Manager) PendingEvents() int { return m.pushQueue.len() }

func (m *Manager) DrainRecentEvents(limit int) []Event {
	if limit <= 0 {
		limit = 100
	}
	return m.pushQueue.drain(limit)
}

// GetRecentEvents returns the most recent events from the ring buffer,
// newest first, NON-destructively — for snapshot/polling APIs.
func (m *Manager) GetRecentEvents(limit int) []Event {
	if limit <= 0 {
		limit = 100
	}
	m.recentEventsMu.Lock()
	defer m.recentEventsMu.Unlock()
	n := len(m.recentEvents)
	if n == 0 {
		return nil
	}
	start := 0
	if n > limit {
		start = n - limit
	}
	// Return newest first.
	out := make([]Event, 0, n-start)
	for i := n - 1; i >= start; i-- {
		out = append(out, m.recentEvents[i])
	}
	return out
}

// ────────────────────────────────────────────────────────────────────────────
//  Internal helpers
// ────────────────────────────────────────────────────────────────────────────

func (m *Manager) writeDefaultConfig() error {
	// One source for the defaults: the control plane delivers the same
	// values for a desired state without "config" (DefaultFullConfigAPI).
	def := DefaultFullConfigAPI()
	var cfg GlobalConfig
	cfg.FromAPI(def.Global)
	var key uint32
	if err := m.configMap.Update(key, &cfg, ebpf.UpdateAny); err != nil {
		return err
	}

	// Default rate config: 10k pps, 100Mbps, 1000 syn/s, all with burst.
	// SynPressurePPS: global pressure mode arms at 50k SYN/s aggregate —
	// far above legitimate traffic, far below a real distributed flood.
	var rateCfg RateConfig
	rateCfg.FromAPI(def.Rate)
	if m.rateConfigMap != nil {
		if err := m.rateConfigMap.Update(key, &rateCfg, ebpf.UpdateAny); err != nil {
			m.log.Printf("WARN: set default rate config: %v", err)
		}
	}

	// Default anomaly config: detect all, log only.
	var anomalyCfg AnomalyConfig
	anomalyCfg.FromAPI(def.Anomaly)
	if m.anomalyConfigMap != nil {
		if err := m.anomalyConfigMap.Update(key, &anomalyCfg, ebpf.UpdateAny); err != nil {
			m.log.Printf("WARN: set default anomaly config: %v", err)
		}
	}

	// Default port policy config: disabled, allow-all (safe start).
	portPolicyCfg := PortPolicyConfig{
		Enabled:        0,
		DefaultIngress: 0, // allow-all
		DefaultEgress:  0, // allow-all
	}
	if m.portPolicyCfgMap != nil {
		if err := m.portPolicyCfgMap.Update(key, &portPolicyCfg, ebpf.UpdateAny); err != nil {
			m.log.Printf("WARN: set default port policy config: %v", err)
		}
	}

	return nil
}

func (m *Manager) cleanup() {
	if m.xdpLink != nil {
		_ = m.xdpLink.Close() // detach on shutdown; the kernel drops the link with its fd
		m.xdpLink = nil
	}
	if m.tcIngressLink != nil {
		_ = m.tcIngressLink.Close() // detach on shutdown; the kernel drops the link with its fd
		m.tcIngressLink = nil
	}
	if m.tcEgressLink != nil {
		_ = m.tcEgressLink.Close() // detach on shutdown; the kernel drops the link with its fd
		m.tcEgressLink = nil
	}
	if m.legacyTC != nil {
		if err := m.legacyTC.close(); err != nil {
			m.log.Printf("WARN: legacy TC cleanup: %v", err)
		}
		m.legacyTC = nil
	}
	if m.xdpColl != nil {
		m.xdpColl.Close()
		m.xdpColl = nil
	}
	if m.tcColl != nil {
		m.tcColl.Close()
		m.tcColl = nil
	}

	// Clean up pin directory.
	if m.cfg.PinPath != "" {
		if err := os.RemoveAll(m.cfg.PinPath); err != nil {
			m.log.Printf("WARN: remove pin path %s: %v", m.cfg.PinPath, err)
		}
	}

	// Nil out map references.
	m.configMap = nil
	m.allow4Map = nil
	m.allow6Map = nil
	m.allowScopesMap = nil
	m.block4Map = nil
	m.block6Map = nil
	m.jailMap = nil
	m.rateConfigMap = nil
	m.rateStateMap = nil
	m.synStateMap = nil
	m.conntrackMap = nil
	m.geoipMap = nil
	m.geoBlockedMap = nil
	m.geoCIDR4Map = nil
	m.geoCIDR6Map = nil
	m.geoConfigMap = nil
	m.geoLocal4Map = nil
	m.geoLocal6Map = nil
	m.geoState = GeoRangeState{}
	m.metricsMap = nil
	m.eventsMap = nil
	m.portscanMap = nil
	m.portscanCfgMap = nil
	m.bandwidthMap = nil
	m.anomalyConfigMap = nil
	m.portPolicyMap = nil
	m.portPolicyCfgMap = nil
	m.egressBlocklistMap = nil
	m.egressSubnetV4Map = nil
	m.egressSubnetV6Map = nil
	m.cpEndpointsMap = nil
	m.lockoutExemptions = false
	m.cpPort = 0
}

func ntohs(v uint16) uint16 {
	return (v>>8)&0xff | (v&0xff)<<8
}

func kernelVersion() (string, error) {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "", err
	}
	// First line: "Linux version X.Y.Z ..."
	fields := bytes.Fields(data)
	if len(fields) >= 3 {
		return string(fields[2]), nil
	}
	return "", fmt.Errorf("unexpected /proc/version format")
}

// ────────────────────────────────────────────────────────────────────────────
//  Port Policy operations (Enterprise ingress/egress port firewall)
// ────────────────────────────────────────────────────────────────────────────

// GetPortPolicyConfig reads the port policy global config from BPF map.
func (m *Manager) GetPortPolicyConfig() (*PortPolicyConfigAPI, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.portPolicyCfgMap == nil {
		return nil, fmt.Errorf("port policy config map not loaded")
	}
	var key uint32
	var val PortPolicyConfig
	if err := m.portPolicyCfgMap.Lookup(key, &val); err != nil {
		// Not configured yet — return defaults
		return &PortPolicyConfigAPI{
			Enabled:        false,
			DefaultIngress: "allow",
			DefaultEgress:  "allow",
		}, nil
	}
	api := PortPolicyConfigAPI{
		Enabled:        val.Enabled != 0,
		DefaultIngress: "allow",
		DefaultEgress:  "allow",
	}
	if val.DefaultIngress == 1 {
		api.DefaultIngress = "deny"
	}
	if val.DefaultEgress == 1 {
		api.DefaultEgress = "deny"
	}
	return &api, nil
}

// UpdatePortPolicyConfig writes the port policy global config to BPF map.
func (m *Manager) UpdatePortPolicyConfig(api PortPolicyConfigAPI) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.portPolicyCfgMap == nil {
		return fmt.Errorf("port policy config map not loaded")
	}
	if api.Enabled && api.DefaultIngress == "deny" && m.tcEgressLink == nil &&
		(m.legacyTC == nil || !m.legacyTC.attached(netlink.HANDLE_MIN_EGRESS)) {
		return fmt.Errorf("ingress deny requires an attached TC egress hook for outbound return traffic")
	}
	val := PortPolicyConfig{}
	if api.Enabled {
		val.Enabled = 1
	}
	if api.DefaultIngress == "deny" {
		val.DefaultIngress = 1
	}
	if api.DefaultEgress == "deny" {
		val.DefaultEgress = 1
	}
	var key uint32
	return m.portPolicyCfgMap.Update(key, &val, ebpf.UpdateAny)
}

// protoStringToNum converts "tcp"/"udp"/"any" → protocol number.
func protoStringToNum(s string) uint8 {
	switch s {
	case "tcp":
		return 6
	case "udp":
		return 17
	default:
		return 0
	}
}

// protoNumToString converts protocol number → "tcp"/"udp"/"any".
func protoNumToString(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "any"
	}
}

// directionStringToNum converts "ingress"/"egress"/"both" → direction constant.
func directionStringToNum(s string) uint8 {
	switch s {
	case "egress":
		return PortDirEgress
	case "both":
		return PortDirBoth
	default:
		return PortDirIngress
	}
}

// directionNumToString converts direction constant → string.
func directionNumToString(d uint8) string {
	switch d {
	case PortDirEgress:
		return "egress"
	case PortDirBoth:
		return "both"
	default:
		return "ingress"
	}
}

// AddPortPolicy adds a port policy rule to the BPF map.
func (m *Manager) AddPortPolicy(api PortPolicyAPI) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.portPolicyMap == nil {
		return fmt.Errorf("port policy map not loaded")
	}
	// Unknown action/proto/direction strings are refused, never mapped to
	// DROP or "any": a rule must do exactly what it says.
	if err := ValidatePortPolicyRule(api); err != nil {
		return err
	}
	key := PortPolicyKey{
		Port:      api.Port,
		Proto:     protoStringToNum(api.Proto),
		Direction: directionStringToNum(api.Direction),
	}
	// Expiry exactly as the lockout guard reads it (PortPolicyDeadline):
	// expires_at is honoured, not only ttl_ms, and a rule
	// already past it empties its slot instead of being written permanent.
	deadline, expiring, expired := PortPolicyDeadline(api, time.Now())
	if expired {
		if err := m.portPolicyMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		return nil
	}
	now := m.ktimeNow()
	val := PortPolicyVal{AddedNs: now}
	if expiring {
		val.ExpiresNs = m.wallToKtime(deadline.UnixNano())
		if val.ExpiresNs <= now {
			val.ExpiresNs = now + 1
		}
	}
	switch api.Action {
	case "allow":
		val.Action = 0 // ACTION_ALLOW
	case "log":
		val.Action = 2 // ACTION_LOG
	case "drop":
		val.Action = 1 // ACTION_DROP
	}
	// Preserve hit_count across desired-state syncs
	var existing PortPolicyVal
	if err := m.portPolicyMap.Lookup(key, &existing); err == nil {
		val.HitCount = existing.HitCount
	}
	return m.portPolicyMap.Update(key, &val, ebpf.UpdateAny)
}

// RemovePortPolicy removes a port policy rule from the BPF map.
func (m *Manager) RemovePortPolicy(port uint16, proto, direction string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.portPolicyMap == nil {
		return fmt.Errorf("port policy map not loaded")
	}
	key := PortPolicyKey{
		Port:      port,
		Proto:     protoStringToNum(proto),
		Direction: directionStringToNum(direction),
	}
	return m.portPolicyMap.Delete(key)
}

// ListPortPolicies iterates the port policy map and returns decoded entries.
func (m *Manager) ListPortPolicies(limit int) ([]PortPolicyAPI, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.portPolicyMap == nil {
		return nil, fmt.Errorf("port policy map not loaded")
	}
	if limit <= 0 {
		limit = 500
	}
	var policies []PortPolicyAPI
	var key PortPolicyKey
	var val PortPolicyVal
	iter := m.portPolicyMap.Iterate()
	for iter.Next(&key, &val) && len(policies) < limit {
		actionStr := "drop"
		switch val.Action {
		case 0:
			actionStr = "allow"
		case 2:
			actionStr = "log"
		}
		p := PortPolicyAPI{
			Port:      key.Port,
			Proto:     protoNumToString(key.Proto),
			Direction: directionNumToString(key.Direction),
			Action:    actionStr,
			HitCount:  val.HitCount,
		}
		if val.AddedNs > 0 {
			p.AddedAt = m.bpfTimeToWall(val.AddedNs).Format(time.RFC3339)
		}
		if val.ExpiresNs > 0 {
			p.ExpiresAt = m.bpfTimeToWall(val.ExpiresNs).Format(time.RFC3339)
		}
		policies = append(policies, p)
	}
	return policies, iter.Err()
}

// Egress blocklist operations (addresses and the family-wide entries in
// the hash, other prefixes in the egress tries) live in ip_lists_linux.go.

// ────────────────────────────────────────────────────────────────────────────
//  GeoIP bulk loader (for initialization from MaxMind DB)
// ────────────────────────────────────────────────────────────────────────────

// LoadGeoIPEntry adds a single IP→country mapping to the geoip map.
func (m *Manager) LoadGeoIPEntry(ip net.IP, countryCode string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.geoipMap == nil {
		return fmt.Errorf("geoip map not loaded")
	}
	if len(countryCode) != 2 {
		return fmt.Errorf("invalid country code: %s", countryCode)
	}
	key := IPKeyFromIP(ip)
	val := GeoVal{
		CountryCode: PackCountry(countryCode[0], countryCode[1]),
		Action:      1, // ACTION_DROP (actual decision by geo_blocked map)
	}
	return m.geoipMap.Update(key, &val, ebpf.UpdateAny)
}

// ────────────────────────────────────────────────────────────────────────────
//  Geo CIDR LPM trie keys
// ────────────────────────────────────────────────────────────────────────────

// geoCIDRv4Key mirrors struct geo_cidr_v4_key in wafio_xdp.c.
// Must be packed: prefixlen (4 bytes) + addr (4 bytes).
type geoCIDRv4Key struct {
	Prefixlen uint32
	Addr      [4]byte
}

// geoCIDRv6Key mirrors struct geo_cidr_v6_key.
type geoCIDRv6Key struct {
	Prefixlen uint32
	Addr      [16]byte
}

// AllowlistPortsSupported reports whether the loaded XDP object matches
// allowlist port scopes (it has the wafio_allow_scopes marker and both allow
// tries). Without it a port-scoped entry is refused, never written as an
// entry that allows every port.
func (m *Manager) AllowlistPortsSupported() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allowlistPortsSupportedLocked()
}

func (m *Manager) allowlistPortsSupportedLocked() bool {
	return m.allow4Map != nil && m.allow6Map != nil && m.allowScopesMap != nil
}

// SetAllowlistScopedSkipped records how many port-scoped allowlist entries
// the last applied desired state carried that this object cannot enforce
// (Status.AllowlistScopedSkipped).
func (m *Manager) SetAllowlistScopedSkipped(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowlistScopedSkipped = n
}

// GeoAllowSupported reports whether the loaded XDP object can enforce geo
// allow mode (it has wafio_geo_config and both geo LPM tries).
func (m *Manager) GeoAllowSupported() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.geoConfigMap != nil && m.geoCIDR4Map != nil && m.geoCIDR6Map != nil
}

// GeoState returns the geo mode, countries and range counts the last
// ApplyGeoRanges left in the dataplane (block with no ranges after a load).
func (m *Manager) GeoState() GeoRangeState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := m.geoState
	st.Countries = slices.Clone(st.Countries)
	return st
}

// ApplyGeoRanges makes the geo LPM tries hold exactly the given ranges for
// mode (block or allow) and switches the XDP geo mode, in the order
// syncGeo documents. countries is recorded for GeoState only.
func (m *Manager) ApplyGeoRanges(mode string, countries []string, prefixes []netip.Prefix) error {
	mode, ok := NormalizeGeoMode(mode)
	if !ok {
		return fmt.Errorf("invalid geo mode")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.geoCIDR4Map == nil || m.geoCIDR6Map == nil {
		if mode == GeoModeAllow {
			return ErrGeoAllowUnsupported
		}
		return nil // no geo tries (mock environment): nothing to enforce
	}
	v4, v6, err := applyGeoRanges(m.geoStore(), mode, prefixes)
	if err != nil {
		// The maps may hold part of the change; the caller restores its
		// snapshot (CaptureGeo / RestoreGeo), and GeoState keeps the last
		// complete apply.
		return err
	}
	m.geoState = GeoRangeState{Mode: mode, Countries: slices.Clone(countries), RangesV4: v4, RangesV6: v6}
	return nil
}

// CaptureGeo snapshots the geo tries, the mode record and GeoState; nil
// without geo tries.
func (m *Manager) CaptureGeo() (*GeoSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.captureGeoLocked()
}

func (m *Manager) captureGeoLocked() (*GeoSnapshot, error) {
	if m.geoCIDR4Map == nil || m.geoCIDR6Map == nil {
		return nil, nil
	}
	snap, err := captureGeo(m.geoStore())
	if err != nil {
		return nil, fmt.Errorf("snapshot geo: %w", err)
	}
	snap.state = m.geoState
	snap.state.Countries = slices.Clone(m.geoState.Countries)
	return snap, nil
}

// RestoreGeo puts a CaptureGeo snapshot back by diff (syncGeo): the mode
// record exactly as captured (allow_since_ns included), the ranges in an
// order that never unlists an allowed source while allow mode is on, and
// GeoState.
func (m *Manager) RestoreGeo(snap *GeoSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreGeoLocked(snap)
}

func (m *Manager) restoreGeoLocked(snap *GeoSnapshot) error {
	if snap == nil || m.geoCIDR4Map == nil || m.geoCIDR6Map == nil {
		return nil
	}
	if err := syncGeo(m.geoStore(), snap.ranges, snap.cfg, snap.hasMode && m.geoConfigMap != nil); err != nil {
		m.reconcileGeoStateLocked()
		return fmt.Errorf("rollback geo: %w", err)
	}
	m.geoState = snap.state
	return nil
}

// reconcileGeoStateLocked makes GeoState describe what the maps hold after
// a failed restore: the live mode and the ranges counted; the countries are
// unknown. The local API and the lockout guard read the mode from it.
func (m *Manager) reconcileGeoStateLocked() {
	st := GeoRangeState{Mode: m.liveGeoMode()}
	if ranges, err := m.geoStore().listGeoRanges(); err == nil {
		for p := range ranges {
			if p.Addr().Is4() {
				st.RangesV4++
			} else {
				st.RangesV6++
			}
		}
	}
	m.geoState = st
}

// SetGeoLocalSubnets makes wafio_geo_local4/6 hold exactly the host's
// subnets of the interface XDP is attached to (allow mode admits a private
// UDP source only from
// them), adding before removing. Objects without the maps ignore it.
func (m *Manager) SetGeoLocalSubnets(prefixes []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.geoLocal4Map == nil || m.geoLocal6Map == nil {
		return nil
	}
	want := make(map[netip.Prefix]bool, len(prefixes))
	for _, p := range prefixes {
		if p.IsValid() {
			want[p.Masked()] = true
		}
	}
	if len(want) > geoLocalCapacity {
		return fmt.Errorf("%d interface subnets exceed the %d the geo local table holds", len(want), geoLocalCapacity)
	}
	local := geoMapStore{v4: m.geoLocal4Map, v6: m.geoLocal6Map}
	existing, err := local.listGeoRanges()
	if err != nil {
		return err
	}
	for p := range want {
		if _, ok := existing[p]; !ok {
			if err := local.putGeoRange(p, 1); err != nil {
				return err
			}
		}
	}
	for p := range existing {
		if !want[p] {
			if err := local.deleteGeoRange(p); err != nil {
				return err
			}
		}
	}
	return nil
}

// SetGeoDegraded records why the desired geo policy is not enforced (code),
// what the dataplane holds instead (state: kept, ranges_cleared, mixed) and
// the detail; an empty code clears it. Status reports it.
func (m *Manager) SetGeoDegraded(code, state, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.geoDegradedCode, m.geoDegradedState, m.geoDegradedMessage = code, state, message
}

// InterfaceName is the interface the XDP program is attached to ("" when
// not running): allow mode admits private UDP sources from its subnets only.
func (m *Manager) InterfaceName() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ifName
}

// geoStore is geoRangeStore over the geo maps. The caller holds Manager.mu.
func (m *Manager) geoStore() geoMapStore {
	return geoMapStore{v4: m.geoCIDR4Map, v6: m.geoCIDR6Map, mode: m.geoConfigMap}
}

// geoMapStore is geoRangeStore over two LPM tries (and the mode record).
// The caller holds Manager.mu.
type geoMapStore struct{ v4, v6, mode *ebpf.Map }

func (s geoMapStore) listGeoRanges() (map[netip.Prefix]uint8, error) {
	out := make(map[netip.Prefix]uint8)
	var k4 geoCIDRv4Key
	var v uint8
	it := s.v4.Iterate()
	for it.Next(&k4, &v) {
		if k4.Prefixlen > 32 {
			continue
		}
		out[netip.PrefixFrom(netip.AddrFrom4(k4.Addr), int(k4.Prefixlen))] = v
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	var k6 geoCIDRv6Key
	it = s.v6.Iterate()
	for it.Next(&k6, &v) {
		if k6.Prefixlen > 128 {
			continue
		}
		out[netip.PrefixFrom(netip.AddrFrom16(k6.Addr), int(k6.Prefixlen))] = v
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s geoMapStore) putGeoRange(p netip.Prefix, value uint8) error {
	if p.Addr().Is4() {
		return s.v4.Update(geoCIDRv4Key{Prefixlen: u32FromInt(p.Bits()), Addr: p.Addr().As4()}, &value, ebpf.UpdateAny)
	}
	return s.v6.Update(geoCIDRv6Key{Prefixlen: u32FromInt(p.Bits()), Addr: p.Addr().As16()}, &value, ebpf.UpdateAny)
}

func (s geoMapStore) deleteGeoRange(p netip.Prefix) error {
	var err error
	if p.Addr().Is4() {
		err = s.v4.Delete(geoCIDRv4Key{Prefixlen: u32FromInt(p.Bits()), Addr: p.Addr().As4()})
	} else {
		err = s.v6.Delete(geoCIDRv6Key{Prefixlen: u32FromInt(p.Bits()), Addr: p.Addr().As16()})
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (s geoMapStore) geoConfig() (GeoConfig, bool, error) {
	if s.mode == nil {
		return GeoConfig{}, false, nil
	}
	var cfg GeoConfig
	if err := s.mode.Lookup(uint32(0), &cfg); err != nil {
		return GeoConfig{}, true, err
	}
	return cfg, true, nil
}

func (s geoMapStore) setGeoConfig(cfg GeoConfig) error {
	if s.mode == nil {
		return nil
	}
	return s.mode.Update(uint32(0), &cfg, ebpf.UpdateAny)
}

// ktimeNow reads CLOCK_MONOTONIC, the clock bpf_ktime_get_ns() reads.
func (s geoMapStore) ktimeNow() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return u64FromInt64(ts.Nano())
}

// liveGeoMode reads wafio_geo_config (block when the object has none).
// The caller holds Manager.mu.
func (m *Manager) liveGeoMode() string {
	cfg, _, err := m.geoStore().geoConfig()
	if err != nil {
		return GeoModeBlock
	}
	return geoModeName(cfg.Mode)
}

// Reclaim a bounded batch of idle entries. A deletion can race a first packet
// after idle and reset its count; table-full telemetry reports lost coverage.
func (m *Manager) pruneDetectionState() {
	now := m.ktimeNow()
	var rate RateConfig
	var scan PortScanConfig
	if m.rateConfigMap == nil || m.portscanCfgMap == nil {
		return
	}
	if err := m.rateConfigMap.Lookup(uint32(0), &rate); err != nil {
		return
	}
	if err := m.portscanCfgMap.Lookup(uint32(0), &scan); err != nil {
		return
	}
	if rate.WindowNs == 0 {
		rate.WindowNs = 1_000_000_000
	}
	if scan.WindowNs == 0 {
		scan.WindowNs = 10_000_000_000
	}
	for _, table := range []struct {
		m      *ebpf.Map
		window uint64
	}{{m.rateStateMap, rate.WindowNs}, {m.synStateMap, rate.WindowNs}, {m.portscanMap, scan.WindowNs}} {
		if table.m == nil {
			continue
		}
		value := make([]byte, table.m.ValueSize())
		var key IPKey
		keys := make([]IPKey, 0, 256)
		iter := table.m.Iterate()
		for iter.Next(&key, &value) {
			start := binary.LittleEndian.Uint64(value[:8])
			if now >= start && now-start > 2*table.window {
				keys = append(keys, key)
				if len(keys) >= 4096 {
					break
				}
			}
		}
		for _, key := range keys {
			if err := table.m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				m.log.Printf("detection state cleanup: %v", err)
				break
			}
		}
	}
}

// HostFirewallEnv reports what the lockout guard needs from this host: the
// SSH listeners, the control-plane port and whether the attached objects
// carry the reply and control-plane exemptions.
func (m *Manager) HostFirewallEnv() HostFirewallEnv {
	exemptions := m.Status().LockoutExemptions
	m.mu.RLock()
	port, expected := m.cpPort, m.cpExpected
	m.mu.RUnlock()
	return HostFirewallEnv{
		SSHPorts:             DetectSSHDPorts(),
		ControlPlanePort:     port,
		Exemptions:           exemptions,
		ControlPlaneUnpinned: expected && port == 0,
	}
}

// ExpectControlPlane records that this agent has a control plane, so the
// lockout guard knows an unpinned control-plane path may depend on DNS.
func (m *Manager) ExpectControlPlane() {
	m.mu.Lock()
	m.cpExpected = true
	m.mu.Unlock()
}

// SetControlPlaneEndpoints replaces the control-plane endpoints the dataplane
// never cuts. An empty list is refused: keeping the previous
// endpoints is safer than none when resolution fails.
func (m *Manager) SetControlPlaneEndpoints(endpoints []netip.AddrPort) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cpEndpointsMap == nil {
		return ErrNoControlPlaneMap
	}
	if len(endpoints) == 0 || len(endpoints) > maxCPEndpoints {
		return fmt.Errorf("control-plane endpoints: need 1..%d, got %d", maxCPEndpoints, len(endpoints))
	}
	want := make(map[CPEndpointKey]struct{}, len(endpoints))
	for _, ep := range endpoints {
		if !ep.IsValid() || ep.Port() == 0 || ep.Addr().Zone() != "" {
			return fmt.Errorf("control-plane endpoint %q invalid", ep.String())
		}
		want[CPEndpointKeyFrom(ep)] = struct{}{}
	}
	m.cpPort = endpoints[0].Port()
	// Add first, then remove stale keys: the live control-plane endpoint is
	// never absent from the map during the swap.
	one := uint32(1)
	for key := range want {
		if err := m.cpEndpointsMap.Update(key, &one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("control-plane endpoints: %w", err)
		}
	}
	var stale []CPEndpointKey
	var key CPEndpointKey
	var val uint32
	iter := m.cpEndpointsMap.Iterate()
	for iter.Next(&key, &val) {
		if _, ok := want[key]; !ok {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("control-plane endpoints: %w", err)
	}
	for _, k := range stale {
		if err := m.cpEndpointsMap.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("control-plane endpoints: %w", err)
		}
	}
	return nil
}
