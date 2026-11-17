package agent

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/agentcore"
	"github.com/wafio/wafio-cp-backend/shared/tracefilter"
)

// ──────────────────────────────────────────────────────────────────────────────
// PushClient — sends eBPF telemetry from agent → wafio server (authenticated)
// ──────────────────────────────────────────────────────────────────────────────
//
// Architecture:
//   Agent (eBPF) → PushClient → HTTP POST /api/internal/ebpf/ingest → Server → PostgreSQL
//
// The agent periodically collects metrics, events, connections, bandwidth, trace
// events, stats, and enforcement log entries — then POSTs them as a single batch
// to the server's ingestion endpoint. The server validates the agent API key
// and stores data in PostgreSQL.
//
// Push intervals:
//   • metrics + events + trace + enforcement  → every 1s
//   • connections + bandwidth + stats/status   → every 3s

type PushClient struct {
	httpSendFailures  atomic.Uint64
	httpDroppedEvents atomic.Uint64
	httpAccepted      atomic.Uint64
	serverURL         string // e.g. "http://localhost:9087"
	apiKey            string // LEGACY raw agent API key (X-Agent-Key path)
	listenAddr        string // agent's own listen address (e.g. "0.0.0.0:9999")
	// HostKey is the new bearer credential (wafh_*) issued by the UI per
	// registered host; when set it is sent as `X-Wafio-Host-Key` and
	// takes precedence over `apiKey`. Plumbed from Config.HostKey.
	HostKey string
	// AgentName labels this process on the server side when multiple
	// agents of the same kind share a host (e.g. two WAF processes).
	AgentName         string
	containerEnricher *ContainerEnricher
	k8sWatcher        *K8sWatcher
	ebpfMgr           *wafebpf.Manager
	traceMgr          *wafebpf.TraceManager
	httpClient        *http.Client
	lastEventPush     time.Time
	lastTracePush     time.Time
	lastEnforcePush   time.Time
}

// RuleStatsSnapshot contains current hit counts read directly from BPF maps.
// Sent every medium push (3s) so the control plane can show live hit counts.
type RuleStatsSnapshot struct {
	Blocklist       []wafebpf.BlocklistEntry       `json:"blocklist,omitempty"`
	Allowlist       []wafebpf.AllowlistEntry       `json:"allowlist,omitempty"`
	PortPolicies    []wafebpf.PortPolicyAPI        `json:"port_policies,omitempty"`
	EgressBlocklist []wafebpf.EgressBlocklistEntry `json:"egress_blocklist,omitempty"`
	TracePolicies   []tracePolicyHitEntry          `json:"trace_policies,omitempty"`
}

// sort orders every list by its key. BPF hash maps and the policy engine's
// map iterate in no fixed order; ruleStatsDelta compares lists by content.
func (s *RuleStatsSnapshot) sort() {
	slices.SortFunc(s.Blocklist, func(a, b wafebpf.BlocklistEntry) int { return strings.Compare(a.IP, b.IP) })
	slices.SortFunc(s.Allowlist, func(a, b wafebpf.AllowlistEntry) int { return strings.Compare(a.IP, b.IP) })
	slices.SortFunc(s.PortPolicies, func(a, b wafebpf.PortPolicyAPI) int {
		return cmp.Or(cmp.Compare(a.Port, b.Port), strings.Compare(a.Proto, b.Proto), strings.Compare(a.Direction, b.Direction))
	})
	slices.SortFunc(s.EgressBlocklist, func(a, b wafebpf.EgressBlocklistEntry) int { return strings.Compare(a.IP, b.IP) })
	slices.SortFunc(s.TracePolicies, func(a, b tracePolicyHitEntry) int { return cmp.Compare(a.PolicyID, b.PolicyID) })
}

// tracePolicyHitEntry carries only the fields needed to update hit counts on
// the control plane (policy ID + live counter). The full policy state is
// managed via the bundle/gRPC sync; hit counts need a lightweight side-channel.
type tracePolicyHitEntry struct {
	PolicyID uint32 `json:"policy_id"`
	HitCount uint64 `json:"hit_count"`
}

// PushPayload is the combined telemetry batch sent to the server.
type PushPayload struct {
	// traceByClass counts TraceEvents by push-queue class
	// (wafebpf.QueuedTraceClass), so a batch lost in transport is reported
	// to the trace manager's loss accounting. Not sent.
	traceByClass [3]int
	// traceUnencoded: drained trace events that failed to encode (already
	// counted as delivery loss), so fullBatch still sees a full drain.
	traceUnencoded int
	// traceFiltered: drained trace events the forwarding filter kept back
	// because ingest would discard them (not loss), so
	// fullBatch still sees a full drain.
	traceFiltered int

	BatchID               string            `json:"batch_id,omitempty"`
	TelemetryDelivery     telemetryDelivery `json:"telemetry_delivery"`
	TelemetrySendFailures uint64            `json:"telemetry_send_failures"`
	// Host info snapshot (hostname, OS, kernel, CPU, memory, uptime, version).
	// Sent on every medium push so the control plane always knows the host.
	HostInfo *agentcore.HostInfo `json:"host_info,omitempty"`

	// Status (both eBPF and trace)
	EBPFStatus  json.RawMessage `json:"ebpf_status,omitempty"`
	TraceStatus json.RawMessage `json:"trace_status,omitempty"`

	// Metrics
	Metrics json.RawMessage `json:"metrics,omitempty"`

	// Events (firewall)
	Events []json.RawMessage `json:"events,omitempty"`

	// Connections snapshot
	Connections []json.RawMessage `json:"connections,omitempty"`

	// Bandwidth snapshot
	Bandwidth []json.RawMessage `json:"bandwidth,omitempty"`

	// Trace events
	TraceEvents []json.RawMessage `json:"trace_events,omitempty"`

	// Trace stats
	TraceStats json.RawMessage `json:"trace_stats,omitempty"`

	// Enforcement log
	Enforcement []json.RawMessage `json:"enforcement,omitempty"`

	// RuleStats reports current hit counts from BPF maps so the UI can
	// display live counters without querying the agent directly.
	RuleStats *RuleStatsSnapshot `json:"rule_stats,omitempty"`

	// TraceForward reports the stream's trace forwarding filter and the rule
	// hits of the events it kept back; only in the fast
	// batches of the gRPC stream.
	TraceForward *tracefilter.TraceForwardReport `json:"trace_forward,omitempty"`
}

// hasTraceForwardHits reports whether the batch carries rule hits of
// events the forwarding filter kept back: such a batch is sent even when it
// holds nothing else.
func (p *PushPayload) hasTraceForwardHits() bool {
	return p.TraceForward != nil && len(p.TraceForward.RuleHits) > 0
}

func NewPushClient(serverURL, apiKey, listenAddr string, ebpfMgr *wafebpf.Manager, traceMgr *wafebpf.TraceManager) *PushClient {
	pc := &PushClient{
		serverURL:  serverURL,
		apiKey:     apiKey,
		listenAddr: listenAddr,
		ebpfMgr:    ebpfMgr,
		traceMgr:   traceMgr,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        5,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     60 * time.Second,
			},
		},
		lastEventPush:   time.Now(),
		lastTracePush:   time.Now(),
		lastEnforcePush: time.Now(),
	}
	// Start container enricher (no-op if Docker is not available on this host)
	pc.containerEnricher = NewContainerEnricher()
	// K8s pod context watcher (no-op outside a Kubernetes cluster): pod name,
	// namespace and service account resolved live from the API watch.
	pc.k8sWatcher = NewK8sWatcher()
	return pc
}

// startEnrichment starts the container enricher (probes the Docker socket;
// no-op if unavailable) and, inside a Kubernetes cluster, the pod context
// watcher. Both transports call it: HTTP push once per Run, the gRPC stream
// once per connection (the gRPC path used to start only the container
// enricher, so pod name/namespace never reached trace events).
func (pc *PushClient) startEnrichment(ctx context.Context) {
	if pc.containerEnricher != nil {
		pc.containerEnricher.Start(ctx)
	}
	if pc.k8sWatcher.Available() {
		pc.k8sWatcher.Start(ctx)
		log.Printf("[push] k8s pod context watcher active")
	}
}

// Run starts the push loop. Blocks until ctx is cancelled.
func (pc *PushClient) Run(ctx context.Context) {
	pc.startEnrichment(ctx)

	// Fast tick: metrics + events + trace + enforcement (1s)
	fastTick := time.NewTicker(1 * time.Second)
	defer fastTick.Stop()

	// Medium tick: connections + bandwidth + stats + status (3s)
	mediumTick := time.NewTicker(3 * time.Second)
	defer mediumTick.Stop()

	// Send initial burst
	pc.pushAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-fastTick.C:
			pc.pushFast(ctx)
		case <-mediumTick.C:
			pc.pushMedium(ctx)
		}
	}
}

func (pc *PushClient) pushAll(ctx context.Context) {
	payload := &PushPayload{}
	pc.collectFast(payload)
	pc.collectMedium(payload)
	pc.send(ctx, payload)
}

func (pc *PushClient) pushFast(ctx context.Context) {
	payload := &PushPayload{}
	pc.collectFast(payload)
	if payload.Metrics == nil && len(payload.Events) == 0 &&
		len(payload.TraceEvents) == 0 && len(payload.Enforcement) == 0 {
		return // nothing to send
	}
	pc.send(ctx, payload)
}

func (pc *PushClient) pushMedium(ctx context.Context) {
	payload := &PushPayload{}
	pc.collectMedium(payload)
	pc.send(ctx, payload)
}

func (pc *PushClient) collectFast(payload *PushPayload) { pc.collectFastBatch(payload, true, nil) }

// fastBatchLimit is how many firewall events, trace events and enforcement
// entries one collectFastBatch drains of each.
const fastBatchLimit = 500

// fullBatch reports whether any drained kind hit fastBatchLimit, i.e. more
// may be waiting.
func (p *PushPayload) fullBatch() bool {
	return len(p.Events) >= fastBatchLimit || p.traceByClass[0]+p.traceByClass[1]+p.traceByClass[2]+p.traceUnencoded+p.traceFiltered >= fastBatchLimit || len(p.Enforcement) >= fastBatchLimit
}

// addTraceEvent encodes one drained trace event into the batch unless the
// forwarding filter fwd keeps it back (counted in traceFiltered, not loss).
// The filter decides on the bytes ingest would decode, so after the
// container enrichment detection rules may read. false: the event could
// not be encoded (counted in traceUnencoded; the caller notes the loss).
func (p *PushPayload) addTraceEvent(e *wafebpf.TraceEvent, fwd *traceForwardFilter) bool {
	b, err := json.Marshal(e)
	if err != nil {
		p.traceUnencoded++
		return false
	}
	if fwd.drop(b) {
		p.traceFiltered++
		return true
	}
	p.TraceEvents = append(p.TraceEvents, b)
	p.traceByClass[wafebpf.QueuedTraceClass(e)]++
	return true
}

// collectFastBatch fills a fast batch. fwd is the gRPC stream's trace
// forwarding filter; nil (HTTP push) sends every event and
// no report.
func (pc *PushClient) collectFastBatch(payload *PushPayload, metrics bool, fwd *traceForwardFilter) {
	// Metrics
	if metrics && pc.ebpfMgr != nil {
		if m, err := pc.ebpfMgr.ReadMetrics(); err == nil {
			if b, err := json.Marshal(m); err == nil {
				payload.Metrics = b
			}
		}
	}

	// Events (firewall perf events — drain since last push)
	if pc.ebpfMgr != nil {
		evts := pc.ebpfMgr.DrainRecentEvents(fastBatchLimit)
		if len(evts) > 0 {
			for _, e := range evts {
				if b, err := json.Marshal(e); err == nil {
					payload.Events = append(payload.Events, b)
				}
			}
		}
	}

	// Trace events
	if pc.traceMgr != nil {
		tevts := pc.traceMgr.DrainRecentTraceEvents(fastBatchLimit)
		if len(tevts) > 0 {
			for i := range tevts {
				// Enrich with container metadata from Docker socket
				if pc.containerEnricher != nil {
					pc.enrichTraceEvent(&tevts[i])
				}
				if !payload.addTraceEvent(&tevts[i], fwd) {
					// Drained but never sent: count it as delivery loss.
					var lost [3]int
					lost[wafebpf.QueuedTraceClass(&tevts[i])]++
					pc.traceMgr.NoteDeliveryLoss(lost)
				}
			}
		}
		payload.TraceForward = fwd.report()
	}

	// Enforcement log — Drain (not Get) so the same entries are not
	// re-pushed every tick. Server has ON CONFLICT DO NOTHING as a
	// safety-net (migration 000026) for any retry path that may be
	// added later.
	if pc.traceMgr != nil {
		elog := pc.traceMgr.DrainEnforcementLog(fastBatchLimit)
		if len(elog) > 0 {
			for _, e := range elog {
				if b, err := json.Marshal(e); err == nil {
					payload.Enforcement = append(payload.Enforcement, b)
				}
			}
		}
	}
}

func (pc *PushClient) collectMedium(payload *PushPayload) { pc.collectMediumWith(payload, true, nil) }

// collectMediumWith fills the medium payload. snapshots: include the
// connections and bandwidth snapshots (the gRPC stream sends
// them on demand); rules, when set, keeps the rule hit counts to the lists
// that changed.
func (pc *PushClient) collectMediumWith(payload *PushPayload, snapshots bool, rules *ruleStatsDelta) {
	// Host info — attached on every medium push so the server can keep the
	// agents table in sync with what the host currently looks like.
	info := collectHostInfo("ebpf")
	payload.HostInfo = &info

	// Status
	if pc.ebpfMgr != nil {
		st := pc.ebpfMgr.Status()
		if b, err := json.Marshal(st); err == nil {
			payload.EBPFStatus = b
		}
	}
	if pc.traceMgr != nil {
		st := pc.traceMgr.Status()
		fillTraceForwardStatus(&st)
		if b, err := json.Marshal(st); err == nil {
			payload.TraceStatus = b
		}
	}

	// Trace stats
	if pc.traceMgr != nil {
		if s, err := pc.traceMgr.GetStats(); err == nil {
			if b, err := json.Marshal(s); err == nil {
				payload.TraceStats = b
			}
		}
	}

	// Connections
	if snapshots && pc.ebpfMgr != nil {
		conns, err := pc.ebpfMgr.ListConnections(500)
		if err == nil && len(conns) > 0 {
			for _, c := range conns {
				if b, err := json.Marshal(c); err == nil {
					payload.Connections = append(payload.Connections, b)
				}
			}
		}
	}

	// Bandwidth
	if snapshots && pc.ebpfMgr != nil {
		bw, err := pc.ebpfMgr.ListBandwidth(500)
		if err == nil && len(bw) > 0 {
			for _, e := range bw {
				if b, err := json.Marshal(e); err == nil {
					payload.Bandwidth = append(payload.Bandwidth, b)
				}
			}
		}
	}

	// Rule stats — BPF map hit counts for display in the UI
	if pc.ebpfMgr != nil || pc.traceMgr != nil {
		snap := &RuleStatsSnapshot{}
		if pc.ebpfMgr != nil {
			if bl, err := pc.ebpfMgr.ListBlocklist(0); err == nil {
				snap.Blocklist = bl
			}
			if al, err := pc.ebpfMgr.ListAllowlist(0); err == nil {
				snap.Allowlist = al
			}
			if pp, err := pc.ebpfMgr.ListPortPolicies(0); err == nil {
				snap.PortPolicies = pp
			}
			if eg, err := pc.ebpfMgr.ListEgressBlocklist(0); err == nil {
				snap.EgressBlocklist = eg
			}
		}
		if pc.traceMgr != nil {
			for _, p := range pc.traceMgr.ListPolicies() {
				snap.TracePolicies = append(snap.TracePolicies, tracePolicyHitEntry{
					PolicyID: p.ID,
					HitCount: p.HitCount,
				})
			}
		}
		snap.sort()
		payload.RuleStats = snap
		if rules != nil {
			payload.RuleStats = rules.filter(snap, time.Now())
		}
	}
}

func (pc *PushClient) send(ctx context.Context, payload *PushPayload) {
	payload.TelemetrySendFailures = pc.httpSendFailures.Load()
	payload.TelemetryDelivery = telemetryDelivery{ProcessAccepted: pc.httpAccepted.Load(), DroppedBatches: pc.httpSendFailures.Load(), DroppedEvents: pc.httpDroppedEvents.Load()}
	recordFailure := func() {
		pc.httpSendFailures.Add(1)
		pc.httpDroppedEvents.Add(uint64(len(payload.Events) + len(payload.TraceEvents) + len(payload.Enforcement)))
		if pc.traceMgr != nil {
			pc.traceMgr.NoteDeliveryLoss(payload.traceByClass)
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		recordFailure()
		return
	}

	url := fmt.Sprintf("%s/api/internal/host/ingest", pc.serverURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		recordFailure()
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if pc.HostKey != "" {
		req.Header.Set("X-Wafio-Host-Key", pc.HostKey)
	}
	if pc.apiKey != "" {
		// Still emit the legacy header when configured so control planes
		// that have not yet been upgraded to host-key auth keep working.
		req.Header.Set("X-Agent-Key", pc.apiKey)
	}
	if pc.AgentName != "" {
		req.Header.Set("X-Wafio-Agent-Name", pc.AgentName)
	}
	if pc.listenAddr != "" {
		req.Header.Set("X-Agent-Listen", pc.listenAddr)
	}

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		recordFailure()
		// Log periodically, not every second
		log.Printf("[push] server unreachable: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing
	_, _ = io.Copy(io.Discard, resp.Body)    // best-effort drain for connection reuse

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		recordFailure()
		log.Printf("[push] server returned %d", resp.StatusCode)
		return
	}
	pc.httpAccepted.Add(1)
}

// enrichTraceEvent adds container metadata to a trace event using the
// ContainerEnricher's cgroup_id → container lookup. If the event doesn't
// match a running container, the event is left unchanged.
func (pc *PushClient) enrichTraceEvent(e *wafebpf.TraceEvent) {
	if pc.containerEnricher == nil || e.CgroupID == 0 {
		return
	}
	info := pc.containerEnricher.Enrich(e.CgroupID)
	if info == nil {
		return
	}
	e.ContainerID = info.ContainerID
	if len(e.ContainerID) > 12 {
		e.ContainerID = e.ContainerID[:12]
	}
	e.ContainerImage = info.ContainerImage
	e.ContainerName = info.ContainerName
	e.IsContainer = true
	e.IsPrivileged = info.IsPrivileged
	e.K8sPod = info.K8sPod
	e.K8sNamespace = info.K8sNamespace
	// K8s watcher supersedes docker-label-derived pod context with live
	// API data and adds the service account.
	if pctx, ok := pc.k8sWatcher.Lookup(info.ContainerID); ok {
		e.K8sPod = pctx.PodName
		e.K8sNamespace = pctx.Namespace
		if e.K8sServiceAccount == "" {
			e.K8sServiceAccount = pctx.ServiceAccount
		}
	}
}
