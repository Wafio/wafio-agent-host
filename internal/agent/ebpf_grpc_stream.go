package agent

// ebpf_grpc_stream.go — eBPF agent gRPC stream client.
//
// Mirrors grpc_stream.go but for the eBPF/runtime-security agent rather than
// the WAF agent. Key differences:
//
//   • BundleUpdate applies host firewall and runtime security snapshots.
//   • Telemetry (metrics, events, trace, connections, …) is sent every 1 s
//     (fast path) and 3 s (slow path) as CommandAck messages with
//     command_id = "ebpf:telemetry". The server-side Stream() handler routes
//     these to application.HostTelemetryIngest for storage.
//
// This approach reuses the existing proto without schema changes:
//   CommandAck.command_id = "ebpf:telemetry"
//   CommandAck.ok        = true
//   CommandAck.error     = <JSON-encoded PushPayload>   ← data, not an error

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/agentcore"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"github.com/wafio/wafio-cp-backend/shared/tracefilter"
	"google.golang.org/grpc"
	grpccreds "google.golang.org/grpc/credentials"
)

// ──────────────────────────────────────────────────────────────────────────────
// Global state
// ──────────────────────────────────────────────────────────────────────────────

type ebpfGRPCStreamConfig struct {
	serverAddr string
	serverName string
	certPEM    []byte
	keyPEM     []byte
	caPEM      []byte
	agentName  string
	hostname   string
	hostKey    string
}

var (
	ebpfGRPCMu  sync.Mutex
	ebpfGRPCCfg *ebpfGRPCStreamConfig

	// eBPF managers set by SetEBPFManagers; used to collect telemetry.
	ebpfGRPCEBPFMgr  *wafebpf.Manager
	ebpfGRPCTraceMgr *wafebpf.TraceManager

	// ebpfGRPCEnricher is the GeoIPEnricher used for CIDR bulk-loading when
	// geo-blocked countries change. Set via SetEBPFGeoEnricher.
	ebpfGRPCEnricher *GeoIPEnricher

	// ebpfGRPCSecDataDir is the base security-data directory for the host agent.
	// Set by SetEBPFSecurityDataDir; defaults to /etc/wafio/security-data.
	ebpfGRPCSecDataDir string

	// pushClientRef holds a reference to the PushClient (if HTTP push is also
	// active) so we can share the collectFast/collectMedium methods rather
	// than duplicating the collection logic.
	ebpfGRPCPushRef *PushClient
)

// SetEBPFManagers registers the eBPF and trace managers so the gRPC stream
// goroutine can collect telemetry. Must be called before
// StartEBPFGRPCStreamIfConfigured. Both args may be nil if only one subsystem
// is active.
func SetEBPFManagers(ebpfMgr *wafebpf.Manager, traceMgr *wafebpf.TraceManager) {
	ebpfGRPCMu.Lock()
	defer ebpfGRPCMu.Unlock()
	ebpfGRPCEBPFMgr = ebpfMgr
	ebpfGRPCTraceMgr = traceMgr
	if traceMgr != nil {
		ebpfTelemetryRetention.setTraceLoss(traceMgr.NoteDeliveryLoss)
	} else {
		ebpfTelemetryRetention.setTraceLoss(nil)
	}
}

// SetEBPFGeoEnricher registers the GeoIPEnricher so applyEBPFState can
// trigger CIDR bulk-loading when blocked countries change.
func SetEBPFGeoEnricher(e *GeoIPEnricher) {
	ebpfGRPCMu.Lock()
	defer ebpfGRPCMu.Unlock()
	ebpfGRPCEnricher = e
}

// SetEBPFSecurityDataDir configures the base security-data directory for the
// host agent. Used by reportHostSecurityDataStatus to find geoip-country.
func SetEBPFSecurityDataDir(dir string) {
	ebpfGRPCMu.Lock()
	defer ebpfGRPCMu.Unlock()
	ebpfGRPCSecDataDir = dir
}

// ebpfComponentPaths holds explicit configured paths for host-agent components.
// Same pattern as WAF agent: explicit path wins over secDataDir derivation.
var ebpfComponentPaths map[string]string

// SetEBPFComponentPaths registers the host agent's own configured file paths.
// The host agent only reports geoip-country; other components are WAF-only.
func SetEBPFComponentPaths(paths map[string]string) {
	ebpfGRPCMu.Lock()
	defer ebpfGRPCMu.Unlock()
	ebpfComponentPaths = paths
}

// SetEBPFPushClientRef optionally shares the PushClient created for HTTP push
// so gRPC can reuse its collection methods. The startup path runs only one
// transport; HTTP must not bypass retained gRPC delivery by draining first.
func SetEBPFPushClientRef(pc *PushClient) {
	ebpfGRPCMu.Lock()
	defer ebpfGRPCMu.Unlock()
	ebpfGRPCPushRef = pc
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

// EnableEBPFGRPCStream arms the eBPF agent to maintain a persistent mTLS gRPC
// connection to the control plane for streaming telemetry. Must be called
// before StartEBPFGRPCStreamIfConfigured.
func EnableEBPFGRPCStream(serverAddr, serverName, certPath, keyPath, caPath, agentName, hostKey string) error {
	if serverAddr == "" {
		return fmt.Errorf("ebpf grpc: serverAddr required")
	}
	certPEM, err := os.ReadFile(certPath) //nolint:gosec // G304: certPath is the operator-configured mTLS client certificate path
	if err != nil {
		return fmt.Errorf("read client cert %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // G304: operator-configured mTLS key path
	if err != nil {
		return fmt.Errorf("read client key %s: %w", keyPath, err)
	}
	caPEM, err := os.ReadFile(caPath) //nolint:gosec // G304: operator-configured CA path
	if err != nil {
		return fmt.Errorf("read CA %s: %w", caPath, err)
	}
	host, _ := os.Hostname()
	if agentName == "" {
		agentName = host + "@ebpf"
	}
	cfg := &ebpfGRPCStreamConfig{
		serverAddr: serverAddr,
		serverName: serverName,
		certPEM:    certPEM,
		keyPEM:     keyPEM,
		caPEM:      caPEM,
		agentName:  agentName,
		hostname:   host,
		hostKey:    hostKey,
	}
	ebpfGRPCMu.Lock()
	ebpfGRPCCfg = cfg
	ebpfGRPCMu.Unlock()
	return nil
}

// StartEBPFGRPCStreamIfConfigured launches the reconnect loop if
// EnableEBPFGRPCStream was called. Returns immediately; the stream lives in
// a background goroutine that reconnects with exponential backoff on
// disconnect.
func StartEBPFGRPCStreamIfConfigured(ctx context.Context) {
	ebpfGRPCMu.Lock()
	cfg := ebpfGRPCCfg
	ebpfGRPCMu.Unlock()
	if cfg == nil {
		return
	}
	ebpfGRPCMu.Lock()
	mgr := ebpfGRPCEBPFMgr
	ebpfGRPCMu.Unlock()
	if mgr != nil {
		mgr.ExpectControlPlane()
	}
	// The host keeps its last good firewall policy across restarts: re-apply
	// it before the stream exists, control plane pinned first.
	restoreLastGoodFirewall(ctx, cfg.serverAddr)
	go runEBPFGRPCStream(ctx, cfg)
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal reconnect loop
// ──────────────────────────────────────────────────────────────────────────────

func runEBPFGRPCStream(ctx context.Context, cfg *ebpfGRPCStreamConfig) {
	var backoff agentcore.ReconnectBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		started := time.Now()
		err := dialAndServeEBPFStream(ctx, cfg)
		if ctx.Err() != nil {
			return
		}
		wait := backoff.Delay(time.Since(started))
		if err != nil {
			log.Printf("[ebpf-grpc] stream ended: %v (reconnect in ~%s)", err, wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(agentcore.Jitter(wait)):
		}
	}
}

func dialAndServeEBPFStream(ctx context.Context, cfg *ebpfGRPCStreamConfig) error {
	cert, err := tls.X509KeyPair(cfg.certPEM, cfg.keyPEM)
	if err != nil {
		return fmt.Errorf("load client keypair: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(cfg.caPEM) {
		return errors.New("append CA: invalid PEM")
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   cfg.serverName,
	}
	creds := grpccreds.NewTLS(tlsCfg)

	// The dataplane must know the control plane before the stream
	// exists, so egress Deny All or a blocklist can never cut it — and the
	// stream dials exactly the endpoints the dataplane passes.
	pinned := refreshControlPlaneEndpoints(ctx, cfg.serverAddr)
	if len(pinned) > 0 {
		reapplyUnrelaxed()
	}
	target, dialOpts := controlPlaneDialTarget(cfg.serverAddr, pinned)

	conn, err := grpc.NewClient(target,
		append(dialOpts, grpc.WithTransportCredentials(creds), agentcore.GRPCKeepaliveOption())...,
	)
	if err != nil {
		return fmt.Errorf("dial %s: %w", cfg.serverAddr, err)
	}
	defer func() { _ = conn.Close() }() // shutdown path; nothing left to report

	client := agentv1.NewAgentControlClient(conn)
	stream, err := client.Stream(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	sendMu := &sync.Mutex{}
	send := func(m *agentv1.AgentMessage) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(m)
	}

	// Send Hello — auth is host_key + mTLS cert.
	if err := send(&agentv1.AgentMessage{
		Kind: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
			AgentName:    cfg.agentName,
			AgentVersion: "wafio-host-agent/" + AgentVersion,
			Hostname:     cfg.hostname,
			HostKey:      cfg.hostKey,
			Features:     hostAgentFeatures(),
		}},
	}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	// Which firewall policy is in force before the first push: saved (last
	// good, restored at start), default, or live. Shown in bundle_status.
	if err := send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{
		CommandId: policySourceCommandID, Ok: true, Error: policySourceJSON(),
	}}}); err != nil {
		return fmt.Errorf("send policy source: %w", err)
	}

	log.Printf("[ebpf-grpc] connected to %s as %q", cfg.serverAddr, cfg.agentName)
	// Snapshot cadence and rule-stats reports of this stream.
	demand := newTelemetryDemand()
	rules := &ruleStatsDelta{}
	// Trace forwarding filter of this stream: none until
	// the control plane sends one.
	forward := newTraceForwardFilter()
	defer forward.close()

	// Grab collector reference (shared or standalone).
	ebpfGRPCMu.Lock()
	pc := ebpfGRPCPushRef
	eMgr := ebpfGRPCEBPFMgr
	tMgr := ebpfGRPCTraceMgr
	ebpfGRPCMu.Unlock()

	// Build a throw-away PushClient for collection if we don't have a shared
	// one. This client is never used for HTTP — it's only used to drive
	// collectFast/collectMedium.
	if pc == nil {
		pc = NewPushClient("", "", eMgr, tMgr)
	}
	enrichmentCtx, enrichmentCancel := context.WithCancel(ctx)
	defer enrichmentCancel()
	pc.startEnrichment(enrichmentCtx)

	// ── Heartbeat goroutine ───────────────────────────────────────────────
	// Sends HostInfo immediately on connect, then every 30 s (includes
	// dynamic fields: uptime, memory, load avg so the dashboard stays live).
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go func() {
		hi := collectHostInfo("ebpf")
		hiJSON, _ := json.Marshal(&hi)
		_ = send(&agentv1.AgentMessage{
			Kind: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
				UnixTime:     time.Now().Unix(),
				HostInfoJson: hiJSON,
			}},
		})

		hbTick := time.NewTicker(30 * time.Second)
		defer hbTick.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-hbTick.C:
				hi := collectHostInfo("ebpf")
				hiJSON, _ := json.Marshal(&hi)
				_ = send(&agentv1.AgentMessage{
					Kind: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
						UnixTime:     time.Now().Unix(),
						HostInfoJson: hiJSON,
					}},
				})
			}
		}
	}()

	// ── Event telemetry (250 ms), metrics (1 s, or 30 s outside a status
	// window when the control plane asks for status on demand) ───────────
	// metrics + firewall events + trace events + enforcement log
	fastCtx, fastCancel := context.WithCancel(ctx)
	defer fastCancel()
	go func() {
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		var lastMetrics, lastBatch time.Time
		backlog := false
		for {
			select {
			case <-fastCtx.Done():
				return
			case <-tick.C:
				flushEBPFTelemetry(send, demand)
				now := time.Now()
				urgent := tMgr != nil && tMgr.TelemetryUrgent()
				full := (eMgr != nil && eMgr.PendingEvents() >= fastBatchLimit) ||
					(tMgr != nil && tMgr.QueuedEvents() >= fastBatchLimit)
				if !ebpfTelemetryBatchDue(now, lastBatch, backlog, urgent, full) {
					continue
				}
				// One batch per interval normally; while a burst keeps
				// batches full, up to ebpfTelemetryBatchesPerTick every tick,
				// as long as the control plane keeps confirming them
				// (retention capacity is the backpressure).
				// A tick that finds the retention full sends nothing and
				// keeps the backlog for the next tick.
				ran := false
				for n := 0; n < ebpfTelemetryBatchesPerTick && ebpfTelemetryRetention.hasCapacity(); n++ {
					ran = true
					payload := &PushPayload{}
					includeMetrics := n == 0 && demand.metricsDue(time.Now(), lastMetrics)
					pc.collectFastBatch(payload, includeMetrics, forward)
					if includeMetrics {
						lastMetrics = time.Now()
					}
					if payload.Metrics == nil && len(payload.Events) == 0 &&
						len(payload.TraceEvents) == 0 && len(payload.Enforcement) == 0 &&
						!payload.hasTraceForwardHits() {
						backlog = false
						break
					}
					sendEBPFTelemetry(send, demand, payload)
					backlog = payload.fullBatch()
					if !backlog {
						break
					}
				}
				if ran {
					lastBatch = now
				}
			}
		}
	}()

	// ── Slow telemetry goroutine ──────────────────────────────────────────
	// connections + bandwidth + status + trace stats + host info: at once on
	// connect, then every 3 s (30 s outside a status window when the control
	// plane asks for status on demand), and at once when a window opens or a
	// configuration bundle was applied.
	slowCtx, slowCancel := context.WithCancel(ctx)
	defer slowCancel()
	go func() {
		tick := time.NewTicker(telemetryLiveInterval)
		defer tick.Stop()
		runSlowTelemetry(slowCtx, demand, tick.C, time.Now, func(now time.Time) {
			snapshots := demand.due(now)
			payload := &PushPayload{}
			pc.collectMediumWith(payload, snapshots, rules)
			if snapshots {
				demand.sent(now)
			}
			sendEBPFTelemetry(send, demand, payload)
		})
	}()

	// ── Receive loop ──────────────────────────────────────────────────────
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if w := msg.GetWelcome(); w != nil {
			log.Printf("[ebpf-grpc] welcome: agent_id=%s heartbeat=%ds",
				w.GetAgentId(), w.GetHeartbeatSeconds())
			// Report installed security-data components so the control plane can
			// display accurate status in the dashboard.
			go reportHostSecurityDataStatus(send)
			continue
		}
		if p := msg.GetPing(); p != nil {
			_ = send(&agentv1.AgentMessage{
				Kind: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
					UnixTime: time.Now().Unix(),
				}},
			})
			continue
		}
		// KeyRotation is ignored for host/eBPF agents.
		if bundle := msg.GetBundle(); bundle != nil {
			if err := dispatchHostBundle(bundle, demand, forward, ebpfBundleApplier.applyBundle, send); err != nil {
				return err
			}
		}
	}
}

// dispatchHostBundle handles one BundleUpdate on the host agent's stream:
// the telemetry demand, the trace forwarding filter and telemetry receipts
// are not acked; anything else is a configuration bundle, applied and acked,
// after which the slow payload goes at once so its result (applied
// generations, bundle status, refusal code) reaches the control plane
// promptly (status on demand). An error ends the stream.
func dispatchHostBundle(bundle *agentv1.BundleUpdate, demand *telemetryDemand, forward *traceForwardFilter,
	apply func(*agentv1.BundleUpdate) error, send func(*agentv1.AgentMessage) error) error {
	switch bundle.GetCommandId() {
	case telemetryDemandCommandID:
		demand.handle(bundle.GetBundleJson(), time.Now())
		return nil
	case tracefilter.TraceForwardFilterCommandID:
		forward.handle(bundle.GetBundleJson()) // not acked: batches report the digest
		return nil
	case "ebpf:telemetry:receipt":
		var receipt struct {
			BatchID         string `json:"batch_id"`
			ProcessAccepted bool   `json:"process_accepted"`
		}
		if json.Unmarshal(bundle.GetBundleJson(), &receipt) == nil {
			ebpfTelemetryRetention.receipt(receipt.BatchID, receipt.ProcessAccepted)
		}
		return nil
	}
	// Host/eBPF agents receive BundleUpdate for two kinds of payloads:
	//   - {"trace_policies": [...]}    — enforcement policy sync
	//   - {"ebpf_state": {...}}         — desired eBPF state push
	err := apply(bundle)
	ack := &agentv1.CommandAck{CommandId: bundle.GetCommandId(), Ok: err == nil}
	if err != nil {
		ack.Error = err.Error()
	}
	if err := send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: ack}}); err != nil {
		return fmt.Errorf("send bundle apply acknowledgement: %w", err)
	}
	demand.configApplied()
	return nil
}

// applyEBPFBundle is the single dispatcher for all BundleUpdate payloads
// received by the eBPF/host agent. It routes to the appropriate handler
// based on which top-level keys are present.
func applyEBPFBundle(bundleJSON []byte, generation int64) error {
	return applyEBPFBundleWith(bundleJSON, generation, true)
}

// applyEBPFBundleWith applies a bundle; save=true records an applied
// ebpf_state as the last good policy (false for the start-up restore).
func applyEBPFBundleWith(bundleJSON []byte, generation int64, save bool) (resultErr error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(bundleJSON, &keys); err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("empty host bundle")
	}
	for kind := range keys {
		if kind != "trace_policies" && kind != "ebpf_state" {
			return fmt.Errorf("unsupported host bundle section %q", kind)
		}
	}
	var policies []wafebpf.EnforcementPolicy
	var state *ebpfDesiredState
	scopedSkipped := 0
	policyRaw, hasPolicies := keys["trace_policies"]
	if hasPolicies {
		if string(policyRaw) == "null" {
			return fmt.Errorf("trace_policies must be an array")
		}
		if err := json.Unmarshal(policyRaw, &policies); err != nil {
			return err
		}
		seen := make(map[uint32]bool)
		for i := range policies {
			// Mixed-version safety: a broad kill without kill_acknowledged is
			// applied as alert instead of failing the whole bundle (see
			// DowngradeUnacknowledgedBroadKill).
			if wafebpf.DowngradeUnacknowledgedBroadKill(&policies[i]) {
				log.Printf("[ebpf-grpc] trace policy id=%d %q: kill without narrowing match (UID 0, \"/\", bare system directories and terms under 3 characters do not narrow) and without kill_acknowledged; applied as alert", policies[i].ID, policies[i].Name)
			}
		}
		for _, p := range policies {
			if err := wafebpf.ValidateEnforcementPolicy(p); err != nil {
				return err
			}
			if p.ID == 0 || seen[p.ID] {
				return fmt.Errorf("invalid or duplicate policy identity")
			}
			seen[p.ID] = true
		}
		if ebpfGRPCTraceMgr == nil {
			return fmt.Errorf("runtime tracing unavailable")
		}
	}
	if raw, ok := keys["ebpf_state"]; ok {
		if string(raw) == "null" {
			return fmt.Errorf("ebpf_state must be an object")
		}
		state = &ebpfDesiredState{}
		if err := json.Unmarshal(raw, state); err != nil {
			return refuseApply(err)
		}
		normalizeEBPFState(state)
		// Port-scoped allowlist entries join the allowlist only when the
		// attached object matches scopes; otherwise they are left out before
		// the lockout check, so an entry this agent never enforces cannot
		// count as an escape hatch.
		scopedSkipped = mergeScopedAllowlist(state, allowlistPortsSupported())
		if err := validateEBPFState(state); err != nil {
			return refuseApply(err)
		}
	}
	var firewall *wafebpf.FirewallSnapshot
	var previousConfig *wafebpf.TraceConfigAPI
	var previousPolicies []wafebpf.EnforcementPolicy
	if state != nil && ebpfGRPCEBPFMgr != nil {
		var err error
		firewall, err = ebpfGRPCEBPFMgr.CaptureFirewallState()
		if err != nil {
			return err
		}
	}
	if state != nil && state.TraceConfig != nil && ebpfGRPCTraceMgr != nil {
		var err error
		previousConfig, err = ebpfGRPCTraceMgr.GetConfig()
		if err != nil {
			return err
		}
	}
	if hasPolicies {
		previousPolicies = ebpfGRPCTraceMgr.ListPolicies()
	}
	defer func() {
		if resultErr == nil {
			return
		}
		var rollbackErrors []error
		if firewall != nil {
			rollbackErrors = append(rollbackErrors, ebpfGRPCEBPFMgr.RestoreFirewallState(firewall))
		}
		if previousConfig != nil {
			rollbackErrors = append(rollbackErrors, ebpfGRPCTraceMgr.UpdateConfig(*previousConfig))
		}
		if hasPolicies {
			rollbackErrors = append(rollbackErrors, ebpfGRPCTraceMgr.ReplacePolicies(previousPolicies))
		}
		if err := errors.Join(rollbackErrors...); err != nil {
			resultErr = fmt.Errorf("apply failed: %w; rollback failed, state degraded: %v", resultErr, err)
		}
	}()
	if hasPolicies {
		if err := applyTracePoliciesFromBundle(policyRaw, policies); err != nil {
			return err
		}
	}
	if state != nil {
		if err := applyEBPFState(state); err != nil {
			return err
		}
		if mgr := ebpfGRPCEBPFMgr; mgr != nil {
			mgr.SetAllowlistScopedSkipped(scopedSkipped)
		}
		if save {
			saveLastGoodFirewall(keys["ebpf_state"], generation)
			restoredRelaxed.Store(false) // a push replaced the relaxed restore
			setPolicySource(policySourceInfo{Source: "live", Generation: generation})
		}
	}
	return nil
}

// ebpfDesiredState mirrors the server-side struct so we can unmarshal
// the desired_state blob pushed via BundleUpdate.
type ebpfDesiredState struct {
	Config    *wafebpf.FullConfigAPI   `json:"config,omitempty"`
	Blocklist []wafebpf.BlocklistEntry `json:"blocklist"`
	Allowlist []wafebpf.AllowlistEntry `json:"allowlist"`
	// AllowlistScoped: the port-scoped allowlist entries, a key of their own
	// so a host agent older than port scopes ignores them instead
	// of reading them as entries that allow every port.
	// mergeScopedAllowlist folds them into Allowlist before validation.
	AllowlistScoped []wafebpf.AllowlistEntry `json:"allowlist_scoped,omitempty"`
	GeoBlocked      []wafebpf.CountryEntry   `json:"geo_blocked"`
	// GeoMode "block" (absent: old control planes) or "allow"; GeoAllowed
	// the allow-mode countries, a key of its own so an agent older than
	// allow mode never reads them as blocked countries.
	GeoMode              string                         `json:"geo_mode,omitempty"`
	GeoAllowed           []string                       `json:"geo_allowed,omitempty"`
	GeoAllowAcknowledged bool                           `json:"geo_allow_acknowledged,omitempty"`
	PortPolicies         []wafebpf.PortPolicyAPI        `json:"port_policies"`
	PortPolicyConfig     *wafebpf.PortPolicyConfigAPI   `json:"port_policy_config,omitempty"`
	EgressBlocklist      []wafebpf.EgressBlocklistEntry `json:"egress_blocklist"`
	TraceConfig          *wafebpf.TraceConfigAPI        `json:"trace_config,omitempty"`
}

// firewallEnv is what the lockout guard needs from the running host.
type firewallEnv struct {
	sshPorts         []uint16 // detected sshd listeners; empty = 22
	controlPlanePort uint16   // port of the configured control plane
	exemptions       bool     // attached objects carry the reply and control-plane exemptions
	// controlPlaneUnpinned: a control plane is configured but no endpoint
	// is pinned in the dataplane yet.
	controlPlaneUnpinned bool
	// geoAllow: the attached XDP object can enforce geo allow mode.
	geoAllow bool
	// allowlistPorts: the attached XDP object matches allowlist port scopes.
	allowlistPorts bool
}

func currentFirewallEnv() firewallEnv {
	ebpfGRPCMu.Lock()
	cfg := ebpfGRPCCfg
	mgr := ebpfGRPCEBPFMgr
	ebpfGRPCMu.Unlock()
	env := firewallEnv{sshPorts: wafebpf.DetectSSHDPorts()}
	if cfg != nil {
		if _, port, err := agentcore.SplitControlPlaneAddr(cfg.serverAddr); err == nil {
			env.controlPlanePort = port
		}
	}
	if mgr != nil {
		env.exemptions = mgr.HostFirewallEnv().Exemptions
		env.geoAllow = mgr.GeoAllowSupported()
		env.allowlistPorts = mgr.AllowlistPortsSupported()
	}
	env.controlPlaneUnpinned = cfg != nil && pinnedCPEndpoints.Load() == nil
	return env
}

// currentGeoEnricher returns the registered GeoIP enricher (nil: none).
func currentGeoEnricher() *GeoIPEnricher {
	ebpfGRPCMu.Lock()
	defer ebpfGRPCMu.Unlock()
	return ebpfGRPCEnricher
}

// collectHostInfo is agentcore.CollectHostInfo plus what only the host agent
// knows: the sshd ports and the optional firewall capabilities.
func collectHostInfo(kind string) agentcore.HostInfo {
	info := agentcore.CollectHostInfo(kind, AgentVersion)
	if kind == "ebpf" {
		info.SSHPorts = wafebpf.DetectSSHDPorts()
		info.FirewallFeatures = firewallFeatures()
	}
	return info
}

// firewallFeatures lists the optional firewall capabilities this host agent
// reports in host_info.firewall_features: "geo_allow" when its XDP object
// and GeoIP dataset can enforce geo allow mode, "allowlist_ports" when its
// XDP object matches allowlist port scopes (the loaded object decides, not
// the agent version).
func firewallFeatures() []string {
	ebpfGRPCMu.Lock()
	mgr := ebpfGRPCEBPFMgr
	enricher := ebpfGRPCEnricher
	ebpfGRPCMu.Unlock()
	if mgr == nil {
		return nil
	}
	var out []string
	if mgr.GeoAllowSupported() && enricher.HasDataset() {
		out = append(out, wafebpf.GeoFeatureAllow)
	}
	if mgr.AllowlistPortsSupported() {
		out = append(out, wafebpf.AllowlistFeaturePorts)
	}
	return out
}

// allowlistPortsSupported: the registered firewall manager's XDP object
// matches allowlist port scopes.
func allowlistPortsSupported() bool {
	ebpfGRPCMu.Lock()
	mgr := ebpfGRPCEBPFMgr
	ebpfGRPCMu.Unlock()
	return mgr != nil && mgr.AllowlistPortsSupported()
}

// mergeScopedAllowlist folds the port-scoped allowlist entries (the
// allowlist_scoped key, and any entry with ports under allowlist) into
// s.Allowlist when the attached object matches scopes. Without that, every
// scoped entry is left out and counted (allowlist_scoped_skipped): such an
// entry is never written as one that allows every port, and it cannot
// satisfy the lockout check. An entry under allowlist_scoped without ports
// is malformed and dropped (an older agent never enforces it either).
func mergeScopedAllowlist(s *ebpfDesiredState, supported bool) (skipped int) {
	if s.Allowlist == nil && len(s.AllowlistScoped) == 0 {
		return 0
	}
	full := make([]wafebpf.AllowlistEntry, 0, len(s.Allowlist))
	var scoped []wafebpf.AllowlistEntry
	for _, e := range s.Allowlist {
		if len(e.Ports) > 0 {
			scoped = append(scoped, e)
		} else {
			full = append(full, e)
		}
	}
	malformed := 0
	for _, e := range s.AllowlistScoped {
		if len(e.Ports) == 0 {
			malformed++
			continue
		}
		scoped = append(scoped, e)
	}
	s.AllowlistScoped = nil
	if malformed > 0 {
		log.Printf("[ebpf-grpc] %d allowlist_scoped entries without ports ignored", malformed)
	}
	if supported {
		s.Allowlist = append(full, scoped...)
		return malformed
	}
	s.Allowlist = full
	if len(scoped) > 0 {
		log.Printf("[ebpf-grpc] allowlist_scoped_skipped=%d: the attached XDP object does not match allowlist port scopes; port-scoped entries are not enforced (update the eBPF objects with the agent)", len(scoped))
	}
	return len(scoped) + malformed
}

// validateEBPFState checks representability and the lockout guard before
// any live map is changed.
func validateEBPFState(s *ebpfDesiredState) error {
	_, err := validateEBPFStateWith(s, currentFirewallEnv())
	return err
}

// validateEBPFStateWith runs the checks against an explicit host
// environment (tests) and returns the lockout-check warnings.
func validateEBPFStateWith(s *ebpfDesiredState, env firewallEnv) ([]wafebpf.FirewallWarning, error) {
	in := wafebpf.FirewallSafetyInput{
		Config:               s.Config,
		PortPolicyConfig:     s.PortPolicyConfig,
		PortPolicies:         s.PortPolicies,
		Blocklist:            s.Blocklist,
		Allowlist:            s.Allowlist,
		EgressBlocklist:      s.EgressBlocklist,
		SSHPorts:             env.sshPorts,
		ControlPlanePort:     env.controlPlanePort,
		ControlPlaneUnpinned: env.controlPlaneUnpinned,
		GeoMode:              s.GeoMode,
		GeoAllowed:           s.GeoAllowed,
		GeoAllowAcknowledged: s.GeoAllowAcknowledged,
	}
	// Same guard as the control plane and the local API; objects
	// without the exemptions refuse states that need them.
	warnings, err := wafebpf.ValidateHostFirewall(in, env.exemptions)
	if err != nil {
		return nil, err
	}
	if err := validateEBPFRepresentable(s); err != nil {
		return nil, err
	}
	return warnings, nil
}

// normalizeEBPFState rewrites values an older control plane may still
// deliver into the form this agent enforces: a port-scan threshold above the
// dataplane limit becomes the limit instead of refusing the bundle.
func normalizeEBPFState(s *ebpfDesiredState) {
	if s.Config != nil && wafebpf.NormalizePortScanConfig(&s.Config.PortScan) {
		log.Printf("[ebpf-grpc] port-scan threshold above %d unique ports lowered to %d and set to log only (the dataplane tracks at most %d ports and only ever logged such a threshold)",
			wafebpf.MaxPortScanUniquePorts, wafebpf.MaxPortScanUniquePorts, wafebpf.MaxPortScanUniquePorts)
	}
}

// validateEBPFRepresentable checks that every value fits the BPF maps.
func validateEBPFRepresentable(s *ebpfDesiredState) error {
	if s.Config != nil {
		if err := wafebpf.ValidateRateConfig(s.Config.Rate); err != nil {
			return err
		}
		if err := wafebpf.ValidatePortScanConfig(s.Config.PortScan); err != nil {
			return err
		}
	}
	if len(s.PortPolicies) > 4096 {
		return fmt.Errorf("port policy snapshot exceeds map capacity")
	}
	if s.TraceConfig != nil {
		if err := wafebpf.ValidateTraceConfig(*s.TraceConfig); err != nil {
			return err
		}
	}
	for _, list := range []struct {
		ips   []string
		limit int
	}{
		{func() []string {
			var ips []string
			for _, e := range s.Blocklist {
				ips = append(ips, e.IP)
			}
			return ips
		}(), 100000},
		{func() []string {
			var ips []string
			for _, e := range s.Allowlist {
				ips = append(ips, e.IP)
			}
			return ips
		}(), 10000},
		{func() []string {
			var ips []string
			for _, e := range s.EgressBlocklist {
				ips = append(ips, e.IP)
			}
			return ips
		}(), 100000},
	} {
		// Prefixes are stored natively: count map entries, not
		// addresses. A list that does not fit is refused here, before any
		// map changes (no map evicts an operator entry to make room).
		if _, err := wafebpf.CountIPListPrefixes(list.ips, list.limit); err != nil {
			return err
		}
	}
	egress := make([]string, 0, len(s.EgressBlocklist))
	for _, e := range s.EgressBlocklist {
		egress = append(egress, e.IP)
	}
	return wafebpf.ValidateEgressBlocklistCapacity(egress)
}

// applyEBPFState applies a full desired-state snapshot to the running eBPF
// manager. Failure is reported to the control plane; multi-map replacement
// is not atomic and a failed acknowledgement may represent partial application.
// applyEBPFState applies a full desired-state snapshot to the running eBPF
func applyEBPFState(s *ebpfDesiredState) error {
	// Same lock as local API firewall writes: neither lands between
	// the other's lockout check and its apply.
	defer wafebpf.LockFirewallWrites()()
	env := currentFirewallEnv()
	warnings, err := validateEBPFStateWith(s, env)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		log.Printf("[ebpf-grpc] firewall lockout check: %s: %s", w.Code, w.Message)
	}
	// The geo plan is resolved — ranges read and checked against the tries'
	// capacity — before any map is written; geo applies last and degrades
	// alone (planGeo, applyGeoState).
	var resolver geoRangeResolver
	if enricher := currentGeoEnricher(); enricher != nil {
		resolver = enricher
	}
	geo := planGeo(s, env, resolver)
	// Trace config
	if s.TraceConfig != nil {
		if ebpfGRPCTraceMgr == nil {
			return fmt.Errorf("runtime tracing unavailable")
		}
		if err := ebpfGRPCTraceMgr.UpdateConfig(*s.TraceConfig); err != nil {
			return err
		}
	}

	mgr := ebpfGRPCEBPFMgr
	if mgr == nil {
		if s.Config != nil || s.Blocklist != nil || s.Allowlist != nil || s.GeoBlocked != nil || s.PortPolicies != nil || s.PortPolicyConfig != nil || s.EgressBlocklist != nil {
			return fmt.Errorf("firewall unavailable")
		}
		return nil
	}

	for _, entry := range s.EgressBlocklist {
		if strings.Contains(entry.IP, ":") && !mgr.Status().EgressIPv6Supported {
			return fmt.Errorf("IPv6 egress filtering unavailable on attached object")
		}
	}
	// Connection tracking is NOT cleared on apply. Clearing it cut
	// every open connection under ingress Deny All, the agent's own stream
	// included. Stale entries cannot override a new policy: specific
	// IP/subnet blocks and explicit port rules are evaluated before the
	// reply bypass in XDP, and TC applies the egress filter to every packet
	// of a flow this host opened. Entries only keep already-open flows
	// alive under a new default deny or wildcard block, and expire after
	// 300 s (TCP) / 30 s (UDP) without outbound traffic.

	// Global / full config
	if s.Config != nil {
		if err := mgr.UpdateFullConfig(*s.Config); err != nil {
			return err
		}
	}

	// IP lists: a diff, never delete-all + re-add. Allowlist additions
	// and changes first, then blocklist and egress ones, stale blocks next
	// and stale allowlist entries last; an entry that stays is never absent.
	if err := wafebpf.ReplaceIPLists(mgr, wafebpf.IPListUpdate{
		Allow:  s.Allowlist,
		Block:  s.Blocklist,
		Egress: s.EgressBlocklist,
	}, time.Now()); err != nil {
		return err
	}

	// Port policies: replace all.
	// The rule table MUST land before the deny switch below: a restart
	// re-applies the full snapshot, and if the config (enabled +
	// default_ingress=deny) went live ahead of the allow rules, every
	// inbound packet — including the allow-listed ports — is dropped until
	// the next successful push. Rules first, switch last. The swap itself
	// never removes a rule that stays: removing every rule and
	// adding the set back left the default deny on with no allow rules for
	// the length of the push.
	if s.PortPolicies != nil {
		if err := mgr.ReplacePortPolicies(s.PortPolicies); err != nil {
			return err
		}
	}

	// Port policy config — applied only after the rule table is populated.
	if s.PortPolicyConfig != nil {
		if err := mgr.UpdatePortPolicyConfig(*s.PortPolicyConfig); err != nil {
			return err
		}
	}

	// Geo last: no later step can fail and roll it back, and a geo failure
	// degrades geo only (it never fails the bundle).
	applyGeoState(mgr, geo, attachedSubnetsOf(mgr))
	return nil
}

// applyTracePoliciesFromBundle applies a pre-parsed list of trace policies
// to the local PolicyEngine. Called from applyEBPFBundle.
func applyTracePoliciesFromBundle(_ json.RawMessage, policies []wafebpf.EnforcementPolicy) error {
	if ebpfGRPCTraceMgr == nil {
		return fmt.Errorf("runtime tracing unavailable")
	}
	return ebpfGRPCTraceMgr.ReplacePolicies(policies)
}

// sendEBPFTelemetry marshals a PushPayload as JSON and sends it as a
// CommandAck with command_id="ebpf:telemetry:v2". The Error field carries the
// JSON data (repurposed as a byte carrier — the name is misleading but the
// wire encoding is identical to any other string field).
var ebpfTelemetrySendFailures atomic.Uint64

var ebpfTelemetryRetention = newTelemetryRetention(64, 16<<20, time.Minute)

// ebpfTelemetryBatchesPerTick caps the batches one 250 ms tick sends while a
// burst keeps them full: 4 × 500 trace events per tick, ±8,000 events/s.
const ebpfTelemetryBatchesPerTick = 4

// ebpfTelemetryBatchInterval is how long the telemetry loop collects events
// into one batch. One batch a second instead of four carries
// four times the events, which gzip shrinks ±6.7× instead of ±3.6× (25 vs 5
// trace events, measured on the demo host), and costs the control plane one
// ingest instead of four.
const ebpfTelemetryBatchInterval = time.Second

// ebpfTelemetryBatchDue reports whether the 250 ms tick at now sends: the
// interval since the last batch passed, the last batch was full (backlog),
// a full batch already waits in the firewall or trace queue (full: the
// firewall queue holds 4,096 events, so a drop flood must not wait a second),
// or something urgent waits (TraceManager.TelemetryUrgent: HIGH+ or enforced
// trace events, kill outcomes, enforcement entries).
func ebpfTelemetryBatchDue(now, lastBatch time.Time, backlog, urgent, full bool) bool {
	return backlog || urgent || full || now.Sub(lastBatch) >= ebpfTelemetryBatchInterval
}

// demand (nil: none) says whether the stream's control plane takes gzip
// payloads.
func sendEBPFTelemetry(send func(*agentv1.AgentMessage) error, demand *telemetryDemand, payload *PushPayload) {
	payload.TelemetrySendFailures = ebpfTelemetrySendFailures.Load()
	payload.TelemetryDelivery = ebpfTelemetryRetention.snapshot()
	payload.TelemetryDelivery.Compression = "none"
	if demand.gzip() {
		payload.TelemetryDelivery.Compression = "gzip"
		payload.TelemetryDelivery.PaddedBatches = telemetryPaddedBatches.Load()
	}
	payload.BatchID = rand.Text()
	counts := telemetryBatchCounts{
		events: len(payload.Events) + len(payload.TraceEvents) + len(payload.Enforcement),
		trace:  payload.traceByClass,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		ebpfTelemetrySendFailures.Add(1)
		ebpfTelemetryRetention.discard(counts)
		return
	}
	if !ebpfTelemetryRetention.add(payload.BatchID, body, counts, time.Now()) {
		log.Printf("[ebpf-grpc] telemetry retention full; discarded batch events=%d", len(payload.Events)+len(payload.TraceEvents)+len(payload.Enforcement))
	}
	flushEBPFTelemetry(send, demand)
}

func flushEBPFTelemetry(send func(*agentv1.AgentMessage) error, demand *telemetryDemand) {
	batch := ebpfTelemetryRetention.next(time.Now())
	if batch == nil {
		return
	}
	if err := send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Ack{Ack: telemetryAck(batch.body, demand.gzip())}}); err != nil {
		ebpfTelemetrySendFailures.Add(1)
		log.Printf("[ebpf-grpc] telemetry send failed; retained for bounded retry: %v", err)
	}
}

// reportHostSecurityDataStatus checks which security-data files the host agent
// has installed and sends a CommandAck{command_id:"secdata:status"} to the
// control plane. Only the components relevant to the host/eBPF agent are
// checked (geoip-country); WAF-only components (crs, firehol, ja3, ua) are
// excluded to avoid misleading "missing" entries in the dashboard.
func reportHostSecurityDataStatus(send func(*agentv1.AgentMessage) error) {
	ebpfGRPCMu.Lock()
	dir := ebpfGRPCSecDataDir
	compPaths := ebpfComponentPaths
	ebpfGRPCMu.Unlock()
	if dir == "" {
		dir = "/etc/wafio/security-data"
	}

	// Default path — control plane recommended layout.
	checks := map[string]string{
		"geoip-country": filepath.Join(dir, "geoip", "country.mmdb"),
	}
	// Override with explicit configured paths (same pattern as WAF agent).
	for comp, path := range compPaths {
		if path != "" {
			checks[comp] = path
		}
	}

	status := make(map[string]agentcore.AgentComponentInfo, len(checks))
	for comp, path := range checks {
		absPath, _ := filepath.Abs(path)
		if absPath == "" {
			absPath = path
		}
		info := agentcore.AgentComponentInfo{Path: absPath}
		if fi, err := os.Stat(path); err == nil {
			info.Exists = true
			info.SizeBytes = fi.Size()
			info.ModifiedAt = fi.ModTime().UTC().Format(time.RFC3339)
		}
		status[comp] = info
	}

	payload, err := json.Marshal(status)
	if err != nil {
		return
	}
	_ = send(&agentv1.AgentMessage{
		Kind: &agentv1.AgentMessage_Ack{Ack: &agentv1.CommandAck{
			CommandId: "secdata:status",
			Ok:        true,
			Error:     string(payload),
		}},
	})
}
