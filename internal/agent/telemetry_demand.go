package agent

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"github.com/wafio/wafio-cp-backend/shared/telemetrygz"
)

// Telemetry on demand: the connections and bandwidth
// snapshots (±20 KB every 3 s on a quiet host, ±24 GB a month) are read only
// by the Firewall page. A control plane that says so (it sends
// telemetryDemandCommandID on the stream) gets them every
// telemetryLiveInterval while someone views the host and every
// telemetryIdleInterval otherwise. A control plane that never sends it
// (older than v1.9.0) gets them every telemetryLiveInterval, as before.
//
// Status on demand: a control plane whose command carries
// "status_on_demand": true gets the slow payload (host info, eBPF and trace
// status, trace stats, rule hit counts, snapshots when due) every
// telemetryLiveInterval and metrics every second only while a status window
// ("status_live_for_sec") or a snapshot window is open, otherwise both every
// telemetryStatusIdleInterval; the slow payload also goes at once on
// connect, when a window opens and after a configuration bundle is applied.
// Without it (an older control plane) they go every 3 s and every second.
const (
	// telemetryDemandFeature is the Hello feature a host agent reports
	// when it handles telemetryDemandCommandID.
	telemetryDemandFeature = "telemetry_demand"
	// telemetryDemandCommandID is the BundleUpdate command the control
	// plane sends: {"live_for_sec": N, "telemetry_gzip": true,
	// "status_on_demand": true, "status_live_for_sec": M}; the first one,
	// on connect, announces on-demand mode and gzip payloads.
	telemetryDemandCommandID = "telemetry:demand"
	telemetryLiveInterval    = 3 * time.Second
	telemetryIdleInterval    = time.Minute
	// telemetryStatusIdleInterval is the slow payload and metrics cadence
	// outside a status window (status on demand).
	telemetryStatusIdleInterval = 30 * time.Second
	// telemetryMetricsLiveInterval is the metrics cadence inside a status
	// window, or always without status on demand.
	telemetryMetricsLiveInterval = time.Second
	// telemetryLiveMax caps one live window, whatever the control plane asks.
	telemetryLiveMax = 10 * time.Minute
)

// telemetryDemand is the snapshot and status cadence of one stream and
// whether its control plane takes gzip telemetry payloads.
type telemetryDemand struct {
	mu        sync.Mutex
	onDemand  bool
	gzipOK    bool
	liveUntil time.Time
	lastSent  time.Time
	// statusOnDemand: the control plane asks for status and metrics on
	// demand; statusUntil ends its status window; lastSlow is when the
	// last slow payload left.
	statusOnDemand bool
	statusUntil    time.Time
	lastSlow       time.Time
	kick           chan struct{}
}

func newTelemetryDemand() *telemetryDemand {
	return &telemetryDemand{kick: make(chan struct{}, 1)}
}

// liveWindow clamps a window the control plane asks for to
// [0, telemetryLiveMax].
func liveWindow(sec int64) time.Duration {
	return time.Duration(min(max(sec, 0), int64(telemetryLiveMax/time.Second))) * time.Second
}

// handle applies a telemetryDemandCommandID payload; a malformed one is
// ignored.
func (d *telemetryDemand) handle(payload []byte, now time.Time) {
	var msg struct {
		LiveForSec       int64 `json:"live_for_sec"`
		TelemetryGzip    bool  `json:"telemetry_gzip"`
		StatusOnDemand   bool  `json:"status_on_demand"`
		StatusLiveForSec int64 `json:"status_live_for_sec"`
	}
	if json.Unmarshal(payload, &msg) != nil {
		return
	}
	if msg.TelemetryGzip {
		d.mu.Lock()
		d.gzipOK = true
		d.mu.Unlock()
	}
	d.signal(liveWindow(msg.LiveForSec), msg.StatusOnDemand, liveWindow(msg.StatusLiveForSec), now)
}

// statusLiveLocked reports whether status and metrics go at the live
// cadence at now: always without status on demand, else inside a status or
// snapshot window. d.mu held.
func (d *telemetryDemand) statusLiveLocked(now time.Time) bool {
	return !d.statusOnDemand || now.Before(d.statusUntil) || (d.onDemand && now.Before(d.liveUntil))
}

// signal switches to on-demand mode (and to status on demand when
// statusOnDemand) and keeps the snapshots live for liveFor and the status
// for statusFor from now (never shortening a longer window). A viewer that
// just arrived gets a slow payload at once instead of at the next tick.
func (d *telemetryDemand) signal(liveFor time.Duration, statusOnDemand bool, statusFor time.Duration, now time.Time) {
	d.mu.Lock()
	wasLive := d.onDemand && now.Before(d.liveUntil)
	wasStatusLive := d.statusLiveLocked(now)
	d.onDemand = true
	if statusOnDemand {
		d.statusOnDemand = true
	}
	if until := now.Add(liveFor); until.After(d.liveUntil) {
		d.liveUntil = until
	}
	if until := now.Add(statusFor); until.After(d.statusUntil) {
		d.statusUntil = until
	}
	kick := (!wasLive && now.Before(d.liveUntil) && now.Sub(d.lastSent) >= telemetryLiveInterval) ||
		(!wasStatusLive && d.statusLiveLocked(now) && now.Sub(d.lastSlow) >= telemetryLiveInterval)
	d.mu.Unlock()
	if kick {
		d.kickNow()
	}
}

func (d *telemetryDemand) kickNow() {
	select {
	case d.kick <- struct{}{}:
	default:
	}
}

// configApplied asks for a slow payload at once after a configuration
// bundle was applied (or refused), so the applied generations and the
// bundle status reach the control plane without waiting for the idle
// cadence (status on demand only; otherwise the next tick is ≤ 3 s away).
func (d *telemetryDemand) configApplied() {
	d.mu.Lock()
	onDemand := d.statusOnDemand
	d.mu.Unlock()
	if onDemand {
		d.kickNow()
	}
}

// due reports whether the medium payload built now carries the snapshots.
func (d *telemetryDemand) due(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dueLocked(now)
}

func (d *telemetryDemand) dueLocked(now time.Time) bool {
	if !d.onDemand || now.Before(d.liveUntil) {
		return true
	}
	return d.lastSent.IsZero() || now.Sub(d.lastSent) >= telemetryIdleInterval
}

// sent records that the snapshots left at now.
func (d *telemetryDemand) sent(now time.Time) {
	d.mu.Lock()
	d.lastSent = now
	d.mu.Unlock()
}

// slowDue reports whether a slow payload goes on the telemetryLiveInterval
// tick at now: every tick at the live cadence, else once the idle interval
// has passed (less half a tick, so ticker jitter does not add a tick) or
// when the snapshots are due.
func (d *telemetryDemand) slowDue(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.statusLiveLocked(now) || d.lastSlow.IsZero() || d.dueLocked(now) {
		return true
	}
	return now.Sub(d.lastSlow) >= telemetryStatusIdleInterval-telemetryLiveInterval/2
}

// slowSent records that a slow payload left at now.
func (d *telemetryDemand) slowSent(now time.Time) {
	d.mu.Lock()
	d.lastSlow = now
	d.mu.Unlock()
}

// metricsInterval is the metrics cadence at now.
func (d *telemetryDemand) metricsInterval(now time.Time) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.statusLiveLocked(now) {
		return telemetryMetricsLiveInterval
	}
	return telemetryStatusIdleInterval
}

// metricsDue reports whether a telemetry batch built at now carries the
// metrics, last sent at last (zero: never).
func (d *telemetryDemand) metricsDue(now, last time.Time) bool {
	return last.IsZero() || now.Sub(last) >= d.metricsInterval(now)
}

// runSlowTelemetry drives the slow payload of one stream: sendSlow(now) at
// once, then on a tick when slowDue and on every kick, until ctx ends.
func runSlowTelemetry(ctx context.Context, d *telemetryDemand, tick <-chan time.Time, clock func() time.Time, sendSlow func(now time.Time)) {
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-tick:
				if !d.slowDue(clock()) {
					continue
				}
			case <-d.kick:
			}
		}
		now := clock()
		sendSlow(now)
		d.slowSent(now)
	}
}

// gzip reports whether the stream's control plane announced gzip telemetry
// payloads (CommandAck.payload); false for nil.
func (d *telemetryDemand) gzip() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gzipOK
}

// telemetryPaddedBatches counts the telemetry batches whose gzip member was
// padded to the control plane's ratio cap (telemetrygz.MaxRatio): batches
// that compress more than real traffic does.
var telemetryPaddedBatches atomic.Uint64

// telemetryAck is the CommandAck carrying one telemetry batch: the JSON in
// error, or its gzip in payload when the control plane takes it (a batch
// shrinks 4–62×). The control plane reads the uncompressed
// size from the gzip trailer and charges it before inflating; it refuses a
// member that declares more than telemetrygz.MaxRatio times its length, so
// telemetrygz.Encode pads the batches that compress more than that.
func telemetryAck(body []byte, gz bool) *agentv1.CommandAck {
	ack := &agentv1.CommandAck{CommandId: "ebpf:telemetry:v2", Ok: true}
	if !gz {
		ack.Error = string(body)
		return ack
	}
	member, padded, err := telemetrygz.Encode(body)
	if err != nil {
		ack.Error = string(body) // a bytes.Buffer never fails; stay correct anyway
		return ack
	}
	if padded {
		telemetryPaddedBatches.Add(1)
	}
	ack.Payload = member
	return ack
}
