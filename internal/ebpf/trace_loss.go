package ebpf

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// traceLossWindow is the period TraceStatus.RecentLost* cover: the dashboard
// warns about loss in this window, not about every loss since the agent
// started (a one-off burst in the morning should not mark the host as
// incomplete for the rest of the day).
const traceLossWindow = time.Hour

const traceLossBuckets = int(traceLossWindow / time.Minute)

// traceClassCounts are counts per push-queue class (index: TraceClass).
type traceClassCounts [traceClassCount]uint64

func (c traceClassCounts) total() uint64 {
	return c[TraceClassNoise] + c[TraceClassWatched] + c[TraceClassSignificant]
}

// traceLossTotals are the agent's cumulative trace loss counters by place
// and class. Kernel loss (shared ring full) has no class: it is counted as
// significant. It includes lost kill candidates (trace_priority_stats LOST
// is counted together with trace_stats[0] in submit_event_routed).
type traceLossTotals struct {
	Kernel   uint64           // trace_stats[0]: shared-ring output failures
	Queue    traceClassCounts // push queue drops
	Delivery traceClassCounts // trace events of batches discarded unconfirmed
}

// traceLossDeltaOf is cur - prev per counter; a counter below its previous
// value restarted (trace object reloaded) and counts in full.
func traceLossDeltaOf(prev, cur traceLossTotals) traceLossTotals {
	d := traceLossTotals{Kernel: traceLossDelta(prev.Kernel, cur.Kernel)}
	for c := range d.Queue {
		d.Queue[c] = traceLossDelta(prev.Queue[c], cur.Queue[c])
		d.Delivery[c] = traceLossDelta(prev.Delivery[c], cur.Delivery[c])
	}
	return d
}

// byClass sums queue and delivery loss per class, kernel loss as
// significant.
func (t traceLossTotals) byClass() traceClassCounts {
	var out traceClassCounts
	for c := range out {
		out[c] = t.Queue[c] + t.Delivery[c]
	}
	out[TraceClassSignificant] += t.Kernel
	return out
}

type traceLossBucket struct {
	minute int64 // Unix minute the counts belong to
	counts traceClassCounts
}

// traceLossHistory turns the cumulative loss counters into per-minute counts
// for the last traceLossWindow. observe attributes every rise since the
// previous call to the minute of now; the loss loop is its only sampler
// (every traceLossCheckInterval).
type traceLossHistory struct {
	mu       sync.Mutex
	prev     traceLossTotals
	buckets  [traceLossBuckets]traceLossBucket
	lastLoss time.Time
}

func (h *traceLossHistory) observe(now time.Time, cur traceLossTotals) {
	h.mu.Lock()
	defer h.mu.Unlock()
	d := traceLossDeltaOf(h.prev, cur).byClass()
	h.prev = cur
	if d.total() == 0 {
		return
	}
	minute := now.Unix() / 60
	b := &h.buckets[minute%int64(traceLossBuckets)]
	if b.minute != minute {
		*b = traceLossBucket{minute: minute}
	}
	for c := range d {
		b.counts[c] += d[c]
	}
	h.lastLoss = now
}

// recent returns the loss per class of the last traceLossWindow (the current
// minute and the traceLossBuckets-1 before it) and the time of the last loss
// ever observed (zero: none).
func (h *traceLossHistory) recent(now time.Time) (traceClassCounts, time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out traceClassCounts
	minute := now.Unix() / 60
	for _, b := range h.buckets {
		if b.minute > minute-int64(traceLossBuckets) && b.minute <= minute {
			for c := range out {
				out[c] += b.counts[c]
			}
		}
	}
	return out, h.lastLoss
}

// traceLossClassText names the class counts of a loss report.
func traceLossClassText(c traceClassCounts) string {
	return fmt.Sprintf("%d process, security, medium+ or enforced; %d sensitive-file accesses below medium; %d other low-severity file/network",
		c[TraceClassSignificant], c[TraceClassWatched], c[TraceClassNoise])
}

// traceAgentLossAlert builds the security event for trace events the agent
// itself dropped since the previous check, in its push queue or in batches
// discarded unconfirmed, or false when none were (kernel loss has its own
// event, traceLossAlert). Significant events lost make it HIGH (an incident:
// the control plane is missing process, security, MEDIUM+ or enforced
// activity); watched events lost make it MEDIUM (stored, no incident:
// accesses of sensitive files below MEDIUM, which ingest may have raised);
// only noise makes it LOW.
//
// The text states only what the counters show. A full send queue means the
// host produced events faster than the agent sends them, whatever the
// control plane is doing; only the unconfirmed batches point at delivery.
func traceAgentLossAlert(d traceLossTotals, now time.Time) (TraceEvent, bool) {
	queue, delivery := d.Queue.total(), d.Delivery.total()
	if queue == 0 && delivery == 0 {
		return TraceEvent{}, false
	}
	sev := SevLow
	switch {
	case d.Queue[TraceClassSignificant] > 0 || d.Delivery[TraceClassSignificant] > 0:
		sev = SevHigh
	case d.Queue[TraceClassWatched] > 0 || d.Delivery[TraceClassWatched] > 0:
		sev = SevMedium
	}
	var parts []string
	if queue > 0 {
		parts = append(parts, fmt.Sprintf("send queue full (events arrived faster than the agent sends them): %d dropped (%s)", queue, traceLossClassText(d.Queue)))
	}
	if delivery > 0 {
		parts = append(parts, fmt.Sprintf("%d in batches the control plane never confirmed (%s)", delivery, traceLossClassText(d.Delivery)))
	}
	return TraceEvent{
		EventName:    traceLossEventName,
		Category:     "security",
		Severity:     sev,
		SeverityName: severityName(sev),
		Timestamp:    now.UTC().Format(time.RFC3339),
		Description:  "trace events lost in the agent since the last check: " + strings.Join(parts, "; "),
	}, true
}
