//go:build linux

package ebpf

import "time"

// lossTotals returns the cumulative trace loss counters; kernel is the
// shared-ring output failure count (trace_stats[0]) the caller already read.
func (tm *TraceManager) lossTotals(kernel uint64) traceLossTotals {
	t := traceLossTotals{Kernel: kernel, Queue: tm.events.push.dropped()}
	for c := range t.Delivery {
		t.Delivery[c] = tm.deliveryLost[c].Load()
	}
	return t
}

// fillLossStatus sets the loss fields of s from the counters and the loss
// history; s.KernelEventsDropped must already be read.
func (tm *TraceManager) fillLossStatus(s *TraceStatus, now time.Time) {
	cur := tm.lossTotals(s.KernelEventsDropped)
	s.QueueDroppedNoise = cur.Queue[TraceClassNoise]
	s.QueueDroppedWatched = cur.Queue[TraceClassWatched]
	s.QueueDroppedSignificant = cur.Queue[TraceClassSignificant]
	s.QueueDropped = cur.Queue.total()
	s.DeliveryLostNoise = cur.Delivery[TraceClassNoise]
	s.DeliveryLostWatched = cur.Delivery[TraceClassWatched]
	s.DeliveryLostSignificant = cur.Delivery[TraceClassSignificant]
	// The loss loop is the history's only sampler (one counter source, so a
	// failed map read cannot be counted twice); recent loss lags by at most
	// traceLossCheckInterval.
	recent, last := tm.lossHistory.recent(now)
	s.LossWindowSec = int(traceLossWindow / time.Second)
	s.RecentLostNoise = recent[TraceClassNoise]
	s.RecentLostWatched = recent[TraceClassWatched]
	s.RecentLostSignificant = recent[TraceClassSignificant]
	if !last.IsZero() {
		s.LastLossAt = last.UTC().Format(time.RFC3339)
	}
}

// NoteDeliveryLoss counts the trace events of a telemetry batch the agent
// discarded without a control plane receipt (retention full or expired,
// encode or send failure), by push-queue class.
func (tm *TraceManager) NoteDeliveryLoss(byClass [3]int) {
	for c, n := range byClass {
		if n > 0 && c < len(tm.deliveryLost) {
			tm.deliveryLost[c].Add(uint64(n))
		}
	}
}
