package agent

import (
	"github.com/wafio/wafio-cp-backend/shared/agentcore"
	"sync"
	"time"
)

type telemetryBatch struct {
	id                string
	body              []byte
	counts            telemetryBatchCounts
	created, lastSent time.Time
}

// telemetryBatchCounts: events of every kind in a batch, and its trace
// events by push-queue class (wafebpf.QueuedTraceClass).
type telemetryBatchCounts struct {
	events int
	trace  [3]int
}
type telemetryDelivery struct {
	PendingBatches            int    `json:"pending_batches"`
	PendingBytes              int    `json:"pending_bytes"`
	ProcessAccepted           uint64 `json:"process_accepted_batches"`
	DroppedBatches            uint64 `json:"dropped_batches"`
	DroppedEvents             uint64 `json:"dropped_events"`
	PersistedAcknowledgements bool   `json:"persisted_acknowledgements"`
	// ResentBatches counts batches sent again because no receipt came
	// within 2 s (each is traffic the control plane deduplicates).
	ResentBatches uint64 `json:"resent_batches"`
	// PaddedBatches counts the gzip members padded to the control plane's
	// ratio cap (telemetrygz.MaxRatio) since the agent
	// started; omitted while the stream sends plain JSON.
	PaddedBatches uint64 `json:"padded_batches,omitempty"`
	// Compression of the stream now open: "gzip" or "none";
	// empty on the HTTP push path.
	Compression string `json:"compression,omitempty"`
}
type telemetryRetention struct {
	mu                   sync.Mutex
	batches              []telemetryBatch
	maxBatches, maxBytes int
	ttl                  time.Duration
	stats                telemetryDelivery
	// traceLoss receives the trace events of every batch discarded
	// unconfirmed; nil = not reported.
	traceLoss func(byClass [3]int)
}

// setTraceLoss registers the trace manager's loss accounting.
func (q *telemetryRetention) setTraceLoss(fn func(byClass [3]int)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.traceLoss = fn
}

// discard accounts a batch that never entered the queue (not encodable).
func (q *telemetryRetention) discard(c telemetryBatchCounts) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.lose(c)
}

// lose accounts a batch discarded unconfirmed; q.mu is held.
func (q *telemetryRetention) lose(c telemetryBatchCounts) {
	q.stats.DroppedBatches++
	q.stats.DroppedEvents += agentcore.NonNegUint64(c.events)
	if q.traceLoss != nil && c.trace != ([3]int{}) {
		q.traceLoss(c.trace)
	}
}

func newTelemetryRetention(batches, bytes int, ttl time.Duration) *telemetryRetention {
	return &telemetryRetention{maxBatches: batches, maxBytes: bytes, ttl: ttl}
}
func (q *telemetryRetention) expire(now time.Time) {
	kept := q.batches[:0]
	for _, b := range q.batches {
		if now.Sub(b.created) >= q.ttl {
			q.stats.PendingBytes -= len(b.body)
			q.lose(b.counts)
		} else {
			kept = append(kept, b)
		}
	}
	clear(q.batches[len(kept):])
	q.batches = kept
}
func (q *telemetryRetention) add(id string, body []byte, counts telemetryBatchCounts, now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.expire(now)
	if len(q.batches) >= q.maxBatches || q.stats.PendingBytes+len(body) > q.maxBytes {
		q.lose(counts)
		return false
	}
	q.batches = append(q.batches, telemetryBatch{id: id, body: body, counts: counts, created: now})
	q.stats.PendingBytes += len(body)
	return true
}
func (q *telemetryRetention) next(now time.Time) *telemetryBatch {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.expire(now)
	for i := range q.batches {
		b := &q.batches[i]
		if b.lastSent.IsZero() || now.Sub(b.lastSent) >= 2*time.Second {
			if !b.lastSent.IsZero() {
				q.stats.ResentBatches++
			}
			b.lastSent = now
			copyBatch := *b
			return &copyBatch
		}
	}
	return nil
}
func (q *telemetryRetention) receipt(id string, accepted bool) {
	if !accepted {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, b := range q.batches {
		if b.id == id {
			q.stats.PendingBytes -= len(b.body)
			q.stats.ProcessAccepted++
			copy(q.batches[i:], q.batches[i+1:])
			q.batches[len(q.batches)-1] = telemetryBatch{}
			q.batches = q.batches[:len(q.batches)-1]
			return
		}
	}
}
func (q *telemetryRetention) snapshot() telemetryDelivery {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.stats
	s.PendingBatches = len(q.batches)
	return s
}
func (q *telemetryRetention) hasCapacity() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.batches) < q.maxBatches && q.stats.PendingBytes < q.maxBytes-(1<<20)
}
