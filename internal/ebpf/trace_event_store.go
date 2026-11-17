package ebpf

import (
	"strconv"
	"sync"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
//  Trace event store (shared by the ring readers)
//
//  Every event the trace ring readers decode lands in three places: the
//  newest-N query ring, a per-category ring (so file events cannot drown out
//  process/network/security ones) and the destructive push queue. The reader
//  goroutine is the bottleneck of the shared trace ring: when it falls
//  behind, the kernel drops events (trace_stats[0]). The rings are allocated
//  once — the former slices re-sliced from the front and re-allocated, copying
//  thousands of ~600-byte events, every few thousand events.
// ────────────────────────────────────────────────────────────────────────────

// eventRing is a bounded, non-destructive ring of the newest events.
type eventRing[T any] struct {
	buf  []T // len == capacity
	head int // index of the oldest element
	n    int
}

func newEventRing[T any](capacity int) *eventRing[T] {
	if capacity < 1 {
		capacity = 1
	}
	return &eventRing[T]{buf: make([]T, capacity)}
}

// push adds v, overwriting the oldest element when full.
func (r *eventRing[T]) push(v T) {
	c := len(r.buf)
	if r.n == c {
		r.buf[r.head] = v
		r.head = (r.head + 1) % c
		return
	}
	r.buf[(r.head+r.n)%c] = v
	r.n++
}

// len is the number of stored elements.
func (r *eventRing[T]) len() int { return r.n }

// newestFirst calls fn from the newest element to the oldest until fn
// returns false.
func (r *eventRing[T]) newestFirst(fn func(*T) bool) {
	c := len(r.buf)
	for i := r.n - 1; i >= 0; i-- {
		if !fn(&r.buf[(r.head+i)%c]) {
			return
		}
	}
}

// traceCategories are the per-category rings FilterRecentEvents serves.
var traceCategories = [...]string{"process", "file", "network", "security"}

// traceEventStore holds the query rings and the push queue.
type traceEventStore struct {
	mu     sync.Mutex
	recent *eventRing[TraceEvent]
	cat    map[string]*eventRing[TraceEvent]
	push   *tracePushQueue
}

func newTraceEventStore(recent, perCategory, pushCap int) *traceEventStore {
	s := &traceEventStore{
		recent: newEventRing[TraceEvent](recent),
		cat:    make(map[string]*eventRing[TraceEvent], len(traceCategories)),
		push:   newTracePushQueue(pushCap),
	}
	for _, c := range traceCategories {
		s.cat[c] = newEventRing[TraceEvent](perCategory)
	}
	return s
}

// record stores evt in the recent ring, the push queue and, when category
// is one of traceCategories, that category's ring.
func (s *traceEventStore) record(evt TraceEvent, category string) {
	s.mu.Lock()
	s.recent.push(evt)
	if r := s.cat[category]; r != nil {
		r.push(evt)
	}
	s.mu.Unlock()
	s.push.push(evt)
}

// filter returns up to limit events (limit <= 0: all) of at least
// minSeverity, oldest first, from the category's ring or, for any other
// category value, from the recent ring.
func (s *traceEventStore) filter(category string, minSeverity uint32, limit int) []TraceEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.recent
	if r := s.cat[category]; r != nil {
		src = r
	}
	var result []TraceEvent
	src.newestFirst(func(e *TraceEvent) bool {
		if e.Severity < minSeverity {
			return true
		}
		result = append(result, *e)
		return limit <= 0 || len(result) < limit
	})
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

// breakdown counts the recent ring by severity name and category.
func (s *traceEventStore) breakdown(bySeverity, byCategory map[string]uint64) (used int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recent.newestFirst(func(e *TraceEvent) bool {
		bySeverity[e.SeverityName]++
		for _, c := range splitCategory(e.Category) {
			byCategory[c]++
		}
		return true
	})
	return s.recent.len()
}

// traceEventCategory is the store category of an event type ("" = none).
func traceEventCategory(eventType uint32) string {
	info := TraceEventTypes[eventType]
	switch {
	case info.Category&CatProcess != 0:
		return "process"
	case info.Category&CatFile != 0:
		return "file"
	case info.Category&CatNetwork != 0:
		return "network"
	case info.Category&CatSecurity != 0:
		return "security"
	}
	return ""
}

// decodeTraceRecord turns one ring record into the user-facing event: the
// per-event work of the trace ring readers before policy evaluation.
func decodeTraceRecord(sample []byte, bootOffset time.Duration, eventPrefix string) (TraceEvent, error) {
	raw, err := ParseRawTraceEvent(sample)
	if err != nil {
		return TraceEvent{}, err
	}
	evt := raw.ToTraceEvent(bootOffset)
	evt.EventID = traceEventID(eventPrefix, raw.TimestampNs, raw.TID, raw.EventType)
	return evt, nil
}

// traceEventID is "<prefix>:<timestamp_ns>:<tid>:<event_type>".
func traceEventID(prefix string, ts uint64, tid, eventType uint32) string {
	b := make([]byte, 0, len(prefix)+40)
	b = append(b, prefix...)
	b = append(b, ':')
	b = strconv.AppendUint(b, ts, 10)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(tid), 10)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(eventType), 10)
	return string(b)
}
func splitCategory(cat string) []string {
	if cat == "" {
		return nil
	}
	parts := make([]string, 0, 2)
	start := 0
	for i := 0; i < len(cat); i++ {
		if cat[i] == ',' {
			parts = append(parts, cat[start:i])
			start = i + 1
		}
	}
	parts = append(parts, cat[start:])
	return parts
}
