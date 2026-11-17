package ebpf

import (
	"sync"
	"sync/atomic"
)

// ────────────────────────────────────────────────────────────────────────────
//  Trace push queue
//
//  Every traced event the agent keeps waits here until the telemetry loop
//  sends it to the control plane. The queue is bounded: when the control
//  plane acknowledges slower than the host produces events (a burst of file
//  activity on a small control plane, or a control plane that is down), it
//  has to drop something. Events fall in three classes (TraceClass), dropped
//  in this order:
//
//    noise        observed file/network events below MEDIUM — the class the
//                 kernel sheds first for ring headroom (TRACE_NOISE_TYPES)
//                 and the one ingest stores only after a later raise;
//    watched      such an openat the kernel never sheds either: a path
//                 component in the shed-exemption names (traceKeepBuiltin:
//                 the credential, auth and persistence files ingest may
//                 raise, plus the filename terms of this host's
//                 Kill/Alert/Simulate policies) or a relative write;
//    significant  process, security, MEDIUM+, enforced events and kill
//                 outcomes, which ingest always stores.
//
//  A full queue drops the oldest event of the most droppable class it holds,
//  or the new event when that is more droppable than everything queued. So a
//  flood of cheap reads cannot push out a read of /etc/pam.d/…, and a flood
//  of reads of commonly read sensitive files (/etc/passwd, nsswitch.conf)
//  cannot push out an exec, a setuid or an enforced event.
// ────────────────────────────────────────────────────────────────────────────

// tracePushQueueCap bounds the push queue (all classes together). A queued
// event takes 496 bytes plus its strings; the buffers grow only while a
// burst outruns the telemetry loop (at most ±32 MiB of slots in a long
// mixed burst) and are released once a class drains empty.
const tracePushQueueCap = 32768

// tracePushInitialCap is the first allocation of each class; a class grows
// by doubling up to the queue's capacity.
const tracePushInitialCap = 64

// tracePushShrinkAbove: a class buffer larger than this is released when the
// class drains empty, so a burst's memory does not stay with the agent.
const tracePushShrinkAbove = 1024

// traceDropOrder lists the classes from the first dropped to the last.
var traceDropOrder = [traceClassCount]TraceClass{TraceClassNoise, TraceClassWatched, TraceClassSignificant}

// traceDroppability ranks a class in traceDropOrder: higher drops first.
func traceDroppability(c TraceClass) int {
	switch c {
	case TraceClassNoise:
		return 2
	case TraceClassWatched:
		return 1
	}
	return 0
}

type queuedTraceEvent struct {
	seq    uint64
	evt    TraceEvent
	urgent bool // traceEventUrgent at push
}

// traceEventUrgent reports whether evt makes the telemetry loop send at its
// next 250 ms tick instead of with the next one-second batch:
// HIGH and above, enforced events and kill outcomes — what an operator acts
// on. Everything else waits at most a second, so batches carry more events
// and compress better.
func traceEventUrgent(evt *TraceEvent) bool {
	return evt.Severity >= SevHigh || evt.Action != ActionMonitor || evt.OutcomeUpdate
}

// tracePushRing is a growable FIFO of queued events.
type tracePushRing struct {
	buf  []queuedTraceEvent
	head int
	n    int
}

func (r *tracePushRing) push(item queuedTraceEvent, limit int) {
	if r.n == len(r.buf) {
		r.grow(limit)
	}
	r.buf[(r.head+r.n)%len(r.buf)] = item
	r.n++
}

// grow doubles the buffer (at least tracePushInitialCap, at most limit),
// keeping the queued events in order from index 0. The queue pushes into a
// class only while all classes together hold fewer than limit events, so a
// full class holds fewer than limit and the new buffer is always larger.
func (r *tracePushRing) grow(limit int) {
	c := min(max(len(r.buf)*2, tracePushInitialCap), limit)
	buf := make([]queuedTraceEvent, c)
	for i := range r.n {
		buf[i] = r.buf[(r.head+i)%len(r.buf)]
	}
	r.buf, r.head = buf, 0
}

func (r *tracePushRing) front() *queuedTraceEvent { return &r.buf[r.head] }

func (r *tracePushRing) pop() queuedTraceEvent {
	item := r.buf[r.head]
	r.buf[r.head] = queuedTraceEvent{} // release references for the GC
	r.head = (r.head + 1) % len(r.buf)
	r.n--
	if r.n == 0 && len(r.buf) > tracePushShrinkAbove {
		r.buf, r.head = nil, 0 // burst over: grow again on demand
	}
	return item
}

// tracePushQueue is the bounded, destructive FIFO between the trace readers
// and the telemetry loop: at most max events in all classes together.
// Delivery is at most once; drain returns events in the order they were
// pushed, across classes.
type tracePushQueue struct {
	mu    sync.Mutex
	max   int
	seq   uint64
	rings [traceClassCount]tracePushRing
	lost  [traceClassCount]uint64
	// urgent counts the queued events traceEventUrgent marks.
	urgent int
	// keep: the shed-exemption names in force (shedKeepNames of the
	// current policies; traceKeepBuiltin until the first policy sync).
	keep atomic.Pointer[map[string]uint8]
}

func newTracePushQueue(capacity int) *tracePushQueue {
	q := &tracePushQueue{max: max(capacity, 1)}
	builtin := traceKeepBuiltin
	q.keep.Store(&builtin)
	return q
}

// setKeepNames replaces the shed-exemption names (shedKeepNames); nil
// restores the built-in ones. The map is read, never written, afterwards.
func (q *tracePushQueue) setKeepNames(names map[string]uint8) {
	if names == nil {
		names = traceKeepBuiltin
	}
	q.keep.Store(&names)
}

// classOf is the push-queue class of evt with the names in force.
func (q *tracePushQueue) classOf(evt *TraceEvent) TraceClass {
	return classifyTraceEvent(evt, *q.keep.Load())
}

func (q *tracePushQueue) total() int {
	n := 0
	for i := range q.rings {
		n += q.rings[i].n
	}
	return n
}

// push queues evt. With the queue full it drops the oldest event of the most
// droppable class queued when that class is at least as droppable as evt's,
// else evt itself.
func (q *tracePushQueue) push(evt TraceEvent) {
	class := q.classOf(&evt)
	evt.QueuedClass = class
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.total() >= q.max {
		victim := class
		for _, c := range traceDropOrder {
			if q.rings[c].n > 0 {
				victim = c
				break
			}
		}
		if q.rings[victim].n == 0 || traceDroppability(victim) < traceDroppability(class) {
			q.lost[class]++
			return
		}
		if q.rings[victim].pop().urgent {
			q.urgent--
		}
		q.lost[victim]++
	}
	q.seq++
	item := queuedTraceEvent{seq: q.seq, evt: evt, urgent: traceEventUrgent(&evt)}
	if item.urgent {
		q.urgent++
	}
	q.rings[class].push(item, q.max)
}

// drain removes and returns at most limit events (limit <= 0: all), oldest
// first across all classes. A later drain never returns an event a previous
// drain already returned.
func (q *tracePushQueue) drain(limit int) []TraceEvent {
	q.mu.Lock()
	defer q.mu.Unlock()
	total := q.total()
	if total == 0 {
		return nil
	}
	if limit <= 0 || limit > total {
		limit = total
	}
	out := make([]TraceEvent, 0, limit)
	for len(out) < limit {
		var from *tracePushRing
		for i := range q.rings {
			r := &q.rings[i]
			if r.n > 0 && (from == nil || r.front().seq < from.front().seq) {
				from = r
			}
		}
		item := from.pop()
		if item.urgent {
			q.urgent--
		}
		out = append(out, item.evt)
	}
	return out
}

// hasUrgent reports whether a queued event is urgent (traceEventUrgent).
func (q *tracePushQueue) hasUrgent() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.urgent > 0
}

// len returns the current queue depth.
func (q *tracePushQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.total()
}

// dropped returns the events dropped since start, by class.
func (q *tracePushQueue) dropped() [traceClassCount]uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.lost
}

// QueuedTraceClass is the class the push queue gave evt; the telemetry
// transport uses it to count lost batches by class. An event that never went
// through the queue is significant.
func QueuedTraceClass(evt *TraceEvent) TraceClass { return evt.QueuedClass }
