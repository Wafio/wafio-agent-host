package ebpf

import "sync"

// drainQueue is a bounded, destructive FIFO. Local drains do not guarantee delivery.
//
// It is a circular buffer allocated once: the trace ring reader pushes every
// event it reads, and the former slice version re-sliced from the front and
// re-allocated (copying the whole queue) every few thousand pushes once full.
type drainQueue[T any] struct {
	mu   sync.Mutex
	buf  []T // len == capacity
	head int // index of the oldest element
	n    int // elements queued
	lost uint64
}

func newDrainQueue[T any](capacity int) *drainQueue[T] {
	if capacity < 1 {
		capacity = 1
	}
	return &drainQueue[T]{buf: make([]T, capacity)}
}

// push appends an event. When the queue is full the OLDEST event is dropped —
// under sustained overload the freshest events survive.
func (q *drainQueue[T]) push(v T) {
	q.mu.Lock()
	defer q.mu.Unlock()
	c := len(q.buf)
	if q.n == c {
		q.buf[q.head] = v
		q.head = (q.head + 1) % c
		q.lost++
		return
	}
	q.buf[(q.head+q.n)%c] = v
	q.n++
}

// drain removes and returns at most limit events, oldest first. limit <= 0
// means everything currently queued. A later drain never returns an event a
// previous drain already returned.
func (q *drainQueue[T]) drain(limit int) []T {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n == 0 {
		return nil
	}
	if limit <= 0 || limit > q.n {
		limit = q.n
	}
	c := len(q.buf)
	out := make([]T, limit)
	var zero T
	for i := range out {
		j := (q.head + i) % c
		out[i] = q.buf[j]
		q.buf[j] = zero // release references for the GC
	}
	q.head = (q.head + limit) % c
	q.n -= limit
	return out
}

// len returns the current queue depth.
func (q *drainQueue[T]) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}

func (q *drainQueue[T]) dropped() uint64 { q.mu.Lock(); defer q.mu.Unlock(); return q.lost }
