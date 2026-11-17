package ebpf

import (
	"strings"
	"testing"
	"time"
)

func lossTotals(kernel uint64, queue, delivery traceClassCounts) traceLossTotals {
	return traceLossTotals{Kernel: kernel, Queue: queue, Delivery: delivery}
}

// classes builds per-class counts: noise, watched, significant.
func classes(noise, watched, significant uint64) traceClassCounts {
	var c traceClassCounts
	c[TraceClassNoise], c[TraceClassWatched], c[TraceClassSignificant] = noise, watched, significant
	return c
}

// The status reports loss of the last hour, by class, and
// when the last loss happened.
func TestTraceLossHistoryWindow(t *testing.T) {
	var h traceLossHistory
	t0 := time.Date(2026, 10, 16, 9, 0, 30, 0, time.UTC)
	h.observe(t0, traceLossTotals{})
	if got, last := h.recent(t0); got.total() != 0 || !last.IsZero() {
		t.Fatalf("no loss: %v %v", got, last)
	}
	// 09:05 — a burst: queue noise, watched and significant, kernel loss.
	t1 := t0.Add(5 * time.Minute)
	burst := lossTotals(2, classes(100, 4, 3), traceClassCounts{})
	h.observe(t1, burst)
	// 09:30 — unconfirmed batches.
	t2 := t0.Add(30 * time.Minute)
	later := lossTotals(2, classes(100, 4, 3), classes(10, 0, 1))
	h.observe(t2, later)
	if got, last := h.recent(t2); got != classes(110, 4, 6) || !last.Equal(t2) {
		t.Fatalf("at 09:30: %v last %v", got, last)
	}
	// Unchanged counters add nothing and keep the last loss time.
	h.observe(t2.Add(time.Minute), later)
	// 10:05:30 — the 09:05 burst is older than an hour.
	t3 := t1.Add(time.Hour)
	if got, last := h.recent(t3); got != classes(10, 0, 1) || !last.Equal(t2) {
		t.Fatalf("at 10:05: %v last %v", got, last)
	}
	// 10:31 — nothing recent; the last loss time stays.
	t4 := t2.Add(time.Hour + time.Minute)
	if got, last := h.recent(t4); got.total() != 0 || !last.Equal(t2) {
		t.Fatalf("at 10:31: %v last %v", got, last)
	}
	// A bucket of an earlier hour is reused, not added to.
	h.observe(t1.Add(time.Hour), lossTotals(2, classes(105, 4, 3), classes(10, 0, 1)))
	if got, _ := h.recent(t1.Add(time.Hour)); got != classes(15, 0, 1) {
		t.Fatalf("reused bucket: %v", got)
	}
}

// A counter below its previous value restarted (trace object reloaded):
// its new value counts in full, never as a huge unsigned delta.
func TestTraceLossHistoryCounterRestart(t *testing.T) {
	var h traceLossHistory
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	h.observe(now, traceLossTotals{Kernel: 500})
	h.observe(now.Add(time.Second), traceLossTotals{Kernel: 7})
	if got, _ := h.recent(now.Add(time.Second)); got[TraceClassSignificant] != 507 {
		t.Fatalf("significant %d, want 507", got[TraceClassSignificant])
	}
}

func TestTraceAgentLossAlert(t *testing.T) {
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	if _, ok := traceAgentLossAlert(traceLossTotals{Kernel: 9}, now); ok {
		t.Fatal("kernel loss has its own event (traceLossAlert)")
	}
	evt, ok := traceAgentLossAlert(lossTotals(0, classes(1200, 0, 0), traceClassCounts{}), now)
	if !ok || evt.Severity != SevLow || evt.EventName != traceLossEventName || evt.Category != "security" {
		t.Fatalf("noise only: %+v", evt)
	}
	const wantQueue = "send queue full (events arrived faster than the agent sends them): 1200 dropped (0 process, security, medium+ or enforced; 0 sensitive-file accesses below medium; 1200 other low-severity file/network)"
	if want := "trace events lost in the agent since the last check: " + wantQueue; evt.Description != want {
		t.Fatalf("description %q, want %q", evt.Description, want)
	}
	// A full queue says nothing about the control plane.
	if strings.Contains(evt.Description, "control plane") {
		t.Fatalf("queue-only description blames the control plane: %q", evt.Description)
	}
	evt, ok = traceAgentLossAlert(lossTotals(0, classes(5, 7, 0), traceClassCounts{}), now)
	if !ok || evt.Severity != SevMedium {
		t.Fatalf("watched lost must be MEDIUM (stored, no incident): %+v", evt)
	}
	evt, ok = traceAgentLossAlert(lossTotals(0, classes(5, 0, 0), classes(0, 0, 2)), now)
	if !ok || evt.Severity != SevHigh {
		t.Fatalf("significant lost must be HIGH: %+v", evt)
	}
	if !strings.Contains(evt.Description, "2 in batches the control plane never confirmed (2 process, security, medium+ or enforced; 0 sensitive-file accesses below medium; 0 other low-severity file/network)") {
		t.Fatalf("description %q", evt.Description)
	}
	if !strings.Contains(evt.Description, "send queue full (events arrived faster than the agent sends them): 5 dropped") {
		t.Fatalf("description %q", evt.Description)
	}
	// Unconfirmed batches alone: only this part names the control plane.
	evt, ok = traceAgentLossAlert(lossTotals(0, traceClassCounts{}, classes(0, 0, 2)), now)
	if !ok || strings.Contains(evt.Description, "send queue") {
		t.Fatalf("delivery only: %+v", evt)
	}
	// The event itself is significant in the push queue.
	if classifyTraceEvent(&evt, traceKeepBuiltin) != TraceClassSignificant {
		t.Fatal("loss event not significant")
	}
}
