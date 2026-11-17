package ebpf

import (
	"strings"
	"testing"
	"time"
)

func TestArgsString(t *testing.T) {
	b := make([]byte, 1024)
	copy(b, "-c")
	copy(b[128:], "echo hi")
	copy(b[256:], "x")
	if got := argsString(b); got != "-c echo hi x" {
		t.Fatalf("got %q", got)
	}
	if got := argsString(make([]byte, 1024)); got != "" {
		t.Fatalf("empty region: %q", got)
	}
	full := []byte(strings.Repeat("a", 16))
	if got := argsString(full); got != strings.Repeat("a", 16) {
		t.Fatalf("unterminated: %q", got)
	}
	if got := argsString([]byte("\x00\x00a\x00\x00b\x00")); got != "a b" {
		t.Fatalf("leading/trailing NULs: %q", got)
	}
}

// The reader decodes an event without per-NUL allocations (argsString used
// bytes.Split over the 1 KiB argv region: ~24 KiB per event).
func TestDecodeTraceRecordAllocations(t *testing.T) {
	raw := make([]byte, TraceEventSizeWithIdentity)
	copy(raw[36:40], []byte{byte(TraceOpen)})
	copy(raw[96:], "/usr/lib/x.so")
	allocs := testing.AllocsPerRun(200, func() {
		if _, err := decodeTraceRecord(raw, time.Second, "a"); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 20 {
		t.Fatalf("decodeTraceRecord: %.0f allocations per event", allocs)
	}
	evt, _ := decodeTraceRecord(raw, 0, "agent-1")
	if !strings.HasPrefix(evt.EventID, "agent-1:0:0:3") || evt.Filename != "/usr/lib/x.so" {
		t.Fatalf("decoded %q %q", evt.EventID, evt.Filename)
	}
}

func TestEventRing(t *testing.T) {
	r := newEventRing[int](3)
	for i := 1; i <= 5; i++ {
		r.push(i)
	}
	var got []int
	r.newestFirst(func(v *int) bool { got = append(got, *v); return true })
	if len(got) != 3 || got[0] != 5 || got[2] != 3 || r.len() != 3 {
		t.Fatalf("ring %v len %d", got, r.len())
	}
}

func TestTraceEventStore(t *testing.T) {
	s := newTraceEventStore(4, 2, 3)
	for i := 0; i < 6; i++ {
		s.record(TraceEvent{TID: uint32(i), Severity: uint32(i % 3), SeverityName: severityName(uint32(i % 3)), Category: "file"}, "file")
	}
	s.record(TraceEvent{TID: 100, Category: "process"}, "process")
	s.record(TraceEvent{TID: 200, Category: "x"}, "")

	// Category ring: newest 2 file events, oldest first.
	if got := s.filter("file", 0, 0); len(got) != 2 || got[0].TID != 4 || got[1].TID != 5 {
		t.Fatalf("file ring %+v", got)
	}
	// Recent ring: newest 4 of everything; severity and limit filters.
	if got := s.filter("", 0, 0); len(got) != 4 || got[0].TID != 4 || got[3].TID != 200 {
		t.Fatalf("recent ring %+v", got)
	}
	if got := s.filter("", 1, 1); len(got) != 1 || got[0].TID != 5 {
		t.Fatalf("filtered %+v", got)
	}
	// Push queue: capacity 3, noise (file below MEDIUM, and the INFO event
	// of category "x") dropped first, the MEDIUM file and process events
	// kept, drained once in push order.
	got := s.push.drain(0)
	lost := s.push.dropped()
	if len(got) != 3 || got[0].TID != 2 || got[1].TID != 5 || got[2].TID != 100 || lost[TraceClassNoise] != 5 || lost[TraceClassSignificant] != 0 {
		t.Fatalf("push queue %+v dropped %v", got, lost)
	}
	if again := s.push.drain(0); again != nil {
		t.Fatalf("drained twice: %+v", again)
	}
	bySev, byCat := map[string]uint64{}, map[string]uint64{}
	if used := s.breakdown(bySev, byCat); used != 4 || byCat["file"] != 2 || byCat["process"] != 1 {
		t.Fatalf("breakdown used=%d %v %v", used, bySev, byCat)
	}
}

// A rise in the shed counters is a security event (≤ 1 per
// check), not only a log line, so a flood that pushes the ring into shedding
// is visible on the dashboard: MEDIUM, HIGH once sustained or large.
func TestTraceShedAlert(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if _, ok := traceShedAlert(nil, nil, 1, now); ok {
		t.Fatal("nothing shed")
	}
	prev := map[uint32]uint64{TraceOpen: 10}
	cur := map[uint32]uint64{TraceOpen: 25, TraceConnect: 2}
	evt, ok := traceShedAlert(prev, cur, 1, now)
	if !ok || evt.EventName != traceShedEventName || evt.Category != "security" || evt.Severity != SevMedium || evt.SeverityName != severityName(SevMedium) {
		t.Fatalf("first shed: ok=%v %+v", ok, evt)
	}
	if !strings.Contains(evt.Description, "17 low-severity events shed") || !strings.Contains(evt.Description, "openat=15 connect=2") ||
		strings.Contains(evt.Description, "consecutive") {
		t.Fatalf("description %q", evt.Description)
	}
	if evt.Timestamp != "2026-10-16T12:00:00Z" {
		t.Errorf("timestamp = %q", evt.Timestamp)
	}
	if _, ok := traceShedAlert(cur, cur, 2, now); ok {
		t.Fatal("no new shed")
	}
	// Sustained: the 6th consecutive check with shedding is HIGH.
	if evt, _ := traceShedAlert(prev, cur, traceShedHighStreak-1, now); evt.Severity != SevMedium {
		t.Fatalf("streak %d: %s", traceShedHighStreak-1, evt.SeverityName)
	}
	evt, _ = traceShedAlert(prev, cur, traceShedHighStreak, now)
	if evt.Severity != SevHigh || !strings.Contains(evt.Description, "shedding for 6 consecutive checks") {
		t.Fatalf("sustained: %s %q", evt.SeverityName, evt.Description)
	}
	// Large: one check over the count is HIGH at once.
	evt, _ = traceShedAlert(nil, map[uint32]uint64{TraceOpen: traceShedHighCount}, 1, now)
	if evt.Severity != SevHigh {
		t.Fatalf("large shed: %s", evt.SeverityName)
	}
	// A counter reset (new trace object) counts from zero.
	evt, ok = traceShedAlert(map[uint32]uint64{TraceOpen: 500}, map[uint32]uint64{TraceOpen: 3}, 1, now)
	if !ok || !strings.Contains(evt.Description, "3 low-severity events shed") {
		t.Fatalf("after reset: ok=%v %q", ok, evt.Description)
	}
}
