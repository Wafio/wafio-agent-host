package agent

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTelemetryRetentionRetriesExactBatchUntilReceipt(t *testing.T) {
	q := newTelemetryRetention(2, 1024, time.Minute)
	now := time.Unix(1, 0)
	if !q.add("a", []byte("payload"), telemetryBatchCounts{events: 3}, now) {
		t.Fatal("enqueue")
	}
	first := q.next(now)
	if first == nil {
		t.Fatal("missing send")
	}
	if q.next(now.Add(time.Second)) != nil {
		t.Fatal("busy retry")
	}
	retry := q.next(now.Add(2 * time.Second))
	if retry == nil || string(first.body) != string(retry.body) || first.id != retry.id {
		t.Fatal("retry changed identity/payload")
	}
	q.receipt("other", true)
	if q.snapshot().PendingBatches != 1 {
		t.Fatal("unknown receipt removed batch")
	}
	q.receipt("a", false)
	if q.snapshot().PendingBatches != 1 {
		t.Fatal("rejection discarded retry")
	}
	q.receipt("a", true)
	if got := q.snapshot(); got.PendingBatches != 0 || got.ProcessAccepted != 1 {
		t.Fatalf("receipt %+v", got)
	}
}

func TestTelemetryRetentionBoundsAndExpiryAccountLostEvents(t *testing.T) {
	q := newTelemetryRetention(1, 4, time.Minute)
	now := time.Unix(1, 0)
	if !q.add("a", []byte("1234"), telemetryBatchCounts{events: 3}, now) {
		t.Fatal("enqueue")
	}
	if q.add("b", []byte("1"), telemetryBatchCounts{events: 2}, now) {
		t.Fatal("capacity exceeded")
	}
	if q.next(now.Add(time.Minute)) != nil {
		t.Fatal("expired batch sent")
	}
	s := q.snapshot()
	if s.DroppedBatches != 2 || s.DroppedEvents != 5 || s.PendingBytes != 0 {
		t.Fatalf("loss counters %+v", s)
	}
}

// Trace events of a discarded batch reach the trace loss
// accounting by class — on expiry, on a full queue and on an encode failure.
// Index: wafebpf.TraceClass (0 significant, 1 watched, 2 noise).
func TestTelemetryRetentionReportsTraceLoss(t *testing.T) {
	q := newTelemetryRetention(1, 1024, time.Minute)
	var lost [3]int
	q.setTraceLoss(func(c [3]int) {
		for i := range c {
			lost[i] += c[i]
		}
	})
	now := time.Unix(1, 0)
	if !q.add("a", []byte("x"), telemetryBatchCounts{events: 5, trace: [3]int{1, 1, 3}}, now) {
		t.Fatal("enqueue")
	}
	if q.add("b", []byte("y"), telemetryBatchCounts{events: 2, trace: [3]int{0, 0, 2}}, now) {
		t.Fatal("capacity exceeded")
	}
	if lost != [3]int{0, 0, 2} {
		t.Fatalf("full queue: %v", lost)
	}
	q.next(now.Add(time.Minute)) // expires "a"
	if lost != [3]int{1, 1, 5} {
		t.Fatalf("expiry: %v", lost)
	}
	q.discard(telemetryBatchCounts{events: 1, trace: [3]int{1, 0, 0}})
	if lost != [3]int{2, 1, 5} {
		t.Fatalf("discard: %v", lost)
	}
	// A batch without trace events reports nothing; a receipt is no loss.
	q.discard(telemetryBatchCounts{events: 4})
	q.add("c", []byte("z"), telemetryBatchCounts{events: 1, trace: [3]int{1, 0, 0}}, now.Add(time.Minute))
	q.receipt("c", true)
	if lost != [3]int{2, 1, 5} {
		t.Fatalf("no loss: %v", lost)
	}
	if s := q.snapshot(); s.DroppedBatches != 4 || s.DroppedEvents != 12 {
		t.Fatalf("delivery counters %+v", s)
	}
}

// The telemetry loop sends more batches in one tick only while
// each drain came back full.
func TestPushPayloadFullBatch(t *testing.T) {
	if (&PushPayload{traceByClass: [3]int{499, 0, 0}}).fullBatch() {
		t.Fatal("499 trace events is not a full drain")
	}
	if !(&PushPayload{traceByClass: [3]int{200, 100, 200}}).fullBatch() {
		t.Fatal("500 trace events is a full drain")
	}
	if !(&PushPayload{traceByClass: [3]int{0, 0, 499}, traceUnencoded: 1}).fullBatch() {
		t.Fatal("an unencodable event still counts toward the drain")
	}
	if !(&PushPayload{Enforcement: make([]json.RawMessage, fastBatchLimit)}).fullBatch() {
		t.Fatal("a full enforcement drain")
	}
}
