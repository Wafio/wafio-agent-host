package ebpf

import "testing"

// drainQueue is the destructive FIFO used by the push path: every event must be
// delivered exactly once — no re-delivery on later ticks (duplicate counts on
// the server), no silent aging-out under load (lost events).
func TestDrainQueue_FIFO_OnceOnly(t *testing.T) {
	q := newDrainQueue[int](8)
	for i := 1; i <= 5; i++ {
		q.push(i)
	}
	got := q.drain(10)
	if len(got) != 5 {
		t.Fatalf("first drain: want 5, got %d (%v)", len(got), got)
	}
	for i, v := range got {
		if v != i+1 {
			t.Fatalf("FIFO order broken: got[%d]=%d", i, v)
		}
	}
	// Second drain with nothing new must return nothing — no duplicates.
	if again := q.drain(10); len(again) != 0 {
		t.Fatalf("second drain: want 0 (no dup), got %d (%v)", len(again), again)
	}
	// Events added after a drain are delivered on the next drain only.
	q.push(6)
	got2 := q.drain(10)
	if len(got2) != 1 || got2[0] != 6 {
		t.Fatalf("post-drain push lost/duplicated: %v", got2)
	}
}

func TestDrainQueue_LimitBatches(t *testing.T) {
	q := newDrainQueue[int](16)
	for i := 1; i <= 10; i++ {
		q.push(i)
	}
	b1 := q.drain(4)
	if len(b1) != 4 || b1[0] != 1 || b1[3] != 4 {
		t.Fatalf("batch 1 wrong: %v", b1)
	}
	b2 := q.drain(4)
	if len(b2) != 4 || b2[0] != 5 || b2[3] != 8 {
		t.Fatalf("batch 2 wrong: %v", b2)
	}
	b3 := q.drain(4)
	if len(b3) != 2 || b3[0] != 9 || b3[1] != 10 {
		t.Fatalf("batch 3 wrong: %v", b3)
	}
}

func TestDrainQueue_CapDropsOldest(t *testing.T) {
	q := newDrainQueue[int](4)
	for i := 1; i <= 10; i++ {
		q.push(i)
	}
	got := q.drain(10)
	// Oldest events were dropped when the cap was hit — the newest survive.
	if len(got) != 4 {
		t.Fatalf("want capped 4, got %d", len(got))
	}
	if got[0] != 7 || got[3] != 10 {
		t.Fatalf("cap must drop oldest, got %v", got)
	}
}

func TestDrainQueue_ZeroLimit(t *testing.T) {
	q := newDrainQueue[int](8)
	q.push(1)
	if got := q.drain(0); len(got) != 1 {
		t.Fatalf("limit<=0 should mean all, got %d", len(got))
	}
}

func TestDrainQueueReportsOverflowLoss(t *testing.T) {
	q := newDrainQueue[int](2)
	q.push(1)
	q.push(2)
	q.push(3)
	if q.dropped() != 1 || q.len() != 2 {
		t.Fatal("queue loss/depth not reported")
	}
	q.drain(0)
	if q.dropped() != 1 {
		t.Fatal("drain reset cumulative loss")
	}
}
