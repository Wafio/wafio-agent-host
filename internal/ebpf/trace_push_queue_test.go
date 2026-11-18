package ebpf

import (
	"sync"
	"testing"
)

func noiseEvt(tid uint32) TraceEvent {
	return TraceEvent{TID: tid, Category: "file", Severity: SevInfo}
}

func keptEvt(tid uint32) TraceEvent {
	return TraceEvent{TID: tid, Category: "process", Severity: SevInfo}
}

func tids(evts []TraceEvent) []uint32 {
	out := make([]uint32, len(evts))
	for i, e := range evts {
		out[i] = e.TID
	}
	return out
}

func equalTIDs(a []uint32, b ...uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The class ingest stores only after a raise is noise; every
// event ingest always stores is kept.
func TestTraceEventIsNoise(t *testing.T) {
	cases := []struct {
		name  string
		evt   TraceEvent
		noise bool
	}{
		{"file info", TraceEvent{Category: "file", Severity: SevInfo}, true},
		{"file low", TraceEvent{Category: "file", Severity: SevLow}, true},
		{"network low", TraceEvent{Category: "network", Severity: SevLow}, true},
		{"file,network info", TraceEvent{Category: "file,network", Severity: SevInfo}, true},
		{"no category info", TraceEvent{Severity: SevInfo}, true},
		{"file medium", TraceEvent{Category: "file", Severity: SevMedium}, false},
		{"network critical", TraceEvent{Category: "network", Severity: SevCritical}, false},
		{"process info", TraceEvent{Category: "process", Severity: SevInfo}, false},
		{"security info", TraceEvent{Category: "security", Severity: SevInfo}, false},
		{"file,security low", TraceEvent{Category: "file,security", Severity: SevLow}, false},
		{"file info alerted", TraceEvent{Category: "file", Severity: SevInfo, Action: ActionAlert}, false},
		{"file info simulated", TraceEvent{Category: "file", Severity: SevInfo, Action: ActionSimulate}, false},
		{"network info killed", TraceEvent{Category: "network", Severity: SevInfo, Action: ActionKill}, false},
		{"kill outcome update", TraceEvent{Category: "file", Severity: SevInfo, OutcomeUpdate: true}, false},
	}
	for _, tc := range cases {
		if got := traceEventIsNoise(&tc.evt); got != tc.noise {
			t.Errorf("%s: noise = %v, want %v", tc.name, got, tc.noise)
		}
	}
}

func TestTracePushQueueDropsNoiseFirst(t *testing.T) {
	q := newTracePushQueue(4)
	q.push(noiseEvt(1))
	q.push(keptEvt(2))
	q.push(noiseEvt(3))
	q.push(keptEvt(4))
	// Full: a kept event evicts the oldest noise event (1).
	q.push(keptEvt(5))
	// Full: a noise event evicts the oldest noise event (3).
	q.push(noiseEvt(6))
	// Full: another kept event evicts the last noise event (6).
	q.push(keptEvt(7))
	// Full of kept events: a noise event is dropped itself.
	q.push(noiseEvt(8))
	lost := q.dropped()
	if lost[TraceClassNoise] != 4 || lost[TraceClassSignificant] != 0 {
		t.Fatalf("dropped %v, want 4 noise and 0 significant", lost)
	}
	// Full of kept events: a kept event evicts the oldest kept event (2).
	q.push(keptEvt(9))
	if lost = q.dropped(); lost[TraceClassNoise] != 4 || lost[TraceClassSignificant] != 1 {
		t.Fatalf("dropped %v, want 4 noise and 1 significant", lost)
	}
	if got := tids(q.drain(0)); !equalTIDs(got, 4, 5, 7, 9) {
		t.Fatalf("drained %v, want [4 5 7 9]", got)
	}
	if q.len() != 0 || q.drain(0) != nil {
		t.Fatal("queue not empty after a full drain")
	}
}

func TestTracePushQueueDrainKeepsPushOrder(t *testing.T) {
	q := newTracePushQueue(100)
	for i := uint32(1); i <= 10; i++ {
		if i%3 == 0 {
			q.push(keptEvt(i))
		} else {
			q.push(noiseEvt(i))
		}
	}
	if got := tids(q.drain(4)); !equalTIDs(got, 1, 2, 3, 4) {
		t.Fatalf("first drain %v", got)
	}
	q.push(keptEvt(11))
	if got := tids(q.drain(0)); !equalTIDs(got, 5, 6, 7, 8, 9, 10, 11) {
		t.Fatalf("second drain %v", got)
	}
	if q.len() != 0 {
		t.Fatalf("len %d after drain", q.len())
	}
}

// Classes grow by doubling up to the capacity and keep order across the
// wrap of a reused buffer.
func TestTracePushQueueGrowsAndWraps(t *testing.T) {
	const capacity = 1000
	q := newTracePushQueue(capacity)
	next := uint32(1)
	want := uint32(1)
	// 5 rounds of 700 pushed and 650 drained: at most 950 queued, nothing
	// dropped, the buffer wraps several times.
	for round := 0; round < 5; round++ {
		for i := 0; i < 700; i++ {
			q.push(noiseEvt(next))
			next++
		}
		for _, e := range q.drain(650) {
			if e.TID != want {
				t.Fatalf("round %d: got TID %d, want %d", round, e.TID, want)
			}
			want++
		}
	}
	if lost := q.dropped(); lost[TraceClassNoise] != 0 || q.len() != 250 {
		t.Fatalf("dropped %v len %d, want 0 and 250", lost, q.len())
	}
	for q.len() < capacity {
		q.push(noiseEvt(next))
		next++
	}
	if got := len(q.rings[TraceClassNoise].buf); got != capacity {
		t.Fatalf("noise buffer %d, want the capacity %d", got, capacity)
	}
	q.push(noiseEvt(next))
	if lost := q.dropped(); lost[TraceClassNoise] != 1 || q.len() != capacity {
		t.Fatalf("over capacity: dropped %v len %d", lost, q.len())
	}
	if first := q.drain(1); first[0].TID != want+1 {
		t.Fatalf("after the drop the oldest is TID %d, want %d", first[0].TID, want+1)
	}
}

func TestTracePushQueueConcurrent(t *testing.T) {
	q := newTracePushQueue(256)
	var wg sync.WaitGroup
	const writers, per = 4, 2000
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if i%5 == 0 {
					q.push(keptEvt(uint32(w*per + i)))
				} else {
					q.push(noiseEvt(uint32(w*per + i)))
				}
			}
		}(w)
	}
	drained := 0
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	for {
		select {
		case <-done:
			drained += len(q.drain(0))
			lost := q.dropped()
			if total := uint64(drained) + lost[0] + lost[1] + lost[2]; total != writers*per {
				t.Fatalf("drained %d + dropped %v != pushed %d", drained, lost, writers*per)
			}
			return
		default:
			drained += len(q.drain(64))
		}
	}
}

func openEvt(tid uint32, path string, flags uint32) TraceEvent {
	return TraceEvent{TID: tid, EventType: TraceOpen, EventName: "openat", Category: "file", Severity: SevInfo, Filename: path, Flags: flags}
}

// An openat the kernel would not shed is not noise in the
// push queue either — same names, same component rules.
func TestTraceOpenKept(t *testing.T) {
	names := shedKeepNames(map[uint32]*EnforcementPolicy{
		1: {Enabled: true, Action: "alert", MatchFilename: "/opt/app/secret.key,/srv/vault/"},
	})
	const wronly, trunc = 1, 0o1000
	cases := []struct {
		name string
		evt  TraceEvent
		kept bool
	}{
		{"auth dir read", openEvt(1, "/etc/pam.d/common-auth", 0), true},
		{"credential final name read", openEvt(1, "/etc/shadow", 0), true},
		{"name only when final", openEvt(1, "/etc/shadow/x", 0), false},
		{"case folded", openEvt(1, "/etc/PAM.D/sshd", 0), true},
		{"write-only name read", openEvt(1, "/etc/hostname", 0), false},
		{"write-only name written", openEvt(1, "/etc/hostname", wronly), true},
		{"truncate counts as write", openEvt(1, "/etc/hosts", trunc), true},
		{"any entry keeps a write below it", openEvt(1, "/etc/systemd/system/x.service", wronly), true},
		{"policy file", openEvt(1, "/opt/app/secret.key", 0), true},
		{"policy dir", openEvt(1, "/srv/vault/a/b", 0), true},
		{"ordinary read", openEvt(1, "/usr/lib/x86_64-linux-gnu/libc.so.6", 0), false},
		{"relative write", openEvt(1, "out.log", wronly), true},
		{"relative read", openEvt(1, "in.txt", 0), false},
		{"not openat", TraceEvent{EventType: TraceUnlink, Category: "file", Filename: "/etc/shadow"}, false},
	}
	for _, tc := range cases {
		if got := traceOpenKept(&tc.evt, names); got != tc.kept {
			t.Errorf("%s (%s): kept = %v, want %v", tc.name, tc.evt.Filename, got, tc.kept)
		}
	}
	// Policy names apply only once the policy sync set them.
	q := newTracePushQueue(8)
	secret := &TraceEvent{EventType: TraceOpen, Category: "file", Filename: "/opt/app/secret.key"}
	if q.classOf(secret) != TraceClassNoise {
		t.Fatal("policy file watched before any policy sync")
	}
	q.setKeepNames(names)
	if q.classOf(secret) != TraceClassWatched {
		t.Fatal("policy file not watched after the policy sync")
	}
	q.setKeepNames(nil)
	if q.classOf(&TraceEvent{EventType: TraceOpen, Category: "file", Filename: "/etc/pam.d/sshd"}) != TraceClassWatched {
		t.Fatal("nil names must restore the built-in ones")
	}
	// A term that does not narrow adds no name, so
	// a policy on "/usr/" cannot make every library load watched.
	broad := shedKeepNames(map[uint32]*EnforcementPolicy{1: {Enabled: true, Action: "alert", MatchFilename: "/usr/,lib,/tmp/,/srv/vault/"}})
	for _, name := range []string{"usr", "lib", "tmp"} {
		if broad[name] != traceKeepBuiltin[name] {
			t.Errorf("broad term %q added keep bits %d", name, broad[name])
		}
	}
	if broad["vault"]&traceKeepDir == 0 {
		t.Error("a narrowing directory term must still be kept")
	}
}

// A flood of cheap reads cannot push a sensitive read out of a full queue,
// and the drained event carries its class for transport loss accounting.
func TestTracePushQueueKeepsSensitiveOpenUnderFlood(t *testing.T) {
	q := newTracePushQueue(4)
	q.push(openEvt(1, "/etc/pam.d/common-auth", 0))
	for i := uint32(2); i < 100; i++ {
		q.push(openEvt(i, "/etc/hostname", 0))
	}
	got := q.drain(0)
	if len(got) != 4 || got[0].TID != 1 {
		t.Fatalf("drained %v, want the pam.d read first", tids(got))
	}
	if QueuedTraceClass(&got[0]) != TraceClassWatched || QueuedTraceClass(&got[1]) != TraceClassNoise {
		t.Fatalf("classes: pam.d %d hostname %d", QueuedTraceClass(&got[0]), QueuedTraceClass(&got[1]))
	}
	if lost := q.dropped(); lost[TraceClassNoise] != 95 || lost[TraceClassWatched] != 0 {
		t.Fatalf("dropped %v", lost)
	}
}

// A burst's buffer is released once its class drains empty; a small one is
// kept for the steady state.
func TestTracePushQueueReleasesBurstMemory(t *testing.T) {
	q := newTracePushQueue(tracePushQueueCap)
	for i := uint32(0); i < 5000; i++ {
		q.push(noiseEvt(i))
	}
	if got := len(q.rings[TraceClassNoise].buf); got < 5000 {
		t.Fatalf("buffer %d for 5000 queued", got)
	}
	q.drain(4999)
	if q.rings[TraceClassNoise].buf == nil {
		t.Fatal("released while an event is still queued")
	}
	q.drain(0)
	if q.rings[TraceClassNoise].buf != nil {
		t.Fatalf("burst buffer of %d kept after draining empty", cap(q.rings[TraceClassNoise].buf))
	}
	q.push(noiseEvt(1))
	q.drain(0)
	if len(q.rings[TraceClassNoise].buf) != tracePushInitialCap {
		t.Fatalf("steady-state buffer %d, want %d kept", len(q.rings[TraceClassNoise].buf), tracePushInitialCap)
	}
	if got := tids(func() []TraceEvent { q.push(noiseEvt(7)); return q.drain(0) }()); !equalTIDs(got, 7) {
		t.Fatalf("after release: %v", got)
	}
}

// A flood of reads of sensitive files (watched)
// evicts only noise and older watched events, never an exec, a setuid or an
// enforced event; a watched event is dropped itself when the queue holds
// only significant ones. Reads of /etc/passwd are noise.
func TestTracePushQueueWatchedFloodKeepsSignificant(t *testing.T) {
	if c := classifyTraceEvent(&TraceEvent{EventType: TraceOpen, Category: "file", Filename: "/etc/passwd"}, traceKeepBuiltin); c != TraceClassNoise {
		t.Fatalf("/etc/passwd read class %d, want noise", c)
	}
	q := newTracePushQueue(4)
	q.push(keptEvt(1)) // exec
	q.push(noiseEvt(2))
	q.push(TraceEvent{TID: 3, Category: "security", EventName: "setuid", Severity: SevHigh})
	for i := uint32(10); i < 1010; i++ {
		q.push(openEvt(i, "/etc/pam.d/common-auth", 0))
	}
	got := tids(q.drain(0))
	if len(got) != 4 || got[0] != 1 || got[1] != 3 || got[2] != 1008 || got[3] != 1009 {
		t.Fatalf("drained %v, want [1 3 1008 1009]", got)
	}
	lost := q.dropped()
	if lost[TraceClassSignificant] != 0 || lost[TraceClassNoise] != 1 || lost[TraceClassWatched] != 998 {
		t.Fatalf("dropped %v", lost)
	}
	full := newTracePushQueue(2)
	full.push(keptEvt(1))
	full.push(keptEvt(2))
	full.push(openEvt(3, "/etc/pam.d/common-auth", 0))
	if got := tids(full.drain(0)); !equalTIDs(got, 1, 2) {
		t.Fatalf("all-significant queue: drained %v", got)
	}
	if lost := full.dropped(); lost[TraceClassWatched] != 1 {
		t.Fatalf("all-significant queue: dropped %v", lost)
	}
}

// The queue knows whether an event the telemetry loop sends at
// once (HIGH+, enforced, kill outcome) waits, through pushes, evictions and
// drains.
func TestTracePushQueueUrgentCount(t *testing.T) {
	q := newTracePushQueue(3)
	if q.hasUrgent() {
		t.Fatal("empty queue urgent")
	}
	q.push(keptEvt(1)) // process INFO: significant, not urgent
	q.push(noiseEvt(2))
	if q.hasUrgent() {
		t.Fatal("process INFO and file INFO are not urgent")
	}
	for _, evt := range []TraceEvent{
		{TID: 3, Category: "process", Severity: SevHigh},
		{TID: 3, Category: "file", Severity: SevInfo, Action: ActionKill},
		{TID: 3, Category: "process", Severity: SevInfo, OutcomeUpdate: true},
	} {
		if !traceEventUrgent(&evt) {
			t.Fatalf("not urgent: %+v", evt)
		}
	}
	if traceEventUrgent(&TraceEvent{Category: "file", Severity: SevMedium}) {
		t.Fatal("MEDIUM is not urgent")
	}
	q.push(TraceEvent{TID: 3, Category: "process", Severity: SevCritical})
	if !q.hasUrgent() {
		t.Fatal("CRITICAL queued, not urgent")
	}
	// Draining the two oldest leaves the urgent one.
	if got := tids(q.drain(2)); !equalTIDs(got, 1, 2) || !q.hasUrgent() {
		t.Fatalf("drain %v urgent %v", got, q.hasUrgent())
	}
	if got := tids(q.drain(0)); !equalTIDs(got, 3) || q.hasUrgent() {
		t.Fatalf("drain %v urgent %v", got, q.hasUrgent())
	}
	// An urgent event evicted from a full queue no longer counts.
	full := newTracePushQueue(1)
	full.push(TraceEvent{TID: 4, Category: "file", Severity: SevInfo, Action: ActionAlert})
	full.push(keptEvt(5)) // same class (significant): evicts the oldest
	if full.hasUrgent() {
		t.Fatal("evicted urgent event still counted")
	}
	if got := tids(full.drain(0)); !equalTIDs(got, 5) {
		t.Fatalf("drain %v", got)
	}
}
