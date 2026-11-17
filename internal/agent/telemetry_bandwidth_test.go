package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/telemetrygz"
)

// Telemetry bandwidth: gzip payloads once the control plane
// announces them, one-second batches, snapshots on demand and rule hit
// counts only for lists that changed.

// The announcement turns gzip payloads on for the stream; a
// control plane that never sends it (older than v1.9.0) gets plain JSON.
func TestTelemetryAckGzipOnlyWhenAnnounced(t *testing.T) {
	body := []byte(`{"batch_id":"b","trace_events":[` + strings.Repeat(`{"event_name":"openat","category":"file"},`, 200) + `{}]}`)
	d := newTelemetryDemand()
	if d.gzip() || (*telemetryDemand)(nil).gzip() {
		t.Fatal("gzip before any announcement")
	}
	plain := telemetryAck(body, d.gzip())
	if plain.GetError() != string(body) || len(plain.GetPayload()) != 0 || plain.GetCommandId() != "ebpf:telemetry:v2" {
		t.Fatalf("plain ack: error %d bytes, payload %d bytes", len(plain.GetError()), len(plain.GetPayload()))
	}
	d.handle([]byte(`{"live_for_sec":0}`), time.Unix(1, 0))
	if d.gzip() {
		t.Fatal("announcement without telemetry_gzip turned gzip on")
	}
	d.handle([]byte(`{"live_for_sec":0,"telemetry_gzip":true}`), time.Unix(2, 0))
	if !d.gzip() {
		t.Fatal("telemetry_gzip announcement ignored")
	}
	gz := telemetryAck(body, d.gzip())
	if gz.GetError() != "" || len(gz.GetPayload()) == 0 || len(gz.GetPayload())*4 > len(body) {
		t.Fatalf("gzip ack: error %d bytes, payload %d bytes of %d", len(gz.GetError()), len(gz.GetPayload()), len(body))
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz.GetPayload()))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil || !bytes.Equal(out, body) {
		t.Fatalf("payload does not inflate to the batch: %v", err)
	}
	// The trailer declares the size the control plane charges before
	// inflating.
	p := gz.GetPayload()
	if n := binary.LittleEndian.Uint32(p[len(p)-4:]); int(n) != len(body) {
		t.Fatalf("declared size %d, want %d", n, len(body))
	}
}

// A batch that compresses more than the control plane's cap
// (telemetrygz.MaxRatio) — here 500 identical trace events, ±150× — is
// padded, not refused: the control plane accepts it and reads the batch
// byte for byte, and the padding is counted.
func TestTelemetryAckPadsHighRatioBatches(t *testing.T) {
	ev := `{"activity_outcome":"observed","timestamp":"2026-10-17T10:00:00.123456789Z","event_name":"openat","category":"file","comm":"nginx","filename":"/var/www/html/index.html"}`
	body := []byte(`{"batch_id":"0123456789abcdef","trace_events":[` + strings.TrimSuffix(strings.Repeat(ev+",", 500), ",") + `]}`)
	before := telemetryPaddedBatches.Load()
	ack := telemetryAck(body, true)
	gz := ack.GetPayload()
	if len(gz) == 0 || ack.GetError() != "" {
		t.Fatalf("not sent as gzip: payload %d bytes, error %d bytes", len(gz), len(ack.GetError()))
	}
	n, ok := telemetrygz.DeclaredSize(gz)
	if !ok || n != len(body) {
		t.Fatalf("control plane refuses the member: declared %d ok %v (%d bytes for %d, %.0f×)", n, ok, len(gz), len(body), float64(len(body))/float64(len(gz)))
	}
	out, err := telemetrygz.Inflate(gz, n)
	if err != nil || !bytes.Equal(out, body) {
		t.Fatalf("inflate: %v", err)
	}
	if got := telemetryPaddedBatches.Load() - before; got != 1 {
		t.Fatalf("padded batches counted %d, want 1", got)
	}
	// An ordinary batch is not padded.
	_ = telemetryAck([]byte(`{"batch_id":"0123456789abcdef","events":[]}`), true)
	if got := telemetryPaddedBatches.Load() - before; got != 1 {
		t.Fatalf("ordinary batch counted as padded (%d)", got)
	}
}

func TestEBPFTelemetryBatchDue(t *testing.T) {
	last := time.Unix(100, 0)
	early := last.Add(250 * time.Millisecond)
	if ebpfTelemetryBatchDue(last.Add(750*time.Millisecond), last, false, false, false) {
		t.Fatal("sent before the batch interval with nothing urgent")
	}
	if !ebpfTelemetryBatchDue(last.Add(time.Second), last, false, false, false) {
		t.Fatal("not sent after the batch interval")
	}
	if !ebpfTelemetryBatchDue(early, last, false, true, false) {
		t.Fatal("urgent event waited for the batch interval")
	}
	if !ebpfTelemetryBatchDue(early, last, true, false, false) {
		t.Fatal("backlog of full batches waited for the batch interval")
	}
	if !ebpfTelemetryBatchDue(early, last, false, false, true) {
		t.Fatal("a full queue (firewall drop flood) waited for the batch interval")
	}
	if !ebpfTelemetryBatchDue(time.Unix(1, 0), time.Time{}, false, false, false) {
		t.Fatal("first batch not sent")
	}
}

func TestTelemetryDemandLegacyUntilAnnounced(t *testing.T) {
	d := newTelemetryDemand()
	now := time.Unix(1000, 0)
	// A control plane that never sends the command (older than v1.9.0):
	// every medium payload carries the snapshots, as before.
	for i := range 3 {
		at := now.Add(time.Duration(i) * telemetryLiveInterval)
		if !d.due(at) {
			t.Fatalf("legacy mode: not due at tick %d", i)
		}
		d.sent(at)
	}
}

func TestTelemetryDemandIdleAndLive(t *testing.T) {
	d := newTelemetryDemand()
	now := time.Unix(1000, 0)
	d.handle([]byte(`{"live_for_sec":0}`), now) // announced on connect
	select {
	case <-d.kick:
		t.Fatal("announcement asked for an immediate snapshot")
	default:
	}
	if !d.due(now) {
		t.Fatal("first snapshot after the announcement not due")
	}
	d.sent(now)
	if d.due(now.Add(3*time.Second)) || d.due(now.Add(59*time.Second)) {
		t.Fatal("idle snapshots more often than once a minute")
	}
	if !d.due(now.Add(time.Minute)) {
		t.Fatal("idle snapshot not due after a minute")
	}
	// A viewer opens the Firewall page: live at once, for the window.
	viewer := now.Add(10 * time.Second)
	d.handle([]byte(`{"live_for_sec":120}`), viewer)
	select {
	case <-d.kick:
	default:
		t.Fatal("new viewer not served at once")
	}
	if !d.due(viewer) || !d.due(viewer.Add(119*time.Second)) {
		t.Fatal("not live inside the window")
	}
	d.sent(viewer.Add(119 * time.Second))
	if d.due(viewer.Add(121 * time.Second)) {
		t.Fatal("still live after the window")
	}
	// A shorter request never shortens a longer window.
	d.handle([]byte(`{"live_for_sec":600}`), viewer)
	d.handle([]byte(`{"live_for_sec":5}`), viewer.Add(time.Second))
	if !d.due(viewer.Add(500 * time.Second)) {
		t.Fatal("window shortened")
	}
}

func TestTelemetryDemandBoundsAndMalformed(t *testing.T) {
	d := newTelemetryDemand()
	now := time.Unix(1000, 0)
	d.handle([]byte(`not json`), now)
	if d.onDemand {
		t.Fatal("malformed command switched to on-demand mode")
	}
	d.handle([]byte(`{"live_for_sec":86400}`), now)
	if !d.due(now.Add(telemetryLiveMax - time.Second)) {
		t.Fatal("not live inside the capped window")
	}
	d.sent(now.Add(telemetryLiveMax - time.Second))
	if d.due(now.Add(telemetryLiveMax + time.Second)) {
		t.Fatal("live window not capped")
	}
	d2 := newTelemetryDemand()
	d2.handle([]byte(`{"live_for_sec":-5}`), now)
	if !d2.onDemand || now.Before(d2.liveUntil) {
		t.Fatalf("negative window: onDemand %v liveUntil %v", d2.onDemand, d2.liveUntil)
	}
}

func TestRuleStatsDeltaSendsChangedListsWhole(t *testing.T) {
	var d ruleStatsDelta
	now := time.Unix(1000, 0)
	snap := func(blHits uint32, tpHits uint64) *RuleStatsSnapshot {
		return &RuleStatsSnapshot{
			// A range is stored as several prefixes; the control plane sums
			// them, so both must travel together.
			Blocklist:     []wafebpf.BlocklistEntry{{IP: "10.0.0.0/25", HitCount: blHits}, {IP: "10.0.0.128/25", HitCount: 7}},
			Allowlist:     []wafebpf.AllowlistEntry{{IP: "192.0.2.1", HitCount: 1}},
			TracePolicies: []tracePolicyHitEntry{{PolicyID: 9, HitCount: tpHits}},
		}
	}
	first := d.filter(snap(1, 1), now)
	if first == nil || len(first.Blocklist) != 2 || len(first.Allowlist) != 1 || len(first.TracePolicies) != 1 {
		t.Fatalf("first report not full: %+v", first)
	}
	if got := d.filter(snap(1, 1), now.Add(3*time.Second)); got != nil {
		t.Fatalf("unchanged counts reported: %+v", got)
	}
	got := d.filter(snap(2, 1), now.Add(6*time.Second))
	if got == nil || len(got.Blocklist) != 2 || got.Allowlist != nil || got.TracePolicies != nil {
		t.Fatalf("one blocklist prefix changed: %+v, want the whole blocklist only", got)
	}
	if got := d.filter(snap(2, 1), now.Add(ruleStatsFullInterval)); got == nil || len(got.Allowlist) != 1 || len(got.TracePolicies) != 1 {
		t.Fatalf("periodic full report missing lists: %+v", got)
	}
	if d.filter(nil, now) != nil {
		t.Fatal("nil snapshot")
	}
}

// BPF hash maps and the policy engine's map iterate in no fixed order: the
// same counts in another order are no change once sorted.
func TestRuleStatsDeltaIgnoresListOrder(t *testing.T) {
	var d ruleStatsDelta
	now := time.Unix(1000, 0)
	mk := func(order ...uint32) *RuleStatsSnapshot {
		s := &RuleStatsSnapshot{Blocklist: []wafebpf.BlocklistEntry{{IP: "198.51.100.2"}, {IP: "198.51.100.1"}}}
		for _, id := range order {
			s.TracePolicies = append(s.TracePolicies, tracePolicyHitEntry{PolicyID: id, HitCount: uint64(id) * 10})
		}
		if order[0] == 3 {
			s.Blocklist[0], s.Blocklist[1] = s.Blocklist[1], s.Blocklist[0]
		}
		s.sort()
		return s
	}
	if d.filter(mk(1, 2, 3), now) == nil {
		t.Fatal("first report empty")
	}
	if got := d.filter(mk(3, 1, 2), now.Add(3*time.Second)); got != nil {
		t.Fatalf("reordered lists reported as changed: %+v", got)
	}
}

func TestTelemetryRetentionCountsResends(t *testing.T) {
	q := newTelemetryRetention(4, 1024, time.Minute)
	now := time.Unix(1, 0)
	q.add("a", []byte("x"), telemetryBatchCounts{}, now)
	if q.next(now) == nil || q.snapshot().ResentBatches != 0 {
		t.Fatal("first send counted as a resend")
	}
	if q.next(now.Add(2*time.Second)) == nil || q.snapshot().ResentBatches != 1 {
		t.Fatalf("resend not counted: %+v", q.snapshot())
	}
}
