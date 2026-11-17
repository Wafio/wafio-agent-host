package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"github.com/wafio/wafio-cp-backend/shared/tracefilter"
)

func drainKick(d *telemetryDemand) bool {
	select {
	case <-d.kick:
		return true
	default:
		return false
	}
}

// Status on demand: the command's status fields switch the
// stream to status on demand and open a status window, capped at
// telemetryLiveMax and never shortened by a later command.
func TestTelemetryStatusDemandParsing(t *testing.T) {
	now := time.Unix(1000, 0)
	d := newTelemetryDemand()
	d.handle([]byte(`{"live_for_sec":0,"telemetry_gzip":true,"status_on_demand":true,"status_live_for_sec":120}`), now)
	if !d.statusOnDemand || !d.gzip() || !d.statusUntil.Equal(now.Add(120*time.Second)) {
		t.Fatalf("statusOnDemand %v gzip %v statusUntil %v", d.statusOnDemand, d.gzip(), d.statusUntil)
	}
	d.handle([]byte(`{"live_for_sec":0,"status_on_demand":true,"status_live_for_sec":5}`), now.Add(time.Second))
	if !d.statusUntil.Equal(now.Add(120 * time.Second)) {
		t.Fatalf("status window shortened to %v", d.statusUntil)
	}
	d.handle([]byte(`{"status_on_demand":true,"status_live_for_sec":86400}`), now)
	if !d.statusUntil.Equal(now.Add(telemetryLiveMax)) {
		t.Fatalf("status window not capped: %v", d.statusUntil)
	}
	d2 := newTelemetryDemand()
	d2.handle([]byte(`{"status_on_demand":true,"status_live_for_sec":-5}`), now)
	if !d2.statusOnDemand || now.Before(d2.statusUntil) {
		t.Fatalf("negative status window: %v %v", d2.statusOnDemand, d2.statusUntil)
	}
	// A message without the field (an older control plane) leaves status
	// at the live cadence.
	d3 := newTelemetryDemand()
	d3.handle([]byte(`{"live_for_sec":0,"telemetry_gzip":true,"status_live_for_sec":0}`), now)
	if d3.statusOnDemand {
		t.Fatal("status on demand without status_on_demand")
	}
	d3.handle([]byte(`not json`), now)
	if d3.statusOnDemand {
		t.Fatal("malformed command switched status on demand")
	}
}

// Without status_on_demand (no command, or a control plane older than this
// feature) the slow payload goes every 3 s tick and metrics every second.
func TestTelemetryStatusLegacyCadence(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, d := range []*telemetryDemand{newTelemetryDemand(), func() *telemetryDemand {
		d := newTelemetryDemand()
		d.handle([]byte(`{"live_for_sec":0,"telemetry_gzip":true}`), now)
		return d
	}()} {
		d.sent(now)
		d.slowSent(now)
		for i := 1; i <= 3; i++ {
			if at := now.Add(time.Duration(i) * telemetryLiveInterval); !d.slowDue(at) {
				t.Fatalf("legacy slow payload not due at tick %d", i)
			}
		}
		if !d.metricsDue(now.Add(time.Second), now) || d.metricsInterval(now) != time.Second {
			t.Fatal("legacy metrics not every second")
		}
	}
}

// With status_on_demand: outside a window the slow payload and metrics go
// every 30 s; inside a status or snapshot window every 3 s and every second.
func TestTelemetryStatusOnDemandCadence(t *testing.T) {
	now := time.Unix(1000, 0)
	d := newTelemetryDemand()
	d.handle([]byte(`{"live_for_sec":0,"telemetry_gzip":true,"status_on_demand":true,"status_live_for_sec":0}`), now)
	d.sent(now)
	d.slowSent(now)
	for _, off := range []time.Duration{3, 6, 15, 27} {
		if d.slowDue(now.Add(off * time.Second)) {
			t.Fatalf("idle slow payload due after %d s", off)
		}
	}
	if !d.slowDue(now.Add(30 * time.Second)) {
		t.Fatal("idle slow payload not due after 30 s")
	}
	if d.metricsDue(now.Add(time.Second), now) || d.metricsDue(now.Add(29*time.Second), now) {
		t.Fatal("idle metrics more often than every 30 s")
	}
	if !d.metricsDue(now.Add(30*time.Second), now) || !d.metricsDue(now, time.Time{}) {
		t.Fatal("idle metrics not due after 30 s (or never sent)")
	}
	// Idle snapshots (every minute) still ride on the slow payload.
	d.slowSent(now.Add(57 * time.Second))
	if !d.slowDue(now.Add(60 * time.Second)) {
		t.Fatal("slow payload not due when the idle snapshots are")
	}

	// A status window: live cadence until it ends.
	viewer := now.Add(100 * time.Second)
	d.sent(viewer)
	d.slowSent(viewer.Add(-10 * time.Second))
	d.handle([]byte(`{"live_for_sec":0,"status_on_demand":true,"status_live_for_sec":120}`), viewer)
	if !drainKick(d) {
		t.Fatal("status window opened without an immediate slow payload")
	}
	d.slowSent(viewer)
	if !d.slowDue(viewer.Add(3*time.Second)) || !d.slowDue(viewer.Add(119*time.Second)) {
		t.Fatal("slow payload not every tick inside the status window")
	}
	if !d.metricsDue(viewer.Add(time.Second), viewer) {
		t.Fatal("metrics not every second inside the status window")
	}
	d.slowSent(viewer.Add(119 * time.Second))
	d.sent(viewer.Add(119 * time.Second))
	if d.slowDue(viewer.Add(123*time.Second)) || d.metricsDue(viewer.Add(122*time.Second), viewer.Add(119*time.Second)) {
		t.Fatal("live cadence after the status window ended")
	}

	// A snapshot window counts as a status window.
	fw := viewer.Add(200 * time.Second)
	d.handle([]byte(`{"live_for_sec":120,"status_on_demand":true,"status_live_for_sec":0}`), fw)
	if !drainKick(d) {
		t.Fatal("snapshot window opened without an immediate slow payload")
	}
	d.sent(fw)
	d.slowSent(fw)
	if !d.slowDue(fw.Add(3*time.Second)) || !d.metricsDue(fw.Add(time.Second), fw) {
		t.Fatal("snapshot window does not keep status live")
	}
}

// Window kicks: none when a window is already open, none when a slow
// payload left less than a tick ago, none for the announcement that
// switches a stream from the legacy cadence (the connect send covers it).
func TestTelemetryStatusWindowKick(t *testing.T) {
	now := time.Unix(1000, 0)
	d := newTelemetryDemand()
	d.slowSent(now)
	d.sent(now)
	d.handle([]byte(`{"live_for_sec":0,"status_on_demand":true,"status_live_for_sec":120}`), now.Add(time.Second))
	if drainKick(d) {
		t.Fatal("announcement on connect kicked")
	}
	d.handle([]byte(`{"live_for_sec":0,"status_on_demand":true,"status_live_for_sec":120}`), now.Add(20*time.Second))
	if drainKick(d) {
		t.Fatal("renewal of an open window kicked")
	}
	d2 := newTelemetryDemand()
	d2.handle([]byte(`{"status_on_demand":true}`), now)
	d2.slowSent(now.Add(10 * time.Second))
	d2.handle([]byte(`{"status_on_demand":true,"status_live_for_sec":120}`), now.Add(11*time.Second))
	if drainKick(d2) {
		t.Fatal("kicked although a slow payload just left")
	}
}

// The slow loop sends at once on connect, on a tick only when due, and on
// every kick.
func TestRunSlowTelemetrySendsOnConnectTickAndKick(t *testing.T) {
	d := newTelemetryDemand()
	base := time.Unix(1000, 0)
	var mu sync.Mutex
	clockAt := base
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return clockAt }
	setClock := func(at time.Time) { mu.Lock(); clockAt = at; mu.Unlock() }
	sends := make(chan time.Time, 16)
	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runSlowTelemetry(ctx, d, tick, clock, func(now time.Time) { d.sent(now); sends <- now })
		close(done)
	}()
	expectSend := func(what string) {
		t.Helper()
		select {
		case <-sends:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no slow payload", what)
		}
	}
	expectNone := func(what string) {
		t.Helper()
		select {
		case <-sends:
			t.Fatalf("%s: unexpected slow payload", what)
		case <-time.After(50 * time.Millisecond):
		}
	}
	expectSend("connect")
	// Status on demand, idle: a tick 3 s later sends nothing.
	d.handle([]byte(`{"live_for_sec":0,"status_on_demand":true,"status_live_for_sec":0}`), base)
	setClock(base.Add(3 * time.Second))
	tick <- base.Add(3 * time.Second)
	expectNone("idle tick")
	setClock(base.Add(30 * time.Second))
	tick <- base.Add(30 * time.Second)
	expectSend("idle tick after 30 s")
	d.configApplied()
	expectSend("configuration applied")
	cancel()
	<-done
}

// A configuration bundle is applied, acked and followed at once by a slow
// payload (success or failure); the telemetry demand, the forward filter
// and receipts are neither applied, acked nor kick one. Without status on
// demand an apply does not kick (the next tick is ≤ 3 s away).
func TestDispatchHostBundleKicksAfterConfigApply(t *testing.T) {
	d := newTelemetryDemand()
	d.handle([]byte(`{"live_for_sec":0,"status_on_demand":true,"status_live_for_sec":0}`), time.Now())
	drainKick(d)
	fwd := newTraceForwardFilter()
	defer fwd.close()
	applied := 0
	var acks []*agentv1.CommandAck
	send := func(m *agentv1.AgentMessage) error {
		acks = append(acks, m.GetAck())
		return nil
	}
	apply := func(*agentv1.BundleUpdate) error { applied++; return nil }
	for _, id := range []string{telemetryDemandCommandID, tracefilter.TraceForwardFilterCommandID, "ebpf:telemetry:receipt"} {
		body := `{}`
		if id == telemetryDemandCommandID {
			body = `{"live_for_sec":0,"status_on_demand":true,"status_live_for_sec":0}`
		}
		if err := dispatchHostBundle(&agentv1.BundleUpdate{CommandId: id, BundleJson: []byte(body)}, d, fwd, apply, send); err != nil {
			t.Fatal(err)
		}
		if drainKick(d) || applied != 0 || len(acks) != 0 {
			t.Fatalf("%s: kick, apply %d or acks %d", id, applied, len(acks))
		}
	}
	if err := dispatchHostBundle(&agentv1.BundleUpdate{CommandId: "cfg-1", Generation: 1, BundleJson: []byte(`{"ebpf_state":{}}`)}, d, fwd, apply, send); err != nil {
		t.Fatal(err)
	}
	if applied != 1 || len(acks) != 1 || !acks[0].GetOk() || !drainKick(d) {
		t.Fatalf("config apply: applied %d acks %v kick missing", applied, acks)
	}
	failing := func(*agentv1.BundleUpdate) error { return errors.New("refused") }
	if err := dispatchHostBundle(&agentv1.BundleUpdate{CommandId: "cfg-2", Generation: 2, BundleJson: []byte(`{"ebpf_state":{}}`)}, d, fwd, failing, send); err != nil {
		t.Fatal(err)
	}
	if len(acks) != 2 || acks[1].GetOk() || acks[1].GetError() != "refused" || !drainKick(d) {
		t.Fatalf("refused apply: acks %v or kick missing", acks)
	}
	legacy := newTelemetryDemand()
	if err := dispatchHostBundle(&agentv1.BundleUpdate{CommandId: "cfg-3", Generation: 3}, legacy, fwd, apply, send); err != nil {
		t.Fatal(err)
	}
	if drainKick(legacy) {
		t.Fatal("legacy stream kicked after an apply")
	}
	if err := dispatchHostBundle(&agentv1.BundleUpdate{CommandId: "cfg-4", Generation: 4}, d, fwd, apply,
		func(*agentv1.AgentMessage) error { return errors.New("gone") }); err == nil {
		t.Fatal("ack send failure did not end the stream")
	}
}
