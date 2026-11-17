package ebpf

import (
	"encoding/binary"
	"os"
	"strconv"
	"testing"
	"time"
)

// Shared trace ring load model (report-only; asserts only the shed
// invariants). The shared ring holds 16 MiB / (1440 + 8 header) records;
// the reader decodes, evaluates userspace policies and stores each event.
// When a burst outpaces the reader, the ring fills and the kernel drops
// (trace_stats[0]) or sheds (trace_shed_wanted, TRACE_SHED_*) events.
//
// TestTraceRingBurstLoad measures the reader's per-event cost on this machine
// (the same pipeline as ringbufLoop: decodeTraceRecord, PolicyEngine.Evaluate,
// traceEventStore.record), then replays a burst against the ring model with
// and without shedding. Environment:
//
//	WAFIO_TRACE_LOAD_COST_NS  per-event reader cost to model instead of the
//	                          measured one (e.g. 75000: a slow reader on a
//	                          1-vCPU host)
//	WAFIO_TRACE_LOAD_SHARE    CPU share of the reader (default 0.4: the host
//	                          agent unit's CPUQuota=40% on one CPU)
//	WAFIO_TRACE_LOAD_RATE     burst rate in events/s (default 8000)
//
// Run on the target host: cross-compile the package test binary and run
// GOMAXPROCS=1 ./ebpf.test -test.run TestTraceRingBurstLoad -test.v.

const traceRingRecords = (1 << 24) / (TraceEventSizeWithIdentity + 8)

// loadEvent is one modelled event: severity and whether its type is in
// TRACE_NOISE_TYPES.
type loadEvent struct {
	sev   uint32
	noise bool
}

// loadMix is the severity/type mix the demo host reported (stats
// by_severity: 84% INFO, 5% LOW, 11% MEDIUM, <1% HIGH+; openat ~65% of all
// events), in a repeating 100-event pattern.
func loadMix(i int) loadEvent {
	switch k := i % 100; {
	case k < 70:
		return loadEvent{SevInfo, true} // openat, socket, connect …
	case k < 84:
		return loadEvent{SevInfo, false} // prctl, kill, clone, execve …
	case k < 89:
		return loadEvent{SevLow, true}
	case k < 99:
		return loadEvent{SevMedium, k%2 == 0}
	default:
		return loadEvent{SevHigh, true}
	}
}

type loadResult struct {
	produced, delivered, dropped, droppedMediumUp, shed uint64
}

// simulateTraceRing replays rate events/s for burst, then 2 s of quiet, with
// a reader that consumes share/cost events per second.
func simulateTraceRing(rate float64, burst time.Duration, cost time.Duration, share float64, shedOn bool) loadResult {
	const tick = time.Millisecond
	var r loadResult
	used := 0 // records in the ring
	readPerTick := share * float64(tick) / float64(cost)
	var readCredit, prodCredit float64
	i := 0
	total := burst + 2*time.Second
	for t := time.Duration(0); t < total; t += tick {
		if t < burst {
			prodCredit += rate * tick.Seconds()
		}
		for ; prodCredit >= 1; prodCredit-- {
			e := loadMix(i)
			i++
			r.produced++
			if shedOn && e.sev < SevMedium {
				fill8 := used * 8
				if fill8 >= traceRingRecords*7 || (e.noise && fill8 >= traceRingRecords*6) {
					r.shed++
					continue
				}
			}
			if used >= traceRingRecords {
				r.dropped++
				if e.sev >= SevMedium {
					r.droppedMediumUp++
				}
				continue
			}
			used++
		}
		readCredit += readPerTick
		for ; readCredit >= 1 && used > 0; readCredit-- {
			used--
			r.delivered++
		}
		if used == 0 && readCredit > 1 {
			readCredit = 1
		}
	}
	r.delivered += uint64(used)
	return r
}

// measureReaderCost runs the reader pipeline over n openat records.
func measureReaderCost(n int) time.Duration {
	raw := make([]byte, TraceEventSizeWithIdentity)
	binary.LittleEndian.PutUint64(raw[0:8], 123456789)
	binary.LittleEndian.PutUint32(raw[16:20], 4242)
	binary.LittleEndian.PutUint32(raw[20:24], 4242)
	binary.LittleEndian.PutUint32(raw[36:40], TraceOpen)
	binary.LittleEndian.PutUint32(raw[56:60], 0xffffff9c)
	copy(raw[80:96], "packagekitd")
	copy(raw[96:352], "/usr/share/locale/en_US/LC_MESSAGES/libc.mo")
	copy(raw[1376:1392], "systemd")
	pe := NewPolicyEngine()
	_, _ = pe.AddPolicy(EnforcementPolicy{Name: "shadow", Enabled: true, Action: "alert", EventTypes: []string{"openat"}, MatchFilename: "/etc/shadow"})
	st := newTraceEventStore(5000, 1000, 8192)
	start := time.Now()
	for i := 0; i < n; i++ {
		if i%2000 == 0 {
			st.push.drain(1000)
		}
		evt, err := decodeTraceRecord(raw, time.Second, "agent")
		if err != nil {
			panic(err)
		}
		pe.Evaluate(evt)
		st.record(evt, traceEventCategory(evt.EventType))
	}
	return time.Since(start) / time.Duration(n)
}

func envFloat(name string, def float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(name), 64); err == nil && v > 0 {
		return v
	}
	return def
}

func TestTraceRingBurstLoad(t *testing.T) {
	n := 20000
	if testing.Short() {
		n = 2000
	}
	cost := measureReaderCost(n)
	if v := envFloat("WAFIO_TRACE_LOAD_COST_NS", 0); v > 0 {
		cost = time.Duration(v)
	}
	share := envFloat("WAFIO_TRACE_LOAD_SHARE", 0.4)
	rate := envFloat("WAFIO_TRACE_LOAD_RATE", 8000)
	burst := 10 * time.Second
	t.Logf("reader cost %v/event, share %.2f → %.0f events/s; burst %.0f events/s for %v; ring %d records",
		cost, share, share/cost.Seconds(), rate, burst, traceRingRecords)
	off := simulateTraceRing(rate, burst, cost, share, false)
	on := simulateTraceRing(rate, burst, cost, share, true)
	for _, c := range []struct {
		name string
		r    loadResult
	}{{"no shed", off}, {"shed", on}} {
		t.Logf("%-8s produced=%d delivered=%d dropped=%d dropped_medium_up=%d shed=%d",
			c.name, c.r.produced, c.r.delivered, c.r.dropped, c.r.droppedMediumUp, c.r.shed)
	}
	if on.droppedMediumUp > off.droppedMediumUp {
		t.Fatalf("shedding lost more MEDIUM+ events (%d) than none (%d)", on.droppedMediumUp, off.droppedMediumUp)
	}
	if on.produced != on.delivered+on.dropped+on.shed || off.produced != off.delivered+off.dropped {
		t.Fatalf("model does not account for every event: %+v %+v", on, off)
	}
}

// The model sheds exactly as trace_shed_wanted does for a sustained flood the
// reader cannot follow: no MEDIUM+ event dropped while a slow reader still
// drains the ring.
func TestTraceRingShedKeepsMediumUp(t *testing.T) {
	r := simulateTraceRing(30000, 5*time.Second, 75*time.Microsecond, 0.4, true)
	if r.droppedMediumUp != 0 {
		t.Fatalf("MEDIUM+ events dropped under shedding: %+v", r)
	}
	if r.shed == 0 {
		t.Fatalf("nothing shed under a flood: %+v", r)
	}
}
