//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

// Kill-candidate priority ring: optional maps of wafio_trace.o.
const (
	traceMapPriorityEvents = "trace_priority_events"
	traceMapPriorityRules  = "trace_priority_rules"
	traceMapPriorityStats  = "trace_priority_stats"
	traceMapPriorityCtl    = "trace_priority_ctl"
	traceMapPriorityNames  = "trace_priority_names"
	// traceMapShedStats: optional per-type shed counters (trace_shed_wanted).
	traceMapShedStats = "trace_shed_stats"
	// traceMapKeepNames: optional openat path components never shed
	// (trace_open_keep); objects without it shed by severity and type only.
	traceMapKeepNames = "trace_keep_names"

	// traceLossCheckInterval: how often the drop counters are compared; at
	// most one loss alert per interval.
	traceLossCheckInterval = 10 * time.Second
)

// TRACE_PRIO_* indexes of trace_priority_stats (wafio_trace.h).
const (
	tracePrioRouted uint32 = 0
	tracePrioFull   uint32 = 1
	tracePrioLost   uint32 = 2
)

// priorityMaps are the agent-written maps of the kill-candidate ring
// (trace_keep_names is TraceManager.keepMap).
type priorityMaps struct {
	rules, ctl, names *ebpf.Map
}

// writeKillRoutes writes every event type's kill-candidate route into
// trace_priority_rules (value: enabled, min_severity; all-zero = off), the
// openat final-component names into trace_priority_names, the shed
// exemption names into trace_keep_names, then trace_priority_ctl
// {attached=1, open_names=n}: the kernel routes nothing to the priority ring
// before that. Called by the PolicyEngine under its lock (which also
// serializes priorityNameKeys and keepNameKeys); it must not take tm.mu.
func (tm *TraceManager) writeKillRoutes(routes killRoutes) {
	// The push queue keeps what the kernel never sheds, and
	// the kernel's own exemption is written whether or not the priority ring
	// is read: neither touches the ring's maps or its attach flag.
	tm.events.push.setKeepNames(routes.KeepNames)
	tm.writeKeepNames(tm.keepMap.Load(), routes.KeepNames)
	m := tm.priorityMaps.Load()
	if m == nil {
		return
	}
	for et := uint32(1); et <= TraceEventMax; et++ {
		var val [8]byte
		if sev, ok := routes.Types[et]; ok {
			binary.LittleEndian.PutUint32(val[0:4], 1)
			binary.LittleEndian.PutUint32(val[4:8], sev)
		}
		if err := m.rules.Update(et, val, ebpf.UpdateAny); err != nil {
			tm.log.Printf("kill-candidate routing: write type %d: %v (candidates of that type use the shared ring)", et, err)
			return
		}
	}
	want := make(map[uint64]struct{}, len(routes.OpenNames))
	for name := range routes.OpenNames {
		want[traceNameHash(name)] = struct{}{}
	}
	for key := range tm.priorityNameKeys {
		if _, keep := want[key]; !keep {
			if err := m.names.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				tm.log.Printf("kill-candidate routing: remove openat name: %v", err)
			}
			delete(tm.priorityNameKeys, key)
		}
	}
	for key := range want {
		if _, have := tm.priorityNameKeys[key]; have {
			continue
		}
		if err := m.names.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			tm.log.Printf("kill-candidate routing: openat name: %v (map full: those opens use the shared ring below the policy severity)", err)
			continue
		}
		tm.priorityNameKeys[key] = struct{}{}
	}
	var ctl [8]byte
	binary.LittleEndian.PutUint32(ctl[0:4], 1) // attached: the agent reads the ring
	binary.LittleEndian.PutUint32(ctl[4:8], u32FromInt(len(tm.priorityNameKeys)))
	if err := m.ctl.Update(uint32(0), ctl, ebpf.UpdateAny); err != nil {
		tm.log.Printf("kill-candidate routing: attach flag: %v (kill candidates stay on the shared ring)", err)
	}
}

// writeKeepNames reconciles trace_keep_names with names (shedKeepNames):
// stale keys removed, new or changed ones written. A failed write only lets
// the kernel shed that name under pressure again; it is logged.
func (tm *TraceManager) writeKeepNames(m *ebpf.Map, names map[string]uint8) {
	if m == nil {
		return
	}
	want := traceKeepNameKeys(names)
	for key := range tm.keepNameKeys {
		if _, keep := want[key]; !keep {
			if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				tm.log.Printf("trace shed exemptions: remove name: %v", err)
			}
			delete(tm.keepNameKeys, key)
		}
	}
	failed := 0
	for key, val := range want {
		if have, ok := tm.keepNameKeys[key]; ok && have == val {
			continue
		}
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			failed++
			continue
		}
		tm.keepNameKeys[key] = val
	}
	if failed > 0 {
		tm.log.Printf("trace shed exemptions: %d of %d names not written (map full?): those opens may be shed under ring pressure", failed, len(want))
	}
}

// sumPerCPU returns the sum over CPUs of one per-CPU counter, 0 when the map
// is missing or the lookup fails.
func sumPerCPU(m *ebpf.Map, key uint32) uint64 {
	if m == nil {
		return 0
	}
	var vals []uint64
	if err := m.Lookup(key, &vals); err != nil {
		return 0
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total
}

// readLossCounters reads the kernel drop counters.
func (tm *TraceManager) readLossCounters() traceLossCounters {
	return traceLossCounters{
		BulkLost:     sumPerCPU(tm.statsMap, 0),
		PriorityFull: sumPerCPU(tm.priorityStatsMap, tracePrioFull),
		PriorityLost: sumPerCPU(tm.priorityStatsMap, tracePrioLost),
	}
}

// readShedCounters returns, per event type with a nonzero count, the events
// the kernel shed for shared-ring headroom (nil without trace_shed_stats).
func (tm *TraceManager) readShedCounters() map[uint32]uint64 {
	if tm.shedStatsMap == nil {
		return nil
	}
	out := make(map[uint32]uint64)
	for et := uint32(1); et <= TraceEventMax; et++ {
		if n := sumPerCPU(tm.shedStatsMap, et); n > 0 {
			out[et] = n
		}
	}
	return out
}

// traceLossLoop turns a rise in the kernel drop counters, and in the
// shed counters, into at most one event of each per check: logged, kept in
// the recent-event views and pushed to the control plane like any trace
// event.
func (tm *TraceManager) traceLossLoop(ctx context.Context) {
	defer tm.wg.Done()
	ticker := time.NewTicker(traceLossCheckInterval)
	defer ticker.Stop()
	prev := tm.readLossCounters()
	prevAgent := tm.lossTotals(prev.BulkLost)
	prevShed := tm.readShedCounters()
	shedStreak := 0
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cur := tm.readLossCounters()
		now := time.Now()
		if ticks++; ticks%traceMapSampleEveryTicks == 0 {
			tm.sampleMaps(now)
		}
		if evt, ok := traceLossAlert(prev, cur, now); ok {
			evt.EventID = fmt.Sprintf("%s-loss-%d", tm.eventPrefix, now.UnixNano())
			evt.PID = agentPID()
			tm.log.Printf("WARNING: %s", evt.Description)
			tm.recordSyntheticEvent(evt, "security")
		}
		prev = cur
		// Loss in the agent (push queue, unconfirmed batches), and the
		// per-minute history the status reports.
		curAgent := tm.lossTotals(cur.BulkLost)
		if evt, ok := traceAgentLossAlert(traceLossDeltaOf(prevAgent, curAgent), now); ok {
			evt.EventID = fmt.Sprintf("%s-agentloss-%d", tm.eventPrefix, now.UnixNano())
			evt.PID = agentPID()
			tm.log.Printf("WARNING: %s", evt.Description)
			tm.recordSyntheticEvent(evt, "security")
		}
		prevAgent = curAgent
		tm.lossHistory.observe(now, curAgent)
		curShed := tm.readShedCounters()
		evt, ok := traceShedAlert(prevShed, curShed, shedStreak+1, now)
		if ok {
			shedStreak++
			evt.EventID = fmt.Sprintf("%s-shed-%d", tm.eventPrefix, now.UnixNano())
			evt.PID = agentPID()
			tm.log.Printf("WARNING: %s", evt.Description)
			tm.recordSyntheticEvent(evt, "security")
		} else {
			shedStreak = 0
		}
		prevShed = curShed
	}
}

// recordSyntheticEvent stores an agent-generated event exactly as the ring
// readers store a traced one.
func (tm *TraceManager) recordSyntheticEvent(evt TraceEvent, category string) {
	tm.events.record(evt, category)
}
