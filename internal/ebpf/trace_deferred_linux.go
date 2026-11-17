//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

var errDeferredExpired = errors.New("event expired before deferred request")

type deferredSignal struct {
	ProcessStartNs uint64
	ExpiresNs      uint64
	State          uint64
	Result         int32
	PolicyID       uint32
	Tgid           uint32 // the map key again: the kernel writes only its own request
	Pad            uint32
}

func deferredRequest(evt TraceEvent, now uint64) (deferredSignal, error) {
	if evt.PID <= 1 || evt.PID == agentPID() {
		return deferredSignal{}, fmt.Errorf("protected process")
	}
	if evt.ProcessStartNs == 0 {
		return deferredSignal{}, fmt.Errorf("stable process identity unavailable")
	}
	if evt.MonotonicNs == 0 || now < evt.MonotonicNs || now-evt.MonotonicNs >= uint64(time.Second) {
		return deferredSignal{}, errDeferredExpired
	}
	return deferredSignal{ProcessStartNs: evt.ProcessStartNs, ExpiresNs: evt.MonotonicNs + uint64(time.Second),
		Result: deferredResultPending, PolicyID: evt.PolicyID, Tgid: evt.PID}, nil
}

func monotonicNow() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return u64FromInt64(ts.Nano()), nil
}

func (tm *TraceManager) requestDeferredSignal(evt TraceEvent) error {
	if tm.deferredMap == nil {
		return fmt.Errorf("deferred termination unsupported by loaded trace object")
	}
	now, err := monotonicNow()
	if err != nil {
		return err
	}
	request, err := deferredRequest(evt, now)
	if err != nil {
		return err
	}
	tm.deferredMu.Lock()
	defer tm.deferredMu.Unlock()
	if previous, ok := tm.deferredEvents[evt.PID]; ok && previous.ProcessStartNs == evt.ProcessStartNs {
		// The original matched request owns this process until its outcome.
		tm.policyEngine.RecordSignalCoalesced(evt.PolicyID, evt)
		return nil
	}
	if err := tm.deferredMap.Update(evt.PID, request, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("queue deferred signal: %w", err)
	}
	evt.SignalOutcome = "requested"
	tm.deferredEvents[evt.PID] = evt
	tm.policyEngine.RecordSignalRequested(evt.PolicyID, evt)
	return nil
}

func (tm *TraceManager) deferredSignalLoop(ctx context.Context) {
	defer tm.wg.Done()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tm.collectDeferredSignals()
		}
	}
}

func (tm *TraceManager) collectDeferredSignals() {
	now, err := monotonicNow()
	if err != nil {
		return
	}
	tm.deferredMu.Lock()
	defer tm.deferredMu.Unlock()
	for pid, evt := range tm.deferredEvents {
		var request deferredSignal
		if err := tm.deferredMap.Lookup(pid, &request); err != nil {
			continue
		}
		if !deferredRequestDone(request.State, request.Result, request.ExpiresNs, now) {
			continue
		}
		evt.SignalOutcome = "accepted"
		var signalErr error
		if request.State != 2 || request.Result == -110 {
			evt.SignalOutcome = "expired"
			signalErr = fmt.Errorf("deferred termination expired before a covered hook")
		} else if request.Result != 0 {
			evt.SignalOutcome = "failed"
			evt.SignalError = request.Result
			signalErr = fmt.Errorf("deferred signal failed: %d", request.Result)
			if request.Result == -1 {
				// check_deferred_signal refuses trace_protected_tgids entries
				// with -1; the helper's own EPERM (exiting task) is -1 too.
				signalErr = fmt.Errorf("deferred signal refused (-1): protected process or not permitted")
			}
		}
		tm.policyEngine.RecordSignalOutcome(evt.PolicyID, evt, signalErr)
		evt.OutcomeUpdate = true
		tm.events.push.push(evt)
		_ = tm.deferredMap.Delete(pid)
		delete(tm.deferredEvents, pid)
	}
}
