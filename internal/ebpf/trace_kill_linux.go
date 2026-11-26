//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// errPidfdFallback marks an immediate-kill attempt that could not be carried
// out SAFELY (no pidfd support, no identity to verify, verification input
// unreadable or mismatched). Callers fall back to the deferred kernel request,
// which re-verifies the exact start_boottime in-kernel before signalling.
var errPidfdFallback = errors.New("immediate pidfd kill unavailable")

// pidfdSupported probes pidfd_open (Linux ≥ 5.3) and pidfd_send_signal
// (≥ 5.1) against the agent's own process with signal 0 (no delivery).
func pidfdSupported() bool {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }() // read-only pidfd
	return unix.PidfdSendSignal(fd, 0, nil, 0) == nil
}

// killVerifiedPidfd delivers SIGKILL to evt's process only if it is provably
// the same process that produced the event:
//
//  1. pidfd_open pins the process currently holding the PID.
//  2. /proc/<pid>/stat starttime is read.
//  3. A signal-0 probe via the pidfd succeeds → the pinned process still holds
//     the PID (a zombie still does), so the stat read in (2) described it.
//  4. starttime must equal the event's process_start_ns (USER_HZ precision).
//  5. pidfd_send_signal(SIGKILL) targets the pinned process, never a number.
//
// Protection checks (pid<=1, self, protected set) are the caller's job and
// run before this.
func killVerifiedPidfd(pid uint32, startNs uint64) error {
	if startNs == 0 {
		return fmt.Errorf("%w: event has no process start time", errPidfdFallback)
	}
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("process exited before kill: %w", err)
		}
		return fmt.Errorf("%w: pidfd_open: %v", errPidfdFallback, err)
	}
	defer func() { _ = unix.Close(fd) }() // read-only pidfd
	stat, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return fmt.Errorf("%w: read stat: %v", errPidfdFallback, err)
	}
	if err := unix.PidfdSendSignal(fd, 0, nil, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("process exited before kill: %w", err)
		}
		return fmt.Errorf("%w: liveness probe: %v", errPidfdFallback, err)
	}
	if err := verifyStartTime(stat, startNs); err != nil {
		// A mismatch is refused here. The deferred path still gets the event:
		// the kernel compares exact ns identity, so a reused PID is rejected
		// there too (-3), while a clock-unit/time-namespace skew does not
		// silently disable termination.
		return fmt.Errorf("%w: %v", errPidfdFallback, err)
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		return fmt.Errorf("pidfd_send_signal: %w", err)
	}
	return nil
}

// userspaceKill terminates the process behind a userspace-matched Kill
// decision and records the outcome in the enforcement log. Order:
// protection guards → verified pidfd kill → deferred kernel request.
func (tm *TraceManager) userspaceKill(evt *TraceEvent, policyID uint32) {
	tm.protected.refreshExeLeads("/proc")
	if reason := tm.protected.protectedPIDReason("/proc", evt.PID, os.Getpid(), evt.Comm); reason != "" {
		err := fmt.Errorf("refusing to kill protected process: %s", reason)
		evt.SignalOutcome = "failed"
		tm.log.Printf("userspace kill pid=%d policy=%d refused: %v", evt.PID, policyID, err)
		tm.policyEngine.RecordSignalOutcome(policyID, *evt, err)
		return
	}
	if tm.pidfdOK {
		err := killVerifiedPidfd(evt.PID, evt.ProcessStartNs)
		if err == nil {
			evt.SignalOutcome = "accepted"
			tm.log.Printf("userspace kill pid=%d policy=%d delivered via verified pidfd", evt.PID, policyID)
			tm.policyEngine.RecordSignalOutcome(policyID, *evt, nil)
			return
		}
		if !errors.Is(err, errPidfdFallback) {
			evt.SignalOutcome = "failed"
			tm.log.Printf("userspace kill pid=%d policy=%d failed: %v", evt.PID, policyID, err)
			tm.policyEngine.RecordSignalOutcome(policyID, *evt, err)
			return
		}
		tm.log.Printf("userspace kill pid=%d policy=%d: %v; falling back to deferred kernel request", evt.PID, policyID, err)
	}
	if err := tm.requestDeferredSignal(*evt); err != nil {
		tm.log.Printf("userspace kill pid=%d policy=%d failed: %v", evt.PID, policyID, err)
		evt.SignalOutcome = "failed"
		if errors.Is(err, errDeferredExpired) {
			evt.SignalOutcome = "expired"
		}
		tm.policyEngine.RecordSignalOutcome(policyID, *evt, err)
		return
	}
	evt.SignalOutcome = "requested"
	tm.log.Printf("deferred signal requested pid=%d policy=%d", evt.PID, policyID)
}

// proc is where /proc is mounted.
func (tm *TraceManager) proc() string {
	if tm.procRoot == "" {
		return "/proc"
	}
	return tm.procRoot
}

// syncProtectedImages brings trace_protected_images to the trusted file set of
// the last scan: the paths of the set, the images of the processes it
// verified and the files PID 1 holds open. Keys are added before stale ones
// are deleted, so no trusted image is missing while the map is swapped. A
// failure leaves the map as it is (an exec of an image that is missing drops
// the entry, the safe direction). Owned by protectedRefreshLoop, like the
// tgid state.
func (tm *TraceManager) syncProtectedImages() {
	m := tm.protectedImagesMap
	if m == nil {
		return
	}
	want := tm.protected.kernelImages(tm.proc(), tm.protectedVerified)
	have := make(map[protectedImageKey]protectedImage, len(want))
	var key protectedImageKey
	var image protectedImage
	iter := m.Iterate()
	for iter.Next(&key, &image) {
		have[key] = image
	}
	if err := iter.Err(); err != nil {
		tm.log.Printf("protected-process image map read: %v; reconciling against own writes", err)
		have = maps.Clone(tm.protectedImages)
	}
	err := applyProtectedImages(have, want,
		func(k protectedImageKey, v protectedImage) error { return m.Update(k, v, ebpf.UpdateAny) },
		func(k protectedImageKey) error {
			if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return err
			}
			return nil
		})
	switch {
	case err == nil:
		tm.protectedImagesErr = ""
	case err.Error() != tm.protectedImagesErr:
		// Once per distinct failure: the refresh repeats it every 5 s.
		tm.protectedImagesErr = err.Error()
		tm.log.Printf("protected-process image map update: %v", err)
	}
	tm.protectedImages = want
}

// bootTicksNow is the current CLOCK_BOOTTIME in USER_HZ ticks, the unit of
// the kernel map values (task start_boottime / 10 ms).
func bootTicksNow() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return startNsToTicks(u64FromInt64(ts.Nano())), nil
}

// protectedChangeGap is the shortest time between two refreshes that file
// changes start: each reads every trusted path, and anyone who can rename a file
// with a protected name in a watched directory starts one.
const protectedChangeGap = time.Second

// protectedRefreshLoop mirrors the protected set into trace_protected_tgids
// so the kernel kill paths (enforce_check, check_deferred_signal) skip those
// processes too. The kernel also inserts children forked by a
// protected process (and by PID 1) at fork, keeps an entry across exec only
// for a trusted image (trace_protected_images), drops it at the exit of setuid,
// setreuid and setresuid when a child gives up root without an exec, and at
// exit; the refresh verifies what the kernel inherited and removes the rest.
// The first sync runs synchronously in Start (runProtectedSelfCheck). A change
// to a file that could be a trusted image refreshes the image set between two
// ticks, at most once per protectedChangeGap: the last change of a burst is
// applied up to that much late. Directories of those files that did not exist,
// or were moved, are watched again before each refresh.
func (tm *TraceManager) protectedRefreshLoop(done <-chan struct{}) {
	defer tm.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var watch *imageWatch
	var changed <-chan struct{}
	if tm.protectedImagesMap != nil {
		w, err := watchProtectedImages(tm.protected, tm.proc())
		if err != nil {
			tm.log.Printf("protected-process image watch unavailable: %v (the image set refreshes every 5 s)", err)
		} else {
			defer w.Close()
			watch, changed = w, w.changed
		}
	}
	var lastChange time.Time
	var later <-chan time.Time // the refresh a change inside the gap waits for
	refreshChange := func() {
		tm.refreshOnChange(watch)
		lastChange = time.Now()
	}
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			tm.refreshOnTick(watch)
		case <-changed:
			if later != nil {
				continue // the timer's refresh runs after this change
			}
			if wait := protectedChangeGap - time.Since(lastChange); wait > 0 {
				later = time.After(wait)
				continue
			}
			refreshChange()
		case <-later:
			later = nil
			refreshChange()
		}
	}
}

// refreshOnTick is the periodic refresh: directories of trusted files that were
// not watched are watched again first, so a file that appears in one is seen by
// the sync that follows and by the watch after it.
func (tm *TraceManager) refreshOnTick(watch *imageWatch) {
	if watch != nil {
		watch.rearm()
	}
	if _, err := tm.syncProtectedTGIDs(); err != nil {
		tm.log.Printf("protected-process scan failed: %v", err)
	}
}

// refreshOnChange follows a change of a file that could be a trusted image: the
// image set alone, at once. The leads are walked again first, so the directory
// a retargeted symlink leads to is watched by the rearm that follows, and a
// directory that was moved or removed is watched again.
func (tm *TraceManager) refreshOnChange(watch *imageWatch) {
	tm.protected.refreshExeLeads(tm.proc())
	if watch != nil {
		watch.rearm()
	}
	tm.syncProtectedImages()
}

// syncProtectedTGIDs rescans /proc and reconciles trace_protected_tgids with
// the result, then refills the kernel's fork-insert budget. Returns how many
// processes the protected set matched; the entries the map holds afterwards
// are len(tm.protectedTGIDs).
func (tm *TraceManager) syncProtectedTGIDs() (int, error) {
	// Objects built with the start-time ABI store the USER_HZ start ticks and
	// the kernel compares them with the task's start_boottime, so a PID reused
	// between refreshes never inherits protection. Older objects (1-byte value)
	// get the presence flag they expect.
	withStart := tm.protectedMap.ValueSize() == 8
	// Taken before the scan: an entry the kernel inserted for a process that
	// started later may be missing from the scan and is left for the next one.
	scanStart, err := bootTicksNow()
	if err != nil {
		withStart = false // no guard possible: fall back to the scan alone
	}
	tm.protected.refreshExeLeads(tm.proc())
	tgids, untrusted, err := tm.protected.scanProtectedTGIDs(tm.proc(), os.Getpid())
	if err != nil {
		return 0, err
	}
	tm.noteUntrusted(untrusted)
	matched := len(tgids)
	defer func() { tm.protectedCount.Store(i32FromInt(len(tm.protectedTGIDs))) }()
	// Images first: an entry the refresh writes below must not meet an exec
	// whose image the kernel does not know yet.
	tm.protectedVerified = tgids
	tm.syncProtectedImages()
	if len(tgids) > maxProtectedTGIDs {
		if !tm.protectedOverflowLogged {
			tm.protectedOverflowLogged = true
			tm.log.Printf("protected-process set has %d entries, kernel map holds %d; extra entries rely on the userspace guard", len(tgids), maxProtectedTGIDs)
		}
		tgids = tgids[:maxProtectedTGIDs]
	}
	want := make(map[uint32]uint64, len(tgids))
	scanned := make(map[uint32]protectedTGID, len(tgids))
	for _, p := range tgids {
		v := uint64(1)
		if tm.protectedMap.ValueSize() == 8 {
			v = p.startTicks
		}
		want[p.tgid] = v
		scanned[p.tgid] = p
	}
	// Reconcile against the map itself, not our own writes: the kernel adds
	// and removes entries between refreshes.
	have, err := readProtectedMap(tm.protectedMap)
	if err != nil {
		tm.log.Printf("protected-process map read: %v; reconciling against own writes", err)
		have = maps.Clone(tm.protectedTGIDs)
	}
	del, put := reconcileProtectedEntries(have, want, scanStart, withStart)
	// Remove first so the map never exceeds max_entries during the swap.
	for _, tgid := range del {
		if err := tm.protectedMap.Delete(tgid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			tm.log.Printf("protected-process map delete %d: %v", tgid, err)
			continue
		}
		delete(have, tgid)
	}
	for tgid, v := range put {
		if beforeProtectedPut != nil {
			beforeProtectedPut(tgid)
		}
		var err error
		if tm.protectedMap.ValueSize() == 8 {
			err = tm.protectedMap.Update(tgid, v, ebpf.UpdateAny)
		} else {
			err = tm.protectedMap.Update(tgid, uint8(1), ebpf.UpdateAny)
		}
		if err != nil {
			tm.log.Printf("protected-process map update %d: %v", tgid, err)
			continue
		}
		// The exec, exit and setuid hooks of the kernel see only an entry that
		// exists. A process that exec'd another image, exited or gave up root
		// after the scan met none, and the write put its entry back: check it
		// now. commit_creds changes the credentials before sys_exit of set*uid
		// runs, so either that hook sees the entry and drops it, or this read
		// sees the new UIDs.
		if !protectedStillRuns(tm.proc(), scanned[tgid]) {
			derr := tm.protectedMap.Delete(tgid)
			if derr == nil || errors.Is(derr, ebpf.ErrKeyNotExist) {
				delete(have, tgid) // when the put replaced another value, have still holds it
				continue
			}
			tm.log.Printf("protected-process map delete %d: %v", tgid, derr)
		}
		have[tgid] = v
	}
	tm.protectedTGIDs = have
	tm.updateProtectedBudget(len(have))
	return matched, nil
}

// noteUntrusted logs each path an account other than root can write when it is
// first seen, and forgets the ones that were fixed, so a path that is made
// writable again is logged again. Owned by protectedRefreshLoop, like the tgid
// state.
func (tm *TraceManager) noteUntrusted(paths []string) {
	now := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		now[p] = struct{}{}
		if _, seen := tm.protectedUntrusted[p]; !seen {
			tm.log.Printf("%s can be written by an account other than root, so the protected process that runs from it is not protected: %s", p, untrustedHint(p))
		}
	}
	tm.protectedUntrusted = now
}

// disableInheritWithoutExec turns fork inheritance off when the fork probe is
// about to attach and the exec probe is not linked: a child would keep its
// entry through any exec. Fork attaches after this point, so nothing was
// inherited yet; the budget stays 0 from now on. Start calls it before each
// probe.
func (tm *TraceManager) disableInheritWithoutExec(probe string) {
	if probe != "sched_process_fork" || !tm.execKeep || slices.Contains(tm.linkNames, "sched_process_exec") {
		return
	}
	tm.execKeep = false
	tm.updateProtectedBudget(len(tm.protectedTGIDs))
	tm.log.Printf("sched_process_exec is not attached: children of protected processes are not inherited")
}

// updateProtectedBudget writes the kernel's fork-insert budget and its limit for
// the next refresh period, and reports inserts the kernel refused since the
// last one. The limit goes first: the kernel gives units back up to it, so a
// lower budget never meets a higher limit. An object whose budget map has two
// slots has no limit and gives nothing back, and its budget stays 0 (no exec
// keep), so the limit slot is skipped there.
func (tm *TraceManager) updateProtectedBudget(entries int) {
	if tm.protectedBudgetMap == nil {
		return
	}
	budget := protectedInheritBudget(entries, tm.execKeep)
	for _, slot := range []uint32{protectedLimitSlot, protectedBudgetSlot} {
		if slot >= tm.protectedBudgetMap.MaxEntries() {
			continue
		}
		if err := tm.protectedBudgetMap.Update(slot, budget, ebpf.UpdateAny); err != nil {
			tm.log.Printf("protected-process fork budget update (slot %d): %v", slot, err)
		}
	}
	var refused int64
	if err := tm.protectedBudgetMap.Lookup(protectedRefusedSlot, &refused); err != nil || refused < 0 {
		return
	}
	if prev := tm.protectedRefused.Swap(uint64(refused)); uint64(refused) > prev {
		tm.log.Printf("protected-process map: %d fork inheritances refused since start (map %d/%d, next budget %d); those children are protected from the next refresh", refused, entries, maxProtectedTGIDs, budget)
	}
}

// readProtectedMap returns the content of trace_protected_tgids, whichever
// value ABI the object uses (8-byte start ticks or the 1-byte legacy flag).
func readProtectedMap(m kernelMap) (map[uint32]uint64, error) {
	out := make(map[uint32]uint64)
	var tgid uint32
	iter := m.Iterate()
	if m.ValueSize() == 8 {
		var v uint64
		for iter.Next(&tgid, &v) {
			out[tgid] = v
		}
	} else {
		var v uint8
		for iter.Next(&tgid, &v) {
			out[tgid] = uint64(v)
		}
	}
	return out, iter.Err()
}
