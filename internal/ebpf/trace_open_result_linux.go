//go:build linux

package ebpf

import (
	"slices"

	"github.com/cilium/ebpf"
)

// Result of a file open: optional maps of wafio_trace.o.
const (
	traceMapOpenCtl   = "trace_open_ctl"
	traceMapOpenStats = "trace_open_stats"
)

// TRACE_OPEN_* indexes of trace_open_stats (wafio_trace.h). Only the first
// is an open that left with its result; the others waited for one and left
// without it.
const (
	traceOpenResult    uint32 = 0
	traceOpenNoFull    uint32 = 1
	traceOpenNoNext    uint32 = 2
	traceOpenNoExit    uint32 = 3
	traceOpenNoRestart uint32 = 4
)

// traceOpenCtl mirrors struct trace_open_ctl (wafio_trace.h).
type traceOpenCtl struct {
	Defer uint32
	Pad   uint32
}

// openResultSyscalls are the open syscalls whose entry probe records the open
// and whose exit probe adds the result.
var openResultSyscalls = []string{"openat", "openat2", "open", "creat"}

// openResultReady reports whether the kernel may hold opens back for their
// result: every open entry probe that is attached has its exit probe attached
// too, and at least one is. An open whose exit probe is missing would wait
// until the thread's next open or exit, so one missing probe turns the whole
// feature off and every open leaves at entry, as an attempt.
func openResultReady(attached []string) bool {
	entered := false
	for _, syscall := range openResultSyscalls {
		if !slices.Contains(attached, "sys_enter_"+syscall) {
			continue
		}
		if !slices.Contains(attached, "sys_exit_"+syscall) {
			return false
		}
		entered = true
	}
	return entered
}

// armOpenResult tells the kernel to hold opens for their result once every
// probe is attached; it leaves the object as it was loaded otherwise. Called
// from Start with tm.mu held, after the probes attach.
func (tm *TraceManager) armOpenResult() {
	tm.openResultArmed = false
	if tm.openCtlMap == nil {
		tm.log.Printf("open results unavailable: trace object predates them; open events carry no result")
		return
	}
	if !openResultReady(tm.linkNames) {
		tm.log.Printf("open results off: an open exit probe is not attached; open events carry no result")
		return
	}
	if err := tm.openCtlMap.Put(uint32(0), traceOpenCtl{Defer: 1}); err != nil {
		tm.log.Printf("open results off: arming the kernel failed: %v", err)
		return
	}
	tm.openResultArmed = true
}

// readOpenResultCounters sums trace_open_stats: open events exported with
// their result, and those that waited for one and left without it.
func readOpenResultCounters(m *ebpf.Map) (known, unknown uint64) {
	known = sumPerCPU(m, traceOpenResult)
	unknown = sumPerCPU(m, traceOpenNoFull) + sumPerCPU(m, traceOpenNoNext) +
		sumPerCPU(m, traceOpenNoExit) + sumPerCPU(m, traceOpenNoRestart)
	return known, unknown
}
