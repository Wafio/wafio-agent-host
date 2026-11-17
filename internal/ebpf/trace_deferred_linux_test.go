//go:build linux

package ebpf

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
)

func TestDeferredRequestRequiresStableIdentity(t *testing.T) {
	for _, evt := range []TraceEvent{{PID: 0}, {PID: 1, ProcessStartNs: 10}, {PID: uint32(os.Getpid()), ProcessStartNs: 10}, {PID: 999999}} {
		if _, err := deferredRequest(evt, 100); err == nil {
			t.Fatalf("unsafe request accepted %+v", evt)
		}
	}
	got, err := deferredRequest(TraceEvent{PID: 999999, ProcessStartNs: 123, MonotonicNs: 100, PolicyID: 42}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProcessStartNs != 123 || got.ExpiresNs != 1_000_000_100 || got.PolicyID != 42 || got.State != 0 ||
		got.Tgid != 999999 || got.Result != deferredResultPending {
		t.Fatalf("request %+v", got)
	}
	// Mirrors struct deferred_signal in wafio_trace.c (40 bytes with tgid).
	if size := unsafe.Sizeof(deferredSignal{}); size != 40 {
		t.Fatalf("deferredSignal is %d bytes, want 40", size)
	}
}

// Native negative test: an impossible identity must never reach bpf_send_signal.
// Fresh maps, one temporary probe, only this test process is targeted.
func TestKernelDeferredSignalRejectsReusedIdentity(t *testing.T) {
	c := packetObjectCollection(t, "wafio_trace.o")
	putPacketMap(t, c, "trace_config_map", uint32(0), TraceConfigBPF{})
	probe, err := link.Tracepoint("syscalls", "sys_enter_openat", c.Programs["trace_sys_enter_openat"], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	now, err := monotonicNow()
	if err != nil {
		t.Fatal(err)
	}
	// The BPF map is keyed by the KERNEL-GLOBAL pid (bpf_get_current_pid_tgid),
	// which differs from os.Getpid() whenever the test runs inside a PID
	// namespace (containers). NSpid lists the global pid first.
	pid := globalPid(t)
	putPacketMap(t, c, "trace_deferred_signals", pid, deferredSignal{ProcessStartNs: ^uint64(0), ExpiresNs: now + uint64(time.Second), PolicyID: 42, Tgid: pid})
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	var request deferredSignal
	if err := c.Maps["trace_deferred_signals"].Lookup(pid, &request); err != nil {
		t.Fatal(err)
	}
	if request.State != 2 || request.Result != -3 {
		t.Fatalf("identity guard failed: %+v", request)
	}
}

// globalPid returns the kernel-global PID of this process: the first entry of
// NSpid in /proc/self/status. Falls back to os.Getpid() when not namespaced.
func globalPid(t *testing.T) uint32 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return uint32(os.Getpid())
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			fields := strings.Fields(strings.TrimPrefix(line, "NSpid:"))
			if len(fields) > 0 {
				if v, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
					return uint32(v)
				}
			}
		}
	}
	return uint32(os.Getpid())
}

func TestDeferredRequestRejectsStaleOrFutureEvent(t *testing.T) {
	for _, stamp := range []uint64{0, 1, 2_000_000_002} {
		if _, err := deferredRequest(TraceEvent{PID: 999999, ProcessStartNs: 123, MonotonicNs: stamp}, 2_000_000_001); err == nil {
			t.Fatalf("invalid event timestamp %d accepted", stamp)
		}
	}
}
