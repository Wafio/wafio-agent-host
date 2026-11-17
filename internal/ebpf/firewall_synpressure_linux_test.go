//go:build linux

package ebpf

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// pinToOneCPU keeps the test on one CPU: the SYN pressure window is per-CPU,
// and BPF_PROG_TEST_RUN runs on the calling CPU, so a migration between two
// runs splits the count (seen on 5.10 and 6.12 VMs with several CPUs).
func pinToOneCPU(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return
	}
	for cpu := 0; cpu < 1024; cpu++ {
		if set.IsSet(cpu) {
			var one unix.CPUSet
			one.Set(cpu)
			if err := unix.SchedSetaffinity(0, &one); err == nil {
				t.Cleanup(func() { _ = unix.SchedSetaffinity(0, &set) })
			}
			return
		}
	}
}

// Global SYN pressure mode: once the aggregate SYN rate crosses the
// threshold, SYNs from sources without an established conntrack entry are
// dropped and no new per-IP state is allocated (LRU eviction protection).
func TestKernelSynPressureMode(t *testing.T) {
	pinToOneCPU(t)
	c := packetTestCollection(t)
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, Mode: 0, EnableSynflood: 1, EnableConntrack: 1})
	putPacketMap(t, c, "wafio_rate_config", uint32(0), RateConfig{WindowNs: 1_000_000_000, MaxSynPPS: 1000, SynPressurePPS: 3, Action: 1})

	pkt := tcpPacket(443) // SYN from 192.0.2.10 → 198.51.100.10:443
	// Threshold 3: first three SYNs stay under pressure (per-IP path allows).
	for i := 0; i < 3; i++ {
		if ret := runPacket(t, c, pkt); ret != 2 {
			t.Fatalf("pre-pressure SYN %d: verdict %d, want 2 (XDP_PASS)", i+1, ret)
		}
	}
	// 4th SYN crosses the global threshold → pressure drop (flow not established).
	if ret := runPacket(t, c, pkt); ret != 1 {
		t.Fatalf("pressure SYN: verdict %d, want 1 (XDP_DROP)", ret)
	}

	var values []MetricsVal
	if err := c.Maps["wafio_metrics"].Lookup(uint32(0), &values); err != nil {
		t.Fatalf("%+v", err)
	}
	var pressure uint64
	for _, v := range values {
		pressure += v.SynPressureDrops
	}
	if pressure != 1 {
		t.Fatalf("syn_pressure_drops = %d, want 1", pressure)
	}
}

// syn_pressure_pps = 0 must leave the classic per-IP path untouched.
func TestKernelSynPressureDisabledByDefault(t *testing.T) {
	c := packetTestCollection(t)
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, Mode: 0, EnableSynflood: 1, EnableConntrack: 1})
	putPacketMap(t, c, "wafio_rate_config", uint32(0), RateConfig{WindowNs: 1_000_000_000, MaxSynPPS: 1000, SynPressurePPS: 0, Action: 1})

	pkt := tcpPacket(443)
	for i := 0; i < 8; i++ {
		if ret := runPacket(t, c, pkt); ret != 2 {
			t.Fatalf("SYN %d with pressure disabled: verdict %d, want 2", i+1, ret)
		}
	}
}
