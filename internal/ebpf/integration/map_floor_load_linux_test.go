//go:build linux

package integration

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

// TestMapFloorLoad runs the detection checks at the smallest map sizes
// (scale 0.001) against real traffic on a private veth pair: an abuser the
// firewall tracks first, then at least 100000 packets from distinct spoofed
// sources that fill the map, while a legitimate client keeps making requests.
// It passes when
//   - 99.9 % or more of the legitimate requests succeed,
//   - the abuser tracked before the flood is still dropped after it, and
//   - the counters agree: the refused inserts of the map in the status equal
//     the state_table_full metric, and entries plus refusals account for the
//     sources that were sent.
//
// A run takes about a minute. Opt in with WAFIO_EBPF_FLOOR_LOAD=1; it needs
// root, the objects (WAFIO_TEST_BPF_DIR) and a kernel with veth, and runs in a
// disposable VM or lab.
func TestMapFloorLoad(t *testing.T) {
	if os.Getenv("WAFIO_EBPF_FLOOR_LOAD") != "1" {
		t.Skip("set WAFIO_EBPF_FLOOR_LOAD=1 in an authorized lab")
	}
	type phase struct {
		name  string
		table string // the sized map the flood fills
		// configure turns on the check under test, with limits a legitimate
		// client at 50 requests a second stays under and an abuser passes at
		// once. The windows are the longest the programs take (60 s), so that
		// nothing ages out or is pruned while the test runs.
		configure func(*ebpf.FullConfigAPI)
		// kind of packet of the abuser and of the flood; abusePackets of the
		// first, spoofed sources of the second.
		kind         string
		abusePackets int
		// dropped reads the metric that counts what the check dropped.
		dropped func(*ebpf.Metrics) uint64
	}
	rate := ebpf.RateConfigAPI{WindowMs: 60000, MaxPPS: 500, MaxSynPPS: 50, BurstSyn: 200, DropOnLimit: true}
	for _, ph := range []phase{
		{
			name: "syn flood", table: "wafio_syn_state", kind: "syn", abusePackets: 6000,
			configure: func(c *ebpf.FullConfigAPI) { c.Global.EnableSynflood, c.Rate = true, rate },
			dropped:   func(m *ebpf.Metrics) uint64 { return m.SynfloodDrops },
		},
		{
			name: "rate limit", table: "wafio_rate_state", kind: "ack", abusePackets: 60000,
			configure: func(c *ebpf.FullConfigAPI) { c.Global.EnableRatelimit, c.Rate = true, rate },
			dropped:   func(m *ebpf.Metrics) uint64 { return m.RatelimitedPackets },
		},
		{
			name: "port scan", table: "wafio_portscan", kind: "scan", abusePackets: 100,
			configure: func(c *ebpf.FullConfigAPI) {
				c.PortScan = ebpf.PortScanConfigAPI{Enabled: true, WindowMs: 60000, MaxUniquePorts: 10, DropOnDetect: true}
			},
			dropped: func(m *ebpf.Metrics) uint64 { return m.PortScanDrops },
		},
	} {
		t.Run(ph.name, func(t *testing.T) {
			const spoofed = 150000
			n := newLabNet(t)
			serveLegit(t, net.JoinHostPort(n.hostAddr.String(), "8080"))
			sizes := ebpf.ComputeMapSizes(0.001, labCPUs(t))
			m := startLabFirewall(t, n, sizes, "load")
			cfg := enforcingConfig()
			cfg.Global.EnableSynflood, cfg.Global.EnableRatelimit = false, false
			cfg.Global.LogBlocked = false
			ph.configure(&cfg)
			applyState(t, m, fwState{cfg: cfg, pp: ebpf.PortPolicyConfigAPI{DefaultIngress: "allow", DefaultEgress: "allow"}})
			dst := net.JoinHostPort(n.hostAddr.String(), "8080")

			// The control: before anything is flooded the abuser's address works.
			n.send("probe %s %s", dst, n.peerAddr)
			if got := n.expect("probe", 10*time.Second); got != "ok" {
				t.Fatalf("control probe from the abuser address: %s", got)
			}

			// The legitimate client, one request every 20 ms for 40 s, from its
			// own address.
			n.send("legit %s %d %d %s", dst, 40000, 20, n.peerAddr2)
			time.Sleep(time.Second)

			// The abuser is tracked and over its limit.
			n.send("abuse %s %s %s %d %d", ph.kind, dst, n.peerAddr, ph.abusePackets, 50000)
			abused := n.expect("abuse sent=", 30*time.Second)

			// Then the flood of spoofed sources, past the capacity of the map.
			n.send("flood %s %s %d %d %d", ph.kind, dst, spoofed, 20000, 0)
			var sent int
			if _, err := fmt.Sscanf(n.expect("flood sent=", 120*time.Second), "%d", &sent); err != nil || sent < 100000 {
				t.Fatalf("the flood sent %d spoofed packets (%v), want at least 100000", sent, err)
			}
			floodEnd := time.Now()

			// The abuser stays dropped.
			n.send("probe %s %s", dst, n.peerAddr)
			if got := n.expect("probe", 10*time.Second); got != "fail" {
				t.Errorf("probe from the abuser address after the flood: %s, want it dropped", got)
			}

			var ok, fail int
			if _, err := fmt.Sscanf(strings.ReplaceAll(n.expect("legit ", 90*time.Second), "=", " "), "ok %d fail %d", &ok, &fail); err != nil {
				t.Fatalf("legit result: %v", err)
			}
			total := ok + fail
			t.Logf("legitimate requests: %d ok, %d failed; abuser packets sent %s; spoofed packets sent %d", ok, fail, abused, sent)
			if total < 1000 || float64(ok) < 0.999*float64(total) {
				t.Errorf("legitimate requests: %d of %d succeeded, want at least 99.9%% of at least 1000", ok, total)
			}

			// The counters, from the first sample taken after the flood (the
			// sampler runs every 30th poll tick, 7.5 s here).
			var entry ebpf.MapCapacity
			var metrics *ebpf.Metrics
			deadline := time.Now().Add(30 * time.Second)
			for {
				st := m.Status()
				if st.MapSizing != nil && st.MapSizing.SampledAt != nil && st.MapSizing.SampledAt.After(floodEnd) {
					for _, mc := range st.MapSizing.Maps {
						if mc.Name == ph.table && mc.FullCount != nil && *mc.FullCount > 0 {
							entry = mc
						}
					}
				}
				if entry.Name != "" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no sample with a full %s after the flood: %+v", ph.table, st.MapSizing)
				}
				time.Sleep(500 * time.Millisecond)
			}
			var err error
			if metrics, err = m.ReadMetrics(); err != nil {
				t.Fatal(err)
			}
			if entry.Entries == nil || entry.MaxEntries != sizes.Entries[ph.table] {
				t.Fatalf("sampled %+v, want the map at its floor %d", entry, sizes.Entries[ph.table])
			}
			refused, entries := *entry.FullCount, *entry.Entries
			t.Logf("%s: %d entries of %d, %d inserts refused, state_table_full %d, drops %d, last full %v",
				ph.table, entries, entry.MaxEntries, refused, metrics.StateTableFull, ph.dropped(metrics), entry.LastFullAt)
			if entries != uint64(entry.MaxEntries) {
				t.Errorf("%s holds %d entries after the flood, want it full at %d", ph.table, entries, entry.MaxEntries)
			}
			if refused != metrics.StateTableFull {
				t.Errorf("refused inserts %d != state_table_full %d", refused, metrics.StateTableFull)
			}
			// Every spoofed source got an entry or was refused. A packet the pair
			// lost on the way (a full queue) is in neither, and the abuser and the
			// clients add a few entries.
			if got := refused + entries; got > uint64(sent)+8 || got < uint64(sent)*9/10 {
				t.Errorf("entries %d + refused %d = %d does not account for %d spoofed sources", entries, refused, got, sent)
			}
			if ph.dropped(metrics) == 0 {
				t.Error("the abuser was dropped but the drop counter did not move")
			}
			if entry.LastFullAt == nil {
				t.Error("last_full_at is missing for a full map")
			}
			if w := warningsOf(m); !strings.Contains(w, ph.table) {
				t.Errorf("no coverage warning names %s: %q", ph.table, w)
			}
		})
	}
}

// warningsOf is the coverage warnings of the status as one string.
func warningsOf(m *ebpf.Manager) string { return strings.Join(m.Status().CoverageWarnings, "\n") }

// serveLegit answers every request with pong on addr.
func serveLegit(t *testing.T, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 5)
				if _, err := c.Read(buf); err == nil {
					_, _ = c.Write([]byte("pong\n"))
				}
			}()
		}
	}()
}
