//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Geo allow mode under BPF_PROG_TEST_RUN (private maps, nothing attached):
// a source inside an allowed country's ranges passes, any other public
// source is dropped (or counted as would-drop in monitor mode), and the
// exemptions — replies, the allowlist, private sources, ICMP errors and
// echo replies, established verified TCP connections — pass.
//
//	WAFIO_TEST_BPF_DIR=<objects> go test -run TestKernelGeo -v ./internal/ebpf/

const (
	xdpDrop = 1
	xdpPass = 2
)

// geoAllowCollection loads wafio_xdp.o with geo filtering and conntrack on,
// the given XDP mode (0 enforce, 1 monitor) and geo mode, and the allowed
// ranges 192.0.2.0/24 and 2001:db8:1::/48 (value GEO_CIDR_ALLOWED).
func geoAllowCollection(t *testing.T, mode uint32, allow bool) *cebpf.Collection {
	t.Helper()
	c := packetTestCollection(t)
	if c.Maps["wafio_geo_config"] == nil {
		t.Fatal("wafio_xdp.o has no wafio_geo_config")
	}
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, Mode: mode, LogBlocked: 1, EnableConntrack: 1, EnableGeoblock: 1})
	gm := GeoConfig{Mode: geoModeBlockValue}
	if allow {
		// Allow mode went live now: connections tracked before it are the
		// "already open" ones (geo_tracked_inbound).
		gm = GeoConfig{Mode: geoModeAllowValue, AllowSinceNs: monoNow(t)}
	}
	putPacketMap(t, c, "wafio_geo_config", uint32(0), gm)
	putPacketMap(t, c, "wafio_geo_cidr4", geoCIDRv4Key{Prefixlen: 24, Addr: [4]byte{192, 0, 2, 0}}, geoCIDRAllowed)
	putPacketMap(t, c, "wafio_geo_cidr6", geoCIDRv6Key{Prefixlen: 48, Addr: netip.MustParseAddr("2001:db8:1::").As16()}, geoCIDRAllowed)
	return c
}

// tcpFrom is tcpPacket with another source address, ports and TCP flags.
func tcpFrom(src [4]byte, sport, dport uint16, flags byte) []byte {
	p := tcpPacket(dport)
	copy(p[26:30], src[:])
	p[34], p[35] = byte(sport>>8), byte(sport)
	p[47] = flags
	return p
}

// tcp6From is ipv6TCPPacket from another source.
func tcp6From(src string) []byte {
	p := ipv6TCPPacket(443)
	copy(p[22:38], net.ParseIP(src).To16())
	return p
}

// inbound seeds the inbound conntrack entry foreign:50000 → host:22 with
// the given TCP state and flags, first seen firstSec and last seen lastSec
// seconds from the moment allow mode went live (approximately now).
func inbound(foreign [4]byte, state, flags uint32, firstSec, lastSec int64) func(*testing.T, *cebpf.Collection) {
	return func(t *testing.T, pc *cebpf.Collection) {
		t.Helper()
		var gc GeoConfig
		if err := pc.Maps["wafio_geo_config"].Lookup(uint32(0), &gc); err != nil {
			t.Fatal(err)
		}
		at := func(sec int64) uint64 { return uint64(int64(gc.AllowSinceNs) + sec*1_000_000_000) }
		key := ConnKey{Src: IPKeyFromIP(net.IP(foreign[:])), Dst: IPKeyFromIP(net.ParseIP("198.51.100.10")), Sport: ntohs(50000), Dport: ntohs(22), Proto: 6}
		putPacketMap(t, pc, "wafio_conntrack", key, ConnVal{FirstSeenNs: at(firstSec), LastSeenNs: at(lastSec), TCPState: state, FlagsSeen: flags})
	}
}

// udpFrom: IPv4 UDP datagram src:sport → 198.51.100.10:dport.
func udpFrom(src [4]byte, sport, dport uint16) []byte {
	p := make([]byte, 14+20+8)
	p[12], p[13] = 0x08, 0x00
	p[14] = 0x45
	p[16], p[17] = 0, 28
	p[22], p[23] = 64, 17
	copy(p[26:30], src[:])
	copy(p[30:34], []byte{198, 51, 100, 10})
	p[34], p[35] = byte(sport>>8), byte(sport)
	p[36], p[37] = byte(dport>>8), byte(dport)
	p[38], p[39] = 0, 8
	return p
}

// udp6From: IPv6 UDP datagram from src to port 53.
func udp6From(src string) []byte {
	p := udpReplyPacket(true)
	copy(p[22:38], net.ParseIP(src).To16())
	p[54], p[55] = 0xcf, 0x08 // sport 53000
	p[56], p[57] = 0, 53
	return p
}

// icmpFrom: IPv4 ICMP message of the given type from src.
func icmpFrom(src [4]byte, typ byte) []byte {
	p := make([]byte, 14+20+8)
	p[12], p[13] = 0x08, 0x00
	p[14] = 0x45
	p[16], p[17] = 0, 28
	p[22], p[23] = 64, 1
	copy(p[26:30], src[:])
	copy(p[30:34], []byte{198, 51, 100, 10})
	p[34] = typ
	return p
}

func geoMetrics(t *testing.T, pc *cebpf.Collection) (drops, would, geo uint64) {
	t.Helper()
	var values []MetricsVal
	if err := pc.Maps["wafio_metrics"].Lookup(uint32(0), &values); err != nil {
		t.Fatalf("%+v", err)
	}
	for _, v := range values {
		drops += v.DroppedPackets
		would += v.WouldDropPackets
		geo += v.GeoblockDrops
	}
	return
}

func TestKernelGeoAllowVerdicts(t *testing.T) {
	foreign := [4]byte{203, 0, 113, 9}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, pc *cebpf.Collection)
		pkt   []byte
		want  uint32
	}{
		{"allowed country", nil, tcpFrom([4]byte{192, 0, 2, 10}, 12345, 443, 0x02), xdpPass},
		{"other country", nil, tcpFrom(foreign, 12345, 443, 0x02), xdpDrop},
		{"private source", nil, tcpFrom([4]byte{10, 1, 2, 3}, 12345, 443, 0x02), xdpPass},
		{"cgnat source", nil, tcpFrom([4]byte{100, 64, 1, 1}, 12345, 443, 0x02), xdpPass},
		{"allowlisted", func(t *testing.T, pc *cebpf.Collection) {
			putListEntry(t, pc, true, net.IP(foreign[:]).String())
		}, tcpFrom(foreign, 12345, 443, 0x02), xdpPass},
		{"reply to a host-opened flow", func(t *testing.T, pc *cebpf.Collection) {
			key := ConnKey{Src: IPKeyFromIP(net.ParseIP("198.51.100.10")), Dst: IPKeyFromIP(net.IP(foreign[:])), Sport: ntohs(40000), Dport: ntohs(443), Proto: 6}
			putPacketMap(t, pc, "wafio_conntrack", key, ConnVal{LastSeenNs: monoNow(t), FlagsSeen: ConnOutbound | 0x02})
		}, tcpFrom(foreign, 443, 40000, 0x12), xdpPass},
		{"established verified inbound", inbound(foreign, 1, ConnVerified|0x12, -10, 0), tcpFrom(foreign, 50000, 22, 0x10), xdpPass},
		// Never a SYN on the tuple, a closing entry only
		// for 300 s, and only entries from before allow mode went live.
		{"syn on an established tuple", inbound(foreign, 1, ConnVerified|0x12, -10, 0), tcpFrom(foreign, 50000, 22, 0x02), xdpDrop},
		{"closing entry, fresh", inbound(foreign, 2, ConnVerified|0x12, -10, 0), tcpFrom(foreign, 50000, 22, 0x11), xdpPass},
		{"closing entry, idle 301 s", inbound(foreign, 2, ConnVerified|0x12, -400, -301), tcpFrom(foreign, 50000, 22, 0x10), xdpDrop},
		{"closing entry idle 4 days, new syn", inbound(foreign, 2, ConnVerified|0x12, -4*86400, -4*86400), tcpFrom(foreign, 50000, 22, 0x02), xdpDrop},
		{"entry opened after allow mode", inbound(foreign, 1, ConnVerified|0x12, +1, 0), tcpFrom(foreign, 50000, 22, 0x10), xdpDrop},
		{"unverified inbound entry", inbound(foreign, 1, 0x12, -10, 0), tcpFrom(foreign, 50000, 22, 0x10), xdpDrop},
		// A private source passes for TCP and ICMP, for
		// UDP only from a connected subnet (wafio_geo_local4/6).
		{"udp from a private source not connected", nil, udpFrom([4]byte{10, 1, 2, 3}, 53000, 53), xdpDrop},
		{"udp from a connected subnet", func(t *testing.T, pc *cebpf.Collection) {
			putPacketMap(t, pc, "wafio_geo_local4", geoCIDRv4Key{Prefixlen: 24, Addr: [4]byte{10, 1, 2, 0}}, uint8(1))
		}, udpFrom([4]byte{10, 1, 2, 3}, 53000, 53), xdpPass},
		{"udp dhcp client 0.0.0.0", nil, udpFrom([4]byte{0, 0, 0, 0}, 68, 67), xdpPass},
		{"icmp fragmentation needed", nil, icmpFrom(foreign, 3), xdpPass},
		{"icmp echo reply", nil, icmpFrom(foreign, 0), xdpPass},
		{"icmp echo request", nil, icmpFrom(foreign, 8), xdpDrop},
		{"ipv6 allowed", nil, tcp6From("2001:db8:1::5"), xdpPass},
		{"ipv6 other", nil, tcp6From("2001:db8:2::5"), xdpDrop},
		{"ipv6 unique local", nil, tcp6From("fd00::5"), xdpPass},
		{"ipv6 udp unique local not connected", nil, udp6From("fd00::5"), xdpDrop},
		{"ipv6 udp unique local connected", func(t *testing.T, pc *cebpf.Collection) {
			putPacketMap(t, pc, "wafio_geo_local6", geoCIDRv6Key{Prefixlen: 64, Addr: netip.MustParseAddr("fd00::").As16()}, uint8(1))
		}, udp6From("fd00::5"), xdpPass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := geoAllowCollection(t, 0, true)
			if tc.setup != nil {
				tc.setup(t, pc)
			}
			if ret := runPacket(t, pc, tc.pkt); ret != tc.want {
				t.Fatalf("verdict %d want %d", ret, tc.want)
			}
			_, _, geo := geoMetrics(t, pc)
			if wantGeo := map[bool]uint64{true: 1, false: 0}[tc.want == xdpDrop]; geo != wantGeo {
				t.Fatalf("geoblock_drops %d want %d", geo, wantGeo)
			}
		})
	}
}

// Monitor mode dry-runs allow mode: the packet passes and counts as a
// would-drop, not as a geoblock drop.
func TestKernelGeoAllowMonitorCountsWouldDrop(t *testing.T) {
	pc := geoAllowCollection(t, 1, true)
	if ret := runPacket(t, pc, tcpFrom([4]byte{203, 0, 113, 9}, 12345, 443, 0x02)); ret != xdpPass {
		t.Fatalf("monitor verdict %d", ret)
	}
	drops, would, geo := geoMetrics(t, pc)
	if drops != 0 || would != 1 || geo != 0 {
		t.Fatalf("monitor drops=%d would=%d geo=%d", drops, would, geo)
	}
}

// Block mode reads only GEO_CIDR_BLOCKED ranges: the allowed ranges the
// agent writes before it switches to allow mode change nothing.
func TestKernelGeoBlockModeIgnoresAllowedRanges(t *testing.T) {
	pc := geoAllowCollection(t, 0, false)
	putPacketMap(t, pc, "wafio_geo_cidr4", geoCIDRv4Key{Prefixlen: 24, Addr: [4]byte{203, 0, 113, 0}}, geoCIDRBlocked)
	if ret := runPacket(t, pc, tcpFrom([4]byte{192, 0, 2, 10}, 12345, 443, 0x02)); ret != xdpPass {
		t.Fatalf("allowed range in block mode: verdict %d", ret)
	}
	if ret := runPacket(t, pc, tcpFrom([4]byte{198, 18, 0, 1}, 12345, 443, 0x02)); ret != xdpPass {
		t.Fatalf("unlisted source in block mode: verdict %d", ret)
	}
	if ret := runPacket(t, pc, tcpFrom([4]byte{203, 0, 113, 9}, 12345, 443, 0x02)); ret != xdpDrop {
		t.Fatalf("blocked range in block mode: verdict %d", ret)
	}
}

// The XDP programs stay well inside the verifier's budget with allow mode
// (logged for reference).
func TestKernelGeoXDPVerifiedInstructions(t *testing.T) {
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if dir == "" {
		t.Skip("set WAFIO_TEST_BPF_DIR to compiled objects for kernel packet tests")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := cebpf.LoadCollectionSpec(filepath.Join(dir, "wafio_xdp.o"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range spec.Maps {
		m.Pinning = cebpf.PinNone
		if m.MaxEntries > 4096 {
			m.MaxEntries = 4096
		}
	}
	c, err := cebpf.NewCollectionWithOptions(spec, cebpf.CollectionOptions{
		Programs: cebpf.ProgramOptions{LogLevel: cebpf.LogLevelStats, LogSizeStart: 1 << 20},
	})
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer c.Close()
	stack := regexp.MustCompile(`stack depth [0-9+]+`)
	for _, name := range []string{"wafio_xdp_firewall", "wafio_xdp_v4", "wafio_xdp_v6"} {
		p := c.Programs[name]
		if p == nil {
			continue
		}
		info, err := p.Info()
		if err != nil {
			t.Fatalf("%s: %+v", name, err)
		}
		n, ok := info.VerifiedInstructions()
		if !ok {
			t.Skip("kernel does not report verified instructions")
		}
		depth := stack.FindString(p.VerifierLog)
		t.Logf("%s: %d static instructions, %d verified instructions, %s", name,
			len(spec.Programs[name].Instructions), n, depth)
		if n > 500000 {
			t.Errorf("%s: %d verified instructions, over half the 1M budget", name, n)
		}
		// The per-family programs' own frame stays at the 320 B it had
		// before allow mode: kernels that round every frame of a call chain
		// to 32 B (5.10) count it against the 512 B limit with the callees'
		// frames, and 6.8 (16 B rounding) would not notice the overflow.
		var main int
		if _, err := fmt.Sscanf(depth, "stack depth %d", &main); err == nil && name != "wafio_xdp_firewall" && main > 320 {
			t.Errorf("%s: own stack frame %d B, over the 320 B budget", name, main)
		}
	}
}

// After a failed restore GeoState follows what the maps hold
// (live mode, ranges counted), since the local API and the lockout guard
// read the mode from it.
func TestKernelGeoStateReconciledWithLiveMode(t *testing.T) {
	c := geoAllowCollection(t, 0, false)
	m := &Manager{geoCIDR4Map: c.Maps["wafio_geo_cidr4"], geoCIDR6Map: c.Maps["wafio_geo_cidr6"], geoConfigMap: c.Maps["wafio_geo_config"]}
	if err := m.ApplyGeoRanges(GeoModeAllow, []string{"ID"}, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}); err != nil {
		t.Fatal(err)
	}
	m.geoState = GeoRangeState{Mode: GeoModeBlock, Countries: []string{"CN"}}
	m.reconcileGeoStateLocked()
	if st := m.GeoState(); st.Mode != GeoModeAllow || st.RangesV4 != 1 || len(st.Countries) != 0 {
		t.Fatalf("GeoState %+v after reconcile", st)
	}
}

// A later step fails after the geo step and the bundle
// rolls back. RestoreFirewallState puts the geo tries and the mode record
// (allow_since_ns included) back by diff, in both directions, and the
// dataplane enforces the restored policy.
func TestKernelGeoRollbackRestoresModeAndRanges(t *testing.T) {
	cn := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	id := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	idPkt := tcpFrom([4]byte{192, 0, 2, 10}, 12345, 443, 0x02)
	cnPkt := tcpFrom([4]byte{203, 0, 113, 9}, 12345, 443, 0x02)
	otherPkt := tcpFrom([4]byte{198, 18, 0, 1}, 12345, 443, 0x02)
	for _, tc := range []struct {
		name               string
		fromMode, toMode   string
		from, to           []netip.Prefix
		wantID, wantCN     uint32
		wantOther          uint32
		wantAllowAfterBack bool
	}{
		{"block to allow, rolled back", GeoModeBlock, GeoModeAllow, cn, id, xdpPass, xdpDrop, xdpPass, false},
		{"allow to block, rolled back", GeoModeAllow, GeoModeBlock, id, cn, xdpPass, xdpDrop, xdpDrop, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := geoAllowCollection(t, 0, false)
			for _, name := range []string{"wafio_geo_cidr4", "wafio_geo_cidr6"} {
				var k []byte
				var v []byte
				it := c.Maps[name].Iterate()
				var keys [][]byte
				for it.Next(&k, &v) {
					keys = append(keys, append([]byte(nil), k...))
				}
				for _, key := range keys {
					_ = c.Maps[name].Delete(key)
				}
			}
			m := &Manager{configMap: c.Maps["wafio_config"], geoCIDR4Map: c.Maps["wafio_geo_cidr4"],
				geoCIDR6Map: c.Maps["wafio_geo_cidr6"], geoConfigMap: c.Maps["wafio_geo_config"]}
			if err := m.ApplyGeoRanges(tc.fromMode, nil, tc.from); err != nil {
				t.Fatal(err)
			}
			var before GeoConfig
			if err := c.Maps["wafio_geo_config"].Lookup(uint32(0), &before); err != nil {
				t.Fatal(err)
			}
			snap, err := m.CaptureFirewallState()
			if err != nil {
				t.Fatal(err)
			}
			if err := m.ApplyGeoRanges(tc.toMode, nil, tc.to); err != nil {
				t.Fatal(err)
			}
			if err := m.RestoreFirewallState(snap); err != nil {
				t.Fatal(err)
			}
			var after GeoConfig
			if err := c.Maps["wafio_geo_config"].Lookup(uint32(0), &after); err != nil {
				t.Fatal(err)
			}
			if after != before || (after.Mode == geoModeAllowValue) != tc.wantAllowAfterBack {
				t.Fatalf("mode record %+v, want %+v", after, before)
			}
			if m.GeoState().Mode != tc.fromMode {
				t.Fatalf("GeoState %+v, want mode %s", m.GeoState(), tc.fromMode)
			}
			for _, chk := range []struct {
				name string
				pkt  []byte
				want uint32
			}{{"allowed country", idPkt, tc.wantID}, {"blocked country", cnPkt, tc.wantCN}, {"unlisted", otherPkt, tc.wantOther}} {
				if ret := runPacket(t, c, chk.pkt); ret != chk.want {
					t.Errorf("%s after rollback: verdict %d want %d", chk.name, ret, chk.want)
				}
			}
		})
	}
}
