//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Tests load fresh private maps/programs and use BPF_PROG_TEST_RUN. No links,
// network interfaces, namespaces or pinned production maps are touched.
func packetTestCollection(t *testing.T) *cebpf.Collection {
	return packetObjectCollection(t, "wafio_xdp.o")
}

func packetObjectCollection(t *testing.T, object string) *cebpf.Collection {
	t.Helper()
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if dir == "" {
		t.Skip("set WAFIO_TEST_BPF_DIR to compiled objects for kernel packet tests")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("%+v", err)
	}
	spec, err := cebpf.LoadCollectionSpec(filepath.Join(dir, object))
	if err != nil {
		t.Fatalf("%+v", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = cebpf.PinNone
		if m.MaxEntries > 4096 {
			m.MaxEntries = 4096
		}
	}
	var coll *cebpf.Collection
	if object == "wafio_lsm.o" {
		// The tracer's own selection: kernel 5.10 loads the basename file_open.
		_, hadFileOpen := spec.Programs[lsmProgFileOpen]
		var dropped map[string]error
		var variant string
		coll, dropped, variant, err = createLSMCollection(spec.Programs,
			func() (*cebpf.Collection, error) { return cebpf.NewCollection(spec) },
			func(c *cebpf.Collection) { c.Close() })
		if err == nil {
			requireLSMSelection(t, variant, dropped, hadFileOpen)
		}
	} else {
		coll, err = cebpf.NewCollection(spec)
	}
	if err != nil {
		t.Fatalf("%+v", err)
	}
	// Populate tail-call PROG_ARRAY so BPF_PROG_TEST_RUN follows the dispatch
	// path through the entry program (tests unchanged). Missing map/programs
	// (e.g. wafio_tc.o) are skipped.
	if pa := coll.Maps["wafio_xdp_progs"]; pa != nil {
		if p := coll.Programs["wafio_xdp_v4"]; p != nil {
			_ = pa.Update(uint32(0), uint32(p.FD()), cebpf.UpdateAny)
		}
		if p := coll.Programs["wafio_xdp_v6"]; p != nil {
			_ = pa.Update(uint32(1), uint32(p.FD()), cebpf.UpdateAny)
		}
	}
	t.Cleanup(coll.Close)
	return coll
}

func tcpPacket(port uint16) []byte {
	p := make([]byte, 54)
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14] = 0x45
	binary.BigEndian.PutUint16(p[16:18], 40)
	p[22] = 64
	p[23] = 6
	copy(p[26:30], []byte{192, 0, 2, 10})
	copy(p[30:34], []byte{198, 51, 100, 10})
	binary.BigEndian.PutUint16(p[34:36], 12345)
	binary.BigEndian.PutUint16(p[36:38], port)
	p[46] = 0x50
	p[47] = 0x02
	return p
}

func putPacketMap(t *testing.T, c *cebpf.Collection, name string, key, value any) {
	t.Helper()
	if err := c.Maps[name].Update(key, value, cebpf.UpdateAny); err != nil {
		t.Fatalf("%+v", err)
	}
}
func runPacket(t *testing.T, c *cebpf.Collection, p []byte) uint32 {
	t.Helper()
	ret, _, err := c.Programs["wafio_xdp_firewall"].Test(p)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	return ret
}

func TestKernelMonitorCountsWouldDropOnly(t *testing.T) {
	for _, mode := range []uint32{0, 1} {
		t.Run(map[uint32]string{0: "enforce", 1: "monitor"}[mode], func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, Mode: mode})
			putListEntry(t, c, false, "192.0.2.10")
			want := uint32(1)
			if mode == 1 {
				want = 2
			}
			if ret := runPacket(t, c, tcpPacket(443)); ret != want {
				t.Fatalf("packet verdict %d want %d", ret, want)
			}
			var values []MetricsVal
			if err := c.Maps["wafio_metrics"].Lookup(uint32(0), &values); err != nil {
				t.Fatalf("%+v", err)
			}
			var drops, would uint64
			for _, v := range values {
				drops += v.DroppedPackets
				would += v.WouldDropPackets
			}
			if mode == 1 && (drops != 0 || would != 1) {
				t.Fatalf("monitor actual=%d would=%d", drops, would)
			}
			if mode == 0 && (drops != 1 || would != 0) {
				t.Fatalf("enforce actual=%d would=%d", drops, would)
			}
		})
	}
}

func TestKernelPortScanCountsDistinctPorts(t *testing.T) {
	c := packetTestCollection(t)
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1})
	putPacketMap(t, c, "wafio_portscan_config", uint32(0), PortScanConfig{WindowNs: 60_000_000_000, MaxUniquePorts: 3, Action: 1})
	for i := 0; i < 100; i++ {
		if ret := runPacket(t, c, tcpPacket(443)); ret != 2 {
			t.Fatalf("same port retransmit %d falsely dropped", i)
		}
	}
	for _, port := range []uint16{80, 22} {
		if ret := runPacket(t, c, tcpPacket(port)); ret != 2 {
			t.Fatal("threshold not exceeded but dropped")
		}
	}
	if ret := runPacket(t, c, tcpPacket(4444)); ret != 1 {
		t.Fatal("distinct port threshold did not drop")
	}
}

func TestKernelRateWindowNormalization(t *testing.T) {
	for _, window := range []uint64{100, 1000, 10000} {
		t.Run(fmt.Sprint(window), func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, EnableRatelimit: 1})
			putPacketMap(t, c, "wafio_rate_config", uint32(0), RateConfig{WindowNs: window * 1_000_000, MaxPPS: 20, Action: 1})
			for i := uint64(0); i < 20*window/1000; i++ {
				if ret := runPacket(t, c, tcpPacket(443)); ret != 2 {
					t.Fatalf("within budget dropped packet %d", i)
				}
			}
			if ret := runPacket(t, c, tcpPacket(443)); ret != 1 {
				t.Fatal("per-second budget exceeded without drop")
			}
		})
	}
}

func TestKernelSynLimitDoesNotUseHiddenHeuristic(t *testing.T) {
	c := packetTestCollection(t)
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, EnableSynflood: 1})
	putPacketMap(t, c, "wafio_rate_config", uint32(0), RateConfig{WindowNs: 1_000_000_000, MaxSynPPS: 1000, Action: 1})
	for i := 0; i < 100; i++ {
		if ret := runPacket(t, c, tcpPacket(443)); ret != 2 {
			t.Fatalf("benign configured SYN burst blocked at %d", i)
		}
	}
}

func TestKernelReplyCacheExpiryAndDirection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		age      uint64
		flags    uint32
		explicit bool
		want     uint32
	}{
		{"fresh", 0, 1 << 31, false, 2}, {"expired", 301_000_000_000, 1 << 31, false, 1},
		{"inbound-cache", 0, 0, false, 1}, {"explicit-rule-wins", 0, 1 << 31, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			putPacketMap(t, c, "wafio_port_policy_config", uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1})
			if tc.explicit {
				putPacketMap(t, c, "wafio_port_policy", PortPolicyKey{Port: 443, Proto: 6}, PortPolicyVal{Action: 1})
			}
			var now unix.Timespec
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
				t.Fatalf("%+v", err)
			}
			key := ConnKey{Src: IPKeyFromIP(net.ParseIP("198.51.100.10")), Dst: IPKeyFromIP(net.ParseIP("192.0.2.10")), Sport: ntohs(443), Dport: ntohs(12345), Proto: 6}
			putPacketMap(t, c, "wafio_conntrack", key, ConnVal{LastSeenNs: uint64(now.Nano()) - tc.age, TCPState: 1, FlagsSeen: tc.flags})
			p := tcpPacket(443)
			p[47] = 0x10
			if ret := runPacket(t, c, p); ret != tc.want {
				t.Fatalf("verdict %d want %d", ret, tc.want)
			}
		})
	}
}

func ipv6TCPPacket(port uint16) []byte {
	p := make([]byte, 74)
	binary.BigEndian.PutUint16(p[12:14], 0x86dd)
	p[14], p[20], p[21] = 0x60, 6, 64
	binary.BigEndian.PutUint16(p[18:20], 20)
	copy(p[22:38], net.ParseIP("2001:db8::1").To16())
	copy(p[38:54], net.ParseIP("2001:db8::2").To16())
	copy(p[54:], tcpPacket(port)[34:])
	return p
}

func udpReplyPacket(v6 bool) []byte {
	if v6 {
		p := make([]byte, 64)
		binary.BigEndian.PutUint16(p[12:14], 0x86dd)
		p[14], p[20], p[21] = 0x60, 17, 64
		binary.BigEndian.PutUint16(p[18:20], 10)
		copy(p[22:38], net.ParseIP("2001:db8::1").To16())
		copy(p[38:54], net.ParseIP("2001:db8::2").To16())
		binary.BigEndian.PutUint16(p[54:56], 443)
		binary.BigEndian.PutUint16(p[56:58], 12345)
		binary.BigEndian.PutUint16(p[58:60], 10)
		return p
	}
	p := make([]byte, 44)
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14], p[22], p[23] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[16:18], 30)
	copy(p[26:30], []byte{192, 0, 2, 10})
	copy(p[30:34], []byte{198, 51, 100, 10})
	binary.BigEndian.PutUint16(p[34:36], 443)
	binary.BigEndian.PutUint16(p[36:38], 12345)
	binary.BigEndian.PutUint16(p[38:40], 10)
	return p
}

func TestKernelUDPReplyCacheExpiryIPv4IPv6(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			name := fmt.Sprintf("v6=%t/expired=%t", v6, expired)
			t.Run(name, func(t *testing.T) {
				c := packetTestCollection(t)
				putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
				putPacketMap(t, c, "wafio_port_policy_config", uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1})
				remote, local := "192.0.2.10", "198.51.100.10"
				if v6 {
					remote, local = "2001:db8::1", "2001:db8::2"
				}
				var now unix.Timespec
				if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
					t.Fatal(err)
				}
				age := uint64(0)
				if expired {
					age = 31_000_000_000
					if uint64(now.Nano()) <= age {
						t.Skip("kernel uptime has not reached UDP conntrack expiry")
					}
				}
				key := ConnKey{Src: IPKeyFromIP(net.ParseIP(local)), Dst: IPKeyFromIP(net.ParseIP(remote)), Sport: ntohs(12345), Dport: ntohs(443), Proto: 17}
				putPacketMap(t, c, "wafio_conntrack", key, ConnVal{LastSeenNs: uint64(now.Nano()) - age, FlagsSeen: 1 << 31})
				want := uint32(2)
				if expired {
					want = 1
				}
				if got := runPacket(t, c, udpReplyPacket(v6)); got != want {
					t.Fatalf("reply verdict %d want %d", got, want)
				}
			})
		}
	}
}

func TestKernelPacketParser(t *testing.T) {
	base := tcpPacket(443)
	vlan := append([]byte{}, base[:12]...)
	vlan = append(vlan, 0x81, 0, 0, 1)
	vlan = append(vlan, base[12:]...)
	qinq := append([]byte{}, vlan[:12]...)
	qinq = append(qinq, 0x88, 0xa8, 0, 2)
	qinq = append(qinq, vlan[12:]...)
	triple := append([]byte{}, qinq[:12]...)
	triple = append(triple, 0x81, 0, 0, 3)
	triple = append(triple, qinq[12:]...)
	v6fragment := ipv6TCPPacket(443)
	v6fragment[20] = 44
	v6fragment = append(v6fragment[:54], append([]byte{6, 0, 0, 1, 0, 0, 0, 1}, v6fragment[54:]...)...)
	binary.BigEndian.PutUint16(v6fragment[18:20], 28)
	shortDeclared := append([]byte{}, base...)
	binary.BigEndian.PutUint16(shortDeclared[16:18], 20)
	options := append([]byte{}, base[:34]...)
	options = append(options, 1, 1, 1, 1)
	options = append(options, base[34:]...)
	options[14] = 0x46
	binary.BigEndian.PutUint16(options[16:18], 44)
	ext := ipv6TCPPacket(443)
	ext[20] = 60
	ext = append(ext[:54], append([]byte{6, 0, 0, 0, 0, 0, 0, 0}, ext[54:]...)...)
	binary.BigEndian.PutUint16(ext[18:20], 28)
	fragment := append([]byte{}, base...)
	fragment[20] = 0x20
	shortIP := append([]byte{}, base...)
	shortIP[14] = 0x44
	shortTCP := append([]byte{}, base...)
	shortTCP[46] = 0x40
	oversized := append([]byte{}, base...)
	binary.BigEndian.PutUint16(oversized[16:18], 100)
	for _, tc := range []struct {
		name      string
		packet    []byte
		malformed bool
	}{
		{"qinq", qinq, false}, {"third_vlan", triple, true}, {"ipv6_fragment", v6fragment, true}, {"l4_outside_declared_ip", shortDeclared, true},
		{"ipv4", base, false}, {"vlan", vlan, false}, {"options", options, false}, {"ipv6", ipv6TCPPacket(443), false}, {"ipv6_extension", ext, false},
		{"fragment", fragment, true}, {"invalid_ihl", shortIP, true}, {"invalid_tcp_offset", shortTCP, true}, {"declared_length", oversized, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1})
			putPacketMap(t, c, "wafio_port_policy_config", uint32(0), PortPolicyConfig{Enabled: 1})
			putPacketMap(t, c, "wafio_port_policy", PortPolicyKey{Port: 443, Proto: 6, Direction: 0}, PortPolicyVal{Action: 1})
			// Valid encapsulations must reach the same port rule; malformed packets fail the parser.
			if ret := runPacket(t, c, tc.packet); ret != 1 {
				t.Fatalf("verdict %d want drop", ret)
			}
			var values []MetricsVal
			if err := c.Maps["wafio_metrics"].Lookup(uint32(0), &values); err != nil {
				t.Fatal(err)
			}
			var failures uint64
			for _, v := range values {
				failures += v.PacketParseFailures
			}
			if (failures == 1) != tc.malformed {
				t.Fatalf("parse failures %d malformed %v", failures, tc.malformed)
			}
		})
	}
}

func TestKernelIPv6EgressBlocklist(t *testing.T) {
	for _, mode := range []uint32{0, 1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			c := packetObjectCollection(t, "wafio_tc.o")
			putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, Mode: mode})
			putPacketMap(t, c, "wafio_egress_blocklist", IPKeyFromIP(net.ParseIP("2001:db8::2")), IPListVal{})
			ret, _, err := c.Programs["wafio_tc_egress"].Test(ipv6TCPPacket(443))
			if err != nil {
				t.Fatalf("%+v", err)
			}
			want := uint32(2)
			if mode == 1 {
				want = 0
			}
			if ret != want {
				t.Fatalf("verdict %d want %d", ret, want)
			}
		})
	}
}

func TestKernelFirewallSnapshotRollback(t *testing.T) {
	c := packetTestCollection(t)
	m := &Manager{configMap: c.Maps["wafio_config"], block4Map: c.Maps[mapBlock4], block6Map: c.Maps[mapBlock6],
		allow4Map: c.Maps[mapAllow4], allow6Map: c.Maps[mapAllow6]}
	oldKey := SubnetV4Key{PrefixLen: 32, Addr: [4]byte{192, 0, 2, 1}}
	newKey := SubnetV4Key{PrefixLen: 24, Addr: [4]byte{192, 0, 2, 0}}
	oldValue := BlockVal{ExpiresNs: 123456789, HitCount: 42, PrefixLen: 32}
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1})
	putPacketMap(t, c, mapBlock4, oldKey, oldValue)
	snapshot, err := m.CaptureFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Maps[mapBlock4].Delete(oldKey); err != nil {
		t.Fatal(err)
	}
	putPacketMap(t, c, mapBlock4, newKey, BlockVal{PrefixLen: 24})
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{})
	if err := m.RestoreFirewallState(snapshot); err != nil {
		t.Fatal(err)
	}
	var got BlockVal
	if err := c.Maps[mapBlock4].Lookup(oldKey, &got); err != nil {
		t.Fatal(err)
	}
	if got != oldValue {
		t.Fatalf("rollback extended expiry or changed value: %+v", got)
	}
	if err := c.Maps[mapBlock4].Lookup(newKey, &got); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("new key survived rollback: %v", err)
	}
	var cfg GlobalConfig
	if err := c.Maps["wafio_config"].Lookup(uint32(0), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled != 1 {
		t.Fatal("prior configuration not restored")
	}
}

func TestKernelWildcardFamilyIsolation(t *testing.T) {
	for _, tc := range []struct {
		cidr   string
		packet []byte
		want   uint32
	}{
		{"0.0.0.0/0", tcpPacket(443), 1}, {"0.0.0.0/0", ipv6TCPPacket(443), 2},
		{"::/0", ipv6TCPPacket(443), 1}, {"::/0", tcpPacket(443), 2},
	} {
		t.Run(fmt.Sprintf("%s-%d", tc.cidr, len(tc.packet)), func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1})
			putListEntry(t, c, false, tc.cidr)
			if got := runPacket(t, c, tc.packet); got != tc.want {
				t.Fatalf("verdict %d want %d", got, tc.want)
			}
		})
	}
}

func TestKernelIPv6DistinctPortScan(t *testing.T) {
	c := packetTestCollection(t)
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1})
	putPacketMap(t, c, "wafio_portscan_config", uint32(0), PortScanConfig{MaxUniquePorts: 2, WindowNs: 60_000_000_000, Action: 1})
	for i := 0; i < 10; i++ {
		if runPacket(t, c, ipv6TCPPacket(443)) != 2 {
			t.Fatal("repeated port falsely counted")
		}
	}
	if runPacket(t, c, ipv6TCPPacket(80)) != 2 {
		t.Fatal("threshold inclusive boundary")
	}
	if runPacket(t, c, ipv6TCPPacket(22)) != 1 {
		t.Fatal("IPv6 scan missed")
	}
}
