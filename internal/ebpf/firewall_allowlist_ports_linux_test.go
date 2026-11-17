//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
)

// Kernel tests for port-scoped allowlist entries. Like the other TestKernel*
// tests they load wafio_xdp.o / wafio_tc.o from WAFIO_TEST_BPF_DIR into
// fresh, unpinned maps and run packets through BPF_PROG_TEST_RUN only:
// nothing is attached and no live agent map is touched.
//
//	WAFIO_TEST_BPF_DIR=<objects> go test -run TestKernelAllowlistPorts -v ./internal/ebpf/

// apFamily is one address family's packets for these tests: src is the
// allowlisted source, other a neighbour in the same /24 (/48) and not
// listed, dst the host.
type apFamily struct {
	name             string
	src, other, dst  string
	wildcard, prefix string // the family-wide entry; the entry's /24 or /48
	tcp              func(src string, sport, dport uint16, flags byte) []byte
	udp              func(src string, sport, dport uint16) []byte
	icmp             func(src string) []byte
}

var apFamilies = []apFamily{
	{
		name: "v4", src: "203.0.113.7", other: "203.0.113.8", dst: "198.51.100.10",
		wildcard: "0.0.0.0/0", prefix: "203.0.113.0/24",
		tcp: func(src string, sport, dport uint16, flags byte) []byte {
			return tcp4(src, "198.51.100.10", sport, dport, flags)
		},
		udp:  func(src string, sport, dport uint16) []byte { return udp4(src, "198.51.100.10", sport, dport) },
		icmp: func(src string) []byte { return icmp4(src, "198.51.100.10", 8) },
	},
	{
		name: "v6", src: "2001:db8:7::7", other: "2001:db8:7::8", dst: "2001:db8::1",
		wildcard: "::/0", prefix: "2001:db8:7::/48",
		tcp: func(src string, sport, dport uint16, flags byte) []byte {
			return tcp6(src, "2001:db8::1", sport, dport, flags)
		},
		udp:  func(src string, sport, dport uint16) []byte { return udp6n(src, "2001:db8::1", sport, dport, 0) },
		icmp: func(src string) []byte { return icmp6(src, "2001:db8::1", 128, 64) },
	},
}

// icmp4 builds an IPv4 ICMP message of the given type.
func icmp4(src, dst string, typ byte) []byte {
	p := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14], p[22], p[23] = 0x45, 64, 1
	binary.BigEndian.PutUint16(p[16:18], 28)
	copy(p[26:30], net.ParseIP(src).To4())
	copy(p[30:34], net.ParseIP(dst).To4())
	p[34] = typ
	return p
}

// putScopedEntry writes an allowlist entry with ports the way the manager
// stores it (allowValScopes; no ports = ALLOW_F_ALL). expiresNs 0 =
// permanent.
func putScopedEntry(t *testing.T, c *cebpf.Collection, entry string, ports []PortScope, expiresNs uint64) {
	t.Helper()
	prefixes, err := IPListPrefixes(entry)
	if err != nil {
		t.Fatalf("%s: %v", entry, err)
	}
	for _, p := range prefixes {
		v := AllowVal{PrefixLen: uint32(p.Bits()), ExpiresNs: expiresNs}
		if err := allowValScopes(&v, ports); err != nil {
			t.Fatal(err)
		}
		if p.Addr().Is4() {
			putPacketMap(t, c, mapAllow4, v4Key(p), v)
		} else {
			putPacketMap(t, c, mapAllow6, v6Key(p), v)
		}
	}
}

func requireScopes(t *testing.T, c *cebpf.Collection) {
	t.Helper()
	if c.Maps[mapAllowScopes] == nil {
		t.Fatal("wafio_xdp.o has no wafio_allow_scopes marker: the object predates allowlist port scopes")
	}
}

type apCase struct {
	name string
	pkt  []byte
	want uint32
}

func runAPCases(t *testing.T, c *cebpf.Collection, cases []apCase) {
	t.Helper()
	for _, tc := range cases {
		if got := runPacket(t, c, tc.pkt); got != tc.want {
			t.Errorf("%s: verdict %d want %d", tc.name, got, tc.want)
		}
	}
}

// Scoped 22/tcp + 5432/tcp + 6000-6010/udp under a wildcard block: only TCP
// or UDP to those ports passes; other ports, the other protocol, ICMP and
// a neighbouring address are dropped.
func TestKernelAllowlistPortsScopeMatch(t *testing.T) {
	for _, f := range apFamilies {
		t.Run(f.name, func(t *testing.T) {
			c := packetTestCollection(t)
			requireScopes(t, c)
			putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			putListEntry(t, c, false, f.wildcard)
			putScopedEntry(t, c, f.src, []PortScope{ps("tcp", 22, 0), ps("tcp", 5432, 0), ps("udp", 6000, 6010)}, 0)
			runAPCases(t, c, []apCase{
				{"22/tcp", f.tcp(f.src, 40000, 22, 0x02), xdpPass},
				{"5432/tcp", f.tcp(f.src, 40000, 5432, 0x02), xdpPass},
				{"80/tcp", f.tcp(f.src, 40000, 80, 0x02), xdpDrop},
				{"22/udp", f.udp(f.src, 40000, 22), xdpDrop},
				{"5432/udp", f.udp(f.src, 40000, 5432), xdpDrop},
				{"6000/udp edge", f.udp(f.src, 40000, 6000), xdpPass},
				{"6010/udp edge", f.udp(f.src, 40000, 6010), xdpPass},
				{"5999/udp", f.udp(f.src, 40000, 5999), xdpDrop},
				{"6011/udp", f.udp(f.src, 40000, 6011), xdpDrop},
				{"6005/tcp", f.tcp(f.src, 40000, 6005, 0x02), xdpDrop},
				{"icmp", f.icmp(f.src), xdpDrop},
				{"neighbour 22/tcp", f.tcp(f.other, 40000, 22, 0x02), xdpDrop},
			})
		})
	}
}

// Nesting: a /32 scoped to 22 under a /24 scoped to 443; an expired /32
// falls through to the /24; an entry without ports passes every port and
// ICMP, also under a scoped longer prefix.
func TestKernelAllowlistPortsNestedAndLegacy(t *testing.T) {
	const expired = 1 // ktime 1 ns: long past
	for _, f := range apFamilies {
		t.Run(f.name, func(t *testing.T) {
			t.Run("nested", func(t *testing.T) {
				c := packetTestCollection(t)
				requireScopes(t, c)
				putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
				putListEntry(t, c, false, f.wildcard)
				putScopedEntry(t, c, f.prefix, []PortScope{ps("tcp", 443, 0)}, 0)
				putScopedEntry(t, c, f.src, []PortScope{ps("tcp", 22, 0)}, 0)
				runAPCases(t, c, []apCase{
					{"/32 22", f.tcp(f.src, 40000, 22, 0x02), xdpPass},
					{"/32 443 via /24", f.tcp(f.src, 40000, 443, 0x02), xdpPass},
					{"/32 80", f.tcp(f.src, 40000, 80, 0x02), xdpDrop},
					{"neighbour 443", f.tcp(f.other, 40000, 443, 0x02), xdpPass},
					{"neighbour 22", f.tcp(f.other, 40000, 22, 0x02), xdpDrop},
				})
			})
			t.Run("expired falls through", func(t *testing.T) {
				c := packetTestCollection(t)
				putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
				putListEntry(t, c, false, f.wildcard)
				putScopedEntry(t, c, f.src, []PortScope{ps("tcp", 22, 0)}, expired)
				if got := runPacket(t, c, f.tcp(f.src, 40000, 22, 0x02)); got != xdpDrop {
					t.Fatalf("expired /32 alone: %d", got)
				}
				putScopedEntry(t, c, f.prefix, []PortScope{ps("tcp", 22, 0)}, 0)
				if got := runPacket(t, c, f.tcp(f.src, 40000, 22, 0x02)); got != xdpPass {
					t.Fatalf("expired /32 over a live /24: %d", got)
				}
			})
			t.Run("legacy full", func(t *testing.T) {
				c := packetTestCollection(t)
				putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
				putListEntry(t, c, false, f.wildcard)
				putListEntry(t, c, true, f.prefix) // ALLOW_F_ALL, as every earlier agent wrote it
				putScopedEntry(t, c, f.src, []PortScope{ps("tcp", 22, 0)}, 0)
				runAPCases(t, c, []apCase{
					{"scoped /32 80 falls to full /24", f.tcp(f.src, 40000, 80, 0x02), xdpPass},
					{"scoped /32 icmp falls to full /24", f.icmp(f.src), xdpPass},
					{"full udp", f.udp(f.other, 40000, 9999), xdpPass},
					{"full icmp", f.icmp(f.other), xdpPass},
				})
			})
		})
	}
}

// Ingress Deny All with no rule for 5432: the port is reachable only from
// the scoped entry, and the entry reaches no other port.
func TestKernelAllowlistPortsDenyAll(t *testing.T) {
	for _, f := range apFamilies {
		t.Run(f.name, func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			putPacketMap(t, c, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1})
			putScopedEntry(t, c, f.src, []PortScope{ps("tcp", 5432, 0)}, 0)
			runAPCases(t, c, []apCase{
				{"entry 5432", f.tcp(f.src, 40000, 5432, 0x02), xdpPass},
				{"other 5432", f.tcp(f.other, 40000, 5432, 0x02), xdpDrop},
				{"entry 80", f.tcp(f.src, 40000, 80, 0x02), xdpDrop},
				{"entry 5432/udp", f.udp(f.src, 40000, 5432), xdpDrop},
			})
		})
	}
}

// A jailed address passes to its scoped ports (the allowlist runs before
// the jail, as for full entries) and is dropped on every other port.
func TestKernelAllowlistPortsJail(t *testing.T) {
	for _, f := range apFamilies {
		t.Run(f.name, func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			putPacketMap(t, c, mapJail, IPKeyFromIP(net.ParseIP(f.src)), IPListVal{ExpiresNs: monoNow(t) + uint64(time.Hour)})
			putScopedEntry(t, c, f.src, []PortScope{ps("tcp", 22, 0)}, 0)
			runAPCases(t, c, []apCase{
				{"jailed 22", f.tcp(f.src, 40000, 22, 0x02), xdpPass},
				{"jailed 80", f.tcp(f.src, 40000, 80, 0x02), xdpDrop},
				{"jailed icmp", f.icmp(f.src), xdpDrop},
			})
		})
	}
}

// Geo: in allow mode a scoped source outside the allowed countries reaches
// its port and nothing else; in block mode the same. A reply from a scoped
// source to a flow this host opened arrives on an ephemeral port: allow mode
// passes it (replies are exempt), block mode drops it when the source's
// country is blocked, where an entry for every port passes it.
func TestKernelAllowlistPortsGeo(t *testing.T) {
	for _, f := range apFamilies {
		t.Run(f.name, func(t *testing.T) {
			blockRange := func(t *testing.T, c *cebpf.Collection) {
				p := netip.MustParsePrefix(f.prefix)
				if p.Addr().Is4() {
					putPacketMap(t, c, "wafio_geo_cidr4", geoCIDRv4Key{Prefixlen: uint32(p.Bits()), Addr: p.Addr().As4()}, geoCIDRBlocked)
				} else {
					putPacketMap(t, c, "wafio_geo_cidr6", geoCIDRv6Key{Prefixlen: uint32(p.Bits()), Addr: p.Addr().As16()}, geoCIDRBlocked)
				}
			}
			hostFlow := func(t *testing.T, c *cebpf.Collection) {
				// The host sent dst:45000 → src:53/udp a moment ago.
				key := ConnKey{Src: IPKeyFromIP(net.ParseIP(f.dst)), Dst: IPKeyFromIP(net.ParseIP(f.src)), Sport: ntohs(45000), Dport: ntohs(53), Proto: 17}
				putPacketMap(t, c, mapConntrack, key, ConnVal{LastSeenNs: monoNow(t), FlagsSeen: ConnOutbound})
			}
			for _, mode := range []struct {
				name      string
				allow     bool
				replyWant uint32
			}{{"allow mode", true, xdpPass}, {"block mode", false, xdpDrop}} {
				t.Run(mode.name, func(t *testing.T) {
					c := geoAllowCollection(t, 0, mode.allow) // src lies outside the allowed ranges
					if !mode.allow {
						blockRange(t, c)
					}
					putScopedEntry(t, c, f.src, []PortScope{ps("tcp", 22, 0), ps("udp", 53, 0)}, 0)
					runAPCases(t, c, []apCase{
						{"scoped 22", f.tcp(f.src, 40000, 22, 0x02), xdpPass},
						{"scoped 80", f.tcp(f.src, 40000, 80, 0x02), xdpDrop},
						{"scoped icmp echo", f.icmp(f.src), xdpDrop},
						{"neighbour 22", f.tcp(f.other, 40000, 22, 0x02), xdpDrop},
					})
					hostFlow(t, c)
					if got := runPacket(t, c, f.udp(f.src, 53, 45000)); got != mode.replyWant {
						t.Fatalf("reply to a host flow from a scoped source: %d want %d", got, mode.replyWant)
					}
					// The same reply from a source allowlisted for every port.
					c2 := geoAllowCollection(t, 0, mode.allow)
					if !mode.allow {
						blockRange(t, c2)
					}
					putScopedEntry(t, c2, f.src, nil, 0)
					hostFlow(t, c2)
					if got := runPacket(t, c2, f.udp(f.src, 53, 45000)); got != xdpPass {
						t.Fatalf("reply to a host flow from a full entry: %d", got)
					}
				})
			}
		})
	}
}

// An in-scope connection gets the trusted conntrack entry, so its replies
// pass egress Deny All; an out-of-scope one is dropped at ingress and
// its replies stay blocked.
func TestKernelAllowlistPortsConntrackEgressDeny(t *testing.T) {
	for _, fam := range []struct {
		name, local, remote string
		tcp                 func(src, dst string, sport, dport uint16, flags byte) []byte
	}{{"v4", local, remote, tcp4}, {"v6", local6, remote6, tcp6}} {
		t.Run(fam.name, func(t *testing.T) {
			port := freeTCPPort(t) // an owned port would be adopted without an entry
			other := freeTCPPort(t)
			for other == port {
				other = freeTCPPort(t)
			}
			xdp, tc := packetPair(t)
			putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1, DefaultEgress: 1})
			putScopedEntry(t, xdp, fam.remote, []PortScope{ps("tcp", int(port), 0)}, 0)
			if got := runPacket(t, xdp, fam.tcp(fam.remote, fam.local, 50000, port, 0x02)); got != xdpPass {
				t.Fatalf("in-scope SYN %d", got)
			}
			if got := runTC(t, tc, fam.tcp(fam.local, fam.remote, port, 50000, 0x12)); got != tcOK {
				t.Fatalf("SYN-ACK of the in-scope connection %d", got)
			}
			if got := runPacket(t, xdp, fam.tcp(fam.remote, fam.local, 50001, other, 0x02)); got != xdpDrop {
				t.Fatalf("out-of-scope SYN %d", got)
			}
			if got := runTC(t, tc, fam.tcp(fam.local, fam.remote, other, 50001, 0x12)); got != tcShot {
				t.Fatalf("SYN-ACK of the out-of-scope connection %d", got)
			}
		})
	}
}

// Monitor mode: an out-of-scope packet is counted as a would-drop, an
// in-scope one as an allowlist pass.
func TestKernelAllowlistPortsMonitor(t *testing.T) {
	for _, f := range apFamilies {
		t.Run(f.name, func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, Mode: 1, EnableConntrack: 1})
			putListEntry(t, c, false, f.wildcard)
			putScopedEntry(t, c, f.src, []PortScope{ps("tcp", 22, 0)}, 0)
			runAPCases(t, c, []apCase{
				{"22", f.tcp(f.src, 40000, 22, 0x02), xdpPass},
				{"80", f.tcp(f.src, 40000, 80, 0x02), xdpPass},
			})
			var values []MetricsVal
			if err := c.Maps[mapMetrics].Lookup(uint32(0), &values); err != nil {
				t.Fatal(err)
			}
			var drops, would, passes uint64
			for _, v := range values {
				drops += v.DroppedPackets
				would += v.WouldDropPackets
				passes += v.AllowlistPasses
			}
			if drops != 0 || would != 1 || passes != 1 {
				t.Fatalf("drops %d would %d allowlist passes %d", drops, would, passes)
			}
		})
	}
}

// A frame whose TCP options the RX buffer cut still has readable
// ports and meets the scopes; one whose TCP header is cut has none and
// never matches a scope.
func TestKernelAllowlistPortsTruncatedFrame(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name, src, wildcard := "v4", "192.0.2.10", "0.0.0.0/0"
		if v6 {
			name, src, wildcard = "v6", "2001:db8::1", "::/0"
		}
		t.Run(name, func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			putListEntry(t, c, false, wildcard)
			putScopedEntry(t, c, src, []PortScope{ps("tcp", 443, 0)}, 0)
			if got := runPacket(t, c, cutFrame(v6, 20, true)); got != xdpPass {
				t.Fatalf("options cut, port 443 in scope: %d", got)
			}
			if got := runPacket(t, c, cutFrame(v6, 10, false)); got != xdpDrop {
				t.Fatalf("header cut, no port: %d", got)
			}
		})
	}
}

// The manager writes scoped entries into the real tries, lists their ports
// back, and the swap narrows an entry in place; an object without the
// wafio_allow_scopes marker refuses scoped entries (never written as
// entries for every port).
func TestKernelAllowlistPortsManager(t *testing.T) {
	c := packetTestCollection(t)
	requireScopes(t, c)
	putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
	putListEntry(t, c, false, "0.0.0.0/0")
	m := &Manager{allow4Map: c.Maps[mapAllow4], allow6Map: c.Maps[mapAllow6], allowScopesMap: c.Maps[mapAllowScopes],
		block4Map: c.Maps[mapBlock4], block6Map: c.Maps[mapBlock6]}
	if !m.AllowlistPortsSupported() {
		t.Fatal("object with the marker not reported as supporting scopes")
	}
	err := ReplaceIPLists(m, IPListUpdate{Allow: []AllowlistEntry{
		{IP: "203.0.113.7", Ports: []PortScope{ps("tcp", 22, 0)}},
		{IP: "2001:db8:7::/48", Ports: []PortScope{ps("any", 53, 0)}},
		{IP: "198.18.0.0/15"},
	}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	listed, err := m.ListAllowlist(100)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range listed {
		got[e.IP] = PortScopesKey(e.Ports)
	}
	if got["203.0.113.7"] != "22/tcp" || got["2001:db8:7::/48"] != "53/any" || got["198.18.0.0/15"] != "" || len(got) != 3 {
		t.Fatalf("listed %v", got)
	}
	runAPCases(t, c, []apCase{
		{"22", tcp4("203.0.113.7", "198.51.100.10", 40000, 22, 0x02), xdpPass},
		{"80", tcp4("203.0.113.7", "198.51.100.10", 40000, 80, 0x02), xdpDrop},
	})
	// Narrowed to 2222: 22 closes, nothing is deleted on the way.
	err = ReplaceIPLists(m, IPListUpdate{Allow: []AllowlistEntry{
		{IP: "203.0.113.7", Ports: []PortScope{ps("tcp", 2222, 0)}},
		{IP: "2001:db8:7::/48", Ports: []PortScope{ps("any", 53, 0)}},
		{IP: "198.18.0.0/15"},
	}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	runAPCases(t, c, []apCase{
		{"22 after narrowing", tcp4("203.0.113.7", "198.51.100.10", 40000, 22, 0x02), xdpDrop},
		{"2222", tcp4("203.0.113.7", "198.51.100.10", 40000, 2222, 0x02), xdpPass},
	})

	old := &Manager{allow4Map: c.Maps[mapAllow4], allow6Map: c.Maps[mapAllow6], block4Map: c.Maps[mapBlock4], block6Map: c.Maps[mapBlock6]}
	if old.AllowlistPortsSupported() {
		t.Fatal("object without the marker reported as supporting scopes")
	}
	if err := old.AddToAllowlistPorts("192.0.2.99", 0, []PortScope{ps("tcp", 22, 0)}); !errors.Is(err, ErrAllowlistPortsUnsupported) {
		t.Fatalf("scoped write on an old object: %v", err)
	}
	if err := old.AddToAllowlistPorts("192.0.2.99", 0, nil); err != nil {
		t.Fatalf("full write on an old object: %v", err)
	}
	if err := m.AddToAllowlistPorts("0.0.0.0/0", 0, []PortScope{ps("tcp", 22, 0)}); !errors.Is(err, ErrAllowlistWildcardScoped) {
		t.Fatalf("scoped /0: %v", err)
	}
}
