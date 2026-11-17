//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Kernel tests for the ingress IP lists, the jail, the rate limit and
// truncated frames. Like the other TestKernel*
// tests they load wafio_xdp.o / wafio_tc.o from WAFIO_TEST_BPF_DIR into fresh,
// unpinned maps and run packets through BPF_PROG_TEST_RUN only: nothing is
// attached and no live agent map is touched.

// ListJail returns up to limit live jail entries (latest expiry first) and
// how many are live in all.
func (m *Manager) ListJail(limit int) ([]BlocklistEntry, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listJailLocked(limit)
}

// putListEntry writes a permanent ingress allowlist (allow) or blocklist
// entry the way the manager stores it (prefixes in LPM tries).
func putListEntry(t *testing.T, c *cebpf.Collection, allow bool, entry string) {
	t.Helper()
	putListEntryExpiring(t, c, allow, entry, 0)
}

// putListEntryExpiring is putListEntry with an absolute expiry (ktime ns).
func putListEntryExpiring(t *testing.T, c *cebpf.Collection, allow bool, entry string, expiresNs uint64) {
	t.Helper()
	prefixes, err := IPListPrefixes(entry)
	if err != nil {
		t.Fatalf("%s: %v", entry, err)
	}
	for _, p := range prefixes {
		plen := uint32(p.Bits())
		var key any
		var name string
		if p.Addr().Is4() {
			key, name = v4Key(p), mapBlock4
			if allow {
				name = mapAllow4
			}
		} else {
			key, name = v6Key(p), mapBlock6
			if allow {
				name = mapAllow6
			}
		}
		if allow {
			putPacketMap(t, c, name, key, AllowVal{Flags: AllowFlagAll, PrefixLen: plen, ExpiresNs: expiresNs})
		} else {
			putPacketMap(t, c, name, key, BlockVal{PrefixLen: plen, ExpiresNs: expiresNs})
		}
	}
}

// metricSum adds one per-CPU metrics counter across CPUs.
func metricSum(t *testing.T, c *cebpf.Collection, field func(MetricsVal) uint64) uint64 {
	t.Helper()
	var values []MetricsVal
	if err := c.Maps["wafio_metrics"].Lookup(uint32(0), &values); err != nil {
		t.Fatalf("%+v", err)
	}
	var sum uint64
	for _, v := range values {
		sum += field(v)
	}
	return sum
}

// conntrack_entries counts entries created, in both families, not
// packets.
func TestKernelConntrackEntriesCountsCreatedEntries(t *testing.T) {
	c := packetTestCollection(t)
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
	created := func() uint64 { return metricSum(t, c, func(v MetricsVal) uint64 { return v.ConntrackEntries }) }
	for i := 0; i < 3; i++ {
		if ret := runPacket(t, c, tcpPacket(443)); ret != 2 {
			t.Fatalf("IPv4 packet %d verdict %d", i, ret)
		}
	}
	if got := created(); got != 1 {
		t.Fatalf("three packets of one IPv4 flow: conntrack_entries = %d, want 1", got)
	}
	for i := 0; i < 3; i++ {
		if ret := runPacket(t, c, ipv6TCPPacket(443)); ret != 2 {
			t.Fatalf("IPv6 packet %d verdict %d", i, ret)
		}
	}
	if got := created(); got != 2 {
		t.Fatalf("plus one IPv6 flow: conntrack_entries = %d, want 2", got)
	}
}

// max_payload_bytes applies to IPv6 as to IPv4 (the upper-layer length:
// a 20-byte TCP segment in both test packets).
func TestKernelMaxPayloadBothFamilies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet func() []byte
	}{{"v4", func() []byte { return tcpPacket(443) }}, {"v6", func() []byte { return ipv6TCPPacket(443) }}} {
		for _, limit := range []uint32{0, 20, 19} {
			c := packetTestCollection(t)
			putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, MaxPayloadBytes: limit})
			want := uint32(2)
			if limit == 19 {
				want = 1
			}
			if got := runPacket(t, c, tc.packet()); got != want {
				t.Fatalf("%s limit %d: verdict %d want %d", tc.name, limit, got, want)
			}
		}
	}
}

// ktimeNowT is bpf_ktime_get_ns() as seen from the test.
func ktimeNowT(t *testing.T) uint64 {
	t.Helper()
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatalf("%+v", err)
	}
	return uint64(now.Nano())
}

// The per-IP rate limit counts new inbound flows only. tcpPacket is
// 192.0.2.10:12345 -> 198.51.100.10:<port>.
func TestKernelRateLimitSparesRepliesAndAcceptedFlows(t *testing.T) {
	peer, self := IPKeyFromIP(net.ParseIP("192.0.2.10")), IPKeyFromIP(net.ParseIP("198.51.100.10"))
	ack := func() []byte {
		p := tcpPacket(443)
		p[47] = 0x10
		return p
	}
	for _, tc := range []struct {
		name   string
		key    ConnKey
		val    ConnVal
		exempt bool
	}{
		// A host-opened flow (TC wrote CONN_OUTBOUND): its replies pass.
		{"reply", ConnKey{Src: self, Dst: peer, Sport: ntohs(443), Dport: ntohs(12345), Proto: 6},
			ConnVal{TCPState: 1, FlagsSeen: ConnOutbound}, true},
		// An inbound connection the host accepted (TC verified it).
		{"accepted-inbound", ConnKey{Src: peer, Dst: self, Sport: ntohs(12345), Dport: ntohs(443), Proto: 6},
			ConnVal{TCPState: 1, FlagsSeen: 0x12 | ConnVerified | ConnHostAcked}, true},
		// Verified (the host sent a SYN-ACK) but the host never spoke after
		// the handshake — a blind spoofed handshake looks like this: counted.
		{"verified-host-silent", ConnKey{Src: peer, Dst: self, Sport: ntohs(12345), Dport: ntohs(443), Proto: 6},
			ConnVal{TCPState: 1, FlagsSeen: 0x12 | ConnVerified}, false},
		// Established in XDP's own view only (a blind SYN + ACK): counted.
		{"unverified-inbound", ConnKey{Src: peer, Dst: self, Sport: ntohs(12345), Dport: ntohs(443), Proto: 6},
			ConnVal{TCPState: 1, FlagsSeen: 0x12}, false},
		{"no-flow", ConnKey{}, ConnVal{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1, EnableRatelimit: 1})
			putPacketMap(t, c, "wafio_rate_config", uint32(0), RateConfig{WindowNs: 1_000_000_000, MaxPPS: 5, Action: 1})
			if tc.key.Proto != 0 {
				tc.val.LastSeenNs = ktimeNowT(t)
				putPacketMap(t, c, "wafio_conntrack", tc.key, tc.val)
			}
			dropped := 0
			for i := 0; i < 50; i++ {
				if runPacket(t, c, ack()) == 1 {
					dropped++
				}
			}
			if tc.exempt && dropped != 0 {
				t.Fatalf("%d of 50 packets of an exempt flow dropped", dropped)
			}
			if !tc.exempt && dropped == 0 {
				t.Fatal("50 packets over a 5 pps limit, none dropped")
			}
		})
	}
	// New connections stay limited: SYNs from one source over the budget drop.
	t.Run("new-syns", func(t *testing.T) {
		c := packetTestCollection(t)
		putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1, EnableRatelimit: 1})
		putPacketMap(t, c, "wafio_rate_config", uint32(0), RateConfig{WindowNs: 1_000_000_000, MaxPPS: 5, Action: 1})
		dropped := 0
		for port := uint16(1000); port < 1050; port++ {
			if runPacket(t, c, tcpPacket(port)) == 1 {
				dropped++
			}
		}
		if dropped == 0 {
			t.Fatal("50 new connections over a 5 pps limit, none dropped")
		}
	})
}

// tcpFromAddr is tcpPacket(443) / ipv6TCPPacket(443) from another source.
func tcpFromAddr(src string) []byte {
	a := netip.MustParseAddr(src)
	if a.Is4() {
		p := tcpPacket(443)
		b := a.As4()
		copy(p[26:30], b[:])
		return p
	}
	p := ipv6TCPPacket(443)
	b := a.As16()
	copy(p[22:38], b[:])
	return p
}

// Prefixes are stored natively — an IPv6 /64 and an IPv4 /15 are one
// entry each — and an allow and a block of the same prefix live side by side.
func TestKernelPrefixListsNative(t *testing.T) {
	for _, tc := range []struct {
		name  string
		allow []string
		block []string
		src   string
		want  uint32
	}{
		{"v6-64-inside", nil, []string{"2001:db8::/64"}, "2001:db8::1", 1},
		{"v6-64-outside", nil, []string{"2001:db8::/64"}, "2001:db8:0:1::1", 2},
		{"v4-15-inside", nil, []string{"192.0.0.0/15"}, "192.1.200.7", 1},
		{"v4-15-outside", nil, []string{"192.0.0.0/15"}, "192.2.0.1", 2},
		{"range-cover", nil, []string{"198.18.0.5-198.18.0.9"}, "198.18.0.9", 1},
		{"range-edge", nil, []string{"198.18.0.5-198.18.0.9"}, "198.18.0.10", 2},
		{"same-prefix-allow-wins", []string{"192.0.2.0/24"}, []string{"192.0.2.0/24"}, "192.0.2.10", 2},
		{"allow-beats-specific-block", []string{"192.0.2.0/24"}, []string{"192.0.2.10"}, "192.0.2.10", 2},
		{"specific-block-beats-family-allow", []string{"0.0.0.0/0"}, []string{"192.0.2.10"}, "192.0.2.10", 1},
		{"family-allow-beats-family-block", []string{"0.0.0.0/0"}, []string{"0.0.0.0/0"}, "192.0.2.10", 2},
		{"v6-family-block", nil, []string{"::/0"}, "2001:db8::1", 1},
		{"v6-family-block-spares-v4", nil, []string{"::/0"}, "192.0.2.10", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1})
			for _, e := range tc.allow {
				putListEntry(t, c, true, e)
			}
			for _, e := range tc.block {
				putListEntry(t, c, false, e)
			}
			if got := runPacket(t, c, tcpFromAddr(tc.src)); got != tc.want {
				t.Fatalf("verdict %d want %d", got, tc.want)
			}
		})
	}
}

// An expired longest prefix does not hide a live shorter one (the
// walk goes up to LIST_WALK_MAX levels), and an allowlist value without
// ALLOW_F_ALL and without port scopes allows nothing (port-scoped entries:
// TestKernelAllowlistPorts*).
func TestKernelPrefixListsWalk(t *testing.T) {
	const expired = 1 // ktime 1 ns: long past
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, c *cebpf.Collection)
		want  uint32
	}{
		{"expired-32-block-falls-to-24", func(t *testing.T, c *cebpf.Collection) {
			putListEntryExpiring(t, c, false, "192.0.2.10", expired)
			putListEntry(t, c, false, "192.0.2.0/24")
		}, 1},
		{"expired-32-block-alone", func(t *testing.T, c *cebpf.Collection) {
			putListEntryExpiring(t, c, false, "192.0.2.10", expired)
		}, 2},
		{"expired-32-allow-falls-to-24-allow", func(t *testing.T, c *cebpf.Collection) {
			putListEntryExpiring(t, c, true, "192.0.2.10", expired)
			putListEntry(t, c, true, "192.0.2.0/24")
			putListEntry(t, c, false, "0.0.0.0/0")
		}, 2},
		{"expired-v6-falls-to-48", func(t *testing.T, c *cebpf.Collection) {
			putListEntryExpiring(t, c, false, "2001:db8::/64", expired)
			putListEntry(t, c, false, "2001:db8::/48")
		}, 1},
		{"three-expired-then-live", func(t *testing.T, c *cebpf.Collection) {
			for _, e := range []string{"192.0.2.10", "192.0.2.10/31", "192.0.2.8/30"} {
				putListEntryExpiring(t, c, false, e, expired)
			}
			putListEntry(t, c, false, "192.0.0.0/8")
		}, 1},
		{"walk-limit", func(t *testing.T, c *cebpf.Collection) {
			// Four expired levels exhaust LIST_WALK_MAX: the live /8 is not
			// reached. The control plane and the agent refuse such a list
			// (BLOCKLIST_NESTING_TOO_DEEP).
			for _, e := range []string{"192.0.2.10", "192.0.2.10/31", "192.0.2.8/30", "192.0.2.8/29"} {
				putListEntryExpiring(t, c, false, e, expired)
			}
			putListEntry(t, c, false, "192.0.0.0/8")
		}, 2},
		{"scoped-allow-does-not-decide", func(t *testing.T, c *cebpf.Collection) {
			p := netip.MustParsePrefix("192.0.2.10/32")
			putPacketMap(t, c, mapAllow4, v4Key(p), AllowVal{PrefixLen: 32}) // no ALLOW_F_ALL, no scopes: allows nothing
			putListEntry(t, c, false, "192.0.2.0/24")
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := packetTestCollection(t)
			putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1})
			tc.setup(t, c)
			src := "192.0.2.10"
			if strings.Contains(tc.name, "v6") {
				src = "2001:db8::1"
			}
			if got := runPacket(t, c, tcpFromAddr(src)); got != tc.want {
				t.Fatalf("verdict %d want %d", got, tc.want)
			}
		})
	}
}

// On the real tries: ReplaceIPLists writes prefixes, lists them back
// in canonical spelling, and a second swap changes only what differs.
func TestKernelReplaceIPListsOnTries(t *testing.T) {
	c := packetTestCollection(t)
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1})
	m := &Manager{allow4Map: c.Maps[mapAllow4], allow6Map: c.Maps[mapAllow6], block4Map: c.Maps[mapBlock4], block6Map: c.Maps[mapBlock6]}
	err := ReplaceIPLists(m, IPListUpdate{
		Allow: []AllowlistEntry{{IP: "203.0.113.7"}},
		Block: []BlocklistEntry{{IP: "2001:db8::/64"}, {IP: "192.0.0.0/15"}, {IP: "198.18.0.5-198.18.0.7"}},
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := m.ListBlocklist(0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range blocks {
		got = append(got, e.IP)
	}
	sort.Strings(got)
	if want := "192.0.0.0/15,198.18.0.5,198.18.0.6/31,2001:db8::/64"; strings.Join(got, ",") != want {
		t.Fatalf("blocklist %v want %s", got, want)
	}
	if v := runPacket(t, c, tcpFromAddr("2001:db8::99")); v != 1 {
		t.Fatalf("/64 member verdict %d", v)
	}
	if err := ReplaceIPLists(m, IPListUpdate{Block: []BlocklistEntry{{IP: "192.0.0.0/15"}}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if v := runPacket(t, c, tcpFromAddr("2001:db8::99")); v != 2 {
		t.Fatalf("removed /64 still drops: %d", v)
	}
	if v := runPacket(t, c, tcpFromAddr("192.1.0.1")); v != 1 {
		t.Fatalf("kept /15 stopped dropping: %d", v)
	}
}

// cutFrame is a frame whose TCP header the buffer cuts (parse_packet -3):
// the IP header declares a full 20-byte TCP header (v4: 192.0.2.10 ->
// 198.51.100.10, v6: 2001:db8::1 -> 2001:db8::2), but only tcpBytes of it
// are present. optionsCut: a complete 20-byte header announcing 12 bytes of
// options that are missing (ports and flags readable).
func cutFrame(v6 bool, tcpBytes int, optionsCut bool) []byte {
	full := tcpPacket(443)
	if v6 {
		full = ipv6TCPPacket(443)
	}
	l4 := 34
	if v6 {
		l4 = 54
	}
	p := append([]byte(nil), full[:l4+tcpBytes]...)
	if optionsCut {
		p = append([]byte(nil), full...)
		p[l4+12] = 0x80 // doff 8: 32-byte header, 12 option bytes absent
		p[l4+13] = 0x10 // ACK
	}
	return p
}

// A frame whose TCP/UDP header the RX buffer cuts still meets the IP
// lists and geo; nothing else applies to it, so an unlisted source passes.
func TestKernelTruncatedL4MeetsIPLists(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		src := "192.0.2.10"
		family := "0.0.0.0/0"
		if v6 {
			src, family = "2001:db8::1", "::/0"
		}
		for _, tc := range []struct {
			name  string
			setup func(t *testing.T, c *cebpf.Collection)
			frame []byte
			want  uint32
		}{
			{"unlisted-passes", func(*testing.T, *cebpf.Collection) {}, cutFrame(v6, 10, false), 2},
			{"blocked-drops", func(t *testing.T, c *cebpf.Collection) { putListEntry(t, c, false, src) }, cutFrame(v6, 10, false), 1},
			{"family-block-drops", func(t *testing.T, c *cebpf.Collection) { putListEntry(t, c, false, family) }, cutFrame(v6, 10, false), 1},
			{"allowlisted-passes", func(t *testing.T, c *cebpf.Collection) {
				putListEntry(t, c, false, family)
				putListEntry(t, c, true, src)
			}, cutFrame(v6, 10, false), 2},
			{"port-rules-not-applied-residual", func(t *testing.T, c *cebpf.Collection) {
				putPacketMap(t, c, "wafio_port_policy_config", uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1})
			}, cutFrame(v6, 10, false), 2},
			{"options-cut-blocked-drops", func(t *testing.T, c *cebpf.Collection) { putListEntry(t, c, false, src) }, cutFrame(v6, 20, true), 1},
		} {
			t.Run(fmt.Sprintf("v6=%t/%s", v6, tc.name), func(t *testing.T) {
				c := packetTestCollection(t)
				putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
				tc.setup(t, c)
				if got := runPacket(t, c, tc.frame); got != tc.want {
					t.Fatalf("verdict %d want %d", got, tc.want)
				}
			})
		}
	}
	// A reply to a host-opened flow whose options are cut keeps the reply
	// exemption from the family-wide block (ports are readable).
	t.Run("options-cut-reply-passes-family-block", func(t *testing.T) {
		c := packetTestCollection(t)
		putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
		putListEntry(t, c, false, "0.0.0.0/0")
		key := ConnKey{Src: IPKeyFromIP(net.ParseIP("198.51.100.10")), Dst: IPKeyFromIP(net.ParseIP("192.0.2.10")),
			Sport: ntohs(443), Dport: ntohs(12345), Proto: 6}
		putPacketMap(t, c, "wafio_conntrack", key, ConnVal{LastSeenNs: ktimeNowT(t), TCPState: 1, FlagsSeen: ConnOutbound})
		if got := runPacket(t, c, cutFrame(false, 20, true)); got != 2 {
			t.Fatalf("verdict %d want 2", got)
		}
	})
	// Geo blocking applies too.
	t.Run("geo-blocked-drops", func(t *testing.T) {
		c := packetTestCollection(t)
		putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1, EnableGeoblock: 1})
		type geo4 struct {
			PrefixLen uint32
			Addr      [4]byte
		}
		putPacketMap(t, c, "wafio_geo_cidr4", geo4{PrefixLen: 24, Addr: [4]byte{192, 0, 2, 0}}, uint8(1))
		if got := runPacket(t, c, cutFrame(false, 10, false)); got != 1 {
			t.Fatalf("verdict %d want 1", got)
		}
	})
}

// Jail entries live in wafio_jail. They drop like a specific block, the
// allowlist still wins over them, and a push of the operator lists
// (ReplaceIPLists) neither removes them nor shortens their TTL.
func TestKernelJailSurvivesListPush(t *testing.T) {
	c := packetTestCollection(t)
	putPacketMap(t, c, "wafio_config", uint32(0), GlobalConfig{Enabled: 1})
	m := &Manager{allow4Map: c.Maps[mapAllow4], allow6Map: c.Maps[mapAllow6], block4Map: c.Maps[mapBlock4],
		block6Map: c.Maps[mapBlock6], jailMap: c.Maps[mapJail]}
	// The manager's clock offset is zero here: ktime = wall time, so keep the
	// TTL far beyond the test's run.
	if err := m.AddToJail("192.0.2.10", 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := m.AddToJail("192.0.2.0/24", time.Hour); err == nil {
		t.Fatal("a prefix was jailed")
	}
	if got := runPacket(t, c, tcpFromAddr("192.0.2.10")); got != 1 {
		t.Fatalf("jailed source verdict %d", got)
	}
	var before IPListVal
	if err := c.Maps[mapJail].Lookup(IPKeyFromIP(net.ParseIP("192.0.2.10")), &before); err != nil {
		t.Fatal(err)
	}
	// A push with an empty blocklist (the old apply deleted every blocklist
	// entry, the jail's among them).
	if err := ReplaceIPLists(m, IPListUpdate{Allow: []AllowlistEntry{}, Block: []BlocklistEntry{}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	var after IPListVal
	if err := c.Maps[mapJail].Lookup(IPKeyFromIP(net.ParseIP("192.0.2.10")), &after); err != nil {
		t.Fatalf("push removed the jail entry: %v", err)
	}
	if after.ExpiresNs != before.ExpiresNs {
		t.Fatalf("push changed the jail TTL: %d -> %d", before.ExpiresNs, after.ExpiresNs)
	}
	if got := runPacket(t, c, tcpFromAddr("192.0.2.10")); got != 1 {
		t.Fatalf("jailed source passes after a push: %d", got)
	}
	jail, total, err := m.ListJail(10)
	if err != nil || total != 1 || len(jail) != 1 || jail[0].IP != "192.0.2.10" || jail[0].HitCount < 2 {
		t.Fatalf("ListJail = %+v total %d err %v", jail, total, err)
	}
	// The allowlist wins over a jail entry.
	putListEntry(t, c, true, "192.0.2.0/24")
	if got := runPacket(t, c, tcpFromAddr("192.0.2.10")); got != 2 {
		t.Fatalf("allowlisted jailed source verdict %d", got)
	}
	// An expired jail entry no longer drops.
	c2 := packetTestCollection(t)
	putPacketMap(t, c2, "wafio_config", uint32(0), GlobalConfig{Enabled: 1})
	putPacketMap(t, c2, mapJail, IPKeyFromIP(net.ParseIP("192.0.2.10")), IPListVal{ExpiresNs: 1})
	if got := runPacket(t, c2, tcpFromAddr("192.0.2.10")); got != 2 {
		t.Fatalf("expired jail entry still drops: %d", got)
	}
}

// The rate-limit exemption needs the host to have spoken on the
// inbound connection after its handshake (TC marks CONN_HOST_ACKED); the
// host's reset ends it. XDP and TC share the conntrack map, as in Manager.
func TestKernelRateExemptionNeedsHostSegment(t *testing.T) {
	xdp, tc := packetPair(t)
	putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1, EnableRatelimit: 1})
	putPacketMap(t, xdp, "wafio_rate_config", uint32(0), RateConfig{WindowNs: 10_000_000_000, MaxPPS: 1, BurstPPS: 3, Action: 1})
	const peer, self = "198.51.100.77", "192.0.2.10"
	flood := func() int {
		dropped := 0
		for i := 0; i < 20; i++ {
			if runPacket(t, xdp, tcp4(peer, self, 40001, 8443, 0x10)) == xdpDrp {
				dropped++
			}
		}
		return dropped
	}
	if got := runPacket(t, xdp, tcp4(peer, self, 40001, 8443, 0x02)); got != xdpPas {
		t.Fatalf("SYN verdict %d", got)
	}
	if got := runTC(t, tc, tcp4(self, peer, 8443, 40001, 0x12)); got != tcOK {
		t.Fatalf("host SYN-ACK verdict %d", got)
	}
	if d := flood(); d == 0 {
		t.Fatal("ACK flood after a handshake the host never spoke on was not limited")
	}
	if got := runTC(t, tc, tcp4(self, peer, 8443, 40001, 0x18)); got != tcOK {
		t.Fatalf("host data verdict %d", got)
	}
	var cv ConnVal
	if err := xdp.Maps[mapConntrack].Lookup(connKey4(peer, self, 40001, 8443), &cv); err != nil {
		t.Fatal(err)
	}
	if cv.FlagsSeen&(ConnVerified|ConnHostAcked) != ConnVerified|ConnHostAcked || cv.TCPState != 1 {
		t.Fatalf("entry after host data: state %d flags %#x", cv.TCPState, cv.FlagsSeen)
	}
	if d := flood(); d != 0 {
		t.Fatalf("%d packets of an accepted connection dropped by the rate limit", d)
	}
	if got := runTC(t, tc, tcp4(self, peer, 8443, 40001, 0x14)); got != tcOK {
		t.Fatalf("host reset verdict %d", got)
	}
	if d := flood(); d == 0 {
		t.Fatal("flood after the host reset the connection was not limited")
	}
}
