//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
)

// Lockout-guard checks, dataplane side (BPF_PROG_TEST_RUN; kernel
// lab, needs WAFIO_TEST_BPF_DIR and root).

func udp4(src, dst string, sport, dport uint16) []byte { return udp4n(src, dst, sport, dport, 0) }

// udp4n builds an IPv4 UDP packet with an n-byte payload (a DHCP message
// needs at least 236).
func udp4n(src, dst string, sport, dport uint16, n int) []byte {
	p := make([]byte, 42+n)
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14], p[22], p[23] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[16:18], uint16(28+n))
	copy(p[26:30], net.ParseIP(src).To4())
	copy(p[30:34], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(p[34:36], sport)
	binary.BigEndian.PutUint16(p[36:38], dport)
	binary.BigEndian.PutUint16(p[38:40], uint16(8+n))
	return p
}

// udp6n builds an IPv6 UDP packet (hop limit 255) with an n-byte payload.
func udp6n(src, dst string, sport, dport uint16, n int) []byte {
	p := make([]byte, 14+40+8+n)
	binary.BigEndian.PutUint16(p[12:14], 0x86dd)
	p[14] = 0x60
	binary.BigEndian.PutUint16(p[18:20], uint16(8+n))
	p[20], p[21] = 17, 255
	copy(p[22:38], net.ParseIP(src).To16())
	copy(p[38:54], net.ParseIP(dst).To16())
	binary.BigEndian.PutUint16(p[54:56], sport)
	binary.BigEndian.PutUint16(p[56:58], dport)
	binary.BigEndian.PutUint16(p[58:60], uint16(8+n))
	return p
}

// udpConnKey is the conntrack key of a UDP flow (connKey4 is TCP).
func udpConnKey(src, dst string, sport, dport uint16) ConnKey {
	return ConnKey{Src: IPKeyFromIP(net.ParseIP(src)), Dst: IPKeyFromIP(net.ParseIP(dst)), Sport: ntohs(sport), Dport: ntohs(dport), Proto: 17}
}

// icmp6 builds an ICMPv6 packet of the given type (24-byte body).
func icmp6(src, dst string, icmpType, hopLimit byte) []byte {
	p := make([]byte, 14+40+24)
	binary.BigEndian.PutUint16(p[12:14], 0x86dd)
	p[14] = 0x60
	binary.BigEndian.PutUint16(p[18:20], 24)
	p[20], p[21] = 58, hopLimit
	copy(p[22:38], net.ParseIP(src).To16())
	copy(p[38:54], net.ParseIP(dst).To16())
	p[54] = icmpType
	return p
}

// An allowlisted SSH client is tracked, so its session's replies pass
// egress Deny All.
func TestKernelAllowlistedSourceRepliesPassEgressDeny(t *testing.T) {
	port := freeTCPPort(t) // an owned port would be adopted without an entry
	xdp, tc := packetPair(t)
	putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
	putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1, DefaultEgress: 1})
	putListEntry(t, xdp, true, remote)
	if got := runPacket(t, xdp, tcp4(remote, local, 50000, port, 0x02)); got != xdpPas {
		t.Fatalf("allowlisted SYN %d", got)
	}
	if got := runTC(t, tc, tcp4(local, remote, port, 50000, 0x12)); got != tcOK {
		t.Fatalf("SYN-ACK to allowlisted client %d", got)
	}
	if got := runTC(t, tc, tcp4(local, remote, port, 50000, 0x18)); got != tcOK {
		t.Fatalf("data to allowlisted client %d (no inbound entry?)", got)
	}
}

// An expired rule never decides: the next key in lookup order does.
func TestKernelExpiredRuleFallsThrough(t *testing.T) {
	for _, tc := range []struct {
		name      string
		permanent bool
		wantXDP   uint32
		wantTC    uint32
	}{
		{"expired exact allow, permanent any/both allow", true, xdpPas, tcOK},
		{"expired exact allow only", false, xdpDrp, tcShot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			xdp, c := packetPair(t)
			putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1})
			putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1, DefaultEgress: 1})
			putPacketMap(t, xdp, mapPortPolicy, PortPolicyKey{Port: 22, Proto: 6, Direction: PortDirIngress}, PortPolicyVal{Action: 0, ExpiresNs: 1})
			putPacketMap(t, xdp, mapPortPolicy, PortPolicyKey{Port: 443, Proto: 6, Direction: PortDirEgress}, PortPolicyVal{Action: 0, ExpiresNs: 1})
			if tc.permanent {
				putPacketMap(t, xdp, mapPortPolicy, PortPolicyKey{Port: 22, Proto: 0, Direction: PortDirBoth}, PortPolicyVal{Action: 0})
				putPacketMap(t, xdp, mapPortPolicy, PortPolicyKey{Port: 443, Proto: 0, Direction: PortDirBoth}, PortPolicyVal{Action: 0})
			}
			if got := runPacket(t, xdp, tcp4(remote, local, 50000, 22, 0x02)); got != tc.wantXDP {
				t.Fatalf("XDP %d want %d", got, tc.wantXDP)
			}
			if got := runTC(t, c, tcp4(local, remote, 40000, 443, 0x02)); got != tc.wantTC {
				t.Fatalf("TC %d want %d", got, tc.wantTC)
			}
		})
	}
}

// IPv6 neighbour discovery passes a ::/0 block both ways — only with hop
// limit 255 and only types 133-137.
func TestKernelNeighbourDiscoveryPassesWildcard(t *testing.T) {
	xdp, tc := packetPair(t)
	putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1})
	putListEntry(t, xdp, false, "::/0")
	putPacketMap(t, xdp, mapEgressBlocklist, IPKeyWildcard("::/0"), IPListVal{})
	for _, c := range []struct {
		icmpType, hop byte
		xdp           uint32
		tc            uint32
	}{
		{135, 255, xdpPas, tcOK}, {136, 255, xdpPas, tcOK}, {134, 255, xdpPas, tcOK},
		{135, 64, xdpDrp, tcShot},  // routed: not on-link
		{128, 255, xdpDrp, tcShot}, // echo request: not ND
	} {
		if got := runPacket(t, xdp, icmp6("fe80::1", "fe80::2", c.icmpType, c.hop)); got != c.xdp {
			t.Fatalf("XDP type %d hop %d: %d want %d", c.icmpType, c.hop, got, c.xdp)
		}
		if got := runTC(t, tc, icmp6("fe80::2", "fe80::1", c.icmpType, c.hop)); got != c.tc {
			t.Fatalf("TC type %d hop %d: %d want %d", c.icmpType, c.hop, got, c.tc)
		}
	}
	// Outbound ND only to link-local or multicast targets.
	if got := runTC(t, tc, icmp6("fe80::2", "ff02::1:ff00:1", 135, 255)); got != tcOK {
		t.Fatalf("NS to solicited-node multicast: %d", got)
	}
	if got := runTC(t, tc, icmp6("2001:db8::2", "2001:db8::99", 136, 255)); got != tcShot {
		t.Fatalf("NA to a global address passed the ::/0 egress block: %d", got)
	}
}

// bootp builds an IPv4 DHCP message: Ethernet destination ethDst, BOOTP op
// (1 request, 2 reply), xid and chaddr, padded to a DHCP-sized payload.
func bootp(ethDst net.HardwareAddr, src, dst string, sport, dport uint16, op byte, xid uint32, chaddr net.HardwareAddr) []byte {
	p := udp4n(src, dst, sport, dport, 300)
	copy(p[0:6], ethDst)
	b := p[42:]
	b[0], b[1], b[2] = op, 1, 6
	binary.BigEndian.PutUint32(b[4:8], xid)
	copy(b[28:34], chaddr)
	return p
}

// DHCP client traffic survives egress Deny All, a 0.0.0.0/0 egress block
// and ingress Deny All — and nothing else rides on the exemption (xid, op,
// chaddr and addressing are checked, servers expire).
// Server replies are never tracked as inbound connections: TC would
// otherwise pass the next request to that server as their reply, past the
// server's expiry.
func TestKernelDHCPClientSurvivesDenyAll(t *testing.T) {
	xdp, tc := packetPair(t)
	putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
	putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1, DefaultEgress: 1})
	putPacketMap(t, xdp, mapEgressBlocklist, IPKeyWildcard("0.0.0.0/0"), IPListVal{})
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x10}
	other := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99}
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	const xid = 0x5eed1234
	server := remote

	// Nothing pending: no reply passes, no request to a unicast server.
	if got := runPacket(t, xdp, bootp(mac, server, local, 67, 68, 2, xid, mac)); got != xdpDrp {
		t.Fatalf("unsolicited BOOTREPLY passed: %d", got)
	}
	if got := runTC(t, tc, bootp(bcast, local, server, 68, 67, 1, xid, mac)); got != tcShot {
		t.Fatalf("RENEW to a server never heard from passed: %d", got)
	}
	if got := runTC(t, tc, udp4("0.0.0.0", "255.255.255.255", 68, 67)); got != tcShot {
		t.Fatalf("undersized broadcast 68→67 passed: %d", got)
	}
	if got := runTC(t, tc, udp4n("0.0.0.0", "255.255.255.255", 68, 67, 300)); got != tcShot {
		t.Fatalf("non-BOOTP broadcast 68→67 passed: %d", got)
	}

	// DISCOVER (broadcast BOOTREQUEST) records xid + chaddr.
	if got := runTC(t, tc, bootp(bcast, "0.0.0.0", "255.255.255.255", 68, 67, 1, xid, mac)); got != tcOK {
		t.Fatalf("DISCOVER %d", got)
	}
	// Negative replies while the request is pending.
	for name, pkt := range map[string][]byte{
		"wrong xid":          bootp(mac, server, local, 67, 68, 2, xid+1, mac),
		"op=1":               bootp(mac, server, local, 67, 68, 1, xid, mac),
		"non-DHCP payload":   udp4n(server, local, 67, 68, 300),
		"other chaddr":       bootp(mac, server, local, 67, 68, 2, xid, other),
		"unicast other host": bootp(other, server, local, 67, 68, 2, xid, mac),
	} {
		if got := runPacket(t, xdp, pkt); got != xdpDrp {
			t.Fatalf("%s passed: %d", name, got)
		}
	}
	var learned uint64
	if err := xdp.Maps[mapDHCPServers].Lookup(net.ParseIP(server).To4(), &learned); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("server learned from a rejected reply: %v", err)
	}
	// A real OFFER: unicast to this host's hardware address, and broadcast.
	if got := runPacket(t, xdp, bootp(mac, server, local, 67, 68, 2, xid, mac)); got != xdpPas {
		t.Fatalf("unicast OFFER %d", got)
	}
	if got := runPacket(t, xdp, bootp(bcast, server, "255.255.255.255", 67, 68, 2, xid, mac)); got != xdpPas {
		t.Fatalf("broadcast ACK %d", got)
	}
	if err := xdp.Maps[mapDHCPServers].Lookup(net.ParseIP(server).To4(), &learned); err != nil {
		t.Fatalf("answering server not learned: %v", err)
	}
	var cv ConnVal
	if err := xdp.Maps[mapConntrack].Lookup(udpConnKey(server, local, 67, 68), &cv); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("DHCP server reply tracked as an inbound flow: %+v %v", cv, err)
	}
	// RENEW to the learned server passes; to another address it does not.
	if got := runTC(t, tc, bootp(bcast, local, server, 68, 67, 1, xid+2, mac)); got != tcOK {
		t.Fatalf("unicast RENEW to the learned server %d", got)
	}
	if got := runTC(t, tc, bootp(bcast, local, "203.0.113.77", 68, 67, 1, xid+2, mac)); got != tcShot {
		t.Fatalf("RENEW to another address passed: %d", got)
	}
	if got := runTC(t, tc, udp4n(local, remote, 68, 68, 300)); got != tcShot {
		t.Fatalf("non-DHCP UDP from 68 passed egress deny: %d", got)
	}
	// Learned servers expire (DHCP_SERVER_TTL_NS, one day).
	if now := monoNow(t); now > 86_400_000_000_000 {
		putPacketMap(t, xdp, mapDHCPServers, net.ParseIP(server).To4(), now-86_400_000_000_001)
		if got := runTC(t, tc, bootp(bcast, local, server, 68, 67, 1, xid+3, mac)); got != tcShot {
			t.Fatalf("expired server still passes: %d", got)
		}
	}
	// DHCPv6: a link-local server's reply passes ingress Deny All but is not
	// tracked, so a unicast message to that server is not its reply (only
	// ff02::1:2 is request-bound exempt) and egress Deny All drops it.
	const server6, client6 = "fe80::1", "fe80::2"
	if got := runPacket(t, xdp, udp6n(server6, client6, 547, 546, 16)); got != xdpPas {
		t.Fatalf("DHCPv6 reply from a link-local server %d", got)
	}
	if err := xdp.Maps[mapConntrack].Lookup(udpConnKey(server6, client6, 547, 546), &cv); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("DHCPv6 server reply tracked as an inbound flow: %+v %v", cv, err)
	}
	if got := runTC(t, tc, udp6n(client6, server6, 546, 547, 16)); got != tcShot {
		t.Fatalf("unicast DHCPv6 to the server passed egress deny as a reply: %d", got)
	}
	// Another machine's DISCOVER seen inbound never touches the pending
	// state (it lives outside conntrack).
	putPacketMap(t, xdp, mapDHCPPending, uint32(0x0badcafe), dhcpPendingVal{SentNs: 1})
	_ = runPacket(t, xdp, bootp(bcast, "0.0.0.0", "255.255.255.255", 68, 67, 1, xid, other))
	var pend dhcpPendingVal
	if err := xdp.Maps[mapDHCPPending].Lookup(uint32(0x0badcafe), &pend); err != nil || pend.SentNs != 1 {
		t.Fatalf("inbound packet refreshed pending state: %+v %v", pend, err)
	}
}

// dhcpPendingVal mirrors struct dhcp_pending_val (16 bytes).
type dhcpPendingVal struct {
	SentNs uint64
	Chaddr [6]byte
	Pad    [2]byte
}

// A SYN-ACK passes egress Deny All only for a tracked inbound SYN;
// an established inbound connection keeps its exemption long past 300 s and
// replies refresh it; a half-open one does not.
func TestKernelEgressHandshakeAndEstablishedTTL(t *testing.T) {
	_, c := packetPair(t)
	putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
	putPacketMap(t, c, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
	if got := runTC(t, c, tcp4(local, remote, 22, 50000, 0x12)); got != tcShot {
		t.Fatalf("SYN-ACK without a tracked SYN passed: %d", got)
	}
	now := monoNow(t)
	putPacketMap(t, c, mapConntrack, connKey4(remote, local, 50000, 22), ConnVal{LastSeenNs: now, FlagsSeen: 0x02})
	if got := runTC(t, c, tcp4(local, remote, 22, 50000, 0x12)); got != tcOK {
		t.Fatalf("SYN-ACK to a tracked SYN %d", got)
	}
	if got := runTC(t, c, tcp4(local, remote, freeTCPPort(t), 50099, 0x10)); got != tcShot {
		t.Fatalf("ACK without inbound entry %d", got)
	}
	if now < 301_000_000_000 {
		t.Skip("kernel uptime below conntrack TTL")
	}
	key := connKey4(remote, local, 50001, 22)
	putPacketMap(t, c, mapConntrack, key, ConnVal{LastSeenNs: now - 301_000_000_000, TCPState: 1, FlagsSeen: 0x12 | ConnVerified})
	if got := runTC(t, c, tcp4(local, remote, 22, 50001, 0x18)); got != tcOK {
		t.Fatalf("established idle 301 s: %d", got)
	}
	var cv ConnVal
	if err := c.Maps[mapConntrack].Lookup(key, &cv); err != nil || cv.LastSeenNs < now {
		t.Fatalf("reply did not refresh the established entry: %+v %v", cv, err)
	}
	half := connKey4(remote, local, 50002, 22)
	putPacketMap(t, c, mapConntrack, half, ConnVal{LastSeenNs: now - 301_000_000_000, TCPState: 0, FlagsSeen: 0x02})
	if got := runTC(t, c, tcp4(local, remote, 22, 50002, 0x18)); got != tcShot {
		t.Fatalf("half-open idle 301 s: %d", got)
	}
}

// Under SYN pressure a SYN allocates no state, the handshake-completing
// ACK does.
func TestKernelPressureAllocatesForCompletedHandshake(t *testing.T) {
	xdp, _ := packetPair(t)
	putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
	putPacketMap(t, xdp, mapRateConfig, uint32(0), RateConfig{WindowNs: 1_000_000_000, SynPressurePPS: 1})
	cpus, err := cebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	type pressure struct{ WindowStartNs, Count uint64 }
	vals := make([]pressure, cpus)
	for i := range vals {
		vals[i] = pressure{WindowStartNs: monoNow(t), Count: 1000}
	}
	if err := xdp.Maps["wafio_syn_pressure"].Update(uint32(0), vals, cebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	_ = runPacket(t, xdp, tcp4(remote, local, 50000, 22, 0x02))
	var cv ConnVal
	if err := xdp.Maps[mapConntrack].Lookup(connKey4(remote, local, 50000, 22), &cv); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("SYN allocated under pressure: %+v %v", cv, err)
	}
	_ = runPacket(t, xdp, tcp4(remote, local, 50000, 22, 0x10))
	if err := xdp.Maps[mapConntrack].Lookup(connKey4(remote, local, 50000, 22), &cv); err != nil {
		t.Fatalf("handshake-completing ACK allocated nothing: %v", err)
	}
	// An allowlisted source's SYN allocates even under pressure (its
	// SYN-ACK then passes egress Deny All as a reply).
	putListEntry(t, xdp, true, "192.0.2.77")
	_ = runPacket(t, xdp, tcp4("192.0.2.77", local, 50001, 22, 0x02))
	if err := xdp.Maps[mapConntrack].Lookup(connKey4("192.0.2.77", local, 50001, 22), &cv); err != nil {
		t.Fatalf("allowlisted SYN under pressure allocated nothing: %v", err)
	}
}

// AddPortPolicy reads expiry like the guard — a rule past
// expires_at empties its slot (never written permanent), a future
// expires_at is honoured.
func TestKernelAddPortPolicyHonoursExpiresAt(t *testing.T) {
	c := packetTestCollection(t)
	m := &Manager{portPolicyMap: c.Maps[mapPortPolicy]}
	key := PortPolicyKey{Port: 22, Proto: 6, Direction: PortDirIngress}
	putPacketMap(t, c, mapPortPolicy, key, PortPolicyVal{Action: 1})
	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := m.AddPortPolicy(PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "drop", ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	var val PortPolicyVal
	if err := c.Maps[mapPortPolicy].Lookup(key, &val); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("expired rule written: %+v %v", val, err)
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := m.AddPortPolicy(PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow", ExpiresAt: future}); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps[mapPortPolicy].Lookup(key, &val); err != nil || val.ExpiresNs == 0 {
		t.Fatalf("future expires_at written permanent: %+v %v", val, err)
	}
}
