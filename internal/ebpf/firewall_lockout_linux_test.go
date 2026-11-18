//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Lockout-guard dataplane tests (BPF_PROG_TEST_RUN, no links or
// interfaces). They need root and compiled objects in WAFIO_TEST_BPF_DIR, so
// they run in the kernel lab, not on developer machines.

const (
	tcOK   = 0 // TC_ACT_OK
	tcShot = 2 // TC_ACT_SHOT
	xdpDrp = 1 // XDP_DROP
	xdpPas = 2 // XDP_PASS

	local  = "192.0.2.10"
	remote = "198.51.100.10"
)

// packetPair loads XDP and TC the way Manager does: TC reuses XDP's shared
// maps, so a TC egress run and an XDP ingress run see the same conntrack.
func packetPair(t *testing.T) (xdp, tc *cebpf.Collection) {
	return packetPairSized(t, MapSizes{})
}

// packetPairSized is packetPair with the sized maps at the sizes of sizes. The
// TC spec takes size and flags of every replaced map from the XDP map, as
// Manager.loadTC does.
func packetPairSized(t *testing.T, sizes MapSizes) (xdp, tc *cebpf.Collection) {
	t.Helper()
	xdp = sizedObjectCollection(t, "wafio_xdp.o", sizes)
	spec, err := cebpf.LoadCollectionSpec(filepath.Join(os.Getenv("WAFIO_TEST_BPF_DIR"), "wafio_tc.o"))
	if err != nil {
		t.Fatalf("%+v", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = cebpf.PinNone
		if m.MaxEntries > 4096 {
			m.MaxEntries = 4096
		}
	}
	applyMapSizes(spec.Maps, sizes)
	repl := make(map[string]*cebpf.Map)
	for _, name := range []string{mapConfig, mapConntrack, mapEvents, mapMetrics, mapPortPolicy, mapPortPolicyConfig, mapEgressBlocklist, mapCPEndpoints, mapDHCPPending, mapDHCPServers} {
		if xm := xdp.Maps[name]; xm != nil && spec.Maps[name] != nil {
			spec.Maps[name].MaxEntries = xm.MaxEntries()
			spec.Maps[name].Flags = xm.Flags()
			repl[name] = xm
		}
	}
	if repl[mapCPEndpoints] == nil {
		t.Fatal("objects lack the shared wafio_cp_endpoints map (exemptions ABI marker)")
	}
	tc, err = cebpf.NewCollectionWithOptions(spec, cebpf.CollectionOptions{MapReplacements: repl})
	if err != nil {
		t.Fatalf("%+v", err)
	}
	t.Cleanup(tc.Close)
	return xdp, tc
}

func tcp4(src, dst string, sport, dport uint16, flags byte) []byte {
	p := tcpPacket(dport)
	copy(p[26:30], net.ParseIP(src).To4())
	copy(p[30:34], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(p[34:36], sport)
	p[47] = flags
	return p
}

func connKey4(src, dst string, sport, dport uint16) ConnKey {
	return ConnKey{Src: IPKeyFromIP(net.ParseIP(src)), Dst: IPKeyFromIP(net.ParseIP(dst)), Sport: ntohs(sport), Dport: ntohs(dport), Proto: 6}
}

func monoNow(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

func runTC(t *testing.T, c *cebpf.Collection, p []byte) uint32 {
	t.Helper()
	ret, _, err := c.Programs["wafio_tc_egress"].Test(p)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	return ret
}

// After an agent restart (fresh maps) or a map reset, the first
// outbound packet of an established flow is a plain ACK. It must create the
// outbound entry so the next reply passes ingress Deny All.
func TestKernelMidFlowOutboundSurvivesRestart(t *testing.T) {
	requirePortFree(t, 40000) // a listener would make the ACK an inbound reply
	xdp, tc := packetPair(t)
	putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
	putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1})
	reply := tcp4(remote, local, 5432, 40000, 0x10)
	if got := runPacket(t, xdp, reply); got != xdpDrp {
		t.Fatalf("reply without state: verdict %d want drop", got)
	}
	if got := runTC(t, tc, tcp4(local, remote, 40000, 5432, 0x18)); got != tcOK {
		t.Fatalf("outbound PSH/ACK verdict %d", got)
	}
	var cv ConnVal
	if err := xdp.Maps[mapConntrack].Lookup(connKey4(local, remote, 40000, 5432), &cv); err != nil {
		t.Fatalf("mid-flow ACK created no outbound entry: %v", err)
	}
	if cv.FlagsSeen&(1<<31) == 0 || cv.TCPState != 1 {
		t.Fatalf("entry %+v: want CONN_OUTBOUND, established", cv)
	}
	if got := runPacket(t, xdp, reply); got != xdpPas {
		t.Fatalf("reply after mid-flow tracking: verdict %d want pass", got)
	}
	// The reply side is marked so TC never mistakes it for an inbound flow.
	var rv ConnVal
	if err := xdp.Maps[mapConntrack].Lookup(connKey4(remote, local, 5432, 40000), &rv); err != nil || rv.FlagsSeen&(1<<30) == 0 {
		t.Fatalf("reply entry %+v %v: want CONN_REPLY", rv, err)
	}
}

// A server's SYN-ACK is not a host-opened flow: no outbound entry.
func TestKernelSynAckCreatesNoOutboundEntry(t *testing.T) {
	_, tc := packetPair(t)
	putPacketMap(t, tc, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
	if got := runTC(t, tc, tcp4(local, remote, 22, 50000, 0x12)); got != tcOK {
		t.Fatalf("verdict %d", got)
	}
	var cv ConnVal
	if err := tc.Maps[mapConntrack].Lookup(connKey4(local, remote, 22, 50000), &cv); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("SYN-ACK created outbound entry %+v (%v)", cv, err)
	}
}

// Under egress Deny All, replies to a verified inbound
// connection (SSH) pass; nothing else does. An inbound entry is verified by
// the host's SYN-ACK to its SYN or by the socket check (a connection for
// exactly the tuple and a listener on the local port).
func TestKernelEgressDenyExemptsInboundReplies(t *testing.T) {
	for _, tc := range []struct {
		name         string
		inbound      *ConnVal // entry XDP would hold for client → local:22
		hostFlow     bool     // a CONN_OUTBOUND entry for local:22 → client
		wildcard     bool     // 0.0.0.0/0 egress block
		specificDeny bool     // egress block of the client address
		listener     bool     // a TCP listener owns the local port (sshd)
		want         uint32
	}{
		{name: "no state", want: tcShot},
		// A listener alone is not enough: the kernel must hold a connection for
		// the tuple.
		{name: "no state, local listener without a connection", listener: true, want: tcShot},
		{name: "verified inbound", inbound: &ConnVal{FlagsSeen: 0x12 | ConnVerified}, want: tcOK},
		{name: "unverified inbound", inbound: &ConnVal{FlagsSeen: 0x10}, want: tcShot},
		// The same holds for the inbound check: a reply forged from a listening
		// port to a remote that sent first finds no connection (accepted
		// connections: TestKernelMidFlowInboundCheckedOnce).
		{name: "unverified inbound, local listener without a connection", inbound: &ConnVal{FlagsSeen: 0x10}, listener: true, want: tcShot},
		{name: "unanswered SYN", inbound: &ConnVal{FlagsSeen: 0x12}, want: tcShot},
		{name: "stale inbound", inbound: &ConnVal{FlagsSeen: 0x12 | ConnVerified, LastSeenNs: 301_000_000_000}, want: tcShot},
		{name: "reply side of host flow", inbound: &ConnVal{FlagsSeen: 0x10 | 1<<30}, want: tcShot},
		{name: "outbound-marked", inbound: &ConnVal{FlagsSeen: 1 << 31}, want: tcShot},
		{name: "host flow wins", inbound: &ConnVal{FlagsSeen: 0x12 | ConnVerified}, hostFlow: true, want: tcShot},
		{name: "wildcard egress block", inbound: &ConnVal{FlagsSeen: 0x12 | ConnVerified}, wildcard: true, want: tcOK},
		{name: "specific egress block", inbound: &ConnVal{FlagsSeen: 0x12 | ConnVerified}, specificDeny: true, want: tcShot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The cases without a listener need a port nothing owns (sshd
			// listens on :22 in the VM, and would be adopted).
			lport := freeTCPPort(t)
			if tc.listener {
				lport = listenTCPPort(t)
			}
			_, c := packetPair(t)
			now := monoNow(t)
			putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			putPacketMap(t, c, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
			if tc.inbound != nil {
				v := *tc.inbound
				if v.LastSeenNs > now {
					t.Skip("kernel uptime below conntrack TTL")
				}
				v.LastSeenNs = now - v.LastSeenNs
				putPacketMap(t, c, mapConntrack, connKey4(remote, local, 50000, lport), v)
			}
			if tc.hostFlow {
				putPacketMap(t, c, mapConntrack, connKey4(local, remote, lport, 50000), ConnVal{LastSeenNs: now, TCPState: 1, FlagsSeen: 1 << 31})
			}
			if tc.wildcard {
				putPacketMap(t, c, mapEgressBlocklist, IPKeyWildcard("0.0.0.0/0"), IPListVal{})
			}
			if tc.specificDeny {
				putPacketMap(t, c, mapEgressBlocklist, IPKeyFromIP(net.ParseIP(remote)), IPListVal{})
			}
			if got := runTC(t, c, tcp4(local, remote, lport, 50000, 0x18)); got != tc.want {
				t.Fatalf("verdict %d want %d", got, tc.want)
			}
		})
	}
}

// A flow this host opened that predates the attach, or lost its entries,
// and whose remote side speaks first: XDP records the remote's packet as it
// records an inbound one. Nothing listens on the local port, so the flow is
// host-opened: egress Deny All cuts it (the host's packets used to pass as
// replies of an inbound connection for as long as the flow stayed active),
// and with egress open it is tracked as CONN_OUTBOUND, whose replies pass
// ingress Deny All.
func TestKernelMidFlowRemoteFirstIsHostOpened(t *testing.T) {
	for _, fam := range adoptFamilies {
		t.Run(fam.name, func(t *testing.T) {
			port := freeTCPPort(t)
			xdp, c := packetPair(t)
			putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			remoteFirst := fam.pkt(fam.remote, fam.local, 5432, port, 0x18)
			hostPkt := fam.pkt(fam.local, fam.remote, port, 5432, 0x18)
			if got := runPacket(t, xdp, remoteFirst); got != xdpPas {
				t.Fatalf("remote PSH/ACK verdict %d", got)
			}
			putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
			if got := runTC(t, c, hostPkt); got != tcShot {
				t.Fatalf("egress Deny All passed a host-opened flow: verdict %d", got)
			}
			var in ConnVal
			if err := xdp.Maps[mapConntrack].Lookup(connKey4(fam.remote, fam.local, 5432, port), &in); err != nil || in.FlagsSeen&ConnReply == 0 || in.FlagsSeen&ConnVerified != 0 {
				t.Fatalf("remote-side entry %+v (%v): want CONN_REPLY, not verified", in, err)
			}
			if got := runTC(t, c, hostPkt); got != tcShot {
				t.Fatalf("second host packet: verdict %d", got)
			}

			putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1})
			if got := runTC(t, c, hostPkt); got != tcOK {
				t.Fatalf("egress open: verdict %d", got)
			}
			var out ConnVal
			if err := xdp.Maps[mapConntrack].Lookup(connKey4(fam.local, fam.remote, port, 5432), &out); err != nil || out.FlagsSeen&ConnOutbound == 0 {
				t.Fatalf("outbound entry %+v (%v): want CONN_OUTBOUND", out, err)
			}
			if got := runPacket(t, xdp, remoteFirst); got != xdpPas {
				t.Fatalf("reply under ingress Deny All: verdict %d", got)
			}
		})
	}
}

// acceptedLoopback opens a wildcard listener (dual-stack, like sshd on [::]),
// connects to it over the given network ("tcp4" or "tcp6") from clientPort
// (0 = ephemeral) and accepts the connection, so it outlives the listener. It
// returns the connection and the listener; the test ends both. It skips the
// test when that loopback is unavailable.
func acceptedLoopback(t *testing.T, network string, port, clientPort uint16) (loopbackConn, net.Listener) {
	t.Helper()
	host := "127.0.0.1"
	if network == "tcp6" {
		host = "::1"
	}
	l, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		t.Fatalf("listen on %d: %v", port, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := uint16(l.Addr().(*net.TCPAddr).Port)
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(host), Port: int(clientPort)}}
	c, err := d.Dial(network, net.JoinHostPort(host, strconv.Itoa(int(srv))))
	if err != nil {
		t.Skipf("no %s loopback: %v", network, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return loopbackConn{host: host, srvPort: srv, cliPort: uint16(c.LocalAddr().(*net.TCPAddr).Port)}, l
}

// The inbound check runs once per entry, on the host's first packet of a flow
// whose remote side spoke first after the attach. An accepted connection (the
// tuple's socket and a listener) verifies the entry, and the flow stays
// inbound after the listener closes (an accepted session outlives its
// listener). A listener without a connection for the tuple — what a reply
// forged from a listening port finds — and a free port leave it host-opened
// (CONN_REPLY), even when that exact connection is accepted later.
func TestKernelMidFlowInboundCheckedOnce(t *testing.T) {
	for _, fam := range adoptFamilies {
		for _, tc := range []struct {
			name  string
			socks string // at the first check: "accepted", "listener" or "none"
			want  uint32
		}{
			{"accepted connection", "accepted", tcOK},
			{"listener without a connection", "listener", tcShot},
			{"free port", "none", tcShot},
		} {
			t.Run(fam.name+"/"+tc.name, func(t *testing.T) {
				// The flow: a real loopback connection, or loopback ports
				// no connection uses yet.
				host := "127.0.0.1"
				if fam.network == "tcp6" {
					host = "::1"
				}
				var lport, rport uint16
				var ln net.Listener
				switch tc.socks {
				case "accepted":
					var lc loopbackConn
					lc, ln = acceptedLoopback(t, fam.network, 0, 0)
					host, lport, rport = lc.host, lc.srvPort, lc.cliPort
				case "listener":
					lport, rport = listenTCPPort(t), freeTCPPort(t)
				default:
					lport, rport = freeTCPPort(t), freeTCPPort(t)
				}
				xdp, c := packetPair(t)
				putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
				if got := runPacket(t, xdp, fam.pkt(host, host, rport, lport, 0x18)); got != xdpPas {
					t.Fatalf("client PSH/ACK verdict %d", got)
				}
				putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
				reply := fam.pkt(host, host, lport, rport, 0x18)
				if got := runTC(t, c, reply); got != tc.want {
					t.Fatalf("first host packet: verdict %d want %d", got, tc.want)
				}
				var in ConnVal
				if err := xdp.Maps[mapConntrack].Lookup(connKey4(host, host, rport, lport), &in); err != nil {
					t.Fatal(err)
				}
				mark := ConnReply
				if tc.socks == "accepted" {
					mark = ConnVerified
				}
				if in.FlagsSeen&(ConnVerified|ConnReply) != mark {
					t.Fatalf("entry %+v: want mark %#x", in, mark)
				}
				// Turn the socket table around: the listener goes, or the
				// connection the check did not find now exists.
				if tc.socks == "accepted" {
					_ = ln.Close()
				} else if tc.socks == "none" {
					acceptedLoopback(t, fam.network, lport, rport)
				}
				if got := runTC(t, c, reply); got != tc.want {
					t.Fatalf("host packet after the sockets changed: verdict %d want %d", got, tc.want)
				}
			})
		}
	}
}

// A SYN in the entry proves nothing by itself: the remote side of a flow
// this host opened can send one first. Only the host's SYN-ACK answering it
// verifies the entry, without a listener in this namespace too (DNAT to a
// container). An established socket answers a stray SYN or SYN-ACK with a
// plain ACK (RFC 5961), which gets the socket check. A RST passes without
// the check and leaves the entry unverified.
func TestKernelRemoteSynNeedsHostSynAck(t *testing.T) {
	for _, tc := range []struct {
		name         string
		remote, host byte   // what XDP saw from the remote, the host's first packet
		want, then   uint32 // verdicts of that packet and of a PSH/ACK after it
	}{
		{"handshake", 0x02, 0x12, tcOK, tcOK},
		{"syn on a host-opened flow", 0x02, 0x10, tcShot, tcShot},
		{"syn-ack on a host-opened flow", 0x12, 0x10, tcShot, tcShot},
		{"rst to a syn", 0x02, 0x14, tcOK, tcShot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := freeTCPPort(t)
			xdp, c := packetPair(t)
			putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			if got := runPacket(t, xdp, tcp4(remote, local, 50000, port, tc.remote)); got != xdpPas {
				t.Fatalf("remote packet verdict %d", got)
			}
			putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
			if got := runTC(t, c, tcp4(local, remote, port, 50000, tc.host)); got != tc.want {
				t.Fatalf("host packet 0x%02x: verdict %d want %d", tc.host, got, tc.want)
			}
			if got := runTC(t, c, tcp4(local, remote, port, 50000, 0x18)); got != tc.then {
				t.Fatalf("host PSH/ACK after it: verdict %d want %d", got, tc.then)
			}
		})
	}
}

// withTCPPayload appends n bytes after the TCP header of a packet built by
// tcp4/tcp6. With fixLen the IP length field counts them (TCP payload);
// without, they trail past the IP datagram, where the peer's capture still
// sees them.
func withTCPPayload(p []byte, n int, fixLen bool) []byte {
	q := append(append([]byte{}, p...), make([]byte, n)...)
	for i := len(p); i < len(q); i++ {
		q[i] = 'x'
	}
	if fixLen {
		off := 18 // IPv6 payload length
		if binary.BigEndian.Uint16(q[12:14]) == 0x0800 {
			off = 16 // IPv4 total length
		}
		binary.BigEndian.PutUint16(q[off:off+2], binary.BigEndian.Uint16(q[off:off+2])+uint16(n))
	}
	return q
}

// Only a bare reset — RST or RST|ACK, no data, not a fragment: the host's
// answer to a SYN on a closed port, or the reset of a socket already gone —
// passes an unverified inbound entry without the check. A reset carrying data
// (as TCP payload or past the IP length) or other flags gets the check like
// any packet: no connection for the tuple → CONN_REPLY, dropped under egress
// Deny All. A crafted RST+payload used to pass egress Deny All.
func TestKernelOnlyBareResetSkipsInboundCheck(t *testing.T) {
	for _, fam := range adoptFamilies {
		for _, tc := range []struct {
			name    string
			flags   byte
			payload int
			fixLen  bool
			bare    bool
		}{
			{"rst", 0x04, 0, true, true},
			{"rst-ack", 0x14, 0, true, true},
			{"rst with payload", 0x04, 1, true, false},
			{"rst-ack with payload", 0x14, 64, true, false},
			{"rst-ack with bytes past the ip length", 0x14, 16, false, false},
			{"rst-psh-ack", 0x1c, 0, true, false},
			{"rst-syn", 0x06, 0, true, false},
			{"rst-fin-ack", 0x15, 0, true, false},
			{"rst-urg-ack", 0x34, 0, true, false},
		} {
			t.Run(fam.name+"/"+tc.name, func(t *testing.T) {
				port := freeTCPPort(t)
				xdp, c := packetPair(t)
				putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
				if got := runPacket(t, xdp, fam.pkt(fam.remote, fam.local, 50000, port, 0x02)); got != xdpPas {
					t.Fatalf("remote SYN verdict %d", got)
				}
				putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
				want, mark := uint32(tcOK), uint32(0)
				if !tc.bare {
					want, mark = tcShot, ConnReply
				}
				rst := withTCPPayload(fam.pkt(fam.local, fam.remote, port, 50000, tc.flags), tc.payload, tc.fixLen)
				if got := runTC(t, c, rst); got != want {
					t.Fatalf("reset 0x%02x (+%d bytes) verdict %d want %d", tc.flags, tc.payload, got, want)
				}
				var in ConnVal
				if err := xdp.Maps[mapConntrack].Lookup(connKey4(fam.remote, fam.local, 50000, port), &in); err != nil {
					t.Fatal(err)
				}
				if in.FlagsSeen&(ConnVerified|ConnReply) != mark {
					t.Fatalf("entry %+v: want mark %#x", in, mark)
				}
			})
		}
	}
}

// The control-plane endpoint passes egress Deny All and every egress
// block, and is tracked even with connection tracking off.
func TestKernelControlPlaneEgressPass(t *testing.T) {
	_, c := packetPair(t)
	putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1})
	putPacketMap(t, c, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
	putPacketMap(t, c, mapEgressBlocklist, IPKeyWildcard("0.0.0.0/0"), IPListVal{})
	putPacketMap(t, c, mapEgressBlocklist, IPKeyFromIP(net.ParseIP(remote)), IPListVal{})
	putPacketMap(t, c, mapCPEndpoints, CPEndpointKeyFrom(netip.MustParseAddrPort(remote+":9090")), uint32(1))
	if got := runTC(t, c, tcp4(local, remote, 41000, 9090, 0x02)); got != tcOK {
		t.Fatalf("control-plane SYN verdict %d", got)
	}
	var cv ConnVal
	if err := c.Maps[mapConntrack].Lookup(connKey4(local, remote, 41000, 9090), &cv); err != nil || cv.FlagsSeen&(1<<31) == 0 {
		t.Fatalf("control-plane flow not tracked: %+v %v", cv, err)
	}
	if got := runTC(t, c, tcp4(local, remote, 41001, 9091, 0x02)); got != tcShot {
		t.Fatalf("other port on the control-plane host passed: %d", got)
	}
}

// A reply to a fresh outbound flow passes a family-wide blocklist
// entry; specific blocks still apply; control-plane replies always pass, a
// spoofed control-plane source without a flow does not.
func TestKernelIngressReplyBeforeWildcard(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flow      bool
		specific  bool
		cp        bool
		conntrack uint32
		sport     uint16
		want      uint32
	}{
		{name: "reply passes wildcard", flow: true, conntrack: 1, sport: 443, want: xdpPas},
		{name: "no flow", conntrack: 1, sport: 443, want: xdpDrp},
		{name: "specific block wins", flow: true, specific: true, conntrack: 1, sport: 443, want: xdpDrp},
		{name: "control plane despite block, conntrack off", flow: true, specific: true, cp: true, sport: 9090, want: xdpPas},
		{name: "spoofed control plane", specific: true, cp: true, sport: 9090, want: xdpDrp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			xdp, _ := packetPair(t)
			putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: tc.conntrack})
			putListEntry(t, xdp, false, "0.0.0.0/0")
			if tc.specific {
				putListEntry(t, xdp, false, remote)
			}
			if tc.cp {
				putPacketMap(t, xdp, mapCPEndpoints, CPEndpointKeyFrom(netip.MustParseAddrPort(remote+":9090")), uint32(1))
			}
			if tc.flow {
				putPacketMap(t, xdp, mapConntrack, connKey4(local, remote, 40000, tc.sport), ConnVal{LastSeenNs: monoNow(t), TCPState: 1, FlagsSeen: 1 << 31})
			}
			if got := runPacket(t, xdp, tcp4(remote, local, tc.sport, 40000, 0x10)); got != tc.want {
				t.Fatalf("verdict %d want %d", got, tc.want)
			}
		})
	}
}
