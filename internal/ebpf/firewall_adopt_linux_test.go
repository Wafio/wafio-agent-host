//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"testing"

	cebpf "github.com/cilium/ebpf"
)

// A flow whose first packet after the attach is one the host sends —
// an SSH session that predates the agent — is the reply side of an inbound
// connection when the kernel holds an established connection for exactly that
// 4-tuple and a TCP listener owns its local port. Adopting it as a host-opened
// flow put it under the egress port policy with the client's ephemeral port as
// destination and stalled it under egress Deny All. The connection check keeps
// a forged ACK from a listening port (CAP_NET_RAW) from being adopted.
// BPF_PROG_TEST_RUN runs in the test process's network namespace, so the
// socket lookups in the program see the loopback connections these tests open.

// loopbackConn is an established TCP connection on loopback: the listener side
// (the "server", like sshd) and the client, both held open until the test ends.
type loopbackConn struct {
	host    string // loopback address of both ends
	srvPort uint16 // listener port
	cliPort uint16 // client ephemeral port
}

// establishedLoopback opens a wildcard listener (dual-stack, like sshd on [::])
// and connects to it over the given network ("tcp4" or "tcp6"). It skips the
// test when that loopback is unavailable.
func establishedLoopback(t *testing.T, network string) loopbackConn {
	t.Helper()
	host := "127.0.0.1"
	if network == "tcp6" {
		host = "::1"
	}
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := uint16(l.Addr().(*net.TCPAddr).Port)
	c, err := net.Dial(network, net.JoinHostPort(host, strconv.Itoa(int(srv))))
	if err != nil {
		t.Skipf("no %s loopback: %v", network, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return loopbackConn{host: host, srvPort: srv, cliPort: uint16(c.LocalAddr().(*net.TCPAddr).Port)}
}

// listenTCPPort opens a TCP listener on every address and returns its port.
func listenTCPPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// freeTCPPort returns a port nothing listens on.
func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// requirePortFree fails when something listens on the port: TC egress would
// adopt a mid-flow ACK from it as an inbound reply and the test would see
// that instead of what it is about.
func requirePortFree(t *testing.T, port uint16) {
	t.Helper()
	l, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		t.Fatalf("port %d is in use on this host, the test needs it free: %v", port, err)
	}
	_ = l.Close()
}

// tcp6 builds an IPv6 TCP packet (IPv6 header, TCP header, no payload).
func tcp6(src, dst string, sport, dport uint16, flags byte) []byte {
	p := ipv6TCPPacket(dport)
	copy(p[22:38], net.ParseIP(src).To16())
	copy(p[38:54], net.ParseIP(dst).To16())
	binary.BigEndian.PutUint16(p[54:56], sport)
	p[67] = flags
	return p
}

const (
	local6  = "2001:db8::1"
	remote6 = "2001:db8::2"
)

type adoptFamily struct {
	name          string
	network       string
	local, remote string // documentation addresses, for the tests without a socket
	pkt           func(src, dst string, sport, dport uint16, flags byte) []byte
}

var adoptFamilies = []adoptFamily{
	{"ipv4", "tcp4", local, remote, tcp4},
	{"ipv6", "tcp6", local6, remote6, tcp6},
}

func TestKernelPreexistingInboundSurvivesEgressDeny(t *testing.T) {
	for _, fam := range adoptFamilies {
		t.Run(fam.name, func(t *testing.T) {
			lc := establishedLoopback(t, fam.network)
			port, cport := lc.srvPort, lc.cliPort
			xdp, tc := packetPair(t)
			putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})

			// The agent attached mid-session: the first packet it sees is
			// the host's reply. The connection and the listener make it an
			// inbound flow.
			if got := runTC(t, tc, fam.pkt(lc.host, lc.host, port, cport, 0x18)); got != tcOK {
				t.Fatalf("mid-flow PSH/ACK verdict %d", got)
			}
			var in ConnVal
			if err := xdp.Maps[mapConntrack].Lookup(connKey4(lc.host, lc.host, cport, port), &in); err != nil {
				t.Fatalf("no inbound entry for a listened port: %v", err)
			}
			if in.FlagsSeen&(ConnOutbound|ConnReply) != 0 || in.FlagsSeen&ConnVerified == 0 || in.TCPState != 1 {
				t.Fatalf("inbound entry %+v: want established and CONN_VERIFIED, neither CONN_OUTBOUND nor CONN_REPLY", in)
			}
			var out ConnVal
			if err := xdp.Maps[mapConntrack].Lookup(connKey4(lc.host, lc.host, port, cport), &out); !errors.Is(err, cebpf.ErrKeyNotExist) {
				t.Fatalf("host-opened entry %+v for an inbound flow (%v)", out, err)
			}

			// The client's next packet is a plain ACK; XDP must not turn
			// the entry into a reply marker.
			if got := runPacket(t, xdp, fam.pkt(lc.host, lc.host, cport, port, 0x10)); got != xdpPas {
				t.Fatalf("client ACK verdict %d", got)
			}
			if err := xdp.Maps[mapConntrack].Lookup(connKey4(lc.host, lc.host, cport, port), &in); err != nil || in.FlagsSeen&(1<<30|1<<31) != 0 {
				t.Fatalf("inbound entry after the client ACK: %+v %v", in, err)
			}

			// Deny All both ways plus an ingress allow for the listener.
			putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1, DefaultEgress: 1})
			putPacketMap(t, xdp, mapPortPolicy, PortPolicyKey{Port: port, Proto: 6, Direction: PortDirIngress}, PortPolicyVal{Action: 0})
			if got := runTC(t, tc, fam.pkt(lc.host, lc.host, port, cport, 0x18)); got != tcOK {
				t.Fatalf("egress Deny All cut the session: verdict %d", got)
			}
			if got := runPacket(t, xdp, fam.pkt(lc.host, lc.host, cport, port, 0x10)); got != xdpPas {
				t.Fatalf("ingress Deny All cut the session: verdict %d", got)
			}
		})
	}
}

// A listener alone is not an inbound flow: a process with CAP_NET_RAW can emit
// a plain ACK sourced from a listening port (sshd :22) to any destination.
// With no connection for the tuple the packet is host-opened — no inbound
// entry, dropped under egress Deny All.
func TestKernelForgedAckFromListenerIsNotAdopted(t *testing.T) {
	for _, fam := range adoptFamilies {
		t.Run(fam.name, func(t *testing.T) {
			lc := establishedLoopback(t, fam.network) // a listener owns lc.srvPort
			xdp, tc := packetPair(t)
			putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
			// A peer the host has no connection with, sourced from the
			// listener's port.
			for _, peer := range []struct {
				name     string
				src, dst string
				dport    uint16
				flags    byte
			}{
				{"documentation peer", fam.local, fam.remote, 50000, 0x18},
				{"loopback, other client port", lc.host, lc.host, lc.cliPort + 1, 0x10},
			} {
				if got := runTC(t, tc, fam.pkt(peer.src, peer.dst, lc.srvPort, peer.dport, peer.flags)); got != tcShot {
					t.Fatalf("%s: forged ACK verdict %d want drop under egress Deny All", peer.name, got)
				}
				var in ConnVal
				if err := xdp.Maps[mapConntrack].Lookup(connKey4(peer.dst, peer.src, peer.dport, lc.srvPort), &in); !errors.Is(err, cebpf.ErrKeyNotExist) {
					t.Fatalf("%s: inbound entry %+v adopted for a forged ACK (%v)", peer.name, in, err)
				}
			}
		})
	}
}

// The host's own outbound connection to a service is not the reply side of an
// inbound flow: no listener owns the client port, so it is tracked as a
// host-opened flow (CONN_OUTBOUND, no inbound entry) and the egress policy
// applies to its next packet. The egress port policy runs before the tracking
// step, so the entry is made with the policy off and Deny All is switched on
// afterwards.
func TestKernelOutboundConnectionStaysHostOpened(t *testing.T) {
	for _, fam := range adoptFamilies {
		t.Run(fam.name, func(t *testing.T) {
			lc := establishedLoopback(t, fam.network)
			xdp, tc := packetPair(t)
			putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			// The client end's next packet: client port -> service port.
			pkt := fam.pkt(lc.host, lc.host, lc.cliPort, lc.srvPort, 0x18)
			if got := runTC(t, tc, pkt); got != tcOK {
				t.Fatalf("verdict %d want pass with the port policy off", got)
			}
			assertHostOpened(t, xdp, lc.host, lc.host, lc.cliPort, lc.srvPort)
			putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
			if got := runTC(t, tc, pkt); got != tcShot {
				t.Fatalf("verdict %d want drop of a host-opened flow under egress Deny All", got)
			}
		})
	}
}

// assertHostOpened checks that TC recorded src:sport -> dst:dport as a
// CONN_OUTBOUND entry and made no inbound-direction entry for it.
func assertHostOpened(t *testing.T, xdp *cebpf.Collection, src, dst string, sport, dport uint16) {
	t.Helper()
	var out ConnVal
	if err := xdp.Maps[mapConntrack].Lookup(connKey4(src, dst, sport, dport), &out); err != nil || out.FlagsSeen&(1<<31) == 0 {
		t.Fatalf("outbound entry %+v (%v): want CONN_OUTBOUND", out, err)
	}
	var in ConnVal
	if err := xdp.Maps[mapConntrack].Lookup(connKey4(dst, src, dport, sport), &in); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("inbound entry %+v (%v) for a host-opened flow", in, err)
	}
}

// Without a listener the same packet is a host-opened flow: an outbound
// entry, and the egress policy applies to it.
func TestKernelMidFlowWithoutListenerIsHostOpened(t *testing.T) {
	for _, fam := range adoptFamilies {
		t.Run(fam.name, func(t *testing.T) {
			port := freeTCPPort(t)
			xdp, tc := packetPair(t)
			putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			pkt := fam.pkt(fam.local, fam.remote, port, 50000, 0x18)
			if got := runTC(t, tc, pkt); got != tcOK {
				t.Fatalf("verdict %d want pass with the port policy off", got)
			}
			assertHostOpened(t, xdp, fam.local, fam.remote, port, 50000)
			putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
			if got := runTC(t, tc, pkt); got != tcShot {
				t.Fatalf("verdict %d want drop of a host-opened flow under egress Deny All", got)
			}
		})
	}
}

// Only a plain ACK is adopted: SYN-ACK, FIN and RST of a mid-flow packet keep
// their handling, a connection and listener or not.
func TestKernelListenerAdoptsOnlyPlainAck(t *testing.T) {
	lc := establishedLoopback(t, "tcp4")
	for _, tc := range []struct {
		name  string
		flags byte
		entry bool
	}{
		{"psh-ack", 0x18, true},
		{"syn-ack", 0x12, false},
		{"fin-ack", 0x11, false},
		{"rst-ack", 0x14, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			xdp, c := packetPair(t)
			putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
			putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
			want := uint32(tcShot)
			if tc.entry {
				want = tcOK
			}
			if got := runTC(t, c, tcp4(lc.host, lc.host, lc.srvPort, lc.cliPort, tc.flags)); got != want {
				t.Fatalf("verdict %d want %d", got, want)
			}
			var in ConnVal
			err := xdp.Maps[mapConntrack].Lookup(connKey4(lc.host, lc.host, lc.cliPort, lc.srvPort), &in)
			if tc.entry != (err == nil) {
				t.Fatalf("inbound entry present=%v want %v (%v)", err == nil, tc.entry, err)
			}
		})
	}
}

// A conntrack timestamp written by another CPU after this run read the clock
// lies slightly in the future: up to 1 s counts as fresh, more does not.
func TestKernelFutureTimestampToleratedForOneSecond(t *testing.T) {
	const skew = 500_000_000
	t.Run("egress inbound reply", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			ahead uint64
			want  uint32
		}{{"500 ms ahead", skew, tcOK}, {"5 s ahead", 5_000_000_000, tcShot}} {
			t.Run(tc.name, func(t *testing.T) {
				_, c := packetPair(t)
				putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
				putPacketMap(t, c, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
				putPacketMap(t, c, mapConntrack, connKey4(remote, local, 50000, 22), ConnVal{LastSeenNs: monoNow(t) + tc.ahead, TCPState: 1, FlagsSeen: 0x10 | ConnVerified})
				if got := runTC(t, c, tcp4(local, remote, 22, 50000, 0x18)); got != tc.want {
					t.Fatalf("verdict %d want %d", got, tc.want)
				}
			})
		}
	})
	t.Run("ingress reply to outbound flow", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			ahead uint64
			want  uint32
			kept  bool
		}{{"500 ms ahead", skew, xdpPas, true}, {"5 s ahead", 5_000_000_000, xdpDrp, false}} {
			t.Run(tc.name, func(t *testing.T) {
				xdp, _ := packetPair(t)
				putPacketMap(t, xdp, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
				putPacketMap(t, xdp, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1})
				key := connKey4(local, remote, 40000, 443)
				putPacketMap(t, xdp, mapConntrack, key, ConnVal{LastSeenNs: monoNow(t) + tc.ahead, TCPState: 1, FlagsSeen: 1 << 31})
				if got := runPacket(t, xdp, tcp4(remote, local, 443, 40000, 0x10)); got != tc.want {
					t.Fatalf("verdict %d want %d", got, tc.want)
				}
				var cv ConnVal
				if err := xdp.Maps[mapConntrack].Lookup(key, &cv); (err == nil) != tc.kept {
					t.Fatalf("entry kept=%v want %v (%v)", err == nil, tc.kept, err)
				}
			})
		}
	})
}
