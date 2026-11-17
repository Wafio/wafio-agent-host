//go:build linux

package ebpf

import (
	"net"
	"testing"
)

// IP fragments (BPF_PROG_TEST_RUN, kernel lab): TC egress polices a first
// fragment by its ports and lets the later fragments of a datagram it passed
// follow; a later fragment it cannot tie to a passed first fragment fails
// closed under egress Deny All or a matching egress block, and passes
// otherwise.

func udpFragments4(id uint16, sport, dport uint16) (head, middle, last []byte) {
	pad := make([]byte, 64)
	head = ipv4Frame(17, id, 0x2000, append(udpHeader(sport, dport, 3000), pad...))
	middle = ipv4Frame(17, id, 0x2000|185, pad)
	last = ipv4Frame(17, id, 370, pad)
	return head, middle, last
}

func TestKernelEgressFragments(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     uint32
		deny     bool
		block    bool
		portRule bool // port policy on, default allow, DROP 443/tcp egress
		packets  func() [][]byte
		want     []uint32
	}{
		{
			// A first fragment whose TCP header is cut hides
			// its port, so any port rule fails it closed.
			name:     "tiny TCP first fragment under a port rule",
			portRule: true,
			packets: func() [][]byte {
				tiny := ipv4Frame(6, 0x1212, 0x2000, tcpHeader(40000, 443, 0x02)[:8])
				whole := ipv4Frame(6, 0x1313, 0x2000, append(tcpHeader(40000, 443, 0x18), make([]byte, 64)...))
				other := ipv4Frame(6, 0x1414, 0x2000, append(tcpHeader(40000, 8443, 0x18), make([]byte, 64)...))
				return [][]byte{tiny, whole, other}
			},
			want: []uint32{tcShot, tcShot, tcOK},
		},
		{
			name: "tiny first fragment, no port policy",
			packets: func() [][]byte {
				return [][]byte{ipv4Frame(6, 0x1515, 0x2000, tcpHeader(40000, 443, 0x02)[:8])}
			},
			want: []uint32{tcOK},
		},
		{
			// RFC 1858: offset 8 only serves to rewrite the first fragment's flags.
			name: "TCP fragment at offset 8, no policy",
			packets: func() [][]byte {
				return [][]byte{ipv4Frame(6, 0x1616, 0x2000|1, make([]byte, 64))}
			},
			want: []uint32{tcShot},
		},
		{
			name: "tail of another protocol with the same id",
			deny: true,
			packets: func() [][]byte {
				h, _, _ := udpFragments4(0x1717, 40000, 53)
				tcpTail := ipv4Frame(6, 0x1717, 0x2000|185, make([]byte, 64))
				return [][]byte{h, tcpTail}
			},
			want: []uint32{tcOK, tcShot},
		},
		{
			name: "allowed port: head and tail pass, datagram forgotten after the last",
			deny: true,
			packets: func() [][]byte {
				h, m, l := udpFragments4(0x1111, 40000, 53)
				return [][]byte{h, m, l, m}
			},
			want: []uint32{tcOK, tcOK, tcOK, tcShot},
		},
		{
			name: "denied port: head and tail dropped",
			deny: true,
			packets: func() [][]byte {
				h, m, _ := udpFragments4(0x2222, 40000, 9999)
				return [][]byte{h, m}
			},
			want: []uint32{tcShot, tcShot},
		},
		{
			name: "tail of an unseen datagram under deny all",
			deny: true,
			packets: func() [][]byte {
				h, _, _ := udpFragments4(0x3333, 40000, 53)
				_, m, _ := udpFragments4(0x4444, 40000, 53)
				return [][]byte{h, m}
			},
			want: []uint32{tcOK, tcShot},
		},
		{
			name: "monitor mode passes and counts",
			mode: 1,
			deny: true,
			packets: func() [][]byte {
				h, m, _ := udpFragments4(0x5555, 40000, 9999)
				return [][]byte{h, m}
			},
			want: []uint32{tcOK, tcOK},
		},
		{
			name: "default allow, no block: unseen tail passes",
			packets: func() [][]byte {
				_, m, _ := udpFragments4(0x6666, 40000, 9999)
				return [][]byte{m}
			},
			want: []uint32{tcOK},
		},
		{
			name:  "egress block of the destination: unseen tail dropped",
			block: true,
			packets: func() [][]byte {
				_, m, _ := udpFragments4(0x7777, 40000, 9999)
				return [][]byte{m}
			},
			want: []uint32{tcShot},
		},
		{
			name: "IPv6 fragment header",
			deny: true,
			packets: func() [][]byte {
				pad := make([]byte, 64)
				head := ipv6Frame(44, append(fragHeader(17, 0, true, 0xabcd), append(udpHeader(40000, 53, 3000), pad...)...))
				tail := ipv6Frame(44, append(fragHeader(17, 100, false, 0xabcd), pad...))
				other := ipv6Frame(44, append(fragHeader(17, 100, false, 0xabce), pad...))
				return [][]byte{head, tail, other}
			},
			want: []uint32{tcOK, tcOK, tcShot},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requirePortFree(t, 40000) // a listener would make its ACKs inbound replies
			_, c := packetPair(t)
			putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, Mode: tc.mode, EnableConntrack: 1})
			if tc.deny {
				putPacketMap(t, c, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
				putPacketMap(t, c, mapPortPolicy, PortPolicyKey{Port: 53, Proto: 17, Direction: PortDirEgress}, PortPolicyVal{Action: 0})
			}
			if tc.block {
				putPacketMap(t, c, mapEgressBlocklist, IPKeyFromIP(net.ParseIP(remote)), IPListVal{})
			}
			if tc.portRule {
				putPacketMap(t, c, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1})
				putPacketMap(t, c, mapPortPolicy, PortPolicyKey{Port: 443, Proto: 6, Direction: PortDirEgress}, PortPolicyVal{Action: 1})
			}
			for i, p := range tc.packets() {
				if got := runTC(t, c, p); got != tc.want[i] {
					t.Fatalf("packet %d: verdict %d want %d", i, got, tc.want[i])
				}
			}
			if tc.mode == 1 {
				var values []MetricsVal
				if err := c.Maps[mapMetrics].Lookup(uint32(0), &values); err != nil {
					t.Fatal(err)
				}
				var would uint64
				for _, v := range values {
					would += v.WouldDropPackets
				}
				if would != 2 {
					t.Fatalf("would-drop %d want 2 (head and tail)", would)
				}
			}
		})
	}
}

// Fragment policing keeps the reply exemption: a fragmented reply of a tracked
// inbound UDP flow (a DNS answer over EDNS) passes egress Deny All and a
// family-wide egress block, tail included.
func TestKernelEgressFragmentedReply(t *testing.T) {
	_, c := packetPair(t)
	putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
	putPacketMap(t, c, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultEgress: 1})
	putPacketMap(t, c, mapEgressBlocklist, IPKeyWildcard("0.0.0.0/0"), IPListVal{})
	in := ConnKey{Src: IPKeyFromIP(net.ParseIP(remote)), Dst: IPKeyFromIP(net.ParseIP(local)), Sport: ntohs(50000), Dport: ntohs(53), Proto: 17}
	putPacketMap(t, c, mapConntrack, in, ConnVal{LastSeenNs: monoNow(t)})
	head, middle, last := udpFragments4(0x8888, 53, 50000)
	for i, p := range [][]byte{head, middle, last} {
		if got := runTC(t, c, p); got != tcOK {
			t.Fatalf("reply fragment %d: verdict %d", i, got)
		}
	}
	_, other, _ := udpFragments4(0x9999, 53, 50000)
	if got := runTC(t, c, other); got != tcShot {
		t.Fatalf("unseen tail under a wildcard block passed: %d", got)
	}
}
