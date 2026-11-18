//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/valyala/fasthttp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// What each sized map does when it is full, on the real kernel
// (BPF_PROG_TEST_RUN, no links or interfaces; root, WAFIO_TEST_BPF_DIR). The
// objects load at the smallest sizes, every bounded map is filled past its
// capacity with distinct keys, and the verdicts are the ones the sizing
// documents: legitimate traffic passes, a source tracked before the flood is
// still limited, and a full map shows in the counters instead of switching a
// protection off silently.

const mapFullScale = 0.001 // every map at its floor

const bpfFNoPrealloc = 1 // BPF_F_NO_PREALLOC

func floorSizes(t *testing.T) MapSizes {
	t.Helper()
	cpus, err := cebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	return ComputeMapSizes(mapFullScale, cpus)
}

// mfAddr is the n-th spoofed source address (n below 2^24).
func mfAddr(n int) [4]byte { return [4]byte{20 + byte(n>>24), byte(n >> 16), byte(n >> 8), byte(n)} }

var mfLocal = [4]byte{198, 51, 100, 10} // the destination of every packet here

// mfTCP is a TCP packet from src to the local address.
func mfTCP(src [4]byte, sport, dport uint16, flags byte) []byte {
	p := tcpPacket(dport)
	copy(p[26:30], src[:])
	binary.BigEndian.PutUint16(p[34:36], sport)
	p[47] = flags
	return p
}

// mfUDP is a UDP packet from src to the local address.
func mfUDP(src [4]byte, sport, dport uint16) []byte {
	p := udp4(local, remote, sport, dport)
	copy(p[26:30], src[:])
	return p
}

func mfKey(a [4]byte) IPKey { return IPKeyFromIP(net.IP(a[:])) }

// eventDrain reads the perf ring of wafio_events, so a test can tell that a
// packet emitted no event.
type eventDrain struct {
	t  *testing.T
	rd *perf.Reader
}

func newEventDrain(t *testing.T, c *cebpf.Collection) *eventDrain {
	t.Helper()
	rd, err := perf.NewReader(c.Maps[mapEvents], 64*os.Getpagesize())
	if err != nil {
		t.Fatalf("perf reader: %+v", err)
	}
	t.Cleanup(func() { _ = rd.Close() })
	return &eventDrain{t: t, rd: rd}
}

// drain returns the events read since the last call.
func (d *eventDrain) drain() int {
	d.t.Helper()
	n := 0
	for {
		d.rd.SetDeadline(time.Now().Add(30 * time.Millisecond))
		rec, err := d.rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return n
		}
		if err != nil {
			d.t.Fatalf("read events: %v", err)
		}
		if rec.LostSamples == 0 {
			n++
		}
	}
}

// bareManager is a Manager that holds the maps of the collections and
// nothing else, so the code that works on live maps (the prune, the capacity
// sampler, the jail) runs against the maps under test.
func bareManager(t *testing.T, sizes MapSizes, xdp, tc *cebpf.Collection) (*Manager, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	var mu sync.Mutex
	m := &Manager{
		cfg:                ManagerConfig{MapSizes: sizes},
		log:                log.New(lockedWriter{&mu, &logs}, "", 0),
		jailMap:            xdp.Maps[mapJail],
		rateConfigMap:      xdp.Maps[mapRateConfig],
		rateStateMap:       xdp.Maps[mapRateState],
		synStateMap:        xdp.Maps[mapSynState],
		conntrackMap:       xdp.Maps[mapConntrack],
		geoipMap:           xdp.Maps[mapGeoIP],
		portscanMap:        xdp.Maps[mapPortscan],
		portscanCfgMap:     xdp.Maps[mapPortscanCfg],
		stateFullMap:       xdp.Maps[mapStateFull],
		metricsMap:         xdp.Maps[mapMetrics],
		egressBlocklistMap: xdp.Maps[mapEgressBlocklist],
	}
	if tc != nil {
		m.bandwidthMap = tc.Maps[mapBandwidth]
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	m.bootTimeOffset = time.Duration(time.Now().UnixNano()) - time.Duration(ts.Nano())
	return m, &logs
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func countEntries(t *testing.T, m *cebpf.Map) uint64 {
	t.Helper()
	var c entryCounter
	n, err := c.count(m)
	if err != nil {
		t.Fatalf("count %s: %v", m, err)
	}
	return n
}

func stateTableFull(t *testing.T, c *cebpf.Collection) uint64 {
	t.Helper()
	var vals []MetricsVal
	if err := c.Maps[mapMetrics].Lookup(uint32(0), &vals); err != nil {
		t.Fatalf("%+v", err)
	}
	var n uint64
	for _, v := range vals {
		n += v.StateTableFull
	}
	return n
}

func refused(c *cebpf.Collection, slot uint32) uint64 { return sumPerCPU(c.Maps[mapStateFull], slot) }

// mapSizingEntry finds a map in the sampled status.
func mapSizingEntry(t *testing.T, sz *MapSizing, name string) MapCapacity {
	t.Helper()
	for _, m := range sz.Maps {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("map_sizing lists no %s: %+v", name, sz.Maps)
	return MapCapacity{}
}

// stateMapFlood is the shape of the SYN, rate-limit and port-scan scenarios.
type stateMapFlood struct {
	name  string
	table string // the map under test
	slot  uint32 // its wafio_state_full slot
	// configure sets the maps the check reads; window is its window in ns.
	configure func(t *testing.T, c *cebpf.Collection, window uint64)
	// first is the packet a source sends to get tracked; abusive is the
	// packet that tips a tracked source over its limit after budget packets.
	first   func(src [4]byte, i int) []byte
	abusive func(src [4]byte, i int) []byte
	// budget is how many packets of abusive a source sends before the limit.
	budget int
}

func TestKernelMapFullStateMaps(t *testing.T) {
	const longWindow = 60_000_000_000 // 60 s, the largest window the programs take
	const shortWindow = 10_000_000    // 10 ms, the smallest
	syn := func(src [4]byte, i int) []byte { return mfTCP(src, 40000, 443, 0x02) }
	ack := func(src [4]byte, i int) []byte { return mfTCP(src, 40000, 443, 0x10) }
	scan := func(src [4]byte, i int) []byte { return mfTCP(src, 40000, uint16(1000+i), 0x02) }
	for _, tc := range []stateMapFlood{
		{
			name: "syn_state", table: mapSynState, slot: stateFullSyn, budget: 60,
			configure: func(t *testing.T, c *cebpf.Collection, window uint64) {
				putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableSynflood: 1, LogBlocked: 1})
				// 60 SYNs a window and source, then the configured action: drop.
				putPacketMap(t, c, mapRateConfig, uint32(0), RateConfig{WindowNs: window, MaxSynPPS: 1, Action: 1})
			},
			first: syn, abusive: syn,
		},
		{
			name: "rate_state", table: mapRateState, slot: stateFullRate, budget: 60,
			configure: func(t *testing.T, c *cebpf.Collection, window uint64) {
				putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableRatelimit: 1, LogBlocked: 1})
				putPacketMap(t, c, mapRateConfig, uint32(0), RateConfig{WindowNs: window, MaxPPS: 1, Action: 1})
			},
			first: ack, abusive: ack,
		},
		{
			name: "portscan", table: mapPortscan, slot: stateFullPortscan, budget: 3,
			configure: func(t *testing.T, c *cebpf.Collection, window uint64) {
				putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, LogBlocked: 1})
				putPacketMap(t, c, mapPortscanCfg, uint32(0), PortScanConfig{WindowNs: window, MaxUniquePorts: 3, Action: 1})
			},
			// One port a source while it is tracked, a new port with each
			// packet of the abuser.
			first:   func(src [4]byte, i int) []byte { return mfTCP(src, 40000, 80, 0x02) },
			abusive: scan,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sizes := floorSizes(t)
			c := sizedObjectCollection(t, "wafio_xdp.o", sizes)
			events := newEventDrain(t, c)
			mgr, logs := bareManager(t, sizes, c, nil)
			capacity := c.Maps[tc.table].MaxEntries()
			if got, _ := sizes.Size(tc.table); capacity != got {
				t.Fatalf("%s holds %d entries, sized %d", tc.table, capacity, got)
			}
			tc.configure(t, c, longWindow)

			// An abuser tracked before the flood: budget packets pass, the
			// next ones are dropped.
			abuser := mfAddr(0)
			for i := 0; i < tc.budget; i++ {
				if got := runPacket(t, c, tc.abusive(abuser, i)); got != xdpPas {
					t.Fatalf("abuser packet %d within its budget: verdict %d", i, got)
				}
			}
			if got := runPacket(t, c, tc.abusive(abuser, tc.budget)); got != xdpDrp {
				t.Fatalf("abuser over its budget: verdict %d, want drop", got)
			}

			// Fill the map past its capacity with distinct sources.
			sent := int(capacity) + 2000
			for n := 1; n <= sent; n++ {
				if got := runPacket(t, c, tc.first(mfAddr(n), 0)); got != xdpPas {
					t.Fatalf("source %d of the flood: verdict %d, want pass", n, got)
				}
			}
			entries := countEntries(t, c.Maps[tc.table])
			if entries != uint64(capacity) {
				t.Fatalf("%s holds %d entries, want it full at %d", tc.table, entries, capacity)
			}
			// Each source either got an entry or was refused: nothing is lost.
			if got := refused(c, tc.slot); got+entries != uint64(sent)+1 {
				t.Fatalf("refused %d + entries %d != %d sources + the abuser", got, entries, sent)
			}
			events.drain()
			beforeSlot, beforeTotal := refused(c, tc.slot), stateTableFull(t, c)

			// A source tracked before the flood is still limited.
			if got := runPacket(t, c, tc.abusive(abuser, tc.budget+1)); got != xdpDrp {
				t.Errorf("tracked abuser after the flood: verdict %d, want drop", got)
			}
			events.drain()

			// A new source passes without an event, and both counters grow.
			fresh := mfAddr(sent + 100)
			if got := runPacket(t, c, tc.first(fresh, 0)); got != xdpPas {
				t.Errorf("new source with the map full: verdict %d, want pass", got)
			}
			if n := events.drain(); n != 0 {
				t.Errorf("a source the full map could not track emitted %d events", n)
			}
			if got := refused(c, tc.slot); got != beforeSlot+1 {
				t.Errorf("wafio_state_full slot %d = %d, want %d", tc.slot, got, beforeSlot+1)
			}
			if got := stateTableFull(t, c); got != beforeTotal+1 {
				t.Errorf("state_table_full = %d, want %d", got, beforeTotal+1)
			}
			// Even a new abuser passes: its address cannot be tracked.
			for i := 0; i < tc.budget+5; i++ {
				if got := runPacket(t, c, tc.abusive(fresh, i)); got != xdpPas {
					t.Fatalf("untracked source packet %d: verdict %d, want pass", i, got)
				}
			}

			// The sampler reports the full map, and the warning names it.
			now := time.Now()
			mgr.sampleMaps(now)
			status := mgr.mapSizingStatus()
			entry := mapSizingEntry(t, status, tc.table)
			if entry.Entries == nil || *entry.Entries != uint64(capacity) || entry.MaxEntries != capacity {
				t.Errorf("sampled %+v, want %d of %d", entry, capacity, capacity)
			}
			if entry.FullCount == nil || *entry.FullCount == 0 || entry.LastFullAt == nil {
				t.Errorf("sampled %+v: full_count and last_full_at expected", entry)
			}
			if w := mapFullWarning(status, now); !strings.Contains(w, tc.table) {
				t.Errorf("coverage warning %q does not name %s", w, tc.table)
			}
			if !strings.Contains(logs.String(), "WARN: eBPF map "+tc.table+" is full") {
				t.Errorf("no WARN logged: %q", logs.String())
			}

			// The entries age. The prune frees them, 4096 a call, and a new
			// abuser is tracked and dropped again.
			tc.configure(t, c, shortWindow)
			time.Sleep(60 * time.Millisecond)
			for i := 0; i < int(capacity)/4096+3 && countEntries(t, c.Maps[tc.table]) > 0; i++ {
				mgr.pruneDetectionState()
			}
			if left := countEntries(t, c.Maps[tc.table]); left != 0 {
				t.Fatalf("%d entries left after the prune", left)
			}
			tc.configure(t, c, longWindow)
			next := mfAddr(sent + 200)
			for i := 0; i < tc.budget; i++ {
				if got := runPacket(t, c, tc.abusive(next, i)); got != xdpPas {
					t.Fatalf("new abuser packet %d after the prune: verdict %d", i, got)
				}
			}
			if got := runPacket(t, c, tc.abusive(next, tc.budget)); got != xdpDrp {
				t.Errorf("new abuser after the prune: verdict %d, want drop", got)
			}
		})
	}
}

// An established flow and a source that was already tracked pass with the
// per-source maps full, and the SYN pressure check still drops the SYNs of
// untracked sources.
func TestKernelMapFullSynKeepsEstablishedFlows(t *testing.T) {
	pinToOneCPU(t) // the SYN pressure window is per CPU
	sizes := floorSizes(t)
	c := sizedObjectCollection(t, "wafio_xdp.o", sizes)
	capacity := int(c.Maps[mapSynState].MaxEntries())
	putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableSynflood: 1, EnableConntrack: 1})
	putPacketMap(t, c, mapRateConfig, uint32(0), RateConfig{WindowNs: 60_000_000_000, MaxSynPPS: 1, Action: 1})
	for n := 1; n <= capacity+500; n++ {
		runPacket(t, c, mfTCP(mfAddr(n), 40000, 443, 0x02))
	}
	if refused(c, stateFullSyn) == 0 {
		t.Fatal("the SYN map did not fill")
	}

	// An established inbound flow: its ACKs pass from a source the map could
	// not track.
	estab := mfAddr(capacity + 1000)
	putPacketMap(t, c, mapConntrack, ConnKey{Src: mfKey(estab), Dst: mfKey(mfLocal), Sport: ntohs(40000), Dport: ntohs(443), Proto: 6},
		ConnVal{LastSeenNs: monoNow(t), TCPState: 1, FlagsSeen: 0x10})
	if got := runPacket(t, c, mfTCP(estab, 40000, 443, 0x10)); got != xdpPas {
		t.Errorf("ACK of an established flow: verdict %d, want pass", got)
	}

	// Pressure mode: the sixth SYN within a second is over the threshold.
	putPacketMap(t, c, mapRateConfig, uint32(0), RateConfig{WindowNs: 60_000_000_000, MaxSynPPS: 1, SynPressurePPS: 5, Action: 1})
	dropped := 0
	for i := 0; i < 20; i++ {
		if runPacket(t, c, mfTCP(mfAddr(capacity+2000+i), 40000, 443, 0x02)) == xdpDrp {
			dropped++
		}
	}
	if dropped == 0 {
		t.Error("SYN pressure dropped no SYN of an untracked source with the map full")
	}
	if got := runPacket(t, c, mfTCP(estab, 40000, 443, 0x02)); got != xdpPas {
		t.Errorf("SYN of an established flow under pressure: verdict %d, want pass", got)
	}
	if got := runPacket(t, c, mfTCP(estab, 40000, 443, 0x10)); got != xdpPas {
		t.Errorf("ACK of an established flow under pressure: verdict %d, want pass", got)
	}
}

// With a reply to a flow the host opened, the rate limit is not applied at
// all, so a full rate map cannot touch it.
func TestKernelMapFullRateKeepsReplies(t *testing.T) {
	sizes := floorSizes(t)
	c := sizedObjectCollection(t, "wafio_xdp.o", sizes)
	capacity := int(c.Maps[mapRateState].MaxEntries())
	putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableRatelimit: 1, EnableConntrack: 1})
	putPacketMap(t, c, mapRateConfig, uint32(0), RateConfig{WindowNs: 60_000_000_000, MaxPPS: 1, Action: 1})
	for n := 1; n <= capacity+500; n++ {
		runPacket(t, c, mfTCP(mfAddr(n), 40000, 443, 0x10))
	}
	if refused(c, stateFullRate) == 0 {
		t.Fatal("the rate map did not fill")
	}
	server := mfAddr(capacity + 1000)
	putPacketMap(t, c, mapConntrack, ConnKey{Src: mfKey(mfLocal), Dst: mfKey(server), Sport: ntohs(40000), Dport: ntohs(443), Proto: 6},
		ConnVal{LastSeenNs: monoNow(t), TCPState: 1, FlagsSeen: ConnOutbound})
	before := refused(c, stateFullRate)
	for i := 0; i < 200; i++ { // far over the 60 packets a window allows
		if got := runPacket(t, c, mfTCP(server, 443, 40000, 0x10)); got != xdpPas {
			t.Fatalf("reply %d with the rate map full: verdict %d, want pass", i, got)
		}
	}
	if got := refused(c, stateFullRate); got != before {
		t.Errorf("replies touched the full rate map: refused %d -> %d", before, got)
	}
}

// Conntrack is an LRU map: a flood of spoofed flows evicts entries instead of
// failing. A reply of a flow the host opened that lost its entry passes by
// socket proof, a forged ACK does not.
func TestKernelMapFullConntrackSocketProof(t *testing.T) {
	sizes := floorSizes(t)
	c := sizedObjectCollection(t, "wafio_xdp.o", sizes)
	mgr, _ := bareManager(t, sizes, c, nil)
	capacity := int(c.Maps[mapConntrack].MaxEntries())
	const allowedTCP, allowedUDP = 8443, 5353
	putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableConntrack: 1})
	putPacketMap(t, c, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1})
	putPacketMap(t, c, mapPortPolicy, PortPolicyKey{Port: allowedTCP, Proto: 6, Direction: PortDirIngress}, PortPolicyVal{Action: 0})
	putPacketMap(t, c, mapPortPolicy, PortPolicyKey{Port: allowedUDP, Proto: 17, Direction: PortDirIngress}, PortPolicyVal{Action: 0})

	// Twice the capacity in distinct spoofed ACK and UDP flows to allowed
	// ports. All pass, and the table stays at its size.
	for n := 0; n < capacity; n++ {
		src := mfAddr(n)
		if got := runPacket(t, c, mfTCP(src, 40000, allowedTCP, 0x10)); got != xdpPas {
			t.Fatalf("spoofed ACK %d to an allowed port: verdict %d, want pass", n, got)
		}
		if got := runPacket(t, c, mfUDP(src, 40000, allowedUDP)); got != xdpPas {
			t.Fatalf("spoofed UDP %d to an allowed port: verdict %d, want pass", n, got)
		}
	}
	entries := countEntries(t, c.Maps[mapConntrack])
	margin := uint64(2 * mapLRUFreeNodesPerCPU * sizes.CPUs)
	if entries > uint64(capacity) || entries+margin < uint64(capacity) {
		t.Fatalf("conntrack holds %d entries after %d flows, want about its size %d", entries, 2*capacity, capacity)
	}

	// The flows of the flood are fresh: the sampler finds the table full of
	// live flows, names it in the warning and reports no refused inserts.
	now := time.Now()
	mgr.sampleMaps(now)
	status := mgr.mapSizingStatus()
	if ct := mapSizingEntry(t, status, mapConntrack); ct.FullCount != nil || ct.LastFullAt == nil || ct.Entries == nil || *ct.Entries+margin < uint64(capacity) {
		t.Errorf("conntrack sample %+v: want about %d fresh entries and last_full_at, no full_count", ct, capacity)
	}
	if w := mapFullWarning(status, now); !strings.Contains(w, mapConntrack) {
		t.Errorf("coverage warning %q does not name %s", w, mapConntrack)
	}

	for _, fam := range adoptFamilies {
		t.Run(fam.name, func(t *testing.T) {
			lc := establishedLoopback(t, fam.network)
			srv, cli := lc.srvPort, lc.cliPort
			requireAbsent := func(key ConnKey) {
				t.Helper()
				var cv ConnVal
				if err := c.Maps[mapConntrack].Lookup(key, &cv); !errors.Is(err, cebpf.ErrKeyNotExist) {
					t.Fatalf("entry %+v present before the packet (%v)", cv, err)
				}
			}

			// An ACK to a denied port that has a listener stays dropped, even
			// with an established connection for its tuple: the listener makes
			// it an inbound connection, not a reply.
			if got := runPacket(t, c, fam.pkt(lc.host, lc.host, cli, srv, 0x10)); got != xdpDrp {
				t.Errorf("ACK to the denied listening port: verdict %d, want drop", got)
			}
			// An ACK no socket matches stays dropped.
			if got := runPacket(t, c, fam.pkt(fam.remote, fam.local, 55555, freeTCPPort(t), 0x10)); got != xdpDrp {
				t.Errorf("ACK without a socket: verdict %d, want drop", got)
			}
			// A SYN-ACK, a FIN or a RST of the same tuple get no proof.
			for _, flags := range []byte{0x12, 0x04, 0x14} {
				if got := runPacket(t, c, fam.pkt(lc.host, lc.host, srv, cli, flags)); got != xdpDrp {
					t.Errorf("flags %#x with a socket: verdict %d, want drop", flags, got)
				}
			}

			// The reply of a connection the host opened (the client end):
			// its entry is gone, the kernel still knows the socket.
			out := connKey4(lc.host, lc.host, cli, srv) // v6 as well: the key is built from the address
			requireAbsent(out)
			if got := runPacket(t, c, fam.pkt(lc.host, lc.host, srv, cli, 0x10)); got != xdpPas {
				t.Fatalf("reply of a host-opened connection after the flood: verdict %d, want pass", got)
			}
			var cv ConnVal
			if err := c.Maps[mapConntrack].Lookup(out, &cv); err != nil {
				t.Fatalf("the outbound entry did not come back: %v", err)
			}
			if cv.FlagsSeen&ConnOutbound == 0 || cv.TCPState != 1 || cv.LastSeenNs == 0 {
				t.Errorf("outbound entry %+v: want CONN_OUTBOUND, established, stamped", cv)
			}
			// With the entry back, the next reply passes without a lookup.
			if got := runPacket(t, c, fam.pkt(lc.host, lc.host, srv, cli, 0x10)); got != xdpPas {
				t.Errorf("second reply: verdict %d, want pass", got)
			}
		})
	}
}

// publicLoopback is establishedLoopback on a public address, which no geo
// exemption covers. The test goroutine stays on its thread, and the thread
// moves to a network namespace of its own with addr on lo. Packets run from
// the same thread, so the program's socket lookups see that namespace. The
// thread is never unlocked, so it ends with the test.
func publicLoopback(t *testing.T, network, addr string) loopbackConn {
	t.Helper()
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Skipf("no network namespace: %v", err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(addr)
	bits := 128
	if ip.To4() != nil {
		bits = 32
	}
	if err := netlink.AddrAdd(lo, &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, Flags: unix.IFA_F_NODAD}); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen(network, net.JoinHostPort(addr, "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	c, err := net.Dial(network, l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return loopbackConn{host: addr, srvPort: uint16(l.Addr().(*net.TCPAddr).Port), cliPort: uint16(c.LocalAddr().(*net.TCPAddr).Port)}
}

// A reply of a flow the host opened that lost its conntrack entry passes on
// socket proof at each drop that a reply skips, and only there. A reply that
// passes anyway costs no socket lookup, so no entry is written for it, and a
// forged ACK stays dropped.
func TestKernelMapFullReplyProofAtDrops(t *testing.T) {
	families := []struct {
		adoptFamily
		host, forged, everyone string
	}{
		{adoptFamilies[0], "203.0.113.7", "203.0.113.99", "0.0.0.0/0"},
		{adoptFamilies[1], "2001:db8:2::7", "2001:db8:2::99", "::/0"},
	}
	conntrackOn := func(t *testing.T, extra GlobalConfig) *cebpf.Collection {
		c := packetTestCollection(t)
		extra.Enabled, extra.EnableConntrack = 1, 1
		putPacketMap(t, c, mapConfig, uint32(0), extra)
		return c
	}
	for _, fam := range families {
		for _, tc := range []struct {
			name  string
			setup func(t *testing.T) *cebpf.Collection
			// budget: replies that pass on the check's own terms first.
			budget int
			proof  bool // the check drops a packet that is not a reply
		}{
			{"passes anyway", func(t *testing.T) *cebpf.Collection { return conntrackOn(t, GlobalConfig{}) }, 0, false},
			{"family-wide block", func(t *testing.T) *cebpf.Collection {
				c := conntrackOn(t, GlobalConfig{})
				putListEntry(t, c, false, fam.everyone)
				return c
			}, 0, true},
			{"geo allow mode", func(t *testing.T) *cebpf.Collection { return geoAllowCollection(t, 0, true) }, 0, true},
			{"ingress default deny", func(t *testing.T) *cebpf.Collection {
				c := conntrackOn(t, GlobalConfig{})
				putPacketMap(t, c, mapPortPolicyConfig, uint32(0), PortPolicyConfig{Enabled: 1, DefaultIngress: 1})
				return c
			}, 0, true},
			{"rate limit", func(t *testing.T) *cebpf.Collection {
				c := conntrackOn(t, GlobalConfig{EnableRatelimit: 1})
				// 60 packets a window and source, then drop.
				putPacketMap(t, c, mapRateConfig, uint32(0), RateConfig{WindowNs: 60_000_000_000, MaxPPS: 1, Action: 1})
				return c
			}, 60, true},
		} {
			t.Run(fam.name+"/"+tc.name, func(t *testing.T) {
				lc := publicLoopback(t, fam.network, fam.host)
				c := tc.setup(t)
				reply := fam.pkt(lc.host, lc.host, lc.srvPort, lc.cliPort, 0x10)
				out := connKey4(lc.host, lc.host, lc.cliPort, lc.srvPort)
				var cv ConnVal
				for i := 0; i <= tc.budget; i++ {
					if got := runPacket(t, c, reply); got != xdpPas {
						t.Fatalf("reply %d: verdict %d, want pass", i, got)
					}
					err := c.Maps[mapConntrack].Lookup(out, &cv)
					if i < tc.budget || !tc.proof {
						if !errors.Is(err, cebpf.ErrKeyNotExist) {
							t.Fatalf("reply %d passed without a drop to skip, yet the outbound entry is there (%v): the socket lookup ran", i, err)
						}
					} else if err != nil || cv.FlagsSeen&ConnOutbound == 0 {
						t.Fatalf("reply %d passed on socket proof, but the outbound entry %+v is missing (%v)", i, cv, err)
					}
				}
				if !tc.proof {
					return
				}
				forged := fam.pkt(fam.forged, lc.host, 55555, freeTCPPort(t), 0x10)
				var got uint32
				for i := 0; i <= tc.budget; i++ {
					got = runPacket(t, c, forged)
				}
				if got != xdpDrp {
					t.Errorf("forged ACK without a socket: verdict %d, want drop", got)
				}
			})
		}
	}
}

// The jail is a HASH map: a full jail refuses a new address, frees the entries
// past their TTL first, and never evicts a live one.
func TestKernelMapFullJail(t *testing.T) {
	sizes := floorSizes(t)
	c := sizedObjectCollection(t, "wafio_xdp.o", sizes)
	mgr, _ := bareManager(t, sizes, c, nil)
	capacity := int(c.Maps[mapJail].MaxEntries())
	putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1})
	jailed := func(n int) string { a := mfAddr(n); return net.IP(a[:]).String() }

	t.Run("every entry live", func(t *testing.T) {
		for n := 0; n < capacity; n++ {
			if err := mgr.AddToJail(jailed(n), time.Hour); err != nil {
				t.Fatalf("jail %d of %d: %v", n, capacity, err)
			}
		}
		err := mgr.AddToJail(jailed(capacity), time.Hour)
		if !errors.Is(err, ErrJailFull) || !errors.Is(err, ErrIPListCapacity) {
			t.Fatalf("add to a full jail: %v, want ErrJailFull wrapping ErrIPListCapacity", err)
		}
		if got := mgr.jailFull.Load(); got != 1 {
			t.Errorf("jail full counter %d, want 1", got)
		}
		if got := countEntries(t, c.Maps[mapJail]); got != uint64(capacity) {
			t.Errorf("jail holds %d entries, want %d: a live entry was evicted", got, capacity)
		}
		// The local API answers 409 IP_LIST_FULL, with what it did add.
		h := &FastHTTPHandler{Manager: mgr}
		var ctx fasthttp.RequestCtx
		h.addJail(&ctx, []IPEntry{{IP: jailed(capacity + 1), TTLMs: 60_000}})
		if code := ctx.Response.StatusCode(); code != fasthttp.StatusConflict ||
			!strings.Contains(string(ctx.Response.Body()), `"code":"IP_LIST_FULL"`) {
			t.Errorf("local API after a refused jail entry: %d %s, want 409 IP_LIST_FULL", code, ctx.Response.Body())
		}
		var okCtx fasthttp.RequestCtx
		h.addJail(&okCtx, []IPEntry{{IP: jailed(0), TTLMs: 60_000}}) // a known address updates in place
		if code := okCtx.Response.StatusCode(); code != fasthttp.StatusOK {
			t.Errorf("local API for an address already in the jail: %d %s, want 200", code, okCtx.Response.Body())
		}
		// Jailed sources stay dropped, others pass.
		for _, n := range []int{0, capacity / 2, capacity - 1} {
			if got := runPacket(t, c, mfTCP(mfAddr(n), 40000, 443, 0x10)); got != xdpDrp {
				t.Errorf("jailed source %d: verdict %d, want drop", n, got)
			}
		}
		if got := runPacket(t, c, mfTCP(mfAddr(capacity), 40000, 443, 0x10)); got != xdpPas {
			t.Errorf("the address the jail refused: verdict %d, want pass", got)
		}
		// The status counts it.
		mgr.sampleMaps(time.Now())
		jail := mapSizingEntry(t, mgr.mapSizingStatus(), mapJail)
		// Two addresses were refused: one directly, one through the local API.
		if jail.FullCount == nil || *jail.FullCount != 2 || jail.LastFullAt == nil {
			t.Errorf("jail sample %+v: want full_count 2 and last_full_at", jail)
		}
	})

	t.Run("expired entries make room", func(t *testing.T) {
		c := sizedObjectCollection(t, "wafio_xdp.o", sizes)
		mgr, _ := bareManager(t, sizes, c, nil)
		putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1})
		const keep = 100
		for n := 0; n < capacity; n++ {
			ttl := 20 * time.Millisecond
			if n < keep {
				ttl = time.Hour
			}
			if err := mgr.AddToJail(jailed(n), ttl); err != nil {
				t.Fatalf("jail %d: %v", n, err)
			}
		}
		time.Sleep(60 * time.Millisecond)
		if err := mgr.AddToJail(jailed(capacity), time.Hour); err != nil {
			t.Fatalf("add after the TTLs ended: %v", err)
		}
		if got := mgr.jailFull.Load(); got != 0 {
			t.Errorf("jail full counter %d, want 0", got)
		}
		if got := countEntries(t, c.Maps[mapJail]); got != keep+1 {
			t.Errorf("jail holds %d entries, want the %d live ones and the new one", got, keep)
		}
		for _, n := range []int{0, keep - 1, capacity} {
			if got := runPacket(t, c, mfTCP(mfAddr(n), 40000, 443, 0x10)); got != xdpDrp {
				t.Errorf("jailed source %d: verdict %d, want drop", n, got)
			}
		}
	})
}

// A full jail of live entries is swept at most once a second, however many
// addresses the WAF agent jails: each sweep reads every entry.
func TestKernelMapFullJailSweepsOnceASecond(t *testing.T) {
	sizes := floorSizes(t)
	c := sizedObjectCollection(t, "wafio_xdp.o", sizes)
	mgr, _ := bareManager(t, sizes, c, nil)
	capacity := int(c.Maps[mapJail].MaxEntries())
	jailed := func(n int) string { a := mfAddr(n); return net.IP(a[:]).String() }
	for n := 0; n < capacity; n++ {
		if err := mgr.AddToJail(jailed(n), time.Hour); err != nil {
			t.Fatalf("jail %d of %d: %v", n, capacity, err)
		}
	}
	if err := mgr.AddToJail(jailed(capacity), time.Hour); !errors.Is(err, ErrJailFull) {
		t.Fatalf("add to a full jail: %v, want ErrJailFull", err)
	}
	swept := mgr.jailSweptAt.Load()
	if swept == 0 {
		t.Fatal("the first refusal did not sweep the jail")
	}
	// An entry runs out right after that sweep. The next adds within the
	// second do not sweep, so its slot stays taken.
	putPacketMap(t, c, mapJail, mfKey(mfAddr(0)), IPListVal{AddedNs: 1, ExpiresNs: 2, RuleType: 1})
	for i := 1; i <= 50; i++ {
		if err := mgr.AddToJail(jailed(capacity+i), time.Hour); !errors.Is(err, ErrJailFull) {
			t.Fatalf("add %d within the second: %v, want ErrJailFull", i, err)
		}
	}
	if got := mgr.jailSweptAt.Load(); got != swept {
		t.Fatalf("the jail was swept again within a second (%d, then %d)", swept, got)
	}
	// A second later the next add sweeps and takes the freed slot.
	mgr.jailSweptAt.Store(swept - int64(jailSweepEvery))
	if err := mgr.AddToJail(jailed(capacity+100), time.Hour); err != nil {
		t.Fatalf("add after the second: %v", err)
	}
	if got := mgr.jailFull.Load(); got != 51 {
		t.Errorf("jail full counter %d, want 51", got)
	}
}

// The LRU maps evict. An address the reactive geo cache lost escapes the geo
// block until it is enriched again, and the accounting map keeps accepting
// sources without a verdict depending on it. Both are caches that fill up by
// design: the sampler reports their entries and never calls them full. The
// conntrack table counts as full only when its fresh flows fill it, not when
// ended flows wait there to be evicted.
func TestKernelMapFullLRUEvict(t *testing.T) {
	sizes := floorSizes(t)
	notFull := func(t *testing.T, mgr *Manager, name string, wantEntries func(uint64) bool) {
		t.Helper()
		now := time.Now()
		mgr.sampleMaps(now)
		status := mgr.mapSizingStatus()
		e := mapSizingEntry(t, status, name)
		if e.Entries == nil || !wantEntries(*e.Entries) || e.FullCount != nil || e.LastFullAt != nil {
			var n any = e.Entries
			if e.Entries != nil {
				n = *e.Entries
			}
			t.Errorf("%s sample %+v, entries %v: want its entries, no full_count and no last_full_at", name, e, n)
		}
		if w := mapFullWarning(status, now); strings.Contains(w, name) {
			t.Errorf("coverage warning %q names %s", w, name)
		}
	}

	t.Run("conntrack of ended flows", func(t *testing.T) {
		c := sizedObjectCollection(t, "wafio_xdp.o", sizes)
		mgr, logs := bareManager(t, sizes, c, nil)
		capacity := int(c.Maps[mapConntrack].MaxEntries())
		now := monoNow(t)
		const fresh = 10
		for n := 0; n < capacity; n++ {
			key := ConnKey{Src: mfKey(mfAddr(n)), Dst: mfKey(mfLocal), Sport: ntohs(40000), Dport: ntohs(443), Proto: 6}
			last := now - 600_000_000_000 // ten minutes ago: past the TCP and UDP TTLs
			if n%2 == 1 {
				key.Proto = 17
			}
			if n >= capacity-fresh { // written last: the LRU evicts the oldest writes first
				last = now
			}
			putPacketMap(t, c, mapConntrack, key, ConnVal{FirstSeenNs: last, LastSeenNs: last, TCPState: 1})
		}
		if got := countEntries(t, c.Maps[mapConntrack]); got+uint64(2*mapLRUFreeNodesPerCPU*sizes.CPUs) < uint64(capacity) {
			t.Fatalf("conntrack holds %d entries, want about its size %d", got, capacity)
		}
		notFull(t, mgr, mapConntrack, func(n uint64) bool { return n == fresh })
		if strings.Contains(logs.String(), "WARN") {
			t.Errorf("a WARN for a table of ended flows: %q", logs.String())
		}
	})

	t.Run("geoip", func(t *testing.T) {
		c := sizedObjectCollection(t, "wafio_xdp.o", sizes)
		mgr, _ := bareManager(t, sizes, c, nil)
		capacity := int(c.Maps[mapGeoIP].MaxEntries())
		putPacketMap(t, c, mapConfig, uint32(0), GlobalConfig{Enabled: 1, EnableGeoblock: 1})
		cn := PackCountry('C', 'N')
		putPacketMap(t, c, mapGeoBlocked, cn, GeoCountryVal{Blocked: 1})
		blocked := mfAddr(0)
		geo := GeoVal{CountryCode: cn, Action: 1}
		putPacketMap(t, c, mapGeoIP, mfKey(blocked), geo)
		var cached GeoVal
		if err := c.Maps[mapGeoIP].Lookup(mfKey(blocked), &cached); err != nil || cached != geo {
			t.Fatalf("geo cache lookup %+v, %v", cached, err)
		}
		// The cache is the only thing that knows the address. No packet
		// touches it (a lookup from a program keeps an LRU entry alive) while
		// twice the size of the cache in other addresses come in.
		other := GeoVal{CountryCode: PackCountry('I', 'D'), Action: 1}
		for n := 1; n <= 2*capacity; n++ {
			putPacketMap(t, c, mapGeoIP, mfKey(mfAddr(n)), other)
		}
		if got := countEntries(t, c.Maps[mapGeoIP]); got > uint64(capacity) {
			t.Fatalf("geoip holds %d entries, more than its %d", got, capacity)
		}
		if err := c.Maps[mapGeoIP].Lookup(mfKey(blocked), &cached); !errors.Is(err, cebpf.ErrKeyNotExist) {
			t.Fatalf("the blocked address is still cached after the flood (%v)", err)
		}
		if got := runPacket(t, c, mfTCP(blocked, 40000, 443, 0x02)); got != xdpPas {
			t.Errorf("address evicted from the geo cache: verdict %d, want pass (it escapes until enriched again)", got)
		}
		notFull(t, mgr, mapGeoIP, func(n uint64) bool { return n+uint64(2*mapLRUFreeNodesPerCPU*sizes.CPUs) >= uint64(capacity) })
		putPacketMap(t, c, mapGeoIP, mfKey(blocked), geo)
		if got := runPacket(t, c, mfTCP(blocked, 40000, 443, 0x02)); got != xdpDrp {
			t.Errorf("address enriched again: verdict %d, want drop", got)
		}
	})

	t.Run("bandwidth", func(t *testing.T) {
		xdpColl, tcColl := packetPairSized(t, sizes)
		mgr, _ := bareManager(t, sizes, xdpColl, tcColl)
		capacity := int(tcColl.Maps[mapBandwidth].MaxEntries())
		putPacketMap(t, tcColl, mapConfig, uint32(0), GlobalConfig{Enabled: 1})
		for n := 0; n < 2*capacity; n++ {
			ret, _, err := tcColl.Programs["wafio_tc_ingress"].Test(mfTCP(mfAddr(n), 40000, 443, 0x10))
			if err != nil || ret != tcOK {
				t.Fatalf("source %d: verdict %d, %v, want pass", n, ret, err)
			}
		}
		got := countEntries(t, tcColl.Maps[mapBandwidth])
		margin := uint64(2 * mapLRUFreeNodesPerCPU * sizes.CPUs)
		if got > uint64(capacity) || got+margin < uint64(capacity) {
			t.Errorf("bandwidth holds %d entries after %d sources, want about %d", got, 2*capacity, capacity)
		}
		notFull(t, mgr, mapBandwidth, func(n uint64) bool { return n+margin >= uint64(capacity) })
	})
}

// The entry count walks a map in chunks, and the key walk that replaces it
// when the kernel refuses batch operations agrees with it.
func TestKernelMapFullEntryCounter(t *testing.T) {
	sizes := floorSizes(t)
	c := sizedObjectCollection(t, "wafio_xdp.o", sizes)
	m := c.Maps[mapSynState]
	const n = 2*mapCountChunk + 123
	zero := make([]byte, m.ValueSize())
	for i := 0; i < n; i++ {
		if err := m.Update(mfKey(mfAddr(i)), zero, cebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	var counter entryCounter
	for round := 0; round < 2; round++ { // the second round reuses the buffers
		got, err := counter.count(m)
		if err != nil || got != n {
			t.Fatalf("batch count %d, %v, want %d", got, err, n)
		}
	}
	if got, err := countByIteration(m); err != nil || got != n {
		t.Fatalf("key walk %d, %v, want %d", got, err, n)
	}
	if k, v := counter.keySize, counter.valSize; k != m.KeySize() || v != m.ValueSize() {
		t.Errorf("buffers sized %d/%d for a %d/%d map", k, v, m.KeySize(), m.ValueSize())
	}
}

// The objects load at the smallest and at the full sizes, and TC shares the
// maps of XDP with the same size and flags either way. It runs the real
// loadXDP and loadTC.
func TestKernelMapFullTCLoads(t *testing.T) {
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if dir == "" {
		t.Skip("set WAFIO_TEST_BPF_DIR to compiled objects for kernel packet tests")
	}
	cpus, err := cebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		sizes MapSizes
	}{
		{"floor", ComputeMapSizes(mapFullScale, cpus)},
		{"ceiling", ComputeMapSizes(1, cpus)},
		{"unsized", MapSizes{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := rlimit.RemoveMemlock(); err != nil {
				t.Fatalf("%+v", err)
			}
			m := NewManager(ManagerConfig{
				XDPObjectPath: dir + "/wafio_xdp.o",
				TCObjectPath:  dir + "/wafio_tc.o",
				PinPath:       t.TempDir(),
				MapSizes:      tc.sizes,
			}, log.New(os.Stderr, "", 0))
			if err := m.loadXDP(); err != nil {
				t.Fatalf("load XDP: %+v", err)
			}
			t.Cleanup(m.cleanup)
			if err := m.loadTC(); err != nil {
				t.Fatalf("load TC: %+v", err)
			}
			// What the kernel charges to the maps of both objects, against the
			// estimate of the sized maps (the trace maps are not loaded here).
			sized := tc.sizes
			if len(sized.Entries) == 0 {
				sized = ComputeMapSizes(1, cpus) // the sizes the objects declare
			}
			est := (sized.EstimatedBytes() - uint64(sized.Entries[traceMapEvents]) -
				uint64(sized.Entries[traceMapOpenPending])*1512) >> 20
			total, inSized := mapMemlockMiB(t, m, sized)
			t.Logf("loaded the firewall objects: the kernel charges %d MiB to their maps, %d MiB of it to the sized ones (estimated %d MiB)", total, inSized, est)
			if m.egressBlocklistMap.Flags()&bpfFNoPrealloc == 0 {
				t.Errorf("egress blocklist flags %#x: not allocated on insert", m.egressBlocklistMap.Flags())
			}
			if m.egressBlocklistMap.MaxEntries() != egressBlocklistCapacity {
				t.Errorf("egress blocklist holds %d entries, want its capacity %d", m.egressBlocklistMap.MaxEntries(), egressBlocklistCapacity)
			}
			if m.jailMap.Type() != cebpf.Hash {
				t.Errorf("jail is a %s map, want a hash map", m.jailMap.Type())
			}
			for _, name := range []string{mapConfig, mapConntrack, mapEvents, mapMetrics, mapPortPolicy, mapPortPolicyConfig, mapEgressBlocklist, mapCPEndpoints, mapDHCPPending, mapDHCPServers} {
				xm, tm := m.xdpColl.Maps[name], m.tcColl.Maps[name]
				if xm == nil || tm == nil {
					t.Errorf("%s missing from a collection", name)
					continue
				}
				xi, _ := xm.Info()
				ti, _ := tm.Info()
				xid, _ := xi.ID()
				tid, _ := ti.ID()
				if xid != tid || xm.MaxEntries() != tm.MaxEntries() || xm.Flags() != tm.Flags() {
					t.Errorf("%s differs between XDP (id %d, %d entries, flags %d) and TC (id %d, %d, %d)",
						name, xid, xm.MaxEntries(), xm.Flags(), tid, tm.MaxEntries(), tm.Flags())
				}
			}
			for name, want := range tc.sizes.Entries {
				var got uint32
				switch {
				case m.xdpColl.Maps[name] != nil:
					got = m.xdpColl.Maps[name].MaxEntries()
				case m.tcColl.Maps[name] != nil:
					got = m.tcColl.Maps[name].MaxEntries()
				default:
					continue // a trace map
				}
				if got != want {
					t.Errorf("%s loaded with %d entries, sized %d", name, got, want)
				}
			}
		})
	}
}

// mapMemlockMiB sums the memory the kernel reports for the maps of both
// collections of m (a shared map once), and for the sized ones among them.
func mapMemlockMiB(t *testing.T, m *Manager, sized MapSizes) (total, inSized uint64) {
	t.Helper()
	seen := map[cebpf.MapID]bool{}
	var all, inS uint64
	for _, coll := range []*cebpf.Collection{m.xdpColl, m.tcColl} {
		for name, mp := range coll.Maps {
			info, err := mp.Info()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			id, _ := info.ID()
			if seen[id] {
				continue
			}
			seen[id] = true
			mem, _ := info.Memlock() // zero for a map the kernel does not account
			all += mem
			if _, ok := sized.Size(name); ok {
				inS += mem
			}
		}
	}
	return all >> 20, inS >> 20
}
