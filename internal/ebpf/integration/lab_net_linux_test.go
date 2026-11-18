//go:build linux

package integration

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A private veth pair for the scenarios that need real traffic: the host end
// lives in this namespace, where the firewall attaches; the peer end lives in
// a namespace of its own, held by a child process of the test binary (a
// re-run of TestLabPeer). The child serves the peer side: a server that pushes
// data, a legitimate client, and a sender of spoofed packets, driven by lines
// on its standard input. Nothing but the pair is touched: no default route, no
// other interface, no global sysctl.

const (
	labPeerEnv = "WAFIO_LAB_PEER"
	labIfEnv   = "WAFIO_LAB_IF"
	labAddrEnv = "WAFIO_LAB_ADDRS"
)

// labNet is the pair seen from the test.
type labNet struct {
	t         *testing.T
	hostIf    string
	hostAddr  netip.Addr // the firewall's side
	peerAddr  netip.Addr // the peer's interface address: the abuser
	peerAddr2 netip.Addr // a second peer address: the legitimate client
	cmd       *exec.Cmd
	in        io.WriteCloser

	mu    sync.Mutex
	cond  *sync.Cond
	lines []string
	done  bool
}

// newLabNet builds the pair and starts the peer. It skips the test when the
// kernel has no veth, and fails on any other error.
func newLabNet(t *testing.T) *labNet {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	// Kernels before 5.11 charge BPF maps to RLIMIT_MEMLOCK, as the agent's
	// unit allows for with LimitMEMLOCK=infinity.
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	suffix := strconv.Itoa(os.Getpid() % 100000)
	subnet := byte(os.Getpid()%200 + 20)
	n := &labNet{
		t:         t,
		hostIf:    "wlh" + suffix,
		hostAddr:  netip.AddrFrom4([4]byte{198, 18, subnet, 1}),
		peerAddr:  netip.AddrFrom4([4]byte{198, 18, subnet, 2}),
		peerAddr2: netip.AddrFrom4([4]byte{198, 18, subnet, 3}),
	}
	n.cond = sync.NewCond(&n.mu)
	peerIf := "wlp" + suffix
	cmd := exec.Command(os.Args[0], "-test.run=^TestLabPeer$", "-test.timeout=3h")
	cmd.Env = append(os.Environ(), labPeerEnv+"=1", labIfEnv+"="+peerIf,
		labAddrEnv+"="+n.peerAddr.String()+"/24,"+n.peerAddr2.String()+"/24")
	// The child's own network namespace, and no child outliving the test.
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the peer: %v", err)
	}
	n.cmd, n.in = cmd, in
	go n.read(out)
	t.Cleanup(n.close)

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: n.hostIf}, PeerName: peerIf}
	if err := netlink.LinkAdd(veth); err != nil {
		if strings.Contains(err.Error(), "not supported") || strings.Contains(err.Error(), "no such device") {
			t.Skipf("no veth on this kernel: %v", err)
		}
		t.Fatalf("create the veth pair: %v", err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(n.hostIf); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	peer, err := netlink.LinkByName(peerIf)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsPid(peer, cmd.Process.Pid); err != nil {
		t.Fatalf("move the peer end: %v", err)
	}
	host, err := netlink.LinkByName(n.hostIf)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(host, &netlink.Addr{IPNet: &net.IPNet{IP: n.hostAddr.AsSlice(), Mask: net.CIDRMask(24, 32)}}); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(host); err != nil {
		t.Fatal(err)
	}
	// Reverse path filtering on the pair, as a server runs it: a packet whose
	// source has no route back is dropped after XDP, not answered.
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+n.hostIf+"/rp_filter", []byte("1"), 0o644); err != nil {
		t.Logf("rp_filter on %s not set: %v", n.hostIf, err)
	}
	n.send("go")
	n.expect("ready", 15*time.Second)
	return n
}

func (n *labNet) read(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		if line, ok := strings.CutPrefix(sc.Text(), "LAB "); ok {
			n.mu.Lock()
			n.lines = append(n.lines, line)
			n.cond.Broadcast()
			n.mu.Unlock()
		}
	}
	n.mu.Lock()
	n.done = true
	n.cond.Broadcast()
	n.mu.Unlock()
}

// send writes one command line to the peer.
func (n *labNet) send(format string, args ...any) {
	n.t.Helper()
	if _, err := fmt.Fprintf(n.in, format+"\n", args...); err != nil {
		n.t.Fatalf("peer command: %v", err)
	}
}

// expect waits for a line of the peer that starts with prefix and returns the
// rest of it. Lines it passes over are kept for later expects.
func (n *labNet) expect(prefix string, wait time.Duration) string {
	n.t.Helper()
	deadline := time.Now().Add(wait)
	timer := time.AfterFunc(wait, func() { n.cond.Broadcast() })
	defer timer.Stop()
	n.mu.Lock()
	defer n.mu.Unlock()
	for {
		for i, l := range n.lines {
			if rest, ok := strings.CutPrefix(l, prefix); ok {
				n.lines = append(n.lines[:i:i], n.lines[i+1:]...)
				return strings.TrimSpace(rest)
			}
		}
		if n.done {
			n.t.Fatalf("the peer ended while waiting for %q (lines %q)", prefix, n.lines)
		}
		if time.Now().After(deadline) {
			n.t.Fatalf("no %q from the peer within %v (lines %q)", prefix, wait, n.lines)
		}
		n.cond.Wait()
	}
}

func (n *labNet) close() {
	if n.cmd == nil || n.cmd.Process == nil {
		return
	}
	_, _ = fmt.Fprintln(n.in, "quit")
	_ = n.in.Close()
	done := make(chan struct{})
	go func() { _ = n.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = n.cmd.Process.Kill()
		<-done
	}
}

// ── the peer ────────────────────────────────────────────────────────────

// TestLabPeer is the peer of a labNet: the test binary run again in a new
// network namespace. It does nothing unless WAFIO_LAB_PEER=1.
func TestLabPeer(t *testing.T) {
	if os.Getenv(labPeerEnv) != "1" {
		t.Skip("run by the lab scenarios as their peer")
	}
	peer := &labPeer{out: os.Stdout}
	peer.run(t)
}

type labPeer struct {
	mu  sync.Mutex
	out io.Writer
}

func (p *labPeer) say(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, _ = fmt.Fprintf(p.out, "LAB "+format+"\n", args...)
}

func (p *labPeer) run(t *testing.T) {
	in := bufio.NewReader(os.Stdin)
	if line, err := in.ReadString('\n'); err != nil || strings.TrimSpace(line) != "go" {
		t.Fatalf("expected go, got %q (%v)", line, err)
	}
	ifName := os.Getenv(labIfEnv)
	var link netlink.Link
	for i := 0; i < 100; i++ {
		var err error
		if link, err = netlink.LinkByName(ifName); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if link == nil {
		t.Fatalf("interface %s never arrived", ifName)
	}
	for _, a := range strings.Split(os.Getenv(labAddrEnv), ",") {
		ipn, err := netlink.ParseAddr(a)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(link, ipn); err != nil {
			t.Fatal(err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	if lo, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(lo)
	}
	p.say("ready")
	for {
		line, err := in.ReadString('\n')
		f := strings.Fields(line)
		if len(f) == 0 {
			if err != nil {
				return
			}
			continue
		}
		switch f[0] {
		case "push":
			go p.push(f[1])
		case "pushnow":
			p.pushNow()
		case "legit":
			go p.legit(f[1], atoi(f[2]), atoi(f[3]), f[4])
		case "flood":
			go p.flood(f[1], f[2], atoi(f[3]), atoi(f[4]), atoi(f[5]))
		case "abuse":
			go p.abuse(f[1], f[2], f[3], atoi(f[4]), atoi(f[5]))
		case "probe":
			go p.probe(f[1], f[2])
		case "quit":
			return
		}
	}
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

// push listens on addr and keeps every accepted connection: pushnow sends on
// all of them. The peer is the sending side only; it reads nothing.
var (
	pushMu    sync.Mutex
	pushConns []net.Conn
)

func (p *labPeer) push(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		p.say("push-error %v", err)
		return
	}
	p.say("push-listening")
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		pushMu.Lock()
		pushConns = append(pushConns, c)
		pushMu.Unlock()
		p.say("push-accepted")
	}
}

func (p *labPeer) pushNow() {
	pushMu.Lock()
	defer pushMu.Unlock()
	sent := 0
	for _, c := range pushConns {
		if _, err := c.Write([]byte("push\n")); err == nil {
			sent++
		}
	}
	p.say("pushed %d", sent)
}

// legit loops requests (connect, "ping", read "pong") from the source address
// src for ms milliseconds, one every every milliseconds, and reports how many
// succeeded.
func (p *labPeer) legit(dst string, ms, every int, src string) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
	ok, fail := 0, 0
	end := time.Now().Add(time.Duration(ms) * time.Millisecond)
	next := time.Now()
	for time.Now().Before(end) {
		if request(&d, dst) {
			ok++
		} else {
			fail++
		}
		next = next.Add(time.Duration(every) * time.Millisecond)
		time.Sleep(time.Until(next))
	}
	p.say("legit ok=%d fail=%d", ok, fail)
}

func request(d *net.Dialer, dst string) bool {
	c, err := d.Dial("tcp", dst)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping\n")); err != nil {
		return false
	}
	buf := make([]byte, 5)
	_, err = io.ReadFull(c, buf)
	return err == nil && string(buf) == "pong\n"
}

// probe makes one connection from the source address and reports whether it
// worked.
func (p *labPeer) probe(dst, src string) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
	if request(&d, dst) {
		p.say("probe ok")
	} else {
		p.say("probe fail")
	}
}

// flood sends count packets of one kind, each from a source address of its
// own (30.a.b.c, counted up from base), at about pps packets a second. Kinds:
// syn and scan send a SYN, ack an ACK; scan to a port of its own.
func (p *labPeer) flood(kind, dst string, count, pps, base int) {
	sent := p.rawSend(kind, dst, count, pps, func(i int) [4]byte {
		n := base + i
		return [4]byte{30, byte(n >> 16), byte(n >> 8), byte(n)}
	})
	p.say("flood sent=%d", sent)
}

// abuse sends count packets of one kind from the one source address src: an
// abuser that is tracked.
func (p *labPeer) abuse(kind, dst, src string, count, pps int) {
	a := netip.MustParseAddr(src).As4()
	sent := p.rawSend(kind, dst, count, pps, func(int) [4]byte { return a })
	p.say("abuse sent=%d", sent)
}

// rawSend returns how many packets the kernel took.
func (p *labPeer) rawSend(kind, dst string, count, pps int, src func(i int) [4]byte) int {
	ap := netip.MustParseAddrPort(dst)
	to := ap.Addr().As4()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		p.say("raw-error %v", err)
		return 0
	}
	defer unix.Close(fd)
	sent := 0
	sa := &unix.SockaddrInet4{Addr: to}
	flags := byte(0x02)
	if kind == "ack" {
		flags = 0x10
	}
	start := time.Now()
	for i := 0; i < count; i++ {
		port := ap.Port()
		if kind == "scan" {
			port = uint16(1000 + i%2000)
		}
		pkt := rawTCP(src(i), to, uint16(40000+i%20000), port, flags)
		// A full device queue refuses a packet; the sender goes on.
		if err := unix.Sendto(fd, pkt, 0, sa); err == nil {
			sent++
		}
		if i%100 == 99 && pps > 0 {
			if ahead := time.Duration(i+1)*time.Second/time.Duration(pps) - time.Since(start); ahead > 0 {
				time.Sleep(ahead)
			}
		}
	}
	return sent
}

// rawTCP is an IPv4 TCP packet without a payload. The kernel fills the IP
// header checksum and length; the TCP checksum stays zero, which XDP does not
// read.
func rawTCP(src, dst [4]byte, sport, dport uint16, flags byte) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	p[8] = 64
	p[9] = unix.IPPROTO_TCP
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	p[32] = 5 << 4
	p[33] = flags
	binary.BigEndian.PutUint16(p[34:36], 1024)
	return p
}
