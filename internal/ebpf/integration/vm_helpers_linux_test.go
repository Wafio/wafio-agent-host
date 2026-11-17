//go:build linux

package integration

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

// vmScenariosEnabled reports whether the VM scenarios were asked for. They
// change the firewall of the machine they run on and are meant only for the
// disposable CI VM (build/vm-test.sh); every test skips first otherwise.
func vmScenariosEnabled() bool { return os.Getenv("WAFIO_EBPF_VM_SCENARIOS") == "1" }

// sshSession is the SSH_CONNECTION of the session that runs the test:
// "client-ip client-port server-ip server-port".
type sshSession struct {
	client netip.AddrPort
	server netip.AddrPort
}

func parseSSHConnection(v string) (sshSession, error) {
	f := strings.Fields(v)
	if len(f) != 4 {
		return sshSession{}, fmt.Errorf("SSH_CONNECTION %q: want 4 fields", v)
	}
	var s sshSession
	for i, dst := range []*netip.AddrPort{&s.client, &s.server} {
		addr, err := netip.ParseAddr(f[i*2])
		if err != nil {
			return sshSession{}, err
		}
		port, err := strconv.ParseUint(f[i*2+1], 10, 16)
		if err != nil {
			return sshSession{}, err
		}
		*dst = netip.AddrPortFrom(addr.Unmap(), uint16(port))
	}
	return s, nil
}

// vmEnv is what every scenario needs from the VM.
type vmEnv struct {
	bpfDir string
	iface  string
	peer   netip.Addr
	ssh    sshSession
}

// newVMEnv skips unless the scenarios are enabled and fails when the VM does
// not look like the CI VM (no root, no objects, no SSH session to protect).
func newVMEnv(t *testing.T) *vmEnv {
	t.Helper()
	if !vmScenariosEnabled() {
		t.Skip("VM scenarios only (WAFIO_EBPF_VM_SCENARIOS=1, run by build/vm-test.sh)")
	}
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if os.Geteuid() != 0 || dir == "" {
		t.Fatal("root and WAFIO_TEST_BPF_DIR required")
	}
	// Kernels before 5.11 charge BPF maps to RLIMIT_MEMLOCK: without this a
	// map create fails with EPERM (production: LimitMEMLOCK=infinity in the
	// unit, and the host agent raises it itself).
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	raw := os.Getenv("SSH_CONNECTION")
	if raw == "" {
		t.Fatal("SSH_CONNECTION missing: the scenarios protect the SSH session they run in")
	}
	session, err := parseSSHConnection(raw)
	if err != nil {
		t.Fatal(err)
	}
	iface, gw, err := defaultRoute("/proc/net/route")
	if err != nil {
		t.Fatal(err)
	}
	peer := gw
	if o := os.Getenv("WAFIO_VM_PEER"); o != "" {
		if peer, err = netip.ParseAddr(o); err != nil {
			t.Fatalf("WAFIO_VM_PEER: %v", err)
		}
	}
	t.Logf("kernel=%s iface=%s peer=%s ssh=%s->%s", kernelRelease(), iface, peer, session.client, session.server)
	return &vmEnv{bpfDir: dir, iface: iface, peer: peer, ssh: session}
}

// defaultRoute returns the interface and IPv4 gateway of the first default
// route in /proc/net/route. The gateway is the QEMU user-mode host alias.
func defaultRoute(path string) (string, netip.Addr, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", netip.Addr{}, err
	}
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x2 == 0 { // RTF_GATEWAY
			continue
		}
		gw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		return f[0], netip.AddrFrom4([4]byte{byte(gw), byte(gw >> 8), byte(gw >> 16), byte(gw >> 24)}), nil
	}
	return "", netip.Addr{}, errors.New("no default route in " + path)
}

func (e *vmEnv) pinPath() string { return fmt.Sprintf("/sys/fs/bpf/wafio-vmtest-%d", os.Getpid()) }

func (e *vmEnv) peerAddr(port int) string {
	return net.JoinHostPort(e.peer.String(), strconv.Itoa(port))
}

// ── established sessions ────────────────────────────────────────────────

// procTCPAddr renders an address the way /proc/net/tcp does (the address as
// a host-order word, so the bytes come reversed).
func procTCPAddr(ap netip.AddrPort, v6file bool) string {
	b := ap.Addr().As4()
	word := fmt.Sprintf("%02X%02X%02X%02X", b[3], b[2], b[1], b[0])
	if v6file {
		word = "0000000000000000FFFF0000" + word
	}
	return fmt.Sprintf("%s:%04X", word, ap.Port())
}

// sshRow reports the state and send-queue length of the SSH session in
// /proc/net/tcp and /proc/net/tcp6 (an IPv4 session on a dual-stack listener
// shows up there as a mapped address).
func sshRow(s sshSession) (state string, txQueue uint64, ok bool) {
	for _, src := range []struct {
		path string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		data, err := os.ReadFile(src.path)
		if err != nil {
			continue
		}
		local, remote := procTCPAddr(s.server, src.v6), procTCPAddr(s.client, src.v6)
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 5 || f[1] != local || f[2] != remote {
				continue
			}
			tx, _, _ := strings.Cut(f[4], ":")
			n, err := strconv.ParseUint(tx, 16, 64)
			if err != nil {
				continue
			}
			return f[3], n, true
		}
	}
	return "", 0, false
}

// sshAlive fails the test unless the SSH session running it is established
// and its send queue drains: the -test.v output streams over that session,
// so a session the firewall cut would not drain.
func (e *vmEnv) sshAlive(t *testing.T, label string) {
	t.Helper()
	e.sshAliveDiag(t, label, nil)
}

// sshAliveDiag is sshAlive that calls diag, when set, before it fails: the
// evidence has to be logged before t.Fatalf ends the test.
func (e *vmEnv) sshAliveDiag(t *testing.T, label string, diag func()) {
	t.Helper()
	var last string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		state, tx, ok := sshRow(e.ssh)
		last = fmt.Sprintf("found=%v state=%s tx_queue=%d", ok, state, tx)
		if ok && state == "01" && tx == 0 {
			t.Logf("%s: ssh session alive (%s)", label, last)
			return
		}
	}
	if diag != nil {
		diag()
	}
	t.Fatalf("%s: ssh session lost or stalled (%s)", label, last)
}

// sshTracking reads the conntrack entries of the SSH session: inbound is the
// client → server entry (XDP, or TC adopting a mid-flow ACK of a listened
// port), hostOpened the server → client one, which only TC egress writes and
// always as CONN_OUTBOUND (a session that has one was taken for a flow
// the host opened and is under the egress port policy).
func (e *vmEnv) sshTracking(m *ebpf.Manager) (inbound, hostOpened bool, entries []string, err error) {
	conns, err := m.ListConnections(4096)
	if err != nil {
		return false, false, nil, err
	}
	client, server := e.ssh.client.Addr().Unmap().String(), e.ssh.server.Addr().Unmap().String()
	for _, c := range conns {
		fwd := c.SrcIP == client && c.SrcPort == e.ssh.client.Port() && c.DstIP == server && c.DstPort == e.ssh.server.Port()
		rev := c.SrcIP == server && c.SrcPort == e.ssh.server.Port() && c.DstIP == client && c.DstPort == e.ssh.client.Port()
		if !fwd && !rev {
			continue
		}
		inbound = inbound || fwd
		hostOpened = hostOpened || rev
		entries = append(entries, fmt.Sprintf("%s:%d -> %s:%d %s %s packets=%d", c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, c.Proto, c.State, c.Packets))
	}
	return inbound, hostOpened, entries, nil
}

// logSSHDiagnostics logs what a lost SSH session needs to be explained: its
// conntrack entries, the drop counters and the filters on the interface.
func (e *vmEnv) logSSHDiagnostics(t *testing.T, m *ebpf.Manager, label string) {
	t.Helper()
	inbound, hostOpened, entries, err := e.sshTracking(m)
	t.Logf("%s: ssh conntrack inbound=%v host_opened=%v err=%v entries=%q", label, inbound, hostOpened, err, entries)
	if mt, err := m.ReadMetrics(); err == nil {
		t.Logf("%s: PortPolicyDrops=%d EgressIPDrops=%d", label, mt.PortPolicyDrops, mt.EgressIPDrops)
	}
	if _, err := exec.LookPath("tc"); err == nil {
		out, err := exec.Command("tc", "filter", "show", "dev", e.iface, "egress").CombinedOutput()
		t.Logf("%s: tc filter show dev %s egress (err=%v):\n%s", label, e.iface, err, out)
	}
}

// requireSSHInbound fails when the SSH session is not tracked as an inbound
// flow: entry client → server present, none server → client. The
// entry appears with the first packet after the attach (the session carries
// this test's own output), so it is polled for a few seconds.
func (e *vmEnv) requireSSHInbound(t *testing.T, m *ebpf.Manager, label string) {
	t.Helper()
	var inbound, hostOpened bool
	var entries []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		var err error
		if inbound, hostOpened, entries, err = e.sshTracking(m); err != nil {
			t.Fatalf("%s: list connections: %v", label, err)
		}
		if hostOpened || inbound {
			break
		}
		t.Logf("%s: waiting for the ssh conntrack entry", label) // also puts a packet on the session
	}
	if !inbound || hostOpened {
		e.logSSHDiagnostics(t, m, label)
		t.Fatalf("%s: ssh session tracked wrongly: inbound=%v host_opened=%v entries=%q", label, inbound, hostOpened, entries)
	}
	t.Logf("%s: ssh session tracked as inbound (%q)", label, entries)
}

// ── the runner peer ─────────────────────────────────────────────────────

func dialTCP(addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
}

// pinger keeps one VM-opened connection busy: PING every 250 ms. The
// connection is driven from the VM on purpose. After a manager restart the
// conntrack map is empty and only a mid-flow ACK sent by the VM re-tracks
// the flow; a flow driven from the peer side would stall by design.
type pinger struct {
	conn   net.Conn
	stop   chan struct{}
	done   chan struct{}
	recv   atomic.Uint64
	failed atomic.Pointer[string]
}

func startPinger(t *testing.T, addr string) *pinger {
	t.Helper()
	conn, err := dialTCP(addr, 5*time.Second)
	if err != nil {
		t.Fatalf("pinger dial %s: %v", addr, err)
	}
	p := &pinger{conn: conn, stop: make(chan struct{}), done: make(chan struct{})}
	go p.run()
	t.Cleanup(p.close)
	return p
}

func (p *pinger) fail(msg string) {
	select {
	case <-p.stop:
		return
	default:
	}
	p.failed.CompareAndSwap(nil, &msg)
}

func (p *pinger) run() {
	defer close(p.done)
	r := bufio.NewReader(p.conn)
	for n := 1; ; n++ {
		select {
		case <-p.stop:
			return
		default:
		}
		_ = p.conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprintf(p.conn, "PING %d\n", n); err != nil {
			p.fail(fmt.Sprintf("PING %d: %v", n, err))
			return
		}
		line, err := r.ReadString('\n')
		if err != nil {
			p.fail(fmt.Sprintf("no PONG %d within 5s: %v", n, err))
			return
		}
		if strings.TrimSpace(line) != fmt.Sprintf("PONG %d", n) {
			p.fail(fmt.Sprintf("PING %d answered %q", n, line))
			return
		}
		p.recv.Add(1)
		select {
		case <-p.stop:
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (p *pinger) close() {
	select {
	case <-p.stop:
		return
	default:
	}
	close(p.stop)
	_ = p.conn.Close()
	<-p.done
}

// expectAlive fails the test when the connection broke, or when it does not
// carry at least two more round trips within 8 s.
func (p *pinger) expectAlive(t *testing.T, label string) {
	t.Helper()
	base := p.recv.Load()
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if msg := p.failed.Load(); msg != nil {
			t.Fatalf("%s: long-lived connection broke: %s", label, *msg)
		}
		if p.recv.Load() >= base+2 {
			t.Logf("%s: long-lived connection alive (%d round trips)", label, p.recv.Load())
			return
		}
	}
	msg := "no failure recorded"
	if m := p.failed.Load(); m != nil {
		msg = *m
	}
	t.Fatalf("%s: long-lived connection made no progress in 8s (%s)", label, msg)
}

// peerProbe asks the runner to dial the forwarded 7002 and reports whether
// the VM listener answered. It uses a fresh connection to the peer.
func (e *vmEnv) peerProbe(t *testing.T) bool {
	t.Helper()
	ok, err := e.peerProbeErr()
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// peerProbeErr is peerProbe without the test handle, so a goroutine can run
// it (t.Fatal is for the test goroutine only). The control connection lasts
// one probe: the VM closes it first, so under ingress Deny All the peer's
// ACK/FIN of that teardown, and every resend of the VM's FIN, count as port
// policy drops. Anything that reads PortPolicyDrops must use probeConn.
func (e *vmEnv) peerProbeErr() (bool, error) {
	pc, err := e.openProbeConn()
	if err != nil {
		return false, err
	}
	defer pc.close()
	return pc.probe()
}

// probeConn is one long-lived control connection to the peer, opened by the
// VM (so its reply path is an outbound flow's) and reused for any number of
// probes. A measurement of PortPolicyDrops reuses one so no teardown packet of
// a closed control connection is counted; it is closed only after the counter
// is read.
type probeConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func (e *vmEnv) openProbeConn() (*probeConn, error) {
	conn, err := dialTCP(e.peerAddr(vmPeerPort0), 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("probe: dial peer: %w", err)
	}
	return &probeConn{conn: conn, r: bufio.NewReader(conn)}, nil
}

func (p *probeConn) close() { _ = p.conn.Close() }

// probe asks the runner to dial the forwarded 7002 and reports whether the VM
// listener answered.
func (p *probeConn) probe() (bool, error) {
	_ = p.conn.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := fmt.Fprintf(p.conn, "PROBE %d\n", vmProbePort); err != nil {
		return false, fmt.Errorf("probe: %w", err)
	}
	line, err := p.r.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("probe: %w", err)
	}
	switch strings.TrimSpace(line) {
	case "PROBE ok":
		return true, nil
	case "PROBE fail":
		return false, nil
	}
	return false, fmt.Errorf("probe: unexpected answer %q", line)
}

// udpEcho sends one datagram to the peer's UDP echo and reports whether it
// came back within wait.
func (e *vmEnv) udpEcho(t *testing.T, wait time.Duration) bool {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "udp4", e.peerAddr(vmPeerDNS))
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("wafio-vm-dns")); err != nil {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	return err == nil && string(buf[:n]) == "wafio-vm-dns"
}

// ── firewall through the real Manager ───────────────────────────────────

// fwState is one desired firewall state, applied like the agent applies a
// gRPC snapshot.
type fwState struct {
	cfg   ebpf.FullConfigAPI
	pp    ebpf.PortPolicyConfigAPI
	rules []ebpf.PortPolicyAPI
}

func allowRule(port uint16, proto, dir string) ebpf.PortPolicyAPI {
	return ebpf.PortPolicyAPI{Port: port, Proto: proto, Direction: dir, Action: "allow"}
}

// enforcingConfig is DefaultFullConfigAPI with enforcement on: the default
// is monitor-only.
func enforcingConfig() ebpf.FullConfigAPI {
	cfg := ebpf.DefaultFullConfigAPI()
	cfg.Global.MonitorOnly = false
	cfg.Global.EnableConntrack = true
	return cfg
}

// applyStateE mirrors applyEBPFState (internal/agent/ebpf_grpc_stream.go):
// the lockout guard first, then the full config, then the port rules swapped
// in place (ReplacePortPolicies), and the deny switch last. The agent
// function is unexported and works on package globals, so it is repeated here
// in the same order. It returns the guard's warnings.
func applyStateE(m *ebpf.Manager, st fwState) ([]ebpf.FirewallWarning, error) {
	defer ebpf.LockFirewallWrites()()
	env := m.HostFirewallEnv()
	warnings, err := ebpf.ValidateHostFirewall(ebpf.FirewallSafetyInput{
		Config:               &st.cfg,
		PortPolicyConfig:     &st.pp,
		PortPolicies:         st.rules,
		SSHPorts:             ebpf.DetectSSHDPorts(),
		ControlPlanePort:     env.ControlPlanePort,
		ControlPlaneUnpinned: env.ControlPlaneUnpinned,
	}, env.Exemptions)
	if err != nil {
		return nil, err
	}
	if err := m.UpdateFullConfig(st.cfg); err != nil {
		return nil, err
	}
	// Rules are swapped without removing one that stays.
	if err := m.ReplacePortPolicies(st.rules); err != nil {
		return nil, err
	}
	// The rule table lands before the deny switch.
	if err := m.UpdatePortPolicyConfig(st.pp); err != nil {
		return nil, err
	}
	return warnings, nil
}

func applyState(t *testing.T, m *ebpf.Manager, st fwState) []ebpf.FirewallWarning {
	t.Helper()
	warnings, err := applyStateE(m, st)
	if err != nil {
		t.Fatalf("apply state: %v", err)
	}
	for _, w := range warnings {
		t.Logf("lockout check warning %s", w.Code)
	}
	return warnings
}

func hasWarning(ws []ebpf.FirewallWarning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}

// vmFirewall is a running Manager on the VM primary interface.
type vmFirewall struct {
	*ebpf.Manager
	cancel context.CancelFunc
}

// startFirewall starts a Manager (generic XDP, private pin directory) and
// registers its Stop for cleanup. The pin directory must not exist: it is
// removed by Stop, and a leftover one means a crashed earlier run.
func (e *vmEnv) startFirewall(t *testing.T) *vmFirewall {
	t.Helper()
	pin := e.pinPath()
	if _, err := os.Stat(pin); err == nil {
		t.Fatalf("pin path %s already exists", pin)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := ebpf.NewManager(ebpf.ManagerConfig{
		Interface:     e.iface,
		XDPObjectPath: filepath.Join(e.bpfDir, "wafio_xdp.o"),
		TCObjectPath:  filepath.Join(e.bpfDir, "wafio_tc.o"),
		PinPath:       pin,
		XDPMode:       ebpf.XDPModeSKB,
		MetricsPollMs: 250,
	}, nil)
	fw := &vmFirewall{Manager: m, cancel: cancel}
	if err := m.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start manager: %v", err)
	}
	t.Cleanup(func() { _ = fw.stop() })
	if st := m.Status(); !st.XDPAttached || !st.TCIngress || !st.TCEgress || !st.LockoutExemptions {
		t.Fatalf("manager attached incompletely: %+v", st)
	}
	return fw
}

func (f *vmFirewall) stop() error {
	f.cancel()
	return f.Stop()
}

// portPolicyDrops reads the drop counter after the metrics poller (250 ms)
// had time to publish.
func portPolicyDrops(t *testing.T, m *ebpf.Manager) uint64 {
	t.Helper()
	time.Sleep(700 * time.Millisecond)
	mt, err := m.ReadMetrics()
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	return mt.PortPolicyDrops
}

// dropTotals sums every drop counter XDP and TC write to the shared metrics
// map. TC drops (egress SYN-ACK, egress IP, port policy on TC) do not raise
// DroppedPackets, so that counter alone would hide them.
type dropTotals struct {
	sum       uint64
	breakdown string
}

func readDropTotals(t *testing.T, m *ebpf.Manager) dropTotals {
	t.Helper()
	mt, err := m.ReadMetrics()
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	sum := mt.DroppedPackets + mt.RatelimitedPackets + mt.SynfloodDrops + mt.BlocklistDrops +
		mt.GeoblockDrops + mt.PortScanDrops + mt.PortPolicyDrops + mt.EgressIPDrops +
		mt.SynPressureDrops + mt.StateTableFull + mt.PacketParseFailures
	return dropTotals{sum: sum, breakdown: fmt.Sprintf(
		"dropped=%d ratelimited=%d synflood=%d blocklist=%d geoblock=%d portscan=%d portpolicy=%d egress_ip=%d syn_pressure=%d state_full=%d parse_fail=%d",
		mt.DroppedPackets, mt.RatelimitedPackets, mt.SynfloodDrops, mt.BlocklistDrops, mt.GeoblockDrops,
		mt.PortScanDrops, mt.PortPolicyDrops, mt.EgressIPDrops, mt.SynPressureDrops, mt.StateTableFull, mt.PacketParseFailures)}
}

// fdCensus logs how many descriptors this process holds and by kind, plus the
// soft limit: the evidence for "too many open files" between scenarios.
func fdCensus(t *testing.T, label string) {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Logf("%s: fd census: %v", label, err)
		return
	}
	kinds := map[string]int{}
	for _, e := range ents {
		tgt, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(tgt, "socket:"):
			kinds["socket"]++
		case strings.HasPrefix(tgt, "anon_inode:"):
			kinds[tgt]++
		case strings.HasPrefix(tgt, "pipe:"):
			kinds["pipe"]++
		default:
			kinds["file"]++
		}
	}
	var rl syscall.Rlimit
	_ = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl)
	t.Logf("%s: fd census: %d open (soft limit %d, hard %d) %v", label, len(ents), rl.Cur, rl.Max, kinds)
}

// vmWarn records an environment limitation that made a check run reduced:
// logged, and appended to WAFIO_VM_WARN_FILE for the runner-side job summary.
func vmWarn(t *testing.T, msg string) {
	t.Helper()
	t.Logf("WARNING: %s", msg)
	path := os.Getenv("WAFIO_VM_WARN_FILE")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s: %s: %s\n", strings.TrimSpace(kernelRelease()), t.Name(), msg)
}

// waitPortPolicyDropsFlat waits until the drop counter stops moving (two reads
// a second apart within 10 s) and returns it: background noise, such as a
// retried SYN to a port the previous state refused, must not be counted
// against the phase that follows.
func waitPortPolicyDropsFlat(t *testing.T, m *ebpf.Manager) uint64 {
	t.Helper()
	prev := portPolicyDrops(t, m)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		time.Sleep(time.Second)
		cur := portPolicyDrops(t, m)
		if cur == prev {
			return cur
		}
		prev = cur
	}
	t.Fatalf("PortPolicyDrops still moving after 10 s (last %d)", prev)
	return prev
}

func runOut(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
	return string(out)
}

// assertFirewallGone checks that Stop left nothing on the interface: no XDP
// program, no wafio TC filter (kernels below 6.6 use a netlink filter that
// outlives a crashed process) and no pin directory.
func (e *vmEnv) assertFirewallGone(t *testing.T) {
	t.Helper()
	if out := runOut(t, "ip", "-d", "link", "show", "dev", e.iface); strings.Contains(out, "xdp") {
		t.Errorf("XDP still attached to %s:\n%s", e.iface, out)
	}
	if _, err := exec.LookPath("tc"); err == nil {
		for _, dir := range []string{"ingress", "egress"} {
			if out := runOut(t, "tc", "filter", "show", "dev", e.iface, dir); strings.Contains(strings.ToLower(out), "wafio") {
				t.Errorf("TC %s filter still present:\n%s", dir, out)
			}
		}
	} else {
		t.Log("tc not installed: TC filter cleanup not checked")
	}
	if _, err := os.Stat(e.pinPath()); !os.IsNotExist(err) {
		t.Errorf("pin directory %s not removed (stat err=%v)", e.pinPath(), err)
	}
}
