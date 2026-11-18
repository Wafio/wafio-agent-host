//go:build linux

package integration

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// The scenarios below replace the earlier "console VM" lockout checks. They
// run inside the disposable CI VM (build/vm-test.sh), over the SSH session
// the job itself uses: if a scenario cuts that session, the job fails, which
// is the signal. Every test skips unless WAFIO_EBPF_VM_SCENARIOS=1.

// vmSwapProbeCap bounds the probes of the swap loop (see the loop).
const vmSwapProbeCap = 300

func vmTCPPort(p uint16) string { return strconv.Itoa(int(p)) }

// TestVMScenarioIngressDenyRestart applies ingress Deny All with an allow for
// the SSH port through the real Manager, pushes a second policy, restarts the
// manager and checks after every step that the SSH session and a long-lived
// VM-opened connection survive.
func TestVMScenarioIngressDenyRestart(t *testing.T) {
	env := newVMEnv(t)
	fdCensus(t, "ingress scenario start")

	// A service inside the VM that the runner reaches through the QEMU port
	// forward (fresh inbound SYNs, so it is governed by the ingress rules).
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", fmt.Sprintf("0.0.0.0:%d", vmProbePort))
	if err != nil {
		t.Fatal(err)
	}
	var (
		connsMu sync.Mutex
		conns   []net.Conn
	)
	t.Cleanup(func() {
		_ = ln.Close()
		connsMu.Lock()
		defer connsMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				// Only a closed listener ends the loop: any other error
				// (EMFILE, a reset in the backlog) must not kill the
				// listener, or every later probe times out.
				if errors.Is(err, net.ErrClosed) {
					return
				}
				t.Logf("echo listener: accept: %v (continuing) at %s", err, time.Now().UTC().Format("15:04:05.000"))
				time.Sleep(50 * time.Millisecond)
				continue
			}
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
			go func() {
				defer c.Close()
				// A deadline per connection so a stuck one cannot hold its fd.
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	pg := startPinger(t, env.peerAddr(vmPeerPort0))
	pg.expectAlive(t, "before attach")
	ok := false
	for i := 0; i < 5 && !ok; i++ {
		if ok = env.peerProbe(t); !ok {
			time.Sleep(time.Second)
		}
	}
	if !ok {
		t.Fatal("baseline probe of 7002 failed before any firewall: is the QEMU port forward 7002:7002 configured?")
	}
	env.sshAlive(t, "before attach")

	sshPort := env.ssh.server.Port()
	stateA := fwState{
		cfg:   enforcingConfig(),
		pp:    ebpf.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"},
		rules: []ebpf.PortPolicyAPI{allowRule(sshPort, "tcp", "ingress")},
	}
	stateB := stateA
	stateB.rules = []ebpf.PortPolicyAPI{
		allowRule(sshPort, "tcp", "ingress"),
		allowRule(vmProbePort, "tcp", "ingress"),
	}

	fw := env.startFirewall(t)
	env.sshAlive(t, "after attach")
	env.requireSSHInbound(t, fw.Manager, "after attach")

	// One control connection carries every probe from here to the counter
	// reads below. Opening and closing one per probe would put the teardown of
	// each (the peer's ACK/FIN of a flow whose outbound entry the VM's FIN
	// just deleted, plus every resend of that FIN) into PortPolicyDrops under
	// ingress Deny All, whether or not the swap works.
	pc, err := env.openProbeConn()
	if err != nil {
		t.Fatal(err)
	}
	pcOpen := true
	closePC := func() {
		if pcOpen {
			pcOpen = false
			pc.close()
		}
	}
	t.Cleanup(closePC)

	// The swap: pushing a policy must not open a window in which a rule that
	// stays is missing. State B first, then 20 pushes alternating B
	// and B plus an unrelated allow while the runner keeps dialling 7002:
	// every probe passes and no packet is dropped by the port policy.
	stateB2 := stateB
	stateB2.rules = append(append([]ebpf.PortPolicyAPI{}, stateB.rules...), allowRule(9, "tcp", "ingress"))
	applyState(t, fw.Manager, stateB)
	if ok, err := pc.probe(); err != nil || !ok {
		t.Fatalf("state B: 7002 unreachable after its allow rule was pushed (ok=%v err=%v)", ok, err)
	}
	dropsSwap := waitPortPolicyDropsFlat(t, fw.Manager)
	totalSwap := readDropTotals(t, fw.Manager)
	fdCensus(t, "swap loop start")
	var probes, failed atomic.Int64
	var firstErr atomic.Pointer[string]
	// Timeline evidence: every failed probe (index, offset from the first
	// push, duration, error) and every push (offset, apply duration), so a
	// loss can be placed relative to the pushes. A kernel-level attach
	// transition would show as a failure aligned with a push; a listener or
	// resource problem shows as failures with no relation to the pushes.
	var (
		tlMu       sync.Mutex
		failEvents []string
		pushEvents []string
	)
	swapStart := time.Now()
	stopProbe := make(chan struct{})
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		for {
			select {
			case <-stopProbe:
				return
			default:
			}
			// Every probe is a forwarded connection, i.e. a descriptor in the
			// QEMU process on the runner: pace them and stop at the cap. The
			// pushes (20, each followed by new SYNs) keep their coverage.
			if probes.Load() >= vmSwapProbeCap {
				return
			}
			time.Sleep(10 * time.Millisecond)
			began := time.Now()
			ok, err := pc.probe()
			dur := time.Since(began)
			idx := probes.Load()
			record := func(msg string) {
				firstErr.CompareAndSwap(nil, &msg)
				failed.Add(1)
				tlMu.Lock()
				failEvents = append(failEvents, fmt.Sprintf("probe #%d at +%dms took %dms: %s", idx, began.Sub(swapStart).Milliseconds(), dur.Milliseconds(), msg))
				tlMu.Unlock()
			}
			switch {
			case err != nil:
				record(err.Error())
			case !ok:
				record("probe to 7002 failed during a policy push (no answer from the VM listener)")
			}
			probes.Add(1)
		}
	}()
	for i := 0; i < 20 || probes.Load() < 10; i++ {
		if time.Since(swapStart) > 90*time.Second {
			break
		}
		st := stateB
		if i%2 == 1 {
			st = stateB2
		}
		pushBegan := time.Now()
		applyState(t, fw.Manager, st)
		tlMu.Lock()
		pushEvents = append(pushEvents, fmt.Sprintf("push %d at +%dms took %dms", i, pushBegan.Sub(swapStart).Milliseconds(), time.Since(pushBegan).Milliseconds()))
		tlMu.Unlock()
		time.Sleep(150 * time.Millisecond)
	}
	close(stopProbe)
	<-probeDone
	dropsAfterSwap := portPolicyDrops(t, fw.Manager)
	t.Logf("swap loop: %d probes, %d failed, PortPolicyDrops %d -> %d", probes.Load(), failed.Load(), dropsSwap, dropsAfterSwap)
	if probes.Load() < 10 {
		t.Fatalf("swap loop ran only %d probes, want at least 10", probes.Load())
	}
	totalAfterSwap := readDropTotals(t, fw.Manager)
	fdCensus(t, "swap loop end")
	tlMu.Lock()
	t.Logf("swap loop timeline: %d pushes, %d failed probes (swap loop lasted %dms)", len(pushEvents), len(failEvents), time.Since(swapStart).Milliseconds())
	for _, e := range pushEvents {
		t.Log("  " + e)
	}
	for _, e := range failEvents {
		t.Log("  FAIL " + e)
	}
	tlMu.Unlock()
	t.Logf("swap loop: drops (XDP+TC, all reasons) %d -> %d; before: %s; after: %s", totalSwap.sum, totalAfterSwap.sum, totalSwap.breakdown, totalAfterSwap.breakdown)
	if totalAfterSwap.sum != totalSwap.sum {
		t.Errorf("%d packets dropped (all reasons, XDP and TC) while rules were swapped (%d -> %d)", totalAfterSwap.sum-totalSwap.sum, totalSwap.sum, totalAfterSwap.sum)
	}
	if msg := firstErr.Load(); msg != nil {
		t.Fatalf("%d of %d probes failed during the swap loop: %s", failed.Load(), probes.Load(), *msg)
	}
	if dropsAfterSwap != dropsSwap {
		t.Fatalf("port policy dropped %d packets while rules were swapped (%d -> %d): a rule that stays went missing", dropsAfterSwap-dropsSwap, dropsSwap, dropsAfterSwap)
	}
	pg.expectAlive(t, "swap loop")
	env.sshAlive(t, "swap loop")
	env.requireSSHInbound(t, fw.Manager, "swap loop")

	// State A: SSH allowed, 7002 not. The probe must FAIL (negative control:
	// a firewall that is loaded but not enforcing would let it through).
	applyState(t, fw.Manager, stateA)
	pg.expectAlive(t, "state A")
	env.sshAlive(t, "state A")
	if ok, err := pc.probe(); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("state A: 7002 reachable although ingress Deny All has no rule for it: the firewall is not enforcing")
	}
	dropsA := portPolicyDrops(t, fw.Manager)
	t.Logf("state A: PortPolicyDrops %d -> %d", dropsAfterSwap, dropsA)
	if dropsA <= dropsAfterSwap {
		t.Errorf("state A: no port policy drop counted for the refused probe")
	}

	// Back to state B through the same apply path as the agent.
	applyState(t, fw.Manager, stateB)
	if ok, err := pc.probe(); err != nil || !ok {
		t.Fatalf("state B: 7002 still unreachable after its allow rule was pushed (ok=%v err=%v)", ok, err)
	}
	closePC()
	pg.expectAlive(t, "state B")
	env.sshAlive(t, "state B")

	// Agent restart: Stop removes the pins, so conntrack starts empty; only
	// the VM's mid-flow ACKs re-track the established flows.
	if err := fw.stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	pg.expectAlive(t, "manager stopped")
	env.sshAlive(t, "manager stopped")
	fw = env.startFirewall(t)
	applyState(t, fw.Manager, stateB)
	if !env.peerProbe(t) {
		t.Fatal("after restart: 7002 unreachable")
	}
	pg.expectAlive(t, "after restart")
	env.sshAlive(t, "after restart")
	env.requireSSHInbound(t, fw.Manager, "after restart")

	if err := fw.stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	env.assertFirewallGone(t)
	pg.expectAlive(t, "after final stop")
	env.sshAlive(t, "after final stop")
}

// TestVMScenarioEgressDenyControlPlane applies egress Deny All with the
// control-plane exemption pointed at the peer's 7000: an established
// connection to it survives, an ordinary outbound flow to 7001 is cut (egress
// policy applies in full to flows the host opened), and the DNS reply path
// follows the 53/udp rule.
func TestVMScenarioEgressDenyControlPlane(t *testing.T) {
	env := newVMEnv(t)
	fdCensus(t, "egress scenario start")

	pg := startPinger(t, env.peerAddr(vmPeerPort0))
	pg.expectAlive(t, "before attach")
	other := startPinger(t, env.peerAddr(vmPeerPort1))
	other.expectAlive(t, "before attach (7001)")
	// UDP through slirp is not reliable before any firewall exists: an
	// environment check, retried; without it the DNS sub-check is skipped
	// (the TCP control-plane and SSH assertions stay mandatory).
	udpOK := false
	for i := 0; i < 5 && !udpOK; i++ {
		udpOK = env.udpEcho(t, 3*time.Second)
	}
	if !udpOK {
		vmWarn(t, "no UDP echo from the peer on 53 before any firewall after 5 tries (UDP to the QEMU gateway is not reachable in this VM): the DNS sub-checks are SKIPPED")
	}
	env.sshAlive(t, "before attach")

	sshPort := env.ssh.server.Port()
	withDNS := fwState{
		cfg: enforcingConfig(),
		pp:  ebpf.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "deny"},
		rules: []ebpf.PortPolicyAPI{
			allowRule(sshPort, "tcp", "ingress"),
			allowRule(vmPeerDNS, "udp", "egress"),
		},
	}
	withoutDNS := withDNS
	withoutDNS.rules = []ebpf.PortPolicyAPI{allowRule(sshPort, "tcp", "ingress")}

	fdCensus(t, "egress scenario before start")
	fw := env.startFirewall(t)
	env.sshAlive(t, "after attach")
	env.requireSSHInbound(t, fw.Manager, "after attach")
	fw.ExpectControlPlane()
	cp := netip.AddrPortFrom(env.peer, vmPeerPort0)
	if err := fw.SetControlPlaneEndpoints([]netip.AddrPort{cp}); err != nil {
		t.Fatalf("pin control plane endpoint %s: %v", cp, err)
	}

	warnings := applyState(t, fw.Manager, withDNS)
	if !hasWarning(warnings, hostpolicy.WarnEgressControlPlaneRuleMissing) {
		t.Errorf("expected warning %s (no egress allow for the control-plane port), got %+v", hostpolicy.WarnEgressControlPlaneRuleMissing, warnings)
	}
	dropsBefore := portPolicyDrops(t, fw.Manager)

	pg.expectAlive(t, "egress deny (control-plane flow)")
	// The session must stay an inbound flow: a host-opened one would meet the
	// egress port policy with the client's ephemeral port as destination and
	// stall.
	env.sshAliveDiag(t, "egress deny", func() { env.logSSHDiagnostics(t, fw.Manager, "egress deny") })
	env.requireSSHInbound(t, fw.Manager, "egress deny")
	c, err := dialTCP(env.peerAddr(vmPeerPort0), 3*time.Second)
	if err != nil {
		t.Fatalf("new connection to the pinned control plane refused: %v", err)
	}
	_ = c.Close()

	// The 7001 flow was opened by this host: egress policy applies to it in
	// full, so it stops carrying data, and a new connection cannot open.
	base := other.recv.Load()
	time.Sleep(5 * time.Second)
	if got := other.recv.Load(); got > base+1 {
		t.Errorf("7001 flow still carries traffic under egress Deny All (%d -> %d): the firewall is not enforcing egress", base, got)
	}
	if c, err := dialTCP(env.peerAddr(vmPeerPort1), 3*time.Second); err == nil {
		_ = c.Close()
		t.Error("new connection to 7001 succeeded under egress Deny All")
	}

	// DNS: allowed by the 53/udp rule, and its reply comes back through the
	// ingress default deny by the tracked flow.
	if udpOK && !env.udpEcho(t, 3*time.Second) {
		t.Error("UDP echo on 53 lost although egress allows 53/udp")
	}

	// Without the 53 rule the query is dropped on egress.
	warnings = applyState(t, fw.Manager, withoutDNS)
	if !hasWarning(warnings, hostpolicy.WarnEgressDNSRuleMissing) {
		t.Errorf("expected warning %s, got %+v", hostpolicy.WarnEgressDNSRuleMissing, warnings)
	}
	if udpOK && env.udpEcho(t, 2*time.Second) {
		t.Error("UDP echo on 53 answered although the 53/udp allow rule was removed")
	}
	if dropsAfter := portPolicyDrops(t, fw.Manager); dropsAfter <= dropsBefore {
		t.Errorf("no port policy drop counted for the 7001 traffic and the refused DNS query (%d -> %d)", dropsBefore, dropsAfter)
	} else {
		t.Logf("PortPolicyDrops %d -> %d", dropsBefore, dropsAfter)
	}
	pg.expectAlive(t, "after DNS rule removal")
	env.sshAliveDiag(t, "after DNS rule removal", func() { env.logSSHDiagnostics(t, fw.Manager, "after DNS rule removal") })
	env.requireSSHInbound(t, fw.Manager, "after DNS rule removal")

	// The guard side: with the control plane not yet pinned, egress Deny All
	// without a DNS rule is refused (the control plane may need DNS).
	_, err = hostpolicy.ValidateFirewallSafety(ebpf.FirewallSafetyInput{
		Config:               &withoutDNS.cfg,
		PortPolicyConfig:     &withoutDNS.pp,
		PortPolicies:         withoutDNS.rules,
		SSHPorts:             []uint16{sshPort},
		ControlPlaneUnpinned: true,
	})
	if !errors.Is(err, hostpolicy.ErrEgressDenyUnpinned) {
		t.Errorf("unpinned control plane without a DNS rule: got %v, want ErrEgressDenyUnpinned", err)
	}

	if err := fw.stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	env.assertFirewallGone(t)
	env.sshAlive(t, "after stop")
}

// ── kill scenarios ──────────────────────────────────────────────────────

// TestVMKillFixtureChild is the process a kill policy targets: it reads the
// marker file for a few seconds, then exits 0. Only started by the scenario.
func TestVMKillFixtureChild(t *testing.T) {
	marker := os.Getenv("WAFIO_VM_KILL_FIXTURE")
	if marker == "" {
		t.Skip("subprocess fixture only")
	}
	until := time.Now().Add(8 * time.Second)
	for time.Now().Before(until) {
		if _, err := os.ReadFile(marker); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// procIdentity is a process as PID plus start time (field 22 of
// /proc/<pid>/stat), so a recycled PID is not mistaken for the original.
type procIdentity struct {
	pid   int
	start string
}

func readStart(pid int) (string, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", false
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return "", false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 { // state is field 3, starttime field 22: index 19 after ')'
		return "", false
	}
	return f[19], true
}

// sshdProcesses lists every sshd, sshd-session and sshd-auth process.
func sshdProcesses(t *testing.T) []procIdentity {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var out []procIdentity
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		switch strings.TrimSpace(string(comm)) {
		case "sshd", "sshd-session", "sshd-auth":
			if start, ok := readStart(pid); ok {
				out = append(out, procIdentity{pid, start})
			}
		}
	}
	return out
}

func requireSSHDIntact(t *testing.T, before []procIdentity, label string) {
	t.Helper()
	for _, p := range before {
		if start, ok := readStart(p.pid); !ok || start != p.start {
			t.Fatalf("%s: sshd process %d (start %s) is gone or replaced", label, p.pid, p.start)
		}
	}
}

// logKey identifies enforcement-log evidence by policy, process and action.
type logKey struct {
	policy uint32
	pid    uint32
	action string
}

type logEvidence struct {
	seen    int
	success bool
}

// logCollector drains the enforcement log continuously. A broad alert policy
// floods the log, so entries are reduced to (policy, pid, action) counts.
type logCollector struct {
	tm   *ebpf.TraceManager
	mu   sync.Mutex
	seen map[logKey]logEvidence
	stop chan struct{}
	done chan struct{}
}

func startLogCollector(tm *ebpf.TraceManager) *logCollector {
	c := &logCollector{tm: tm, seen: map[logKey]logEvidence{}, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		for {
			for _, e := range tm.DrainEnforcementLog(4096) {
				k := logKey{e.PolicyID, e.Event.PID, strings.ToLower(e.Action)}
				c.mu.Lock()
				ev := c.seen[k]
				ev.seen++
				ev.success = ev.success || e.Success
				c.seen[k] = ev
				c.mu.Unlock()
			}
			select {
			case <-c.stop:
				return
			case <-time.After(25 * time.Millisecond):
			}
		}
	}()
	return c
}

func (c *logCollector) close() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	<-c.done
}

func (c *logCollector) get(policy uint32, pid int, action string) logEvidence {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen[logKey{policy, uint32(pid), action}]
}

// anyFor reports whether any evidence exists for the process under the policy.
func (c *logCollector) anyFor(policy uint32, pid int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.seen {
		if k.policy == policy && k.pid == uint32(pid) {
			return true
		}
	}
	return false
}

func (c *logCollector) waitFor(t *testing.T, policy uint32, pid int, action string, wantSuccess bool) logEvidence {
	t.Helper()
	var ev logEvidence
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if ev = c.get(policy, pid, action); ev.seen > 0 && (!wantSuccess || ev.success) {
			return ev
		}
	}
	return ev
}

// fixtureChild is one running copy of the test binary.
type fixtureChild struct {
	name string
	pid  int
	done chan error
}

func startFixtureChild(t *testing.T, bin, marker string) *fixtureChild {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, bin, "-test.run=^TestVMKillFixtureChild$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "WAFIO_VM_KILL_FIXTURE="+marker)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	c := &fixtureChild{name: filepath.Base(bin), pid: cmd.Process.Pid, done: make(chan error, 1)}
	go func() { c.done <- cmd.Wait() }()
	return c
}

// outcome waits for the child and reports how it ended: "exit 0" or the
// signal that killed it.
func (c *fixtureChild) outcome(t *testing.T, within time.Duration) string {
	t.Helper()
	select {
	case err := <-c.done:
		if err == nil {
			return "exit 0"
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				return "signal " + ws.Signal().String()
			}
			return "exit " + strconv.Itoa(ee.ExitCode())
		}
		return "error " + err.Error()
	case <-time.After(within):
		t.Fatalf("%s (pid %d) did not end within %s", c.name, c.pid, within)
		return ""
	}
}

func copyExecutable(t *testing.T, dst string) {
	t.Helper()
	src, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, src); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestVMScenarioKillNarrowAndBroad checks that a narrowed Kill policy only
// ever hits its own uniquely named fixture process (Simulate first, then
// Kill), that sshd and its sessions are untouched, and that a broad Kill
// policy without kill_acknowledged is applied as alert.
func TestVMScenarioKillNarrowAndBroad(t *testing.T) {
	env := newVMEnv(t)
	openat := ebpf.TraceEventTypes[ebpf.TraceOpen].Name

	ctx, cancel := context.WithCancel(context.Background())
	tm := ebpf.NewTraceManager(ebpf.TraceManagerConfig{ObjectPath: filepath.Join(env.bpfDir, "wafio_trace.o")}, nil)
	if err := tm.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start trace manager: %v", err)
	}
	collector := startLogCollector(tm)
	t.Cleanup(func() {
		collector.close()
		_ = tm.ReplacePolicies(nil)
		cancel()
		if err := tm.Stop(); err != nil {
			t.Errorf("detach: %v", err)
		}
	})
	st := tm.Status()
	t.Logf("trace probes %d/%d missing=%v termination=%s", st.Probes, st.ExpectedProbes, st.MissingProbes, st.TerminationMode)
	if err := tm.UpdateConfig(ebpf.TraceConfigAPI{Enabled: true, EventTypes: []string{openat}, MinSeverity: "info", FilterSelf: true}); err != nil {
		t.Fatal(err)
	}

	// Fixtures: two copies of this binary with unique names (comm is limited
	// to 15 characters), both reading the same marker file.
	dir := t.TempDir()
	pid := os.Getpid()
	target := filepath.Join(dir, fmt.Sprintf("wfk%d", pid))
	decoy := filepath.Join(dir, fmt.Sprintf("wfd%d", pid))
	copyExecutable(t, target)
	copyExecutable(t, decoy)
	marker := filepath.Join(dir, "kill-fixture-marker")
	if err := os.WriteFile(marker, []byte("inert fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	targetComm := filepath.Base(target)

	sshd := sshdProcesses(t)
	if len(sshd) == 0 {
		t.Fatal("no sshd process found to protect")
	}
	env.sshAlive(t, "before policies")

	narrow := func(id uint32, action string) ebpf.EnforcementPolicy {
		return ebpf.EnforcementPolicy{
			ID: id, Name: "vm scenario narrow " + action, Enabled: true,
			EventTypes: []string{openat}, MinSeverity: "info",
			MatchComm: targetComm, MatchCommMode: ebpf.CommMatchExact,
			MatchFilename: marker, Action: action,
		}
	}
	runPair := func() (*fixtureChild, *fixtureChild) {
		tc := startFixtureChild(t, target, marker)
		dc := startFixtureChild(t, decoy, marker)
		return tc, dc
	}

	// Simulate: nothing dies, the log names the target only.
	sim := narrow(7401, "simulate")
	if err := ebpf.ValidateEnforcementPolicy(sim); err != nil {
		t.Fatal(err)
	}
	if err := tm.ReplacePolicies([]ebpf.EnforcementPolicy{sim}); err != nil {
		t.Fatal(err)
	}
	tc, dc := runPair()
	if o := tc.outcome(t, 20*time.Second); o != "exit 0" {
		t.Fatalf("simulate: target ended with %s", o)
	}
	if o := dc.outcome(t, 20*time.Second); o != "exit 0" {
		t.Fatalf("simulate: decoy ended with %s", o)
	}
	if ev := collector.waitFor(t, sim.ID, tc.pid, "simulate", false); ev.seen == 0 {
		t.Error("simulate: no simulate entry for the target in the enforcement log")
	}
	if collector.anyFor(sim.ID, dc.pid) {
		t.Error("simulate: the policy matched the decoy")
	}
	requireSSHDIntact(t, sshd, "simulate")
	env.sshAlive(t, "simulate")

	// Kill: only the target dies.
	kill := narrow(7401, "kill")
	if err := ebpf.ValidateEnforcementPolicy(kill); err != nil {
		t.Fatalf("narrowed kill policy refused: %v", err)
	}
	if err := tm.ReplacePolicies([]ebpf.EnforcementPolicy{kill}); err != nil {
		t.Fatal(err)
	}
	tc, dc = runPair()
	if o := tc.outcome(t, 6*time.Second); o != "signal killed" {
		t.Fatalf("kill: target ended with %q, want SIGKILL within 6s", o)
	}
	if o := dc.outcome(t, 20*time.Second); o != "exit 0" {
		t.Fatalf("kill: decoy ended with %s", o)
	}
	if ev := collector.waitFor(t, kill.ID, tc.pid, "kill", true); !ev.success {
		t.Errorf("kill: no successful kill entry for the target in the log (seen=%d)", ev.seen)
	}
	if collector.anyFor(kill.ID, dc.pid) {
		t.Error("kill: the policy matched the decoy")
	}
	requireSSHDIntact(t, sshd, "kill")
	env.sshAlive(t, "kill")

	// Broad Kill without kill_acknowledged: refused as saved, applied as alert.
	if err := tm.ReplacePolicies(nil); err != nil {
		t.Fatal(err)
	}
	broad := ebpf.EnforcementPolicy{ID: 7402, Name: "vm scenario broad kill", Enabled: true, EventTypes: []string{openat}, MinSeverity: "info", Action: "kill"}
	if err := ebpf.ValidateEnforcementPolicy(broad); err == nil {
		t.Fatal("broad kill without kill_acknowledged passed validation")
	}
	if err := tm.ReplacePolicies([]ebpf.EnforcementPolicy{broad}); err == nil {
		t.Fatal("broad kill without kill_acknowledged was accepted by ReplacePolicies")
	}
	if n := len(tm.ListPolicies()); n != 0 {
		t.Fatalf("refused snapshot left %d policies behind", n)
	}
	if !ebpf.DowngradeUnacknowledgedBroadKill(&broad) {
		t.Fatal("broad kill was not downgraded")
	}
	if broad.Action != "alert" {
		t.Fatalf("downgraded action = %q, want alert; nothing may reach the kernel as kill", broad.Action)
	}
	if err := tm.ReplacePolicies([]ebpf.EnforcementPolicy{broad}); err != nil {
		t.Fatal(err)
	}
	tc, dc = runPair()
	if o := tc.outcome(t, 20*time.Second); o != "exit 0" {
		t.Fatalf("broad: target ended with %s", o)
	}
	if o := dc.outcome(t, 20*time.Second); o != "exit 0" {
		t.Fatalf("broad: decoy ended with %s", o)
	}
	if ev := collector.waitFor(t, broad.ID, tc.pid, "alert", false); ev.seen == 0 {
		t.Error("broad: no alert entry for the target")
	}
	if ev := collector.get(broad.ID, tc.pid, "kill"); ev.seen != 0 {
		t.Errorf("broad: %d kill entries for a downgraded policy", ev.seen)
	}
	requireSSHDIntact(t, sshd, "broad")
	env.sshAlive(t, "broad")

	if err := tm.ReplacePolicies(nil); err != nil {
		t.Fatal(err)
	}
	if n := len(tm.ListPolicies()); n != 0 {
		t.Fatalf("final snapshot kept %d policies", n)
	}
}

// ── map sizing ──────────────────────────────────────────────────────────

// The three scenarios below run on a private veth pair (labNet), not on the
// primary interface: they need root and the objects, not the SSH session.

// startLabFirewall starts a Manager on the host end of n with the given map
// sizes and registers its stop. tag keeps the pin directories of two managers
// of one test apart.
func startLabFirewall(t *testing.T, n *labNet, sizes ebpf.MapSizes, tag string) *ebpf.Manager {
	t.Helper()
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if dir == "" {
		t.Fatal("WAFIO_TEST_BPF_DIR required")
	}
	pin := fmt.Sprintf("/sys/fs/bpf/wafio-vmtest-%d-%s", os.Getpid(), tag)
	ctx, cancel := context.WithCancel(context.Background())
	m := ebpf.NewManager(ebpf.ManagerConfig{
		Interface:     n.hostIf,
		XDPObjectPath: filepath.Join(dir, "wafio_xdp.o"),
		TCObjectPath:  filepath.Join(dir, "wafio_tc.o"),
		PinPath:       pin,
		XDPMode:       ebpf.XDPModeSKB,
		MetricsPollMs: 250,
		MapSizes:      sizes,
	}, nil)
	if err := m.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start the firewall (%s): %v", tag, err)
	}
	t.Cleanup(func() {
		cancel()
		_ = m.Stop()
		_ = os.RemoveAll(pin)
	})
	if st := m.Status(); !st.XDPAttached || !st.TCIngress || !st.TCEgress || !st.LockoutExemptions {
		t.Fatalf("firewall attached incompletely: %+v", st)
	}
	return m
}

func labCPUs(t *testing.T) int {
	t.Helper()
	n, err := cebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// watchXDP polls whether an XDP program is attached to the interface and
// returns, when called, the longest time none was: the window in which the
// host runs without its firewall.
func watchXDP(t *testing.T, ifName string) (longestGap func() time.Duration) {
	t.Helper()
	stop := make(chan struct{})
	done := make(chan time.Duration, 1)
	go func() {
		var gap, longest time.Duration
		var since time.Time
		for {
			select {
			case <-stop:
				done <- longest
				return
			default:
			}
			link, err := netlink.LinkByName(ifName)
			attached := err == nil && link.Attrs().Xdp != nil && link.Attrs().Xdp.Attached
			switch {
			case !attached && since.IsZero():
				since = time.Now()
			case attached && !since.IsZero():
				if gap = time.Since(since); gap > longest {
					longest = gap
				}
				since = time.Time{}
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	return func() time.Duration {
		close(stop)
		return <-done
	}
}

// denyAllIngress is the policy of the restart scenarios: ingress Deny All with
// the SSH ports the lockout guard asks for, egress open.
func denyAllIngress() fwState {
	rules := []ebpf.PortPolicyAPI{allowRule(22, "tcp", "ingress")}
	for _, p := range ebpf.DetectSSHDPorts() {
		if p != 22 {
			rules = append(rules, allowRule(p, "tcp", "ingress"))
		}
	}
	return fwState{
		cfg:   enforcingConfig(),
		pp:    ebpf.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"},
		rules: rules,
	}
}

// TestVMScenarioMapScaleRestartKeepsServerPush: a connection the host opened
// to a server that only pushes data (the host sends nothing after it connects)
// keeps working across an agent restart with another map scale, under ingress
// Deny All. The restart loses every conntrack entry; the socket proof lets the
// server's next segment in. The time between stopping the first firewall and
// attaching the second, the fail-open window, is logged.
func TestVMScenarioMapScaleRestartKeepsServerPush(t *testing.T) {
	if !vmScenariosEnabled() {
		t.Skip("set WAFIO_EBPF_VM_SCENARIOS=1 inside the disposable VM")
	}
	n := newLabNet(t)
	cpus := labCPUs(t)
	m1 := startLabFirewall(t, n, ebpf.ComputeMapSizes(1, cpus), "full")
	applyState(t, m1, denyAllIngress())

	n.send("push %s", net.JoinHostPort(n.peerAddr.String(), "7100"))
	n.expect("push-listening", 5*time.Second)
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(n.peerAddr.String(), "7100"), 3*time.Second)
	if err != nil {
		t.Fatalf("the host-opened connection under ingress Deny All: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	n.expect("push-accepted", 3*time.Second)
	var received atomic.Int64
	go func() {
		buf := make([]byte, 256)
		for {
			k, err := conn.Read(buf)
			received.Add(int64(k))
			if err != nil {
				return
			}
		}
	}()
	waitReceived := func(atLeast int64, what string) {
		t.Helper()
		deadline := time.Now().Add(4 * time.Second)
		for received.Load() < atLeast {
			if time.Now().After(deadline) {
				t.Fatalf("%s: received %d bytes, want %d: the pushed data does not arrive", what, received.Load(), atLeast)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	n.send("pushnow")
	n.expect("pushed", 3*time.Second)
	waitReceived(5, "before the restart")

	// The restart: the scale changes from 1 to the smallest.
	gap := watchXDP(t, n.hostIf)
	stopped := time.Now()
	if err := m1.Stop(); err != nil {
		t.Fatal(err)
	}
	m2 := startLabFirewall(t, n, ebpf.ComputeMapSizes(0.001, cpus), "floor")
	total := time.Since(stopped)
	applyState(t, m2, denyAllIngress())
	time.Sleep(50 * time.Millisecond)
	t.Logf("fail-open window: XDP detached for %v; stop and start took %v in all", gap().Round(time.Millisecond), total.Round(time.Millisecond))

	sizing := m2.Status().MapSizing
	if sizing == nil || sizing.Scale != 0.001 {
		t.Fatalf("map_sizing after the restart: %+v", sizing)
	}
	want, _ := ebpf.ComputeMapSizes(0.001, cpus).Size("wafio_conntrack")
	found := false
	for _, mc := range sizing.Maps {
		if mc.Name == "wafio_conntrack" {
			found = true
			if mc.MaxEntries != want || mc.DefaultMaxEntries != 500000 {
				t.Errorf("conntrack %+v after the restart, want %d of 500000", mc, want)
			}
		}
	}
	if !found {
		t.Errorf("map_sizing lists no conntrack: %+v", sizing.Maps)
	}

	// Nothing but the server speaks now.
	before := received.Load()
	n.send("pushnow")
	n.expect("pushed", 3*time.Second)
	waitReceived(before+5, "after the restart")
}

// TestVMScenarioKilledAgentRestartAttachesTC: on a kernel that attaches TC
// through a legacy clsact filter (before 6.6), an agent that is killed leaves
// its filters behind, and the next start removes them instead of failing to
// add its own. XDP and TCX attach through links, which end with the process.
func TestVMScenarioKilledAgentRestartAttachesTC(t *testing.T) {
	if !vmScenariosEnabled() {
		t.Skip("set WAFIO_EBPF_VM_SCENARIOS=1 inside the disposable VM")
	}
	if major, minor := kernelVersionForTest(t); major > 6 || major == 6 && minor >= 6 {
		t.Skip("TCX attaches TC on this kernel; the filters of a killed agent go with its links")
	}
	n := newLabNet(t)
	cpus := labCPUs(t)

	pin := fmt.Sprintf("/sys/fs/bpf/wafio-vmchild-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pin) })
	child := exec.Command(os.Args[0], "-test.run=^TestVMAgentChild$", "-test.timeout=1h")
	child.Env = append(os.Environ(), "WAFIO_VM_AGENT_CHILD=1", "WAFIO_VM_AGENT_IF="+n.hostIf, "WAFIO_VM_AGENT_PIN="+pin,
		fmt.Sprintf("WAFIO_VM_AGENT_CPUS=%d", cpus))
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill() })
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "AGENT attached") {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("the agent child ended before it attached")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the agent child did not attach in 30 s")
	}
	link, err := netlink.LinkByName(n.hostIf)
	if err != nil {
		t.Fatal(err)
	}
	wafioFilters := func(parent uint32) []*netlink.BpfFilter {
		t.Helper()
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			t.Fatal(err)
		}
		var out []*netlink.BpfFilter
		for _, f := range filters {
			if bf, ok := f.(*netlink.BpfFilter); ok && strings.HasPrefix(bf.Name, "wafio_") {
				out = append(out, bf)
			}
		}
		return out
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		if got := wafioFilters(parent); len(got) != 1 {
			t.Fatalf("the running agent has %d wafio filters on parent %#x, want 1", len(got), parent)
		}
	}

	// The agent dies without detaching.
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		if got := wafioFilters(parent); len(got) != 1 {
			t.Fatalf("after the kill: %d wafio filters on parent %#x; the kernel is expected to keep the one of the dead agent", len(got), parent)
		}
	}

	// The next start attaches TC again, and the stale filters are gone.
	m := startLabFirewall(t, n, ebpf.ComputeMapSizes(0.001, cpus), "restart")
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		if got := wafioFilters(parent); len(got) != 1 {
			t.Errorf("after the restart: %d wafio filters on parent %#x, want 1", len(got), parent)
		}
	}
	if st := m.Status(); !st.TCIngress || !st.TCEgress {
		t.Errorf("TC not attached after the restart: %+v", st)
	}
}

// TestVMAgentChild is the agent of TestVMScenarioKilledAgentRestartAttachesTC:
// the test binary run again, attached until it is killed.
func TestVMAgentChild(t *testing.T) {
	if os.Getenv("WAFIO_VM_AGENT_CHILD") != "1" {
		t.Skip("run by the kill scenario")
	}
	cpus := atoi(os.Getenv("WAFIO_VM_AGENT_CPUS"))
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	m := ebpf.NewManager(ebpf.ManagerConfig{
		Interface:     os.Getenv("WAFIO_VM_AGENT_IF"),
		XDPObjectPath: filepath.Join(dir, "wafio_xdp.o"),
		TCObjectPath:  filepath.Join(dir, "wafio_tc.o"),
		PinPath:       os.Getenv("WAFIO_VM_AGENT_PIN"),
		XDPMode:       ebpf.XDPModeSKB,
		MapSizes:      ebpf.ComputeMapSizes(0.001, cpus),
	}, nil)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fmt.Println("AGENT attached")
	select {} // until the parent kills this process
}

// TestVMScenarioLastGoodEgressListAtFloorScale: the egress list of a saved
// policy, at the 100000 entries the control plane allows, applies on a firewall
// sized at the smallest scale. The egress blocklist is allocated on insert and
// does not follow the scale, so no scale can refuse it.
func TestVMScenarioLastGoodEgressListAtFloorScale(t *testing.T) {
	if !vmScenariosEnabled() {
		t.Skip("set WAFIO_EBPF_VM_SCENARIOS=1 inside the disposable VM")
	}
	n := newLabNet(t)
	m := startLabFirewall(t, n, ebpf.ComputeMapSizes(0.001, labCPUs(t)), "lastgood")

	const entries = 100000
	list := make([]ebpf.EgressBlocklistEntry, entries)
	ips := make([]string, entries)
	for i := range list {
		ips[i] = fmt.Sprintf("11.%d.%d.%d", i>>16&255, i>>8&255, i&255)
		list[i] = ebpf.EgressBlocklistEntry{IP: ips[i]}
	}
	if err := ebpf.ValidateEgressBlocklistCapacity(ips); err != nil {
		t.Fatalf("the control plane check refuses %d egress entries: %v", entries, err)
	}
	unlock := ebpf.LockFirewallWrites()
	err := ebpf.ReplaceIPLists(m, ebpf.IPListUpdate{Egress: list}, time.Now())
	unlock()
	if err != nil {
		t.Fatalf("restore %d egress entries at the smallest scale: %v", entries, err)
	}
	live, err := m.ListEgressBlocklist(2 * entries)
	if err != nil || len(live) != entries {
		t.Fatalf("egress list holds %d entries, %v; want %d", len(live), err, entries)
	}
	// The same list again changes nothing, and one entry more is refused as capacity.
	unlock = ebpf.LockFirewallWrites()
	err = ebpf.ReplaceIPLists(m, ebpf.IPListUpdate{Egress: list}, time.Now())
	if err != nil {
		t.Errorf("the same list again: %v", err)
	}
	over := append(slices.Clone(list), ebpf.EgressBlocklistEntry{IP: "12.0.0.1"})
	err = ebpf.ReplaceIPLists(m, ebpf.IPListUpdate{Egress: over}, time.Now())
	unlock()
	if !errors.Is(err, ebpf.ErrIPListCapacity) {
		t.Errorf("%d entries: %v, want ErrIPListCapacity", entries+1, err)
	}
	if sz := m.Status().MapSizing; sz == nil {
		t.Error("no map_sizing in the status")
	} else {
		for _, mc := range sz.Maps {
			if mc.Name == "wafio_egress_blocklist" {
				t.Errorf("the egress blocklist is in the sized maps: %+v", mc)
			}
		}
	}
}
