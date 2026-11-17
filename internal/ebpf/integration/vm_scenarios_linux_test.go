//go:build linux

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
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
	if !hasWarning(warnings, ebpf.WarnEgressControlPlaneRuleMissing) {
		t.Errorf("expected warning %s (no egress allow for the control-plane port), got %+v", ebpf.WarnEgressControlPlaneRuleMissing, warnings)
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
	if !hasWarning(warnings, ebpf.WarnEgressDNSRuleMissing) {
		t.Errorf("expected warning %s, got %+v", ebpf.WarnEgressDNSRuleMissing, warnings)
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
	_, err = ebpf.ValidateFirewallSafety(ebpf.FirewallSafetyInput{
		Config:               &withoutDNS.cfg,
		PortPolicyConfig:     &withoutDNS.pp,
		PortPolicies:         withoutDNS.rules,
		SSHPorts:             []uint16{sshPort},
		ControlPlaneUnpinned: true,
	})
	if !errors.Is(err, ebpf.ErrEgressDenyUnpinned) {
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
