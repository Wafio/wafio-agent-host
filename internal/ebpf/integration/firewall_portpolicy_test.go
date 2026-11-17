//go:build linux

package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

// TestPortPolicyDenyDefaultAllowsListed reproduces the production demo
// lockout: enforcement ON, port policy deny-by-default, explicit allow rules
// for the service ports. Every TCP connection to an allowed port must
// succeed; every other port must be denied. A failure here is the remote
// lockout that took the demo box offline.
func TestPortPolicyDenyDefaultAllowsListed(t *testing.T) {
	if os.Getenv("WAFIO_EBPF_INTEGRATION") != "1" {
		t.Skip("authorized Linux lab only")
	}
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if os.Geteuid() != 0 || dir == "" {
		t.Fatal("root and WAFIO_TEST_BPF_DIR required")
	}
	suffix := fmt.Sprint(os.Getpid())
	iface, peer, ns := "wlq"+suffix, "wpq"+suffix, "wafio-lab-pp-"+suffix
	pin := filepath.Join("/sys/fs/bpf", ns)
	if _, err := os.Stat(pin); !os.IsNotExist(err) {
		t.Fatal("test pin path must not exist")
	}
	// Clean up any stale interfaces or namespaces from previously aborted runs.
	_ = exec.Command("bash", "-c", "for dev in $(ip -o link show | awk -F': ' '{print $2}' | grep -E '^wlq'); do ip link del $dev 2>/dev/null; done").Run()
	_ = exec.Command("bash", "-c", "for n in $(ip netns list | awk '{print $1}' | grep -E '^wafio-lab-pp-'); do ip netns del $n 2>/dev/null; done").Run()

	run := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	run("netns", "add", ns)
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "netns", "del", ns).CombinedOutput(); err != nil {
			t.Errorf("namespace cleanup: %v %s", err, out)
		}
	})
	run("link", "add", iface, "type", "veth", "peer", "name", peer)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })
	run("link", "set", peer, "netns", ns)
	run("addr", "add", "10.77.0.1/24", "dev", iface)
	run("link", "set", iface, "up")
	run("-n", ns, "addr", "add", "10.77.0.2/24", "dev", peer)
	run("-n", ns, "link", "set", peer, "up")
	run("-n", ns, "link", "set", "lo", "up")

	hostIP := "10.77.0.1"
	allowed := map[int]bool{19443: true, 19022: true}
	listeners := map[int]net.Listener{}
	for _, port := range []int{19443, 19022, 19999} {
		l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", hostIP, port))
		if err != nil {
			t.Fatalf("listen %d: %v", port, err)
		}
		defer l.Close()
		listeners[port] = l
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Write([]byte("ok"))
				c.Close()
			}
		}(l)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	skipAttach := os.Getenv("WAFIO_TEST_SKIPATTACH") == "1"
	var m *ebpf.Manager
	if !skipAttach {
		m = ebpf.NewManager(ebpf.ManagerConfig{Interface: iface, XDPObjectPath: filepath.Join(dir, "wafio_xdp.o"), TCObjectPath: filepath.Join(dir, "wafio_tc.o"), PinPath: pin, XDPMode: ebpf.XDPModeSKB}, nil)
		t.Cleanup(func() {
			cancel()
			if err := m.Stop(); err != nil {
				t.Errorf("detach at cleanup: %v", err)
			}
			_ = os.RemoveAll(pin)
		})
		if err := m.Start(ctx); err != nil {
			t.Fatal(err)
		}
		if status := m.Status(); !status.XDPAttached {
			t.Fatalf("XDP not attached: %+v", status)
		} else {
			t.Logf("hooks: %+v", status)
		}
	} else {
		t.Log("WAFIO_TEST_SKIPATTACH=1 — manager not started (isolation baseline)")
	}

	// Dial from INSIDE the namespace so packets traverse the veth pair and
	// actually hit the XDP/TC hooks on the host-side interface. Host-local
	// dials take loopback and never cross the attachment point.
	dial := func(port int) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		script := fmt.Sprintf("timeout 3 bash -c 'exec 3<>/dev/tcp/%s/%d && head -c 2 <&3 && echo READ-OK'", hostIP, port)
		out, err := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "bash", "-c", script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v %s", err, out)
		}
		return nil
	}

	dumpMetrics := func(tag string) {
		metrics, err := m.ReadMetrics()
		if err != nil {
			t.Logf("metrics %s: unavailable: %v", tag, err)
			return
		}
		t.Logf("metrics %s: rx=%d dropped=%d ratelimited=%d synflood=%d blocklist=%d geo=%d portscan=%d portpolicy=%d egressip=%d parsefail=%d",
			tag, metrics.RxPackets, metrics.DroppedPackets, metrics.RatelimitedPackets, metrics.SynfloodDrops,
			metrics.BlocklistDrops, metrics.GeoblockDrops, metrics.PortScanDrops, metrics.PortPolicyDrops,
			metrics.EgressIPDrops, metrics.PacketParseFailures)
	}

	// Baseline without enforcement: every port connects.
	for port := range listeners {
		if err := dial(port); err != nil {
			dumpMetrics(fmt.Sprintf("fail-%d", port))
			t.Fatalf("baseline connect %d failed before enforcement: %v", port, err)
		}
	}
	dumpMetrics("baseline")

	if err := m.UpdateGlobalConfig(ebpf.GlobalConfigAPI{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdatePortPolicyConfig(ebpf.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []ebpf.PortPolicyAPI{
		{Port: 19443, Proto: "tcp", Direction: "ingress", Action: "allow"},
		{Port: 19022, Proto: "tcp", Direction: "ingress", Action: "allow"},
	} {
		if err := m.AddPortPolicy(p); err != nil {
			t.Fatalf("add policy %d: %v", p.Port, err)
		}
	}
	dumpMetrics("enforced")

	// Allowed ports must connect.
	for port := range allowed {
		if err := dial(port); err != nil {
			t.Errorf("ALLOWED port %d blocked under enforce+deny-default: %v", port, err)
		}
	}
	// Unlisted port must be denied.
	if err := dial(19999); err == nil {
		t.Errorf("unlisted port 19999 connected under deny-by-default; deny did not apply")
	}
	dumpMetrics("after-verdicts")
	bpfDump := func(args ...string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "bpftool", args...).CombinedOutput()
		t.Logf("bpftool %v: %s", args, out)
		if err != nil {
			t.Logf("bpftool err: %v", err)
		}
	}
	// ICMP check: does XDP see ANY packet? rx counter must move on ping.
	if out, err := exec.Command("ip", "netns", "exec", ns, "ping", "-n", "-c", "3", "-W", "1", hostIP).CombinedOutput(); err != nil {
		t.Logf("ping during enforcement failed: %v %s", err, out)
	} else {
		t.Logf("ping during enforcement: ok")
	}
	time.Sleep(500 * time.Millisecond)
	dumpMetrics("after-ping")
	t.Logf("pin dir %s:", pin)
	out, _ := exec.Command("ls", pin).CombinedOutput()
	t.Logf("pin contents: %s", out)
	bpfDump("net", "show", "dev", iface)
	bpfDump("net", "show")

	// Sustained traffic to an allowed port must stay up.
	for i := 0; i < 20; i++ {
		if err := dial(19443); err != nil {
			t.Fatalf("sustained connect %d to allowed 19443 failed: %v", i, err)
		}
	}
	dumpMetrics("sustained")
	t.Log("enforce + deny-default + allow rules: allowed ports reachable, unlisted denied")
}
