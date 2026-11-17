//go:build linux

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

// TestFirewallOnPrivateVeth creates its own interface and namespace, with no
// default route. Management interfaces and pre-existing BPF pins are untouched.
func TestFirewallOnPrivateVeth(t *testing.T) {
	if os.Getenv("WAFIO_EBPF_INTEGRATION") != "1" {
		t.Skip("authorized Linux lab only")
	}
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if os.Geteuid() != 0 || dir == "" {
		t.Fatal("root and WAFIO_TEST_BPF_DIR required")
	}
	suffix := fmt.Sprint(os.Getpid())
	iface, peer, ns := "wlh"+suffix, "wlp"+suffix, "wafio-lab-"+suffix
	pin := filepath.Join("/sys/fs/bpf", ns)
	if _, err := os.Stat(pin); !os.IsNotExist(err) {
		t.Fatal("test pin path must not exist")
	}
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
	run("addr", "add", "198.18.0.1/30", "dev", iface)
	run("link", "set", iface, "up")
	run("-n", ns, "addr", "add", "198.18.0.2/30", "dev", peer)
	run("-n", ns, "link", "set", peer, "up")
	run("-n", ns, "link", "set", "lo", "up")
	// The agent needs NET_ADMIN, not NET_RAW. Permit datagram ICMP only for
	// this root-owned fixture inside its private namespace.
	run("netns", "exec", ns, "sysctl", "-qw", "net.ipv4.ping_group_range=0 0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := ebpf.NewManager(ebpf.ManagerConfig{Interface: iface, XDPObjectPath: filepath.Join(dir, "wafio_xdp.o"), TCObjectPath: filepath.Join(dir, "wafio_tc.o"), PinPath: pin, XDPMode: ebpf.XDPModeSKB}, nil)
	t.Cleanup(func() {
		cancel()
		if err := m.Stop(); err != nil {
			t.Errorf("detach: %v", err)
		}
		if err := os.RemoveAll(pin); err != nil {
			t.Errorf("own pins cleanup: %v", err)
		}
	})
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if status := m.Status(); !status.XDPAttached || !status.TCIngress || !status.TCEgress {
		t.Fatalf("missing hooks: %+v", status)
	}
	ping := func(want bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "ping", "-n", "-c", "1", "-W", "1", "198.18.0.1").CombinedOutput()
		if (err == nil) != want {
			t.Fatalf("ping allowed=%v want=%v: %s", err == nil, want, out)
		}
	}
	if err := m.UpdateGlobalConfig(ebpf.GlobalConfigAPI{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ping(true)
	if err := m.AddToBlocklist("198.18.0.2", 0); err != nil {
		t.Fatal(err)
	}
	ping(false)
	if err := m.UpdateGlobalConfig(ebpf.GlobalConfigAPI{Enabled: true, MonitorOnly: true}); err != nil {
		t.Fatal(err)
	}
	ping(true)
	if err := m.RemoveFromBlocklist("198.18.0.2"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateGlobalConfig(ebpf.GlobalConfigAPI{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ping(true)
	t.Log("private veth: XDP + TC ingress/egress attached; allow, block, monitor, remove-block passed")
}
