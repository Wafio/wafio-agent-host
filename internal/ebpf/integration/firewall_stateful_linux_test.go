//go:build linux

package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

const (
	labHost4 = "198.18.1.1"
	labPeer4 = "198.18.1.2"
	labHost6 = "2001:db8:1::1"
	labPeer6 = "2001:db8:1::2"
)

// TestStatefulPortPolicyPeer is launched only inside the private network namespace.
func TestStatefulPortPolicyPeer(t *testing.T) {
	switch os.Getenv("WAFIO_STATEFUL_PEER") {
	case "server":
		for _, addr := range []string{net.JoinHostPort(labPeer4, "18443"), net.JoinHostPort(labPeer6, "18443")} {
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					_, _ = conn.Write([]byte("ok"))
					_ = conn.Close()
				}
			}()
		}
		for _, addr := range []string{net.JoinHostPort(labPeer4, "18444"), net.JoinHostPort(labPeer6, "18444")} {
			listener, err := net.ListenPacket("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				buf := make([]byte, 32)
				for {
					_, peer, err := listener.ReadFrom(buf)
					if err != nil {
						return
					}
					_, _ = listener.WriteTo([]byte("ok"), peer)
				}
			}()
		}
		fmt.Println("READY")
		select {}
	case "probe":
		conn, err := net.DialTimeout("tcp", os.Getenv("WAFIO_STATEFUL_PROBE_ADDR"), 700*time.Millisecond)
		if err != nil {
			fmt.Println("BLOCKED")
			return
		}
		_ = conn.Close()
		fmt.Println("ALLOWED")
	default:
		t.Skip("network namespace helper")
	}
}

// TestStatefulPortPolicyPrivateVeth uses only a newly created veth, namespace,
// and BPF pin path. No existing interface or firewall state is modified.
func TestStatefulPortPolicyPrivateVeth(t *testing.T) {
	if os.Getenv("WAFIO_EBPF_INTEGRATION") != "1" {
		t.Skip("authorized Linux lab only")
	}
	dir := os.Getenv("WAFIO_TEST_BPF_DIR")
	if os.Geteuid() != 0 || dir == "" {
		t.Fatal("root and WAFIO_TEST_BPF_DIR required")
	}
	suffix := fmt.Sprint(os.Getpid())
	iface, peer, ns := "wfs"+suffix, "wfp"+suffix, "wafio-state-"+suffix
	pin := filepath.Join("/sys/fs/bpf", ns)
	if _, err := os.Stat(pin); !os.IsNotExist(err) {
		t.Fatal("private pin path already exists")
	}
	runIP := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, output)
		}
	}
	runIP("netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	runIP("link", "add", iface, "type", "veth", "peer", "name", peer)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })
	runIP("link", "set", peer, "netns", ns)
	runIP("addr", "add", labHost4+"/30", "dev", iface)
	runIP("-6", "addr", "add", labHost6+"/64", "dev", iface, "nodad")
	runIP("link", "set", iface, "up")
	runIP("-n", ns, "addr", "add", labPeer4+"/30", "dev", peer)
	runIP("-n", ns, "-6", "addr", "add", labPeer6+"/64", "dev", peer, "nodad")
	runIP("-n", ns, "link", "set", peer, "up")
	runIP("-n", ns, "link", "set", "lo", "up")

	server := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestStatefulPortPolicyPeer$", "-test.v")
	server.Env = append(os.Environ(), "WAFIO_STATEFUL_PEER=server")
	server.Stdout = os.Stderr
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	// A successful baseline probe confirms that the private peer is ready.
	for deadline := time.Now().Add(3 * time.Second); ; {
		conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(labPeer4, "18443"), 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer not ready: %v", dialErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := ebpf.NewManager(ebpf.ManagerConfig{Interface: iface, XDPObjectPath: filepath.Join(dir, "wafio_xdp.o"), TCObjectPath: filepath.Join(dir, "wafio_tc.o"), PinPath: pin, XDPMode: ebpf.XDPModeSKB}, nil)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = m.Stop(); _ = os.RemoveAll(pin) })
	if status := m.Status(); !status.XDPAttached || !status.TCIngress || !status.TCEgress || !status.EgressIPv6Supported {
		t.Fatalf("required XDP/TC hooks missing: %+v", status)
	}
	if err := m.UpdateGlobalConfig(ebpf.GlobalConfigAPI{Enabled: true, EnableConntrack: true}); err != nil {
		t.Fatal(err)
	}
	// Mirror the agent lockout guard: keep a management ingress allow rule.
	if err := m.AddPortPolicy(ebpf.PortPolicyAPI{Port: 19442, Proto: "tcp", Direction: "ingress", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdatePortPolicyConfig(ebpf.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"}); err != nil {
		t.Fatal(err)
	}

	request := func(network, remote string, localPort int) bool {
		t.Helper()
		address := net.JoinHostPort(remote, "18443")
		if network == "udp" {
			address = net.JoinHostPort(remote, "18444")
		}
		dialer := net.Dialer{Timeout: 800 * time.Millisecond}
		if localPort != 0 {
			dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(labHost4), Port: localPort}
		}
		conn, err := dialer.Dial(network, address)
		if err != nil {
			return false
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
		if network == "udp" {
			if _, err := conn.Write([]byte("hi")); err != nil {
				return false
			}
		}
		buf := make([]byte, 2)
		_, err = io.ReadFull(conn, buf)
		return err == nil && string(buf) == "ok"
	}
	for _, remote := range []string{labPeer4, labPeer6} {
		for _, network := range []string{"tcp", "udp"} {
			if !request(network, remote, 0) {
				t.Errorf("outbound %s %s reply denied", network, remote)
			}
		}
	}

	for _, host := range []string{labHost4, labHost6} {
		for _, port := range []string{"19442", "19443"} {
			listener, err := net.Listen("tcp", net.JoinHostPort(host, port))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					_ = conn.Close()
				}
			}()
		}
	}
	probeInbound := func(host, port string, want bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestStatefulPortPolicyPeer$", "-test.v")
		cmd.Env = append(os.Environ(), "WAFIO_STATEFUL_PEER=probe", "WAFIO_STATEFUL_PROBE_ADDR="+net.JoinHostPort(host, port))
		output, err := cmd.CombinedOutput()
		if err != nil || strings.Contains(string(output), "ALLOWED") != want {
			t.Errorf("inbound %s:%s allowed=%v want=%v: %v %s", host, port, strings.Contains(string(output), "ALLOWED"), want, err, output)
		}
	}
	probeInbound(labHost4, "19442", true)
	probeInbound(labHost6, "19442", true)
	probeInbound(labHost4, "19443", false)
	probeInbound(labHost6, "19443", false)
	if err := m.AddPortPolicy(ebpf.PortPolicyAPI{Port: 19443, Proto: "tcp", Direction: "ingress", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	probeInbound(labHost4, "19443", true)
	probeInbound(labHost6, "19443", true)
	if err := m.RemovePortPolicy(19443, "tcp", "ingress"); err != nil {
		t.Fatal(err)
	}

	if err := m.AddToEgressBlocklist(labPeer4, 150*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if request("tcp", labPeer4, 0) {
		t.Error("egress IP blocklist did not override allow default")
	}
	time.Sleep(200 * time.Millisecond)
	if !request("tcp", labPeer4, 0) {
		t.Error("expired egress blocklist still denied outbound")
	}
	if err := m.AddToBlocklist(labPeer4, 0); err != nil {
		t.Fatal(err)
	}
	if request("udp", labPeer4, 0) {
		t.Error("ingress blocklist did not override stateful reply")
	}
	if err := m.RemoveFromBlocklist(labPeer4); err != nil {
		t.Fatal(err)
	}

	if err := m.AddPortPolicy(ebpf.PortPolicyAPI{Port: 20333, Proto: "udp", Direction: "ingress", Action: "drop", TTLMs: 150}); err != nil {
		t.Fatal(err)
	}
	if request("udp", labPeer4, 20333) {
		t.Error("explicit ingress port drop did not override reply state")
	}
	time.Sleep(200 * time.Millisecond)
	if !request("udp", labPeer4, 20333) {
		t.Error("expired ingress port rule still denied reply")
	}
	if err := m.UpdateGlobalConfig(ebpf.GlobalConfigAPI{Enabled: true, MonitorOnly: true, EnableConntrack: true}); err != nil {
		t.Fatal(err)
	}
	probeInbound(labHost4, "19443", true)
	if err := m.UpdateGlobalConfig(ebpf.GlobalConfigAPI{Enabled: true, EnableConntrack: true}); err != nil {
		t.Fatal(err)
	}
	probeInbound(labHost4, "19443", false)
}
