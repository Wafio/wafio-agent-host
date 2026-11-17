//go:build linux

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"github.com/wafio/wafio-agent-host/internal/ebpf"
	"golang.org/x/sys/unix"
)

func TestLegacyTCOwnershipAndDenyGuard(t *testing.T) {
	if os.Getenv("WAFIO_EBPF_INTEGRATION") != "1" {
		t.Skip("authorized Linux lab only")
	}
	if os.Geteuid() != 0 || os.Getenv("WAFIO_TEST_BPF_DIR") == "" {
		t.Fatal("root and WAFIO_TEST_BPF_DIR required")
	}
	if kernelMajor, kernelMinor := kernelVersionForTest(t); kernelMajor > 6 || kernelMajor == 6 && kernelMinor >= 6 {
		t.Skip("legacy TC fallback requires kernel below 6.6")
	}
	iface := fmt.Sprintf("wtc%d", os.Getpid())
	peer := fmt.Sprintf("wtp%d", os.Getpid())
	if out, err := exec.Command("ip", "link", "add", iface, "type", "veth", "peer", "name", peer).CombinedOutput(); err != nil {
		t.Fatalf("create private veth: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })
	link, err := netlink.LinkByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	objectDir := os.Getenv("WAFIO_TEST_BPF_DIR")
	start := func(suffix string) *ebpf.Manager {
		t.Helper()
		pin := filepath.Join("/sys/fs/bpf", fmt.Sprintf("wafio-tc-%d-%s", os.Getpid(), suffix))
		m := ebpf.NewManager(ebpf.ManagerConfig{
			Interface:     iface,
			XDPObjectPath: filepath.Join(objectDir, "wafio_xdp.o"),
			TCObjectPath:  filepath.Join(objectDir, "wafio_tc.o"),
			PinPath:       pin,
			XDPMode:       ebpf.XDPModeSKB,
		}, nil)
		if err := m.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Stop(); _ = os.RemoveAll(pin) })
		return m
	}
	qdiscPresent := func() bool {
		t.Helper()
		qdiscs, err := netlink.QdiscList(link)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range qdiscs {
			if q.Type() == "clsact" {
				return true
			}
		}
		return false
	}
	m := start("preexisting")
	if status := m.Status(); !status.TCIngress || !status.TCEgress {
		t.Fatalf("legacy hooks missing: %+v", status)
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 || filters[0].Type() != "bpf" {
		t.Fatalf("unexpected egress filters: %+v", filters)
	}
	if err := netlink.FilterDel(filters[0]); err != nil {
		t.Fatal(err)
	}
	if status := m.Status(); status.TCEgress {
		t.Fatalf("detached egress hook reported attached: %+v", status)
	}
	if err := m.UpdatePortPolicyConfig(ebpf.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"}); err == nil {
		t.Fatal("ingress deny accepted after TC egress disappeared")
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if !qdiscPresent() {
		t.Fatal("preexisting clsact removed")
	}
	if err := netlink.QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	m = start("owned")
	foreignProgram, err := cebpf.NewProgram(&cebpf.ProgramSpec{
		Type:         cebpf.SchedCLS,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer foreignProgram.Close()
	foreign := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    0x1234,
			Priority:  2,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           foreignProgram.FD(),
		Name:         "foreign_test",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(foreign); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if !qdiscPresent() {
		t.Fatal("manager removed clsact containing a foreign filter")
	}
	filters, err = netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil || len(filters) != 1 || filters[0].(*netlink.BpfFilter).Name != "foreign_test" {
		t.Fatalf("foreign filter changed on stop: %+v, %v", filters, err)
	}
	if err := netlink.FilterDel(filters[0]); err != nil {
		t.Fatal(err)
	}
	if err := netlink.QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	m = start("empty")
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if qdiscPresent() {
		t.Fatal("manager-owned clsact remained after stop")
	}
}

func TestLegacyTCRejectsIncompatibleIngressQdisc(t *testing.T) {
	if os.Getenv("WAFIO_EBPF_INTEGRATION") != "1" {
		t.Skip("authorized Linux lab only")
	}
	if os.Geteuid() != 0 || os.Getenv("WAFIO_TEST_BPF_DIR") == "" {
		t.Fatal("root and WAFIO_TEST_BPF_DIR required")
	}
	if major, minor := kernelVersionForTest(t); major > 6 || major == 6 && minor >= 6 {
		t.Skip("legacy TC fallback requires kernel below 6.6")
	}
	iface := fmt.Sprintf("wti%d", os.Getpid())
	peer := fmt.Sprintf("wtj%d", os.Getpid())
	if out, err := exec.Command("ip", "link", "add", iface, "type", "veth", "peer", "name", peer).CombinedOutput(); err != nil {
		t.Fatalf("create private veth: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })
	link, err := netlink.LinkByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	ingress := &netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_INGRESS,
	}}
	if err := netlink.QdiscAdd(ingress); err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join("/sys/fs/bpf", fmt.Sprintf("wafio-tc-%d-incompatible", os.Getpid()))
	m := ebpf.NewManager(ebpf.ManagerConfig{
		Interface:     iface,
		XDPObjectPath: filepath.Join(os.Getenv("WAFIO_TEST_BPF_DIR"), "wafio_xdp.o"),
		TCObjectPath:  filepath.Join(os.Getenv("WAFIO_TEST_BPF_DIR"), "wafio_tc.o"),
		PinPath:       pin,
		XDPMode:       ebpf.XDPModeSKB,
	}, nil)
	t.Cleanup(func() { _ = m.Stop(); _ = os.RemoveAll(pin) })
	if err := m.Start(context.Background()); err == nil {
		t.Fatal("manager started without a usable TC egress hook")
	}
	if m.IsRunning() || m.Status().XDPAttached {
		t.Fatalf("failed start left XDP active: %+v", m.Status())
	}
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range qdiscs {
		if q.Type() == "ingress" {
			return
		}
	}
	t.Fatal("preexisting ingress qdisc removed after failed start")
}

func kernelVersionForTest(t *testing.T) (int, int) {
	t.Helper()
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		t.Fatal(err)
	}
	var major, minor int
	if _, err := fmt.Sscanf(string(out), "%d.%d", &major, &minor); err != nil {
		t.Fatal(err)
	}
	return major, minor
}
