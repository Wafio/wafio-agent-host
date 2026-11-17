//go:build linux

package integration

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The parsers behind the VM scenarios run everywhere (no privileges, no VM),
// so a mistake in them shows up in the ordinary linux test job rather than
// as a confusing failure inside the VM.

func TestParseSSHConnection(t *testing.T) {
	s, err := parseSSHConnection("10.0.2.2 54321 10.0.2.15 22")
	if err != nil {
		t.Fatal(err)
	}
	if s.client != netip.MustParseAddrPort("10.0.2.2:54321") || s.server != netip.MustParseAddrPort("10.0.2.15:22") {
		t.Fatalf("parsed %+v", s)
	}
	for _, bad := range []string{"", "10.0.2.2 54321 10.0.2.15", "x 1 y 2", "10.0.2.2 99999 10.0.2.15 22"} {
		if _, err := parseSSHConnection(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestProcTCPAddr(t *testing.T) {
	ap := netip.MustParseAddrPort("10.0.2.15:22")
	if got := procTCPAddr(ap, false); got != "0F02000A:0016" {
		t.Errorf("tcp: %s", got)
	}
	if got := procTCPAddr(ap, true); got != "0000000000000000FFFF00000F02000A:0016" {
		t.Errorf("tcp6: %s", got)
	}
}

func TestDefaultRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route")
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0202000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0002000A\t00000000\t0001\t0\t0\t100\tFFFFFFFF\t0\t0\t0\n"
	if err := os.WriteFile(path, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	iface, gw, err := defaultRoute(path)
	if err != nil {
		t.Fatal(err)
	}
	if iface != "eth0" || gw != netip.MustParseAddr("10.0.2.2") {
		t.Fatalf("iface=%s gw=%s", iface, gw)
	}
	if err := os.WriteFile(path, []byte("Iface\tDestination\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := defaultRoute(path); err == nil {
		t.Error("table without default route accepted")
	}
}
