package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The threshold the control plane, the agent and the local API accept
// must be one the XDP distinct-port table can reach.
func TestPortScanLimitMatchesDataplane(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("bpf", "wafio_xdp.c"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^#define MAX_SCAN_PORTS (\d+)`).FindSubmatch(src)
	if m == nil {
		t.Fatal("MAX_SCAN_PORTS not found in wafio_xdp.c")
	}
	n, _ := strconv.Atoi(string(m[1]))
	if n != MaxPortScanUniquePorts {
		t.Fatalf("MAX_SCAN_PORTS = %d, MaxPortScanUniquePorts = %d", n, MaxPortScanUniquePorts)
	}
}

func TestValidatePortScanConfigBounds(t *testing.T) {
	ok := PortScanConfigAPI{Enabled: true, WindowMs: 10_000, MaxUniquePorts: MaxPortScanUniquePorts}
	if err := ValidatePortScanConfig(ok); err != nil {
		t.Fatalf("threshold %d refused: %v", MaxPortScanUniquePorts, err)
	}
	for _, n := range []uint32{0, MaxPortScanUniquePorts + 1, 128} {
		bad := ok
		bad.MaxUniquePorts = n
		if err := ValidatePortScanConfig(bad); err == nil {
			t.Fatalf("threshold %d accepted", n)
		}
	}
	off := PortScanConfigAPI{MaxUniquePorts: 500}
	if err := ValidatePortScanConfig(off); err != nil {
		t.Fatalf("disabled config judged: %v", err)
	}
}

func TestNormalizePortScanConfig(t *testing.T) {
	cfg := PortScanConfigAPI{Enabled: true, WindowMs: 10_000, MaxUniquePorts: 64, DropOnDetect: true}
	if !NormalizePortScanConfig(&cfg) || cfg.MaxUniquePorts != MaxPortScanUniquePorts {
		t.Fatalf("64 not lowered: %+v", cfg)
	}
	// Such a threshold only ever logged: lowering it must not start drops.
	if cfg.DropOnDetect {
		t.Fatal("normalised threshold left dropping on")
	}
	if err := ValidatePortScanConfig(cfg); err != nil {
		t.Fatalf("normalised config refused: %v", err)
	}
	same := PortScanConfigAPI{Enabled: true, WindowMs: 10_000, MaxUniquePorts: 20, DropOnDetect: true}
	if NormalizePortScanConfig(&same) || same.MaxUniquePorts != 20 || !same.DropOnDetect {
		t.Fatalf("valid threshold changed: %+v", same)
	}
	off := PortScanConfigAPI{MaxUniquePorts: 64}
	if NormalizePortScanConfig(&off) || off.MaxUniquePorts != 64 {
		t.Fatalf("disabled config changed: %+v", off)
	}
	if NormalizePortScanConfig(nil) {
		t.Fatal("nil config reported a change")
	}
}
