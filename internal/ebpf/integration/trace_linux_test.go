//go:build linux

package integration

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

// This opt-in test creates a new unpinned collection and attaches observation
// probes only. It never requests kill, packet enforcement, or existing maps.
func TestTraceObserveAndSimulate(t *testing.T) {
	if os.Getenv("WAFIO_EBPF_INTEGRATION") != "1" {
		t.Skip("set WAFIO_EBPF_INTEGRATION=1 on an authorized Linux lab")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration requires root to load observation probes")
	}
	object := os.Getenv("WAFIO_TRACE_OBJECT")
	if object == "" {
		t.Fatal("WAFIO_TRACE_OBJECT is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tm := ebpf.NewTraceManager(ebpf.TraceManagerConfig{ObjectPath: object}, nil)
	if err := tm.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := tm.Stop(); err != nil {
			t.Errorf("detach: %v", err)
		}
	})
	status := tm.Status()
	if status.Probes != status.ExpectedProbes || len(status.MissingProbes) != 0 {
		t.Fatalf("incomplete attachment: %+v", status)
	}
	if err := tm.UpdateConfig(ebpf.TraceConfigAPI{Enabled: true, MinSeverity: "info", FilterSelf: false}); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "wafio-simulate-fixture")
	policy := ebpf.EnforcementPolicy{ID: 7301, Name: "fixture only", Enabled: true, EventTypes: []string{ebpf.TraceEventTypes[ebpf.TraceOpen].Name}, MinSeverity: "info", MatchFilename: marker, Action: "simulate"}
	if err := tm.ReplacePolicies([]ebpf.EnforcementPolicy{policy}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("inert fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	seenFile, seenExit, seenSimulate := false, false, false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, event := range tm.DrainRecentTraceEvents(8192) {
			if event.PID != uint32(os.Getpid()) {
				continue
			}
			if event.EventType == ebpf.TraceOpen && event.Filename == marker {
				seenFile = true
				seenSimulate = event.Action == ebpf.ActionSimulate && event.PolicyID == policy.ID
			}
			if event.EventType == ebpf.TraceConnExit {
				seenExit = true
				if event.RetVal > 0 {
					t.Fatalf("connect syscall result must be success or errno, got %d; check exit ABI", event.RetVal)
				}
			}
		}
		if seenFile && seenExit && seenSimulate {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !seenFile || !seenExit || !seenSimulate {
		t.Fatalf("missing evidence: file=%v syscall_exit=%v simulate=%v", seenFile, seenExit, seenSimulate)
	}
	if err := tm.ReplacePolicies(nil); err != nil {
		t.Fatal(err)
	}
	if len(tm.ListPolicies()) != 0 {
		t.Fatal("empty snapshot retained the final policy")
	}
	t.Logf("kernel=%s attached=%d/%d observed fixture file, connect exit, simulate, empty snapshot; no kill tested", kernelRelease(), status.Probes, status.ExpectedProbes)
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return string(b)
}
