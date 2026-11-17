//go:build linux

package ebpf

import (
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Run with WAFIO_TRACE_FORK_TEST_OBJECT on a privileged Linux lab host.
func TestForkTracepointKernelABI(t *testing.T) {
	objectPath := os.Getenv("WAFIO_TRACE_FORK_TEST_OBJECT")
	if objectPath == "" {
		t.Skip("set WAFIO_TRACE_FORK_TEST_OBJECT for kernel tracepoint test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel tracepoint test requires root")
	}

	manager := NewTraceManager(TraceManagerConfig{ObjectPath: objectPath}, log.New(io.Discard, "", 0))
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Stop(); err != nil {
			t.Error(err)
		}
	})
	status := manager.Status()
	if status.Probes != status.ExpectedProbes {
		t.Fatalf("attached %d/%d probes; failures: %v", status.Probes, status.ExpectedProbes, status.MissingProbes)
	}
	if err := manager.UpdateConfig(TraceConfigAPI{
		Enabled: true, EventTypes: []string{"clone"}, MinSeverity: "info",
	}); err != nil {
		t.Fatal(err)
	}

	child := exec.Command("/bin/true")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	childPID := uint32(child.Process.Pid)
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		for _, event := range manager.FilterRecentEvents("process", 0, 100) {
			if event.EventType == TraceClone && event.PID == uint32(os.Getpid()) && event.Detail == childPID {
				if event.Filename == "" || event.ParentComm == "" {
					t.Fatalf("fork event missing process context: %+v", event)
				}
				return
			}
		}
		select {
		case <-deadline:
			t.Fatalf("fork event for child PID %d not observed", childPID)
		case <-tick.C:
		}
	}
}
