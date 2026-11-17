//go:build linux

package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

// This helper only reads the parent-created inert marker, then exits normally.
func TestDeferredTerminationChild(t *testing.T) {
	marker := os.Getenv("WAFIO_TERMINATION_FIXTURE")
	if marker == "" {
		t.Skip("subprocess fixture only")
	}
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if _, err := os.ReadFile(marker); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The only matching filename is a fresh private fixture used by our child.
// No host agent configuration or existing policy/map is modified.
func TestTraceDeferredFixtureTermination(t *testing.T) {
	if os.Getenv("WAFIO_EBPF_INTEGRATION") != "1" {
		t.Skip("authorized Linux lab only")
	}
	object := os.Getenv("WAFIO_TRACE_OBJECT")
	if os.Geteuid() != 0 || object == "" {
		t.Fatal("root and WAFIO_TRACE_OBJECT required")
	}
	marker := filepath.Join(t.TempDir(), "deferred-termination-fixture")
	if err := os.WriteFile(marker, []byte("inert fixture"), 0600); err != nil {
		t.Fatal(err)
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
	if err := tm.UpdateConfig(ebpf.TraceConfigAPI{Enabled: true, EventTypes: []string{ebpf.TraceEventTypes[ebpf.TraceOpen].Name}, MinSeverity: "info", FilterSelf: true}); err != nil {
		t.Fatal(err)
	}
	policy := ebpf.EnforcementPolicy{ID: 7302, Name: "own child marker only", Enabled: true, EventTypes: []string{ebpf.TraceEventTypes[ebpf.TraceOpen].Name}, MinSeverity: "info", MatchFilename: marker, Action: "kill"}
	if err := tm.ReplacePolicies([]ebpf.EnforcementPolicy{policy}); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childCtx, childCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer childCancel()
	child := exec.CommandContext(childCtx, executable, "-test.run=^TestDeferredTerminationChild$", "-test.timeout=7s")
	child.Env = append(os.Environ(), "WAFIO_TERMINATION_FIXTURE="+marker)
	err = child.Run()
	var exit *exec.ExitError
	if childCtx.Err() != nil || !errors.As(err, &exit) {
		t.Fatalf("expected kernel termination before fixture exits; err=%v deadline=%v", err, childCtx.Err())
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("unexpected child exit: %v", err)
	}
	accepted := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, entry := range tm.DrainEnforcementLog(500) {
			if entry.PolicyID != policy.ID {
				continue
			}
			t.Logf("fixture policy=%d pid=%d mode=%s outcome=%s success=%v", entry.PolicyID, entry.Event.PID, entry.Mode, entry.Event.SignalOutcome, entry.Success)
			if entry.Success && entry.Event.SignalOutcome == "accepted" {
				accepted = true
			}
		}
		if accepted {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !accepted {
		t.Fatal("missing accepted deferred outcome after observed child SIGKILL")
	}
}
