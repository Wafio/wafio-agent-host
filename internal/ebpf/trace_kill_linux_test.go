//go:build linux

package ebpf

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// startSleeper spawns a child of this test only; nothing else is targeted.
func startSleeper(t *testing.T) (*exec.Cmd, uint64) {
	t.Helper()
	if !pidfdSupported() {
		t.Skip("pidfd_open/pidfd_send_signal unavailable on this kernel")
	}
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(child.Process.Pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := parseProcStatStartTicks(stat)
	if err != nil {
		t.Fatal(err)
	}
	// Any ns inside the observed tick is a valid event identity.
	return child, ticks * (1_000_000_000 / userHZ)
}

func TestKillVerifiedPidfdRefusesMismatchedIdentity(t *testing.T) {
	child, startNs := startSleeper(t)
	err := killVerifiedPidfd(uint32(child.Process.Pid), startNs+uint64(time.Second))
	if !errors.Is(err, errPidfdFallback) {
		t.Fatalf("mismatched identity: want fallback error, got %v", err)
	}
	if err := child.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("child signalled despite identity mismatch: %v", err)
	}
	if err := killVerifiedPidfd(uint32(child.Process.Pid), 0); !errors.Is(err, errPidfdFallback) {
		t.Fatalf("missing identity: want fallback error, got %v", err)
	}
}

func TestKillVerifiedPidfdKillsExactProcess(t *testing.T) {
	child, startNs := startSleeper(t)
	if err := killVerifiedPidfd(uint32(child.Process.Pid), startNs); err != nil {
		t.Fatal(err)
	}
	err := child.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("child not terminated: %v", err)
	}
	if ws, ok := exit.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("unexpected child exit: %v", err)
	}
	// The reaped PID is gone: no signal may be attempted by number.
	if err := killVerifiedPidfd(uint32(child.Process.Pid), startNs); err == nil {
		t.Fatal("kill reported success for a reaped process")
	}
}
