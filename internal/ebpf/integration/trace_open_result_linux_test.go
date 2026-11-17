//go:build linux

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

// traceLab starts a trace manager on a private collection (no pins, no
// network hooks), as TestTraceObserveAndSimulate does, with the agent's own
// events unfiltered.
func traceLab(t testing.TB) *ebpf.TraceManager {
	t.Helper()
	return traceLabWithout(t, nil)
}

// traceLabWithout is traceLab for an object that may lack the probes of the
// names `allowMissing` accepts (an object from before open results has no open
// exit probes).
func traceLabWithout(t testing.TB, allowMissing func(string) bool) *ebpf.TraceManager {
	t.Helper()
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
	tm := ebpf.NewTraceManager(ebpf.TraceManagerConfig{ObjectPath: object}, nil)
	if err := tm.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := tm.Stop(); err != nil {
			t.Errorf("detach: %v", err)
		}
	})
	status := tm.Status()
	for name := range status.MissingProbes {
		if allowMissing == nil || !allowMissing(name) {
			t.Fatalf("incomplete attachment: %+v", status)
		}
	}
	if allowMissing == nil && status.Probes != status.ExpectedProbes {
		t.Fatalf("incomplete attachment: %+v", status)
	}
	if err := tm.UpdateConfig(ebpf.TraceConfigAPI{Enabled: true, MinSeverity: "info", FilterSelf: false}); err != nil {
		t.Fatal(err)
	}
	return tm
}

// openResultLab is traceLab with open results armed.
func openResultLab(t testing.TB) *ebpf.TraceManager {
	t.Helper()
	tm := traceLab(t)
	if status := tm.Status(); !status.OpenResult {
		t.Fatalf("open results not armed: %+v", status)
	}
	return tm
}

// openEvents collects the open events of the given processes until done
// reports true or the time is up; one entry per event, so a doubled event
// shows as two.
func openEvents(tm *ebpf.TraceManager, pids map[uint32]bool, wait time.Duration, done func([]ebpf.TraceEvent) bool) []ebpf.TraceEvent {
	var got []ebpf.TraceEvent
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		for _, e := range tm.DrainRecentTraceEvents(8192) {
			if e.EventType == ebpf.TraceOpen && pids[e.PID] {
				got = append(got, e)
			}
		}
		if done(got) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return got
}

func opensOf(events []ebpf.TraceEvent, path string) []ebpf.TraceEvent {
	var out []ebpf.TraceEvent
	for _, e := range events {
		if e.Filename == path {
			out = append(out, e)
		}
	}
	return out
}

// A successful open and a denied open of the same file give a non-negative
// and a negative result, and an open of a missing file the errno; each open is
// one event.
func TestTraceOpenResult(t *testing.T) {
	dir := t.TempDir() // 0700, owned by root: another user cannot reach the file
	file := filepath.Join(dir, "result-fixture")
	missing := filepath.Join(dir, "result-missing")
	if err := os.WriteFile(file, []byte("inert fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	tm := openResultLab(t) // after the write: its open is not under test

	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Open(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open of a missing file: %v", err)
	}
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not found")
	}
	denied := exec.Command(cat, file)
	denied.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if err := denied.Run(); err == nil {
		t.Fatal("an unprivileged read of a root-only directory succeeded")
	}

	pids := map[uint32]bool{uint32(os.Getpid()): true, uint32(denied.Process.Pid): true} //nolint:gosec // G115: pids are small positive integers
	events := openEvents(tm, pids, 5*time.Second, func(got []ebpf.TraceEvent) bool {
		return len(opensOf(got, file)) >= 2 && len(opensOf(got, missing)) >= 1
	})

	var ok, notFound, refused []ebpf.TraceEvent
	for _, e := range opensOf(events, file) {
		if e.PID == uint32(os.Getpid()) { //nolint:gosec // G115: see above
			ok = append(ok, e)
		} else {
			refused = append(refused, e)
		}
	}
	notFound = opensOf(events, missing)
	if len(ok) != 1 || len(notFound) != 1 || len(refused) != 1 {
		t.Fatalf("one event per open wanted: success %d, missing %d, denied %d (all: %+v)", len(ok), len(notFound), len(refused), events)
	}
	if e := ok[0]; e.RetVal < 0 || e.ActivityOutcome != "success" {
		t.Errorf("successful open: ret_val %d, outcome %q", e.RetVal, e.ActivityOutcome)
	}
	if e := notFound[0]; e.RetVal != -int64(unix.ENOENT) || e.ActivityOutcome != "failure" {
		t.Errorf("open of a missing file: ret_val %d, outcome %q, want %d failure", e.RetVal, e.ActivityOutcome, -int64(unix.ENOENT))
	}
	if e := refused[0]; e.RetVal != -int64(unix.EACCES) || e.ActivityOutcome != "failure" {
		t.Errorf("denied open: ret_val %d, outcome %q, want %d failure", e.RetVal, e.ActivityOutcome, -int64(unix.EACCES))
	}
	status := tm.Status()
	t.Logf("kernel=%s success=%d denied=%d missing=%d known=%d unknown=%d", kernelRelease(), ok[0].RetVal, refused[0].RetVal, notFound[0].RetVal, status.OpenResultKnown, status.OpenResultUnknown)
}

// procState is the state letter of /proc/<pid>/stat (S sleeping, T stopped).
func procState(pid int) byte {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 || i+2 >= len(b) {
		return 0
	}
	return b[i+2]
}

// waitBlockedInOpen waits until the process sleeps inside an openat: only the
// open of a FIFO without a writer blocks there, so the kernel has the open
// event waiting for its result. A fixed delay would pass without testing
// anything when the process is slow to get there.
func waitBlockedInOpen(t *testing.T, pid int) {
	t.Helper()
	prefix := strconv.Itoa(unix.SYS_OPENAT) + " "
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/syscall", pid))
		if err == nil && strings.HasPrefix(string(b), prefix) && procState(pid) == 'S' {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/syscall", pid))
	t.Fatalf("process %d never blocked in openat (state %c, syscall %q)", pid, procState(pid), strings.TrimSpace(string(b)))
}

func waitProcState(t *testing.T, pid int, state byte) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if procState(pid) == state {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d never reached state %c (now %c)", pid, state, procState(pid))
}

// fifoReader starts cat on a new FIFO: its open blocks until a writer opens
// the FIFO.
func fifoReader(t *testing.T) (child *exec.Cmd, fifo string, pid int) {
	t.Helper()
	fifo = filepath.Join(t.TempDir(), "result-fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not found")
	}
	child = exec.Command(cat, fifo)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid = child.Process.Pid
	t.Cleanup(func() {
		_ = child.Process.Kill() // test cleanup: the child may already be gone
		_ = child.Wait()         // reaped; its status is not the test's result
	})
	return child, fifo, pid
}

// An open that blocks has not happened yet: its event is held, not sent at
// entry and again at exit. A process killed inside the open runs the exit
// probe with the kernel's restart code, which is not a result: the event
// leaves as an attempt, counted among the opens that left without one.
func TestTraceOpenResultBlockedAndKilled(t *testing.T) {
	tm := openResultLab(t)
	child, fifo, pid := fifoReader(t)
	waitBlockedInOpen(t, pid)

	before := tm.Status()
	only := map[uint32]bool{uint32(pid): true} //nolint:gosec // G115: pids are small positive integers
	early := openEvents(tm, only, 500*time.Millisecond, func(got []ebpf.TraceEvent) bool { return len(opensOf(got, fifo)) > 0 })
	if n := len(opensOf(early, fifo)); n != 0 {
		t.Fatalf("a blocked open was sent before it returned (%d events)", n)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait() // killed on purpose

	got := openEvents(tm, only, 5*time.Second, func(got []ebpf.TraceEvent) bool { return len(opensOf(got, fifo)) > 0 })
	events := opensOf(got, fifo)
	if len(events) != 1 {
		t.Fatalf("the open of the killed process: %d events, want 1", len(events))
	}
	e := events[0]
	if e.ActivityOutcome != "attempt" || e.RetVal != 0 {
		t.Errorf("killed open reported %q with ret_val %d, want an attempt without a result", e.ActivityOutcome, e.RetVal)
	}
	after := tm.Status()
	if after.OpenResultUnknown <= before.OpenResultUnknown {
		t.Errorf("the open that left without a result was not counted: %+v -> %+v", before, after)
	}
	t.Logf("kernel=%s killed inside open: outcome=%s ret_val=%d known=%d unknown=%d", kernelRelease(), e.ActivityOutcome, e.RetVal, after.OpenResultKnown, after.OpenResultUnknown)
}

// A stopped process blocked in an open gets the kernel's restart code from the
// open and runs the syscall again after it continues. The first event is an
// attempt, not a failed open; the second carries the real result.
func TestTraceOpenResultRestart(t *testing.T) {
	tm := openResultLab(t)
	child, fifo, pid := fifoReader(t)
	only := map[uint32]bool{uint32(pid): true} //nolint:gosec // G115: pids are small positive integers
	waitBlockedInOpen(t, pid)

	if err := child.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	waitProcState(t, pid, 'T')
	first := openEvents(tm, only, 5*time.Second, func(got []ebpf.TraceEvent) bool { return len(opensOf(got, fifo)) > 0 })
	if err := child.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	waitBlockedInOpen(t, pid)
	writer, err := unix.Open(fifo, unix.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(writer); err != nil {
		t.Fatal(err)
	}
	second := openEvents(tm, only, 5*time.Second, func(got []ebpf.TraceEvent) bool { return len(opensOf(got, fifo)) > 0 })
	_ = child.Wait() // cat reads the end of the FIFO and exits

	a, b := opensOf(first, fifo), opensOf(second, fifo)
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("a restarted open is two events: %d before the continue, %d after (all: %+v %+v)", len(a), len(b), first, second)
	}
	if a[0].ActivityOutcome != "attempt" || a[0].RetVal != 0 {
		t.Errorf("interrupted open reported %q with ret_val %d, want an attempt", a[0].ActivityOutcome, a[0].RetVal)
	}
	if b[0].ActivityOutcome != "success" || b[0].RetVal < 0 {
		t.Errorf("restarted open reported %q with ret_val %d, want its descriptor", b[0].ActivityOutcome, b[0].RetVal)
	}
}

// pidsAvailable is how many more tasks the cgroup of this process may start,
// or -1 without a limit.
func pidsAvailable() int {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return -1
	}
	rel := strings.TrimPrefix(strings.TrimSpace(string(b)), "0::")
	dir := filepath.Join("/sys/fs/cgroup", rel)
	limit, err := os.ReadFile(filepath.Join(dir, "pids.max"))
	if err != nil || strings.TrimSpace(string(limit)) == "max" {
		return -1
	}
	ceiling, err1 := strconv.Atoi(strings.TrimSpace(string(limit)))
	cur, err2 := os.ReadFile(filepath.Join(dir, "pids.current"))
	used, err3 := strconv.Atoi(strings.TrimSpace(string(cur)))
	if err1 != nil || err2 != nil || err3 != nil {
		return -1
	}
	return ceiling - used
}

// More threads blocked in an open than trace_open_pending has room for: the
// opens the map refuses leave at entry as attempts and are counted, the ones
// it holds leave with their result once the FIFO has a writer, and no open is
// missing. A full map costs results, never events.
func TestTraceOpenResultPendingFull(t *testing.T) {
	const slots = 2048 // TRACE_OPEN_PENDING_MAX
	const extra = 64
	if free := pidsAvailable(); free >= 0 && free < slots+extra+512 {
		t.Skipf("the cgroup of this process allows %d more tasks, the test needs %d threads", free, slots+extra)
	}
	tm := openResultLab(t)
	fifo := filepath.Join(t.TempDir(), "result-fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	before := tm.Status()
	pids := map[uint32]bool{uint32(os.Getpid()): true} //nolint:gosec // G115: pids are small positive integers

	var wg sync.WaitGroup
	failed := make(chan error, slots+extra)
	for i := 0; i < slots+extra; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fd, err := unix.Open(fifo, unix.O_RDONLY, 0) // blocks in its own thread until a writer opens
			if err != nil {
				failed <- err
				return
			}
			_ = unix.Close(fd)
		}()
	}
	writer := -1
	t.Cleanup(func() {
		if writer < 0 { // the test failed before the release: let the readers go
			if fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
				_ = unix.Close(fd)
			}
		}
		wg.Wait()
	})

	// Every reader is inside its open before the FIFO gets a writer: one that
	// starts later would block for good.
	prefix := strconv.Itoa(unix.SYS_OPENAT) + " "
	deadline := time.Now().Add(60 * time.Second)
	for blocked := 0; blocked < slots+extra && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		blocked = 0
		tasks, _ := os.ReadDir("/proc/self/task")
		for _, task := range tasks {
			if b, err := os.ReadFile("/proc/self/task/" + task.Name() + "/syscall"); err == nil && strings.HasPrefix(string(b), prefix) {
				blocked++
			}
		}
	}
	refused := opensOf(openEvents(tm, pids, 10*time.Second, func(got []ebpf.TraceEvent) bool { return len(opensOf(got, fifo)) >= extra }), fifo)
	mid := tm.Status()
	if got := mid.OpenResultUnknown - before.OpenResultUnknown; got < extra || len(refused) < extra {
		t.Fatalf("%d opens counted and %d events for the opens the full map refused, want at least %d (shed %d, priority lost %d, queued %d, armed %v)",
			got, len(refused), extra, mid.KernelEventsShed-before.KernelEventsShed, mid.PriorityEventsLost-before.PriorityEventsLost, tm.QueuedEvents(), mid.OpenResult)
	}
	for _, e := range refused {
		if e.ActivityOutcome != "attempt" || e.RetVal != 0 {
			t.Fatalf("an open the full map refused reported %q with ret_val %d, want an attempt", e.ActivityOutcome, e.RetVal)
		}
	}

	// Release the readers: the ones the map holds leave with their result.
	w, err := unix.Open(fifo, unix.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	writer = w
	wg.Wait()
	_ = unix.Close(writer)
	close(failed)
	for err := range failed {
		t.Fatalf("a reader failed: %v", err)
	}

	// The readers' opens only: the open of the writer is one more event of
	// the FIFO, and the map was still full when it entered.
	readers := func(events []ebpf.TraceEvent) []ebpf.TraceEvent {
		var out []ebpf.TraceEvent
		for _, e := range opensOf(events, fifo) {
			if e.Flags&unix.O_ACCMODE == unix.O_RDONLY {
				out = append(out, e)
			}
		}
		return out
	}
	all := refused
	var resulted int
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range readers(openEvents(tm, pids, 200*time.Millisecond, func([]ebpf.TraceEvent) bool { return false })) {
			all = append(all, e)
			if e.ActivityOutcome == "success" {
				resulted++
			}
		}
		if len(all) >= slots+extra {
			break
		}
	}
	// A signal the Go runtime sends to a blocked thread ends its open with the
	// restart code: that open is an attempt and its restart is one more event.
	if len(all) < slots+extra {
		t.Errorf("an open is missing: %d events for %d opens", len(all), slots+extra)
	}
	after := tm.Status()
	if resulted < slots/2 {
		t.Errorf("only %d of the held opens left with a result", resulted)
	}
	if after.OpenResultKnown-before.OpenResultKnown < uint64(resulted) { //nolint:gosec // G115: resulted is a count
		t.Errorf("kernel counted %d opens with a result, the events show %d", after.OpenResultKnown-before.OpenResultKnown, resulted)
	}
	t.Logf("kernel=%s refused=%d with result=%d known=%d unknown=%d", kernelRelease(), len(all)-resulted, resulted, after.OpenResultKnown-before.OpenResultKnown, after.OpenResultUnknown-before.OpenResultUnknown)
}
