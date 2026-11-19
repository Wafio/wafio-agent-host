//go:build linux

package ebpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// kernelProtectLab loads wafio_trace.o, attaches only the fork, exec, exit and
// UID call programs of the protected set, makes this process a protected
// process, and returns the maps. The programs run for every process of the host while they
// are attached, and touch only these private maps. Needs root, the compiled
// objects (WAFIO_TEST_BPF_DIR) and a filesystem that reports inode generations
// for the binary run.
type kernelProtectLab struct {
	tgids, images, budget *cebpf.Map
}

func newKernelProtectLab(t *testing.T, budget int64) *kernelProtectLab {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("attaching the protected-set programs needs root")
	}
	coll := packetObjectCollection(t, "wafio_trace.o")
	lab := &kernelProtectLab{tgids: coll.Maps["trace_protected_tgids"], images: coll.Maps["trace_protected_images"], budget: coll.Maps["trace_protected_budget"]}
	if lab.tgids == nil || lab.images == nil || lab.budget == nil {
		t.Fatal("wafio_trace.o lacks a protected-set map")
	}
	for name, funcName := range map[string]string{"sched_process_exec": "trace_sched_process_exec", "sched_process_exit": "trace_sched_process_exit"} {
		l, err := link.Tracepoint("sched", name, coll.Programs[funcName], nil)
		if err != nil {
			t.Skipf("cannot attach %s: %v", name, err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	for _, name := range []string{"sys_exit_setuid", "sys_exit_setreuid", "sys_exit_setresuid"} {
		l, err := link.Tracepoint("syscalls", name, coll.Programs["trace_"+name], nil)
		if err != nil {
			t.Skipf("cannot attach %s: %v", name, err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_fork", Program: coll.Programs["trace_sched_process_fork"]})
	if err != nil {
		t.Skipf("cannot attach sched_process_fork: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	lab.setBudget(t, budget)
	lab.protect(t, os.Getpid())
	return lab
}

func (l *kernelProtectLab) setBudget(t *testing.T, n int64) {
	t.Helper()
	for _, slot := range []uint32{protectedLimitSlot, protectedBudgetSlot} {
		if err := l.budget.Update(slot, n, cebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
}

func (l *kernelProtectLab) slot(t *testing.T, slot uint32) int64 {
	t.Helper()
	var v int64
	if err := l.budget.Lookup(slot, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (l *kernelProtectLab) protect(t *testing.T, pid int) {
	t.Helper()
	if err := l.tgids.Update(uint32(pid), startTicksOfPID(t, pid), cebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

func (l *kernelProtectLab) has(pid int) bool {
	var ticks uint64
	return l.tgids.Lookup(uint32(pid), &ticks) == nil
}

// waitFor polls cond until it holds or the time is up.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// An inherited entry survives the exec of a unit-bound image only inside the
// unit's cgroup, in the real kernel: the same image run by root in another
// cgroup, one level deeper, under another parent or in the cgroup of the test
// loses it. This is the check the C harness runs on mocked structures.
func TestKernelProtectedExecKeepsEntryOnlyInUnit(t *testing.T) {
	const system = "/sys/fs/cgroup"
	var fs unix.Statfs_t
	if err := unix.Statfs(system, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Skipf("%s is not a cgroup v2 mount", system)
	}
	if _, err := os.Stat(filepath.Join(system, "system.slice")); err != nil {
		t.Skip("no system.slice cgroup: not a systemd host")
	}
	binary, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := identityOf(binary, "/proc/self/mountinfo")
	if !ok {
		t.Skipf("%s has no identity here (a filesystem without inode generations, or not root's)", binary)
	}

	lab := newKernelProtectLab(t, 16)
	unit := "wafio-itest-" + strconv.Itoa(os.Getpid()) + ".service"
	img, ok := unitImage(unit)
	if !ok {
		t.Fatal("no image for the test unit")
	}
	if err := lab.images.Update(key, img, cebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	mkcg := func(path string) string {
		t.Helper()
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		// A cgroup goes away a moment after its last process does.
		t.Cleanup(func() { waitFor(2*time.Second, func() bool { return os.Remove(path) == nil }) })
		return path
	}
	slice := mkcg(filepath.Join(system, "wafio-itest-"+strconv.Itoa(os.Getpid())+".slice"))
	inUnit := mkcg(filepath.Join(system, "system.slice", unit))
	cases := []struct {
		name string
		cg   string // "" means the cgroup of the test
		keep bool
	}{
		{"inside its unit", inUnit, true},
		{"in another unit of system.slice", mkcg(filepath.Join(system, "system.slice", "wafio-itest-other-"+strconv.Itoa(os.Getpid())+".service")), false},
		{"in a sub-cgroup of its unit", mkcg(filepath.Join(inUnit, "sub")), false},
		{"in the unit name under another slice", mkcg(filepath.Join(slice, unit)), false},
		{"in the cgroup of the test", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binary, "30")
			if tc.cg != "" {
				fd, err := unix.Open(tc.cg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = unix.Close(fd) }() // read-only descriptor
				cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
			}
			if err := cmd.Start(); err != nil {
				t.Skipf("cannot start a process in %s: %v", tc.cg, err)
			}
			pid := cmd.Process.Pid
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			// The entry exists from the fork; the exec decides. A child that keeps
			// it proves the fork inserted it, which the others share.
			if tc.keep && !waitFor(5*time.Second, func() bool { return lab.has(pid) }) {
				t.Fatal("the child got no entry at fork")
			}
			time.Sleep(300 * time.Millisecond) // the exec has run, whatever it decided
			if got := lab.has(pid); got != tc.keep {
				t.Fatalf("entry after exec: %t, want %t", got, tc.keep)
			}
		})
	}
}

// A protected child that gives up root without exec keeps its entry only when
// the image it runs keeps it for any user, in the real kernel. setpriv switches
// to another user and then execs sleep, whose image is listed for any user, so
// only what setpriv's image says at the switch can drop the entry: the exec of
// sleep alone would keep it.
func TestKernelProtectedEntryDroppedWithRoot(t *testing.T) {
	find := func(name string) (path string, key protectedImageKey) {
		t.Helper()
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("no %s binary", name)
		}
		if path, err = filepath.EvalSymlinks(path); err != nil {
			t.Fatal(err)
		}
		key, ok := identityOf(path, "/proc/self/mountinfo")
		if !ok {
			t.Skipf("%s has no identity here (a filesystem without inode generations, or not root's)", path)
		}
		return path, key
	}
	setpriv, setprivKey := find("setpriv")
	sleep, sleepKey := find("sleep")

	const budget = 16
	lab := newKernelProtectLab(t, budget)
	if err := lab.images.Update(sleepKey, protectedImage{Flags: protectedImageAny}, cebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		flags uint64
		keep  bool
	}{
		{"setpriv image for root only", protectedImageRoot, false},
		{"setpriv image for any user", protectedImageAny, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := lab.images.Update(setprivKey, protectedImage{Flags: tc.flags}, cebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(setpriv, "--reuid=65534", "--regid=65534", "--clear-groups", sleep, "30")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			pid := cmd.Process.Pid
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			if !waitFor(5*time.Second, func() bool { return lab.has(pid) }) && tc.keep {
				t.Fatal("the child got no entry at fork")
			}
			time.Sleep(300 * time.Millisecond) // the switch and the exec of sleep have run
			if got := lab.has(pid); got != tc.keep {
				t.Fatalf("entry of the process that dropped root: %t, want %t", got, tc.keep)
			}
			if !tc.keep && !waitFor(2*time.Second, func() bool { return lab.slot(t, protectedBudgetSlot) == budget }) {
				t.Fatalf("the budget is %d, want the unit back (%d)", lab.slot(t, protectedBudgetSlot), budget)
			}
		})
	}
}

// The fork budget follows the entries in the map: a client that opens and
// closes connections as fast as sshd forks does not use it up, in the real
// kernel. Each child below is forked by a protected process, execs a file that
// is not listed (the entry is dropped) and exits.
func TestKernelProtectedBudgetSurvivesForkChurn(t *testing.T) {
	const budget = 8
	lab := newKernelProtectLab(t, budget)
	binary, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true binary")
	}
	for i := 0; i < 200; i++ {
		if err := exec.Command(binary).Run(); err != nil {
			t.Fatal(err)
		}
	}
	// Other children of PID 1 or of the processes the test inherited from may
	// be in flight; give them a moment to finish.
	if !waitFor(5*time.Second, func() bool { return lab.slot(t, protectedBudgetSlot) == budget }) {
		t.Fatalf("the budget is %d after 200 forks, want %d back", lab.slot(t, protectedBudgetSlot), budget)
	}
	if refused := lab.slot(t, protectedRefusedSlot); refused != 0 {
		t.Fatalf("%d forks of a protected process were refused", refused)
	}
	if limit := lab.slot(t, protectedLimitSlot); limit != budget {
		t.Fatalf("the limit moved to %d", limit)
	}

	// With the limit at 0 (no exec program in the agent, or no image map) the
	// kernel inherits nothing and the exits cannot raise it.
	lab.setBudget(t, 0)
	for i := 0; i < 20; i++ {
		if err := exec.Command(binary).Run(); err != nil {
			t.Fatal(err)
		}
	}
	if got := lab.slot(t, protectedBudgetSlot); got != 0 {
		t.Fatalf("the budget rose to %d with the limit at 0", got)
	}
	if lab.slot(t, protectedRefusedSlot) == 0 {
		t.Fatal("forks without a budget were not counted as refused")
	}
}
