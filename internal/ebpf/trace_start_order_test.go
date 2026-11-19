package ebpf

import (
	"os"
	"strings"
	"testing"
)

// Start fills trace_protected_tgids and trace_protected_images (the first sync
// writes both) and sets the fork-insert budget before the first probe attaches,
// so events right after a restart are exe_verified like later ones and the exec
// program knows the trusted images from its first run; the self-check sync
// after attach runs too. Start is Linux-only, so the order is checked on the
// source.
func TestTraceStartFillsProtectedSetBeforeAttach(t *testing.T) {
	src, err := os.ReadFile("trace_manager.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "func (tm *TraceManager) Start(")
	if start < 0 {
		t.Fatal("Start not found")
	}
	body := s[start:]
	images := strings.Index(body, "coll.Maps[traceMapProtectedImages]")
	preSync := strings.Index(body, "tm.syncProtectedTGIDs()")
	attach := strings.Index(body, "link.Tracepoint(")
	if kp := strings.Index(body, "tm.attachKprobeTwin("); kp >= 0 && (attach < 0 || kp < attach) {
		attach = kp
	}
	attached := strings.Index(body, `"attached %d/%d tracepoints"`)
	selfCheck := strings.Index(body, "tm.runProtectedSelfCheck()")
	for name, at := range map[string]int{"protected images map": images, "syncProtectedTGIDs": preSync, "attached log": attached, "runProtectedSelfCheck": selfCheck} {
		if at < 0 {
			t.Fatalf("%s not found in Start", name)
		}
	}
	if attach < 0 {
		attach = attached
	}
	if images > preSync || preSync > attach {
		t.Fatalf("protected images map (%d) and the sync (%d) must come before the first attach (%d)", images, preSync, attach)
	}
	if selfCheck < attached {
		t.Fatal("the self-check sync must also run after attach")
	}

	// The tgid sync writes the images first: an entry it writes must never meet
	// an exec whose image the kernel does not know.
	kill, err := os.ReadFile("trace_kill_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	sync := string(kill)[strings.Index(string(kill), "func (tm *TraceManager) syncProtectedTGIDs("):]
	if img, tgids := strings.Index(sync, "tm.syncProtectedImages()"), strings.Index(sync, "tm.protectedMap.Update("); img < 0 || tgids < 0 || img > tgids {
		t.Fatalf("syncProtectedTGIDs must sync the images (%d) before it writes entries (%d)", img, tgids)
	}

	// Fork inheritance without the exec program would keep an entry through any
	// exec: the fork probe attaches only while the exec probe is linked.
	if !strings.Contains(body, `probe.name == "sched_process_fork" && tm.execKeep && !slices.Contains(tm.linkNames, "sched_process_exec")`) {
		t.Fatal("Start does not turn fork inheritance off when sched_process_exec is not attached")
	}
}

// With the fork budget set before attach, the
// exec and exit maintenance programs must attach before fork, or a child
// forked and exec'd into another image between the two attaches would keep
// an inherited protected entry.
func TestTraceProbesAttachExecAndExitBeforeFork(t *testing.T) {
	at := map[string]int{}
	for i, p := range traceProbes {
		at[p.name] = i
	}
	fork, ok := at["sched_process_fork"]
	if !ok {
		t.Fatal("sched_process_fork not in traceProbes")
	}
	for _, name := range []string{"sched_process_exec", "sched_process_exit"} {
		i, ok := at[name]
		if !ok {
			t.Fatalf("%s not in traceProbes", name)
		}
		if i > fork {
			t.Errorf("%s attaches after sched_process_fork", name)
		}
	}
}
