//go:build linux

package ebpf

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"slices"
	"strconv"
	"testing"
)

// The kernel holds open events for their result only while every attached
// open entry probe has its exit probe: one without it would keep an open
// waiting until the thread's next open or exit.
func TestOpenResultReady(t *testing.T) {
	for _, tc := range []struct {
		name     string
		attached []string
		want     bool
	}{
		{"nothing attached", nil, false},
		{"openat pair", []string{"sys_enter_openat", "sys_exit_openat"}, true},
		{"all four pairs", []string{"sys_enter_openat", "sys_exit_openat", "sys_enter_openat2", "sys_exit_openat2", "sys_enter_open", "sys_exit_open", "sys_enter_creat", "sys_exit_creat"}, true},
		{"no open and creat on this architecture", []string{"sys_enter_openat", "sys_exit_openat", "sys_enter_openat2", "sys_exit_openat2"}, true},
		{"entry without exit", []string{"sys_enter_openat"}, false},
		{"openat2 entry without exit", []string{"sys_enter_openat", "sys_exit_openat", "sys_enter_openat2"}, false},
		{"exit without entry", []string{"sys_exit_openat"}, false},
		{"exit of a dropped entry", []string{"sys_enter_openat", "sys_exit_openat", "sys_exit_creat"}, true},
		{"other probes only", []string{"sys_enter_execve", "sys_exit_execve"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := openResultReady(tc.attached); got != tc.want {
				t.Fatalf("openResultReady(%v) = %v, want %v", tc.attached, got, tc.want)
			}
		})
	}
}

// Every open syscall of the probe table has an entry and an exit probe, so
// armOpenResult has nothing to wait for that is never attached.
func TestOpenResultProbesPair(t *testing.T) {
	var names []string
	for _, p := range traceProbes {
		names = append(names, p.name)
	}
	for _, syscall := range openResultSyscalls {
		for _, side := range []string{"sys_enter_", "sys_exit_"} {
			found := false
			for _, n := range names {
				found = found || n == side+syscall
			}
			if !found {
				t.Errorf("probe %s%s missing from traceProbes", side, syscall)
			}
		}
	}
	if !openResultReady(names) {
		t.Error("the full probe table does not arm open results")
	}
}

// A kernel that rejects an exit probe at load drops only that program: the
// trace object stays, and open events carry no result.
func TestOpenResultExitProbesAreOptional(t *testing.T) {
	optional := optionalTracePrograms()
	for _, syscall := range openResultSyscalls {
		found := false
		for _, p := range traceProbes {
			if p.name != "sys_exit_"+syscall {
				continue
			}
			found = true
			if !slices.Contains(optional, p.funcName) {
				t.Errorf("%s is not optional at load", p.funcName)
			}
		}
		if !found {
			t.Errorf("sys_exit_%s missing from traceProbes", syscall)
		}
	}
}

// Start arms open results only after its last return of an error: a Start that
// fails (the ring reader, say) must not leave the manager reporting them.
func TestStartArmsOpenResultLast(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "trace_manager.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var start *ast.FuncDecl
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "Start" && fn.Recv != nil {
			start = fn
		}
	}
	if start == nil {
		t.Fatal("TraceManager.Start not found")
	}
	var armed, lastError token.Pos
	ast.Inspect(start.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false // a goroutine's returns are not Start's
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "armOpenResult" {
				armed = n.Pos()
			}
		case *ast.ReturnStmt:
			if len(n.Results) == 1 {
				if id, ok := n.Results[0].(*ast.Ident); ok && id.Name == "nil" {
					return true
				}
			}
			lastError = max(lastError, n.Pos())
		}
		return true
	})
	if armed == token.NoPos {
		t.Fatal("Start does not arm open results")
	}
	if armed < lastError {
		t.Errorf("armOpenResult at %s comes before a return of an error at %s", fset.Position(armed), fset.Position(lastError))
	}
}

// The Go side mirrors wafio_trace.h: a drifted counter index would sum another
// counter, a drifted flag would hide every result.
func TestOpenResultConstantsMatchHeader(t *testing.T) {
	header, err := os.ReadFile("bpf/wafio_trace.h")
	if err != nil {
		t.Fatal(err)
	}
	value := func(name string) uint32 {
		m := regexp.MustCompile(`(?m)^#define ` + name + `\s+(?:\(1u << (\d+)\)|(\d+))`).FindSubmatch(header)
		if m == nil {
			t.Fatalf("%s not defined in wafio_trace.h", name)
		}
		if len(m[1]) > 0 {
			n, _ := strconv.Atoi(string(m[1]))
			return 1 << n
		}
		n, _ := strconv.Atoi(string(m[2]))
		return uint32(n) //nolint:gosec // G115: small constant read from the header
	}
	for name, got := range map[string]uint32{
		"TRACE_OPEN_RESULT":     traceOpenResult,
		"TRACE_OPEN_NO_FULL":    traceOpenNoFull,
		"TRACE_OPEN_NO_NEXT":    traceOpenNoNext,
		"TRACE_OPEN_NO_EXIT":    traceOpenNoExit,
		"TRACE_OPEN_NO_RESTART": traceOpenNoRestart,
		"TRACE_EVT_OPEN_RESULT": traceEvtOpenResult,
	} {
		if want := value(name); got != want {
			t.Errorf("%s is %d in wafio_trace.h and %d in Go", name, want, got)
		}
	}
	if n := value("TRACE_OPEN_STATS"); n != traceOpenNoRestart+1 {
		t.Errorf("TRACE_OPEN_STATS is %d, the last counter is %d", n, traceOpenNoRestart)
	}
}
