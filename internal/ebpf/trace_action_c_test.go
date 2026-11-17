package ebpf

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The userspace action constants and the TRACE_ACTION_*
// defines the kernel programs compile against must agree exactly. A silent
// mismatch makes userspace read a kernel "kill" as something else (or the
// other way round) when it decodes trace_enforce_map and events.
func TestTraceActionConstantsMatchCHeaders(t *testing.T) {
	want := map[string]uint32{
		"TRACE_ACTION_MONITOR":  ActionMonitor,
		"TRACE_ACTION_ALERT":    ActionAlert,
		"TRACE_ACTION_KILL":     ActionKill,
		"TRACE_ACTION_SIMULATE": ActionSimulate,
		"TRACE_ACTION_BLOCK":    ActionBlock,
	}
	define := regexp.MustCompile(`(?m)^\s*#define\s+(TRACE_ACTION_[A-Z_]+)\s+(\d+)\b`)
	// wafio_lsm.c carries its own copy of the defines (it does not include
	// wafio_trace.h), so both sources are checked.
	for _, file := range []string{"bpf/wafio_trace.h", "bpf/wafio_lsm.c"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, m := range define.FindAllStringSubmatch(string(src), -1) {
			name := m[1]
			v, err := strconv.ParseUint(m[2], 10, 32)
			if err != nil {
				t.Fatalf("%s: %s = %q", file, name, m[2])
			}
			goVal, ok := want[name]
			if !ok {
				t.Errorf("%s defines %s = %d with no Go counterpart", file, name, v)
				continue
			}
			if uint32(v) != goVal {
				t.Errorf("%s: %s = %d, Go constant = %d", file, name, v, goVal)
			}
			seen[name] = true
		}
		// The four actions must be defined in every source.
		for _, name := range []string{"TRACE_ACTION_MONITOR", "TRACE_ACTION_ALERT", "TRACE_ACTION_KILL", "TRACE_ACTION_SIMULATE"} {
			if !seen[name] {
				t.Errorf("%s does not define %s", file, name)
			}
		}
	}
	// Names userspace shows for each action are distinct.
	names := map[string]uint32{}
	for _, a := range []uint32{ActionMonitor, ActionAlert, ActionKill, ActionSimulate, ActionBlock} {
		n := actionName(a)
		if prev, dup := names[n]; dup || n == "" {
			t.Errorf("action %d name %q collides with %d", a, n, prev)
		}
		names[n] = a
	}
}
