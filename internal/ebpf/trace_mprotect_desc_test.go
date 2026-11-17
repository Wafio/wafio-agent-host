package ebpf

import "testing"

// RWX is what JIT runtimes do as well as shellcode loaders; the description
// must not call every such event shellcode (migration 000113 downgrades the
// JIT runtimes by name).
func TestMprotectDescription(t *testing.T) {
	for prot, want := range map[uint32]string{
		7: "mprotect(RWX) — W^X violation (JIT runtimes do this; shellcode indicator otherwise)",
		6: "mprotect(WX) — W^X violation (JIT runtimes do this; shellcode indicator otherwise)",
		5: "mprotect(RX) — memory made executable",
	} {
		if got := buildDescription(TraceEvent{EventType: TraceMprotect, Flags: prot}); got != want {
			t.Errorf("prot=%d: %q, want %q", prot, got, want)
		}
	}
}
