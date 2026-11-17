package ebpf

import (
	"fmt"
	"maps"
	"strings"
	"testing"
)

func nameSet(names ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}

// The kernel raises openat severity on an exact path only,
// so /etc/./shadow or "shadow" opened from /etc reached the kernel at INFO
// and, behind a flood, was dropped before userspace could clean the path and
// raise it to the HIGH a Kill policy waits for. The final component of every
// filename term of such a policy now routes an openat at any kernel severity.
func TestKillCandidateOpenNames(t *testing.T) {
	cases := []struct {
		name     string
		policies map[uint32]*EnforcementPolicy
		want     map[string]struct{}
	}{
		{"kill on shadow above info", policySet(EnforcementPolicy{Enabled: true, Action: "kill", EventTypes: []string{"openat"}, MinSeverity: "high", MatchFilename: "/etc/shadow"}),
			nameSet("shadow")},
		{"every term, lowercased, trailing slash is the directory", policySet(EnforcementPolicy{Enabled: true, Action: "kill", MinSeverity: "medium", MatchFilename: "/etc/Shadow, /etc/sudoers.d/ ,passwd"}),
			nameSet("shadow", "sudoers.d", "passwd")},
		{"at info every openat is routed by type: no names", policySet(EnforcementPolicy{Enabled: true, Action: "kill", EventTypes: []string{"openat"}, MatchFilename: "/etc/shadow"}),
			nameSet()},
		{"not an openat policy", policySet(EnforcementPolicy{Enabled: true, Action: "kill", EventTypes: []string{"unlinkat"}, MinSeverity: "high", MatchFilename: "/etc/shadow"}),
			nameSet()},
		{"alert, disabled, no filename", policySet(
			EnforcementPolicy{Enabled: true, Action: "alert", MinSeverity: "high", MatchFilename: "/etc/shadow"},
			EnforcementPolicy{Enabled: false, Action: "kill", MinSeverity: "high", MatchFilename: "/etc/shadow"},
			EnforcementPolicy{Enabled: true, Action: "kill", MinSeverity: "high", MatchComm: "cat"},
		), nameSet()},
		{"root, dot and empty terms name nothing", policySet(EnforcementPolicy{Enabled: true, Action: "kill", MinSeverity: "high", MatchFilename: "/, ., .., ,/etc/.."}),
			nameSet()},
	}
	for _, tc := range cases {
		if got := killCandidateOpenNames(tc.policies); !maps.Equal(got, tc.want) {
			t.Errorf("%s: names = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The engine hands the names along with the type routes.
func TestKillCandidateRoutingCarriesOpenNames(t *testing.T) {
	pe := NewPolicyEngine()
	var last killRoutes
	pe.SetKillCandidateRouting(func(r killRoutes) { last = r })
	addPolicy(t, pe, EnforcementPolicy{Name: "shadow", Enabled: true, Action: "kill", EventTypes: []string{"openat"}, MinSeverity: "high", MatchFilename: "/etc/shadow"})
	if !maps.Equal(last.OpenNames, nameSet("shadow")) || last.Types[TraceOpen] != SevHigh {
		t.Fatalf("routes = %+v", last)
	}
}

func TestDeferredRequestDone(t *testing.T) {
	cases := []struct {
		state        uint64
		result       int32
		expires, now uint64
		want         bool
	}{
		{2, 0, 100, 50, true},                                           // completed
		{2, -3, 100, 50, true},                                          // completed with an error
		{2, deferredResultPending, 100, 500, false},                     // state visible before the result
		{1, deferredResultPending, 100, 500, false},                     // claimed, still running
		{1, deferredResultPending, 100, 100 + deferredClaimGrace, true}, // claim abandoned (element reused)
		{0, deferredResultPending, 100, 50, false},                      // pending
		{0, deferredResultPending, 100, 100, true},                      // never claimed, expired
	}
	for _, tc := range cases {
		if got := deferredRequestDone(tc.state, tc.result, tc.expires, tc.now); got != tc.want {
			t.Errorf("state=%d result=%d expires=%d now=%d: done=%v, want %v", tc.state, tc.result, tc.expires, tc.now, got, tc.want)
		}
	}
}

// traceNameHash must equal the kernel's trace_final_name_hash (checked
// against the C code in TestTracePriorityRouting); fixed vectors guard the
// Go side on its own.
func TestTraceNameHashVectors(t *testing.T) {
	if got := traceNameHash(""); got != 0xcbf29ce484222325 {
		t.Errorf("empty = %#x", got)
	}
	if got := traceNameHash("a"); got != 0xaf63dc4c8601ec8c { // FNV-1a 64("a")
		t.Errorf(`"a" = %#x`, got)
	}
	if traceNameHash("SHADOW") != traceNameHash("shadow") {
		t.Error("ASCII case must not change the hash")
	}
	if traceNameHash("shadow") == traceNameHash("gshadow") {
		t.Error("distinct names collide")
	}
}

// goNameHashes renders traceNameHash for names the C harness also hashes.
func goNameHashes(paths ...string) string {
	var b strings.Builder
	for _, p := range paths {
		name := p
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			name = p[i+1:]
		}
		fmt.Fprintf(&b, "%s %016x\n", p, traceNameHash(name))
	}
	return b.String()
}
