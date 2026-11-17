package ebpf

import (
	"strings"
	"testing"
)

// The narrowing check that lets a kill policy skip kill_acknowledged
// used to accept any non-empty value. "match_uid 0" (every root daemon),
// "match_filename /" (every absolute path) and a two-letter comm term ("nc"
// also hits runc and rsync) passed as narrow and killed host-wide without the
// operator's acknowledgement.
func TestKillNarrowingRejectsWeakCriteria(t *testing.T) {
	cases := []struct {
		name   string
		policy EnforcementPolicy
		narrow bool
	}{
		{"uid 0 is every root daemon", EnforcementPolicy{MatchUID: uidPtr(0)}, false},
		{"uid 1000", EnforcementPolicy{MatchUID: uidPtr(1000)}, true},
		{"filename slash", EnforcementPolicy{MatchFilename: "/"}, false},
		{"filename slashes only", EnforcementPolicy{MatchFilename: "///"}, false},
		{"filename two chars", EnforcementPolicy{MatchFilename: "/t"}, false},
		{"filename one weak term broadens the list", EnforcementPolicy{MatchFilename: "/dev/shm/, /"}, false},
		// Directory prefixes every process path runs through.
		{"filename /tmp/", EnforcementPolicy{MatchFilename: "/tmp/"}, false},
		{"filename /usr/", EnforcementPolicy{MatchFilename: "/usr/"}, false},
		{"filename /bin", EnforcementPolicy{MatchFilename: "/bin"}, false},
		{"filename lib", EnforcementPolicy{MatchFilename: "lib"}, false},
		{"filename /usr/bin/", EnforcementPolicy{MatchFilename: "/usr/bin/"}, false},
		{"filename /usr/local/bin", EnforcementPolicy{MatchFilename: "/usr/local/bin"}, false},
		{"filename top-level unknown dir", EnforcementPolicy{MatchFilename: "/srv"}, false},
		{"filename /dev/shm/", EnforcementPolicy{MatchFilename: "/dev/shm/"}, true},
		{"filename /tmp/x", EnforcementPolicy{MatchFilename: "/tmp/.x"}, true},
		{"filename /var/log/", EnforcementPolicy{MatchFilename: "/var/log/"}, true},
		{"filename bare name", EnforcementPolicy{MatchFilename: "xmrig"}, true},
		{"comm nc", EnforcementPolicy{MatchComm: "nc"}, false},
		{"comm nc even exact", EnforcementPolicy{MatchComm: "nc", MatchCommMode: CommMatchExact}, false},
		{"comm one weak term broadens the list", EnforcementPolicy{MatchComm: "ncat, nc"}, false},
		{"comm only separators", EnforcementPolicy{MatchComm: " , ,"}, false},
		{"comm ncat", EnforcementPolicy{MatchComm: "ncat"}, true},
		{"comm xmrig list", EnforcementPolicy{MatchComm: "xmrig, minerd"}, true},
		{"port", EnforcementPolicy{MatchDestPort: "4444"}, true},
		{"dest ip", EnforcementPolicy{MatchDestIP: "198.51.100.7"}, true},
		{"weak comm with strong uid", EnforcementPolicy{MatchComm: "nc", MatchUID: uidPtr(1000)}, true},
		{"root with strong comm", EnforcementPolicy{MatchComm: "xmrig", MatchUID: uidPtr(0)}, true},
		{"root and slash", EnforcementPolicy{MatchFilename: "/", MatchUID: uidPtr(0)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.policy
			p.Name, p.Action, p.EventTypes = "k", "kill", []string{"openat"}
			if got := policyHasNarrowingMatch(p); got != tc.narrow {
				t.Fatalf("policyHasNarrowingMatch = %v, want %v", got, tc.narrow)
			}
			err := ValidateEnforcementPolicy(p)
			if tc.narrow && err != nil {
				t.Fatalf("narrow kill rejected: %v", err)
			}
			if !tc.narrow && (err == nil || !strings.Contains(err.Error(), "kill_acknowledged")) {
				t.Fatalf("weakly narrowed kill accepted without kill_acknowledged: err=%v", err)
			}
			p.KillAcknowledged = true
			if err := ValidateEnforcementPolicy(p); err != nil {
				t.Fatalf("acknowledged kill rejected: %v", err)
			}
		})
	}
}

// A control-plane bundle carrying a weakly narrowed, unacknowledged kill is
// applied as alert on the agent instead of killing every root process.
func TestDowngradeWeaklyNarrowedKill(t *testing.T) {
	p := EnforcementPolicy{ID: 1, Name: "root kill", Enabled: true, Action: "kill", MatchUID: uidPtr(0)}
	if !DowngradeUnacknowledgedBroadKill(&p) || p.Action != "alert" {
		t.Fatalf("uid-0 kill not downgraded: %+v", p)
	}
}

func TestCommMatchModes(t *testing.T) {
	cases := []struct {
		mode  string
		term  string
		comm  string
		match bool
	}{
		// word (default for new policies): the term is delimited by a
		// non-letter or the edge of the name.
		{CommMatchWord, "nc", "nc", true},
		{CommMatchWord, "nc", "nc.openbsd", true},
		{CommMatchWord, "nc", "runc", false},
		{CommMatchWord, "nc", "rsync", false},
		{CommMatchWord, "nc", "ncat", false},
		{CommMatchWord, "python", "python3", true},
		{CommMatchWord, "python", "python3.12", true},
		{CommMatchWord, "php", "php-fpm8.2", true},
		{CommMatchWord, "sh", "bash", false},
		{CommMatchWord, "sh", "sshd", false},
		{CommMatchWord, "xmrig", "XMRig", true},
		{CommMatchWord, "runc:[2:init]", "runc:[2:INIT]", true},
		// exact: the whole name, case-insensitive.
		{CommMatchExact, "nc", "nc", true},
		{CommMatchExact, "nc", "nc.openbsd", false},
		{CommMatchExact, "NCAT", "ncat", true},
		// A term longer than TASK_COMM_LEN-1 matches the truncated comm.
		{CommMatchExact, "systemd-journald", "systemd-journal", true},
		// substring: the legacy behaviour kept for existing policies.
		{CommMatchSubstring, "nc", "runc", true},
		{CommMatchSubstring, "nc", "rsync", true},
		{CommMatchSubstring, "sh", "bash", true},
	}
	pe := NewPolicyEngine()
	for _, tc := range cases {
		p := &EnforcementPolicy{Name: "m", Enabled: true, Action: "alert", MatchComm: tc.term, MatchCommMode: tc.mode}
		evt := TraceEvent{EventName: "connect", Comm: tc.comm}
		if got := pe.matchPolicy(p, evt); got != tc.match {
			t.Errorf("mode=%s term=%q comm=%q: match=%v, want %v", tc.mode, tc.term, tc.comm, got, tc.match)
		}
	}
}

// On execve the executed file's basename stands in for comm, under the same
// mode: a word policy for "nc" matches /usr/bin/nc but not /usr/sbin/runc.
func TestCommMatchModeAppliesToExecveBasename(t *testing.T) {
	pe := NewPolicyEngine()
	p := &EnforcementPolicy{Name: "nc", Enabled: true, Action: "alert", MatchComm: "nc", MatchCommMode: CommMatchWord}
	if !pe.matchPolicy(p, TraceEvent{EventName: "execve", Comm: "sh", Filename: "/usr/bin/nc"}) {
		t.Error("word policy missed execve of /usr/bin/nc")
	}
	if pe.matchPolicy(p, TraceEvent{EventName: "execve", Comm: "containerd-shim", Filename: "/usr/sbin/runc"}) {
		t.Error("word policy for nc matched execve of runc")
	}
}

// New policies default to word; a policy from a control-plane bundle that
// predates match_comm_mode keeps the substring semantics it was written for.
func TestCommMatchModeDefaults(t *testing.T) {
	pe := NewPolicyEngine()
	added := addPolicy(t, pe, EnforcementPolicy{Name: "new", Enabled: true, Action: "alert", MatchComm: "nc"})
	if added.MatchCommMode != CommMatchWord {
		t.Fatalf("new policy mode = %q, want %q", added.MatchCommMode, CommMatchWord)
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Comm: "runc"}); action != ActionMonitor {
		t.Fatal("new nc policy matched runc")
	}

	// An update without a mode keeps the stored one.
	updated, err := pe.UpdatePolicy(added.ID, EnforcementPolicy{Name: "new", Enabled: true, Action: "alert", MatchComm: "nc"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.MatchCommMode != CommMatchWord {
		t.Fatalf("update without mode changed it to %q", updated.MatchCommMode)
	}

	if err := pe.ReplacePolicies([]EnforcementPolicy{{ID: 9, Name: "legacy", Enabled: true, Action: "alert", MatchComm: "nc"}}); err != nil {
		t.Fatal(err)
	}
	got, err := pe.GetPolicy(9)
	if err != nil {
		t.Fatal(err)
	}
	if got.MatchCommMode != CommMatchSubstring {
		t.Fatalf("legacy bundle policy mode = %q, want %q", got.MatchCommMode, CommMatchSubstring)
	}
	if action, _ := pe.Evaluate(TraceEvent{EventName: "execve", Comm: "runc"}); action != ActionAlert {
		t.Fatal("legacy substring policy stopped matching runc")
	}
}

func TestCommMatchModeValidation(t *testing.T) {
	for _, mode := range []string{"", CommMatchExact, CommMatchWord, CommMatchSubstring} {
		if err := ValidateEnforcementPolicy(EnforcementPolicy{Name: "m", Action: "alert", MatchComm: "curl", MatchCommMode: mode}); err != nil {
			t.Errorf("mode %q rejected: %v", mode, err)
		}
	}
	if err := ValidateEnforcementPolicy(EnforcementPolicy{Name: "m", Action: "alert", MatchComm: "curl", MatchCommMode: "regex"}); err == nil {
		t.Error("unknown match_comm_mode accepted")
	}
}
