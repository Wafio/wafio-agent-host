package ebpf

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestSplitProtectedList(t *testing.T) {
	for in, want := range map[string][]string{
		"":                       nil,
		"   ":                    nil,
		"nginx":                  {"nginx"},
		" nginx , haproxy,sshd ": {"nginx", "haproxy", "sshd"},
		// Empty items are kept so Validate reports them.
		"a,,b": {"a", "", "b"},
		"a,":   {"a", ""},
	} {
		if got := SplitProtectedList(in); !slices.Equal(got, want) {
			t.Errorf("SplitProtectedList(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProtectedProcessConfigValidate(t *testing.T) {
	valid := []ProtectedProcessConfig{
		{},
		{Names: []string{"nginx", " haproxy ", "my.daemon", "foo..bar"}},
		{ExePaths: []string{"/opt/acme/bin/agentd", "/usr/lib/postgresql/16/bin/postgres"}},
		{Names: []string{"nginx"}, ReplaceDefaults: true},
		{ExePaths: []string{"/opt/acme/bin/agentd"}, ReplaceDefaults: true},
	}
	for _, c := range valid {
		if err := c.Validate(); err != nil {
			t.Errorf("%+v rejected: %v", c, err)
		}
	}

	for _, tc := range []struct {
		name string
		cfg  ProtectedProcessConfig
		want string // substring of the error
	}{
		{"empty name", ProtectedProcessConfig{Names: []string{"nginx", " "}}, "name #2: empty entry"},
		{"name is path", ProtectedProcessConfig{Names: []string{"/usr/sbin/sshd"}}, "basename, not a path"},
		{"name traversal", ProtectedProcessConfig{Names: []string{".."}}, "path traversal"},
		{"name dot", ProtectedProcessConfig{Names: []string{"."}}, "path traversal"},
		{"name backslash", ProtectedProcessConfig{Names: []string{`a\b`}}, "basename, not a path"},
		{"name control", ProtectedProcessConfig{Names: []string{"ss\nhd"}}, "control characters"},
		{"name too long", ProtectedProcessConfig{Names: []string{strings.Repeat("n", 256)}}, "longer than 255"},
		{"empty exe", ProtectedProcessConfig{ExePaths: []string{""}}, "exe path #1: empty entry"},
		{"relative exe", ProtectedProcessConfig{ExePaths: []string{"bin/agentd"}}, "absolute"},
		{"exe traversal", ProtectedProcessConfig{ExePaths: []string{"/opt/acme/../../usr/bin/bash"}}, "path traversal"},
		{"exe trailing dotdot", ProtectedProcessConfig{ExePaths: []string{"/opt/acme/.."}}, "path traversal"},
		{"exe directory", ProtectedProcessConfig{ExePaths: []string{"/opt/acme/bin/"}}, "not a directory"},
		{"exe root", ProtectedProcessConfig{ExePaths: []string{"/"}}, "not a directory"},
		{"exe double slash", ProtectedProcessConfig{ExePaths: []string{"/opt//acme/agentd"}}, "canonical"},
		{"exe dot segment", ProtectedProcessConfig{ExePaths: []string{"/opt/./agentd"}}, "canonical"},
		{"exe control", ProtectedProcessConfig{ExePaths: []string{"/opt/a\x00d"}}, "control characters"},
		{"exe too long", ProtectedProcessConfig{ExePaths: []string{"/" + strings.Repeat("p", 4095)}}, "longer than 4095"},
		{"replace with nothing", ProtectedProcessConfig{ReplaceDefaults: true}, "replace defaults requested"},
		{"too many names", ProtectedProcessConfig{Names: slices.Repeat([]string{"n"}, maxProtectedEntries+1)}, "at most 256"},
	} {
		err := tc.cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Validate() = %v, want error containing %q", tc.name, err, tc.want)
		}
	}

	// Every problem is reported, not only the first.
	err := ProtectedProcessConfig{Names: []string{"a/b", ""}, ExePaths: []string{"rel"}}.Validate()
	if err == nil || strings.Count(err.Error(), "\n") != 2 {
		t.Errorf("want three joined errors, got %v", err)
	}
}

func TestProtectedProcessConfigEffective(t *testing.T) {
	withDefaults := func(extra ...string) []string {
		out := slices.Concat(DefaultProtectedProcessNames, extra)
		slices.Sort(out)
		return slices.Compact(out)
	}
	// The WAF agent's two install paths and systemd-networkd's two are built in, so they are in every list that keeps the defaults.
	const waf, wafBundle = "/usr/local/bin/wafio-waf-agent", "/opt/wafio/wafio-waf-agent"
	const networkd, networkdLib = "/usr/lib/systemd/systemd-networkd", "/lib/systemd/systemd-networkd"
	builtinExes := []string{networkdLib, wafBundle, networkd, waf}
	for _, tc := range []struct {
		name      string
		cfg       ProtectedProcessConfig
		wantNames []string
		wantExes  []string
	}{
		{"no config keeps built-ins", ProtectedProcessConfig{}, withDefaults(), builtinExes},
		{"names merged and de-duplicated",
			ProtectedProcessConfig{Names: []string{"envoy", " sshd ", "envoy"}},
			withDefaults("envoy"), builtinExes},
		{"invalid entries dropped",
			ProtectedProcessConfig{Names: []string{"bad/name", "", "haproxy"}, ExePaths: []string{"rel/x", "/opt/b", "/opt/a", "/opt/b", "/opt/../x"}},
			withDefaults("haproxy"), []string{networkdLib, "/opt/a", "/opt/b", wafBundle, networkd, waf}},
		{"configured copy of a built-in path is not doubled",
			ProtectedProcessConfig{ExePaths: []string{waf, wafBundle}},
			withDefaults(), builtinExes},
		{"replace drops built-ins",
			ProtectedProcessConfig{Names: []string{"haproxy"}, ReplaceDefaults: true},
			[]string{"haproxy"}, nil},
		{"replace with exe paths only",
			ProtectedProcessConfig{ExePaths: []string{"/opt/acme/bin/agentd"}, ReplaceDefaults: true},
			nil, []string{"/opt/acme/bin/agentd"}},
		// A configuration whose every entry is invalid never empties the set.
		{"replace with only invalid entries keeps built-ins",
			ProtectedProcessConfig{Names: []string{"a/b"}, ExePaths: []string{"rel"}, ReplaceDefaults: true},
			withDefaults(), builtinExes},
	} {
		if got := tc.cfg.EffectiveNames(); !slices.Equal(got, tc.wantNames) {
			t.Errorf("%s: EffectiveNames() = %q, want %q", tc.name, got, tc.wantNames)
		}
		if got := tc.cfg.EffectiveExePaths(); !slices.Equal(got, tc.wantExes) {
			t.Errorf("%s: EffectiveExePaths() = %q, want %q", tc.name, got, tc.wantExes)
		}
		s := NewProtectedProcessSetFromConfig(tc.cfg)
		if got := s.Names(); !slices.Equal(got, tc.wantNames) {
			t.Errorf("%s: set names %q, want %q", tc.name, got, tc.wantNames)
		}
		if got := s.ExePaths(); !slices.Equal(got, tc.wantExes) {
			t.Errorf("%s: set exe paths %q, want %q", tc.name, got, tc.wantExes)
		}
	}
	// The built-in list itself is never modified by merging.
	before := slices.Clone(DefaultProtectedProcessNames)
	_ = ProtectedProcessConfig{Names: []string{"zzz", "aaa"}}.EffectiveNames()
	if !slices.Equal(before, DefaultProtectedProcessNames) {
		t.Fatalf("DefaultProtectedProcessNames mutated: %q", DefaultProtectedProcessNames)
	}
}

func TestProtectedSetFromConfigMatching(t *testing.T) {
	merged := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{Names: []string{"haproxy"}, ExePaths: []string{"/opt/acme/bin/agentd"}})
	replaced := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{Names: []string{"haproxy"}, ReplaceDefaults: true})
	wafInUnit := hostRoot("/usr/local/bin/wafio-waf-agent", "wafio-waf-agent")
	wafInUnit.rootUIDs = triNo
	wafInUnit.cgroup = "/system.slice/wafio-waf-agent.service"
	wafInSession := wafInUnit
	wafInSession.cgroup = "/user.slice/user-1000.slice/session-3.scope"
	bundleWafInUnit := wafInUnit
	bundleWafInUnit.exe = "/opt/wafio/wafio-waf-agent"
	for _, tc := range []struct {
		name             string
		id               procIdentity
		merged, replaced bool
	}{
		{"built-in sshd", hostRoot("/usr/sbin/sshd", "sshd"), true, false},
		// The built-in WAF agent entry carries its unit; replacing the defaults drops both.
		{"built-in waf agent in its unit", wafInUnit, true, false},
		{"built-in waf agent outside its unit", wafInSession, false, false},
		{"built-in bundle waf agent in its unit", bundleWafInUnit, true, false},
		{"built-in nginx", hostRoot("/usr/sbin/nginx", "nginx"), true, false},
		{"configured name", hostRoot("/usr/sbin/haproxy", "haproxy"), true, true},
		{"configured exe", hostRoot("/opt/acme/bin/agentd", "agentd"), true, false},
		// Configured names get the same trust rules as the built-ins.
		{"configured name outside system dir", hostRoot("/tmp/haproxy", "haproxy"), false, false},
		{"built-in name outside system dir", hostRoot("/tmp/nginx", "nginx"), false, false},
		{"unrelated", hostRoot("/usr/bin/bash", "bash"), false, false},
	} {
		if got, _ := merged.matchIdentity(tc.id); got != tc.merged {
			t.Errorf("%s: merged set = %v, want %v", tc.name, got, tc.merged)
		}
		if got, _ := replaced.matchIdentity(tc.id); got != tc.replaced {
			t.Errorf("%s: replaced set = %v, want %v", tc.name, got, tc.replaced)
		}
	}
}

// Replacing the defaults drops the built-in WAF agent entry, but listing its
// path again must not skip the unit requirement.
func TestProtectedSetReplacedDefaultsKeepUnitRequirement(t *testing.T) {
	const exe = "/usr/local/bin/wafio-waf-agent"
	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{exe}, ReplaceDefaults: true})
	id := hostRoot(exe, "wafio-waf-agent")
	id.rootUIDs = triNo
	id.cgroup = "/system.slice/wafio-waf-agent.service"
	if ok, _ := s.matchIdentity(id); !ok {
		t.Error("built-in path in its unit not protected")
	}
	id.cgroup = "/user.slice/user-1000.slice/session-3.scope"
	if ok, _ := s.matchIdentity(id); ok {
		t.Error("built-in path in a session scope protected after replacing the defaults")
	}
}

func TestTraceManagerConfigProtectedConfig(t *testing.T) {
	cfg := TraceManagerConfig{
		ProtectedProcessNames:    []string{"haproxy"},
		ProtectedExePaths:        []string{"/opt/acme/bin/agentd"},
		ProtectedReplaceDefaults: true,
	}
	got := cfg.ProtectedConfig()
	if !slices.Equal(got.Names, cfg.ProtectedProcessNames) || !slices.Equal(got.ExePaths, cfg.ProtectedExePaths) || !got.ReplaceDefaults {
		t.Fatalf("ProtectedConfig() = %+v", got)
	}
}

func TestProtectedSetSummary(t *testing.T) {
	s := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{Names: []string{"haproxy"}, ExePaths: []string{"/opt/b", "/opt/a"}})
	got := s.Summary()
	want := "names=[containerd,dockerd,haproxy,kubelet,nginx,sshd,sshd-auth,sshd-session,systemd,systemd-executor,systemd-journald] exe_paths=[/lib/systemd/systemd-networkd,/opt/a,/opt/b,/opt/wafio/wafio-waf-agent,/usr/lib/systemd/systemd-networkd,/usr/local/bin/wafio-waf-agent] builtin_defaults=merged"
	if got != want {
		t.Errorf("Summary() = %q\nwant        %q", got, want)
	}
	r := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{Names: []string{"haproxy"}, ReplaceDefaults: true})
	if got := r.Summary(); got != "names=[haproxy] exe_paths=[] builtin_defaults=replaced" {
		t.Errorf("replaced Summary() = %q", got)
	}
	var nilSet *ProtectedProcessSet
	if got := nilSet.Summary(); got != "names=[] exe_paths=[] builtin_defaults=merged" {
		t.Errorf("nil Summary() = %q", got)
	}
}

func TestProtectedSelfCheckString(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    protectedSelfCheck
		want []string
		not  []string
	}{
		{
			"present",
			protectedSelfCheck{kernelSet: true, valueSize: 8, kernelTGIDs: 3, matched: 3},
			[]string{"protected-process self-check: kernel_set=present map=trace_protected_tgids value=start_ticks protected_tgids=3 matched_processes=3 userspace_guard=on"},
			[]string{"kernel_missing", "scan_error", "note=", "proc_access", "hint=", "untrusted_owner"},
		},
		{
			"identity links denied (no CAP_SYS_PTRACE)",
			protectedSelfCheck{kernelSet: true, valueSize: 8, procDenied: true},
			[]string{"protected_tgids=0 matched_processes=0 userspace_guard=degraded proc_access=denied", `hint="grant CAP_SYS_PTRACE`},
			[]string{"userspace_guard=on"},
		},
		{
			"legacy value",
			protectedSelfCheck{kernelSet: true, valueSize: 1, kernelTGIDs: 2, matched: 2},
			[]string{"value=presence_flag protected_tgids=2"},
			nil,
		},
		{
			"map overflow or update failure",
			protectedSelfCheck{kernelSet: true, valueSize: 8, kernelTGIDs: 1024, matched: 1030},
			[]string{"protected_tgids=1024", "matched_processes=1030", "kernel_missing=6"},
			nil,
		},
		{
			"absent",
			protectedSelfCheck{matched: 4},
			[]string{"protected-process self-check: kernel_set=absent map=trace_protected_tgids protected_tgids=0 matched_processes=4", "note="},
			[]string{"kernel_missing"},
		},
		{
			"untrusted owner",
			protectedSelfCheck{kernelSet: true, valueSize: 8, kernelTGIDs: 3, matched: 3, untrusted: []string{"/usr/local/bin", "/usr/local/bin/kubelet"}},
			[]string{" untrusted_owner=/usr/local/bin,/usr/local/bin/kubelet"},
			nil,
		},
		{
			"scan error",
			protectedSelfCheck{kernelSet: true, valueSize: 8, scanErr: errors.New("open /proc: permission denied")},
			[]string{"protected_tgids=0", `scan_error="open /proc: permission denied"`},
			[]string{"kernel_missing"},
		},
	} {
		got := tc.c.String()
		if strings.Contains(got, "\n") {
			t.Errorf("%s: self-check must be one line: %q", tc.name, got)
		}
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", tc.name, got, w)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(got, n) {
				t.Errorf("%s: %q must not contain %q", tc.name, got, n)
			}
		}
	}
}

// Shells and interpreters are accepted (an operator may have a reason) but
// named in a startup warning and on the self-check line: protecting one
// exempts every root process running it from Kill enforcement.
func TestProtectedSelfCheckWarning(t *testing.T) {
	if w := (protectedSelfCheck{kernelSet: true, valueSize: 8, matched: 3, kernelTGIDs: 3}).Warning(); w != "" {
		t.Fatalf("healthy self-check warns: %q", w)
	}
	w := protectedSelfCheck{kernelSet: true, valueSize: 8, procDenied: true}.Warning()
	if !strings.HasPrefix(w, "WARNING: ") || !strings.Contains(w, "CAP_SYS_PTRACE") || strings.Contains(w, "\n") {
		t.Fatalf("denied self-check warning = %q", w)
	}
	// A file others can write leaves a protected process unprotected: the
	// warning names the path and the fix, on a line of its own.
	w = protectedSelfCheck{kernelSet: true, valueSize: 8, matched: 3, kernelTGIDs: 3, untrusted: []string{"/usr/local/bin/kubelet"}}.Warning()
	if !strings.HasPrefix(w, "WARNING: ") || !strings.Contains(w, "/usr/local/bin/kubelet") || !strings.Contains(w, "make root the owner") || strings.Contains(w, "\n") {
		t.Fatalf("untrusted owner warning = %q", w)
	}
	both := protectedSelfCheck{kernelSet: true, valueSize: 8, procDenied: true, untrusted: []string{"/usr/local/bin/kubelet"}}.Warning()
	if lines := strings.Split(both, "\n"); len(lines) != 2 || !strings.Contains(lines[0], "CAP_SYS_PTRACE") || !strings.Contains(lines[1], "/usr/local/bin/kubelet") {
		t.Fatalf("two causes did not give two lines: %q", both)
	}
}

func TestProtectedRiskyEntries(t *testing.T) {
	for name, want := range map[string]bool{
		"bash": true, "sh": true, "busybox": true, "env": true, "python3": true,
		"python3.12": true, "perl5.36": true, "php8.2": true, "ruby": true, "node": true,
		"nginx": false, "php-fpm": false, "postgres": false, "pythonista": false, "sshd": false,
	} {
		if got := isRiskyProtectedName(name); got != want {
			t.Errorf("isRiskyProtectedName(%q) = %v, want %v", name, got, want)
		}
	}
	for _, n := range DefaultProtectedProcessNames {
		if isRiskyProtectedName(n) {
			t.Errorf("built-in protected name %q must not be flagged", n)
		}
	}

	set := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{
		Names:    []string{"haproxy", "bash"},
		ExePaths: []string{"/usr/bin/python3", "/opt/app/bin/server"},
	})
	if got := strings.Join(set.RiskyEntries(), ","); got != "/usr/bin/python3,bash" {
		t.Fatalf("RiskyEntries() = %q", got)
	}
	if w := set.RiskyWarning(); !strings.Contains(w, "WARNING") || !strings.Contains(w, "bash") || !strings.Contains(w, "/usr/bin/python3") {
		t.Fatalf("RiskyWarning() = %q", w)
	}
	line := protectedSelfCheck{kernelSet: true, valueSize: 8, risky: set.RiskyEntries()}.String()
	if !strings.Contains(line, " warning=risky_protected:/usr/bin/python3,bash") || strings.Contains(line, "\n") {
		t.Fatalf("self-check line lacks the warning token: %q", line)
	}

	safe := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{Names: []string{"haproxy"}})
	if safe.RiskyWarning() != "" || len(safe.RiskyEntries()) != 0 {
		t.Fatal("a daemon-only set must not warn")
	}
	var nilSet *ProtectedProcessSet
	if nilSet.RiskyEntries() != nil || nilSet.RiskyWarning() != "" {
		t.Fatal("nil set must not warn")
	}
	if l := (protectedSelfCheck{kernelSet: true, valueSize: 8}).String(); strings.Contains(l, "warning=") {
		t.Fatalf("no risky entries, no warning token: %q", l)
	}
}
