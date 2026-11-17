package agent

import (
	"slices"
	"strings"
	"testing"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadProtectedProcessesFromEnv(t *testing.T) {
	cfg := DefaultHostConfig()
	err := cfg.LoadProtectedProcesses(envMap(map[string]string{
		EnvProtectedProcesses:       " nginx, haproxy ",
		EnvProtectedExePaths:        "/opt/acme/bin/agentd,/usr/lib/postgresql/16/bin/postgres",
		EnvProtectedReplaceDefaults: "false",
	}), ProtectedFlagsSet{})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"nginx", "haproxy"}; !slices.Equal(cfg.ProtectedProcessNames, want) {
		t.Errorf("names %q, want %q", cfg.ProtectedProcessNames, want)
	}
	if want := []string{"/opt/acme/bin/agentd", "/usr/lib/postgresql/16/bin/postgres"}; !slices.Equal(cfg.ProtectedExePaths, want) {
		t.Errorf("exe paths %q, want %q", cfg.ProtectedExePaths, want)
	}
	if cfg.ProtectedReplaceDefaults {
		t.Error("replace defaults set from \"false\"")
	}
	// Configured names extend the built-ins.
	names := cfg.ProtectedProcessConfig().EffectiveNames()
	for _, n := range append([]string{"nginx", "haproxy"}, wafebpf.DefaultProtectedProcessNames...) {
		if !slices.Contains(names, n) {
			t.Errorf("effective names %q lack %q", names, n)
		}
	}
}

func TestLoadProtectedProcessesFlagsWin(t *testing.T) {
	cfg := DefaultHostConfig()
	cfg.ProtectedProcessNames = []string{"nginx", " haproxy"} // pflag keeps the space after a comma
	cfg.ProtectedExePaths = nil                               // flag given as --protected-exe-paths=""
	err := cfg.LoadProtectedProcesses(envMap(map[string]string{
		EnvProtectedProcesses:       "from-env",
		EnvProtectedExePaths:        "/opt/from/env",
		EnvProtectedReplaceDefaults: "not-a-bool", // ignored: the flag was given
	}), ProtectedFlagsSet{Names: true, ExePaths: true, ReplaceDefaults: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"nginx", "haproxy"}; !slices.Equal(cfg.ProtectedProcessNames, want) {
		t.Errorf("names %q, want %q", cfg.ProtectedProcessNames, want)
	}
	if len(cfg.ProtectedExePaths) != 0 {
		t.Errorf("explicitly empty flag replaced by env: %q", cfg.ProtectedExePaths)
	}
}

func TestLoadProtectedProcessesBlankEnvKeepsConfig(t *testing.T) {
	cfg := DefaultHostConfig()
	cfg.ProtectedProcessNames = []string{"nginx"}
	if err := cfg.LoadProtectedProcesses(envMap(map[string]string{EnvProtectedProcesses: "  "}), ProtectedFlagsSet{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.ProtectedProcessNames, []string{"nginx"}) {
		t.Errorf("blank env cleared configured names: %q", cfg.ProtectedProcessNames)
	}
	cfg = DefaultHostConfig()
	if err := cfg.LoadProtectedProcesses(envMap(nil), ProtectedFlagsSet{}); err != nil {
		t.Fatalf("no configuration at all must be valid: %v", err)
	}
	if got := cfg.ProtectedProcessConfig().EffectiveNames(); len(got) != len(wafebpf.DefaultProtectedProcessNames) {
		t.Errorf("unconfigured agent effective names %q, want the built-ins", got)
	}
}

func TestLoadProtectedProcessesReplaceDefaults(t *testing.T) {
	cfg := DefaultHostConfig()
	err := cfg.LoadProtectedProcesses(envMap(map[string]string{
		EnvProtectedProcesses:       "nginx",
		EnvProtectedReplaceDefaults: "true",
	}), ProtectedFlagsSet{})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ProtectedProcessConfig().EffectiveNames(); !slices.Equal(got, []string{"nginx"}) {
		t.Errorf("replaced effective names %q, want [nginx]", got)
	}
}

func TestLoadProtectedProcessesRejectsInvalid(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"bad bool", map[string]string{EnvProtectedReplaceDefaults: "yes please"}, EnvProtectedReplaceDefaults},
		{"empty item", map[string]string{EnvProtectedProcesses: "nginx,,haproxy"}, "empty entry"},
		{"name is a path", map[string]string{EnvProtectedProcesses: "/usr/sbin/nginx"}, "not a path"},
		{"relative exe", map[string]string{EnvProtectedExePaths: "opt/agentd"}, "absolute"},
		{"exe traversal", map[string]string{EnvProtectedExePaths: "/opt/acme/../../bin/sh"}, "path traversal"},
		{"replace with nothing", map[string]string{EnvProtectedReplaceDefaults: "1"}, "replace defaults"},
	} {
		cfg := DefaultHostConfig()
		err := cfg.LoadProtectedProcesses(envMap(tc.env), ProtectedFlagsSet{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.want)
		}
	}
	// A flag-supplied list is validated the same way.
	cfg := DefaultHostConfig()
	cfg.ProtectedExePaths = []string{"/opt/ok", "relative"}
	if err := cfg.LoadProtectedProcesses(envMap(nil), ProtectedFlagsSet{ExePaths: true}); err == nil {
		t.Error("invalid flag exe path accepted")
	}
}
