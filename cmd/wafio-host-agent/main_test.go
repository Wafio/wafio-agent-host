package main

import (
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/wafio/wafio-agent-host/internal/agent"
)

// The protected-process flags parse into the agent config and, being set,
// win over the environment.
func TestProtectedProcessFlags(t *testing.T) {
	saved := cfg
	t.Cleanup(func() { cfg = saved })

	fs := rootCmd.Flags()
	if err := fs.Parse([]string{
		"--" + flagProtectedProcesses, "nginx, haproxy",
		"--" + flagProtectedExePaths + "=/opt/acme/bin/agentd",
	}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		agent.EnvProtectedProcesses:       "from-env",
		agent.EnvProtectedReplaceDefaults: "true",
	}
	err := cfg.LoadProtectedProcesses(func(k string) string { return env[k] }, agent.ProtectedFlagsSet{
		Names:           fs.Changed(flagProtectedProcesses),
		ExePaths:        fs.Changed(flagProtectedExePaths),
		ReplaceDefaults: fs.Changed(flagProtectedReplaceDefaults),
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"nginx", "haproxy"}; !slices.Equal(cfg.ProtectedProcessNames, want) {
		t.Errorf("names %q, want %q", cfg.ProtectedProcessNames, want)
	}
	if want := []string{"/opt/acme/bin/agentd"}; !slices.Equal(cfg.ProtectedExePaths, want) {
		t.Errorf("exe paths %q, want %q", cfg.ProtectedExePaths, want)
	}
	// The replace flag was not given, so the environment decides it.
	if !cfg.ProtectedReplaceDefaults {
		t.Error("replace-defaults env fallback not applied")
	}
}

// The help names the transport the agent uses: gRPC with mutual TLS, with HTTP
// push to --server-url only as the fallback. --agent-api-key stays declared so
// an old unit file starts, and its help says the control plane ignores it.
func TestHelpDescribesTheTransport(t *testing.T) {
	for _, want := range []string{"gRPC", "mutual TLS", "falls back to HTTP push to --server-url"} {
		if !strings.Contains(rootCmd.Long, want) {
			t.Errorf("long description lacks %q", want)
		}
	}
	if strings.Contains(rootCmd.Long, "HMAC") {
		t.Error("long description still names HMAC-authenticated HTTP")
	}
	fs := rootCmd.Flags()
	if f := fs.Lookup("server-url"); f == nil || !strings.Contains(f.Usage, "fallback") || strings.Contains(f.Usage, "enables telemetry push") {
		t.Errorf("--server-url help: %+v", f)
	}
	f := fs.Lookup("agent-api-key")
	if f == nil || f.Hidden || !strings.Contains(f.Usage, "DEPRECATED") || !strings.Contains(f.Usage, "ignores") {
		t.Errorf("--agent-api-key must stay declared and visible with a deprecation note: %+v", f)
	}
}

// fetch-data on the host agent downloads the GeoIP country database only: a
// WAF profile or another component is refused before anything is downloaded.
func TestHostFetchDataRefusesWAFComponents(t *testing.T) {
	savedProfile, savedOnly := hostFetchProfile, hostFetchOnly
	t.Cleanup(func() { hostFetchProfile, hostFetchOnly = savedProfile, savedOnly })

	for _, tc := range []struct{ profile, only string }{
		{"agent", ""},
		{"all", ""},
		{"host-agent", "crs"},
		{"host-agent", "geoip-country,malware"},
	} {
		hostFetchProfile, hostFetchOnly = tc.profile, tc.only
		if err := runHostFetchData(nil, nil); err == nil {
			t.Errorf("profile %q only %q: want an error", tc.profile, tc.only)
		}
	}
}

// --ebpf-map-scale parses into the agent config and, being set, wins over
// WAFIO_EBPF_MAP_SCALE; without it the environment decides.
func TestMapScaleFlagBeatsEnv(t *testing.T) {
	saved := cfg
	t.Cleanup(func() { cfg = saved })
	fs := rootCmd.Flags()
	t.Cleanup(func() {
		_ = fs.Set(flagMapScale, "auto")
		fs.Lookup(flagMapScale).Changed = false
	})
	t.Setenv(agent.EnvEBPFMapScale, "0.25")

	if err := cfg.LoadMapScale(os.Getenv, fs.Changed(flagMapScale)); err != nil || cfg.EBPFMapScale != "0.25" {
		t.Fatalf("env only: scale %q, error %v, want 0.25", cfg.EBPFMapScale, err)
	}
	if err := fs.Parse([]string{"--" + flagMapScale + "=0.5"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.LoadMapScale(os.Getenv, fs.Changed(flagMapScale)); err != nil || cfg.EBPFMapScale != "0.5" {
		t.Fatalf("flag and env: scale %q, error %v, want 0.5", cfg.EBPFMapScale, err)
	}
}

// An invalid value stops the start before anything is loaded.
func TestInvalidMapScaleStopsTheStart(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("run stops on the OS check first")
	}
	saved := cfg
	t.Cleanup(func() { cfg = saved })
	t.Setenv(agent.EnvEBPFMapScale, "1.5")
	err := run(rootCmd, nil)
	want := `invalid --ebpf-map-scale "1.5" (or WAFIO_EBPF_MAP_SCALE): want auto or a number above 0 and at most 1`
	if err == nil || err.Error() != want {
		t.Fatalf("run returned %v, want %q", err, want)
	}
}
