package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
)

// A bundle the lockout guard rejects is acknowledged as
// "apply refused (<code>)" and never replaces the last good policy.
func TestRefusedBundleKeepsLastGoodPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "last-good.json")
	t.Setenv(envFirewallStateFile, path)

	// Accepted (empty state: nothing to write, no manager needed) → saved.
	if err := applyEBPFBundle([]byte(`{"ebpf_state":{}}`), 5); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("last good not saved: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("last good file mode: %v %v", fi.Mode(), err)
	}
	if info := currentPolicySource.Load(); info == nil || info.Source != "live" || info.Generation != 5 {
		t.Fatalf("policy source after a live apply: %+v", info)
	}

	// Refused: unknown action, and ingress Deny All with only 80/udp.
	for payload, code := range map[string]string{
		`{"ebpf_state":{"port_policies":[{"port":22,"proto":"tcp","direction":"ingress","action":"Allow"}]}}`: "PORT_POLICY_INVALID",
		`{"ebpf_state":{"config":{"global":{"enable_conntrack":true}},"port_policy_config":{"enabled":true,"default_ingress":"deny","default_egress":"allow"},` +
			`"port_policies":[{"port":80,"proto":"udp","direction":"ingress","action":"allow"}]}}`: "SSH_ALLOW_REQUIRED",
		`{"ebpf_state":{"port_policies":"nope"}}`: "STATE_INVALID",
	} {
		err := applyEBPFBundle([]byte(payload), 6)
		if err == nil || !strings.HasPrefix(err.Error(), applyRefusedPrefix+code+")") {
			t.Fatalf("%s: %v, want apply refused (%s)", payload, err, code)
		}
	}
	if after, _ := os.ReadFile(path); string(after) != string(saved) {
		t.Fatalf("refused bundle replaced the last good policy: %q", after)
	}
	rec, got, err := loadLastGoodFirewall()
	if err != nil || got != path || string(rec.State) != `{}` || rec.Generation != 5 {
		t.Fatalf("load: %+v %q %v", rec, got, err)
	}
}

func TestLastGoodFallsBackToSecondPath(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "file-not-dir")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := defaultFirewallStateFiles
	t.Cleanup(func() { defaultFirewallStateFiles = old })
	defaultFirewallStateFiles = []string{filepath.Join(blocked, "x.json"), filepath.Join(dir, "run", "x.json")}
	t.Setenv(envFirewallStateFile, "")
	saveLastGoodFirewall([]byte(`{"a":1}`), 3)
	rec, path, err := loadLastGoodFirewall()
	if err != nil || path != defaultFirewallStateFiles[1] || string(rec.State) != `{"a":1}` {
		t.Fatalf("fallback: %+v %q %v", rec, path, err)
	}
}

// With records in /var/lib and /run, the newer one wins —
// higher generation first, then the later save.
func TestLastGoodPrefersNewerRecord(t *testing.T) {
	dir := t.TempDir()
	old := defaultFirewallStateFiles
	t.Cleanup(func() { defaultFirewallStateFiles = old })
	defaultFirewallStateFiles = []string{filepath.Join(dir, "lib.json"), filepath.Join(dir, "run.json")}
	t.Setenv(envFirewallStateFile, "")
	write := func(path string, gen int64, at time.Time, state string) {
		t.Helper()
		b, _ := json.Marshal(savedFirewall{Version: 1, Generation: gen, SavedAt: at, State: json.RawMessage(state)})
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	write(defaultFirewallStateFiles[0], 7, now, `{"from":"lib"}`)
	write(defaultFirewallStateFiles[1], 9, now.Add(-time.Hour), `{"from":"run"}`)
	if rec, _, _ := loadLastGoodFirewall(); rec == nil || rec.Generation != 9 {
		t.Fatalf("higher generation must win: %+v", rec)
	}
	write(defaultFirewallStateFiles[0], 9, now, `{"from":"lib"}`)
	if rec, path, _ := loadLastGoodFirewall(); rec == nil || path != defaultFirewallStateFiles[0] {
		t.Fatalf("same generation: later save must win: %q", path)
	}
	if err := os.WriteFile(defaultFirewallStateFiles[0], []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec, path, err := loadLastGoodFirewall(); err != nil || path != defaultFirewallStateFiles[1] || rec == nil {
		t.Fatalf("corrupt record must be skipped: %q %v", path, err)
	}
}

// The record keeps the pinned control-plane endpoints, and a change of
// endpoints is written back.
func TestLastGoodKeepsControlPlaneEndpoints(t *testing.T) {
	t.Setenv(envFirewallStateFile, filepath.Join(t.TempDir(), "s.json"))
	pinnedCPEndpoints.Store(nil)
	t.Cleanup(func() { pinnedCPEndpoints.Store(nil) })
	eps := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:9090"), netip.MustParseAddrPort("[2001:db8::9]:9090")}
	pinnedCPEndpoints.Store(&eps)
	saveLastGoodFirewall([]byte(`{}`), 1)
	rec, _, err := loadLastGoodFirewall()
	if err != nil || !slices.Equal(rec.endpoints(), eps) {
		t.Fatalf("saved endpoints %+v %v", rec, err)
	}
	moved := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.4:9090")}
	updateSavedControlPlane(moved)
	if rec, _, _ := loadLastGoodFirewall(); !slices.Equal(rec.endpoints(), moved) || rec.Generation != 1 {
		t.Fatalf("updated endpoints %+v", rec)
	}
}

// Without pinned endpoints, egress Deny All needs DNS; the start-up
// restore relaxes a saved egress Deny All for DNS until the endpoints are
// pinned, and the guard refuses the unrelaxed state meanwhile.
func TestEgressDenyNeedsPinnedControlPlaneOrDNS(t *testing.T) {
	raw := json.RawMessage(`{"config":{"global":{"enable_conntrack":true}},` +
		`"port_policy_config":{"enabled":true,"default_ingress":"allow","default_egress":"deny"},` +
		`"port_policies":[{"port":443,"proto":"tcp","direction":"egress","action":"allow"}]}`)
	var s ebpfDesiredState
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	env := firewallEnv{exemptions: true, controlPlaneUnpinned: true}
	if _, err := validateEBPFStateWith(&s, env); !errors.Is(err, wafebpf.ErrEgressDenyUnpinned) {
		t.Fatalf("unpinned egress deny without DNS accepted: %v", err)
	}
	relaxed, ok := relaxEgressForDNS(raw)
	if !ok {
		t.Fatal("egress deny not relaxed")
	}
	var r ebpfDesiredState
	if err := json.Unmarshal(relaxed, &r); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEBPFStateWith(&r, env); err != nil {
		t.Fatalf("relaxed state refused: %v", err)
	}
	env.controlPlaneUnpinned = false
	if _, err := validateEBPFStateWith(&s, env); err != nil {
		t.Fatalf("pinned egress deny refused: %v", err)
	}
	if _, ok := relaxEgressForDNS(json.RawMessage(`{"port_policy_config":{"enabled":true,"default_egress":"allow"}}`)); ok {
		t.Fatal("egress allow relaxed")
	}
}

// An empty saved record restores as "saved"; nothing saved → "default".
func TestRestoreReportsPolicySource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	t.Setenv(envFirewallStateFile, path)
	restoreLastGoodFirewall(context.Background(), "192.0.2.1:9090")
	if !strings.Contains(policySourceJSON(), `"source":"default"`) {
		t.Fatalf("nothing saved: %s", policySourceJSON())
	}
	saveLastGoodFirewall([]byte(`{}`), 4)
	restoreLastGoodFirewall(context.Background(), "192.0.2.1:9090")
	if got := policySourceJSON(); !strings.Contains(got, `"source":"saved"`) || !strings.Contains(got, `"generation":"4"`) ||
		strings.Contains(got, "dns_relaxed") {
		t.Fatalf("restored: %s", got)
	}
	setPolicySource(policySourceInfo{Source: "saved", Generation: 4, DNSRelaxed: true})
	if got := policySourceJSON(); !strings.Contains(got, `"dns_relaxed":true`) {
		t.Fatalf("relaxed restore not reported: %s", got)
	}
}

type fakeCPSetter struct {
	err   error
	calls atomic.Int32
}

func (f *fakeCPSetter) SetControlPlaneEndpoints([]netip.AddrPort) error {
	f.calls.Add(1)
	return f.err
}

// The stream dials exactly the endpoints in the map; a
// failed resolution keeps the previous ones instead of falling back to DNS.
func TestPinnedControlPlaneEndpoints(t *testing.T) {
	t.Setenv(envFirewallStateFile, filepath.Join(t.TempDir(), "s.json"))
	pinnedCPEndpoints.Store(nil)
	t.Cleanup(func() { pinnedCPEndpoints.Store(nil) })
	ok := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}
	dnsDown := func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("egress deny") }
	set := &fakeCPSetter{}
	want := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:9090")}
	if got := refreshPinnedEndpoints(context.Background(), "cp.example.com:9090", set, ok); !slices.Equal(got, want) {
		t.Fatalf("resolved: %v", got)
	}
	if got := refreshPinnedEndpoints(context.Background(), "cp.example.com:9090", set, dnsDown); !slices.Equal(got, want) {
		t.Fatalf("DNS down must keep the pinned endpoints: %v", got)
	}
	if got := refreshPinnedEndpoints(context.Background(), "cp.example.com:9090", &fakeCPSetter{err: wafebpf.ErrNoControlPlaneMap}, ok); got != nil {
		t.Fatalf("no map, no pinning: %v", got)
	}

	target, opts := controlPlaneDialTarget("dns:///cp.example.com:9090", want)
	if target != "passthrough:///cp.example.com:9090" || len(opts) != 1 {
		t.Fatalf("pinned target %q opts %d", target, len(opts))
	}
	if target, opts := controlPlaneDialTarget("cp.example.com:9090", nil); target != "cp.example.com:9090" || opts != nil {
		t.Fatalf("unpinned target %q", target)
	}
}

func TestPinnedDialerTriesEndpointsInOrder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := netip.MustParseAddrPort(dead.Addr().String())
	_ = dead.Close() // nothing listens here any more
	live := netip.MustParseAddrPort(ln.Addr().String())

	conn, err := pinnedDialer([]netip.AddrPort{deadAddr, live})(context.Background(), "ignored:1")
	if err != nil {
		t.Fatal(err)
	}
	if conn.RemoteAddr().String() != live.String() {
		t.Fatalf("dialed %s want %s", conn.RemoteAddr(), live)
	}
	_ = conn.Close()
	if _, err := pinnedDialer([]netip.AddrPort{deadAddr})(context.Background(), "ignored:1"); err == nil {
		t.Fatal("dead endpoint dialed")
	}
}
