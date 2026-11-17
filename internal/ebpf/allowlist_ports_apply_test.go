package ebpf

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// Port-scoped allowlist entries on the write paths: the
// diff-based swap rewrites a key whose ports changed in place and leaves an
// unchanged one alone; the local API judges the ports a re-add leaves.

func TestReplaceIPListsPorts(t *testing.T) {
	f := newFakeListStore()
	now := time.Now()
	ssh := []PortScope{ps("tcp", 22, 0)}
	err := ReplaceIPLists(f, IPListUpdate{Allow: []AllowlistEntry{
		{IP: "198.51.100.7", Ports: []PortScope{ps("TCP", 22, 22)}},
		{IP: "198.51.100.0/24"},
	}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := PortScopesKey(f.ports["198.51.100.7"]); got != "22/tcp" {
		t.Fatalf("scoped key written with %q", got)
	}
	if _, scoped := f.ports["198.51.100.0/24"]; scoped {
		t.Fatal("full entry written with ports")
	}

	// Unchanged: nothing is rewritten.
	f.ops = nil
	if err := ReplaceIPLists(f, IPListUpdate{Allow: []AllowlistEntry{
		{IP: "198.51.100.7", Ports: ssh}, {IP: "198.51.100.0/24"},
	}}, now); err != nil {
		t.Fatal(err)
	}
	if len(f.ops) != 0 {
		t.Fatalf("unchanged lists rewritten: %v", f.ops)
	}

	// Narrowed and widened in place: one put each, never a delete (no
	// moment without the entry).
	f.ops = nil
	if err := ReplaceIPLists(f, IPListUpdate{Allow: []AllowlistEntry{
		{IP: "198.51.100.7"},
		{IP: "198.51.100.0/24", Ports: []PortScope{ps("tcp", 443, 0)}},
	}}, now); err != nil {
		t.Fatal(err)
	}
	slices.Sort(f.ops)
	if want := []string{"put allow 198.51.100.0/24", "put allow 198.51.100.7"}; !slices.Equal(f.ops, want) {
		t.Fatalf("ops %v want %v", f.ops, want)
	}
	if _, scoped := f.ports["198.51.100.7"]; scoped {
		t.Fatal("widened entry kept its ports")
	}
	if got := PortScopesKey(f.ports["198.51.100.0/24"]); got != "443/tcp" {
		t.Fatalf("narrowed entry has %q", got)
	}

	// A live value that allows nothing is rewritten, never taken as the
	// desired full entry.
	f.ports["198.51.100.7"] = []PortScope{{Proto: portProtoNone}}
	f.ops = nil
	if err := ReplaceIPLists(f, IPListUpdate{Allow: []AllowlistEntry{
		{IP: "198.51.100.7"}, {IP: "198.51.100.0/24", Ports: []PortScope{ps("tcp", 443, 0)}},
	}}, now); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.ops, []string{"put allow 198.51.100.7"}) {
		t.Fatalf("none sentinel: ops %v", f.ops)
	}

	// Two spellings of one prefix with different ports, or a scoped /0,
	// are refused before any write.
	f.ops = nil
	for _, allow := range [][]AllowlistEntry{
		{{IP: "10.0.0.0/24", Ports: ssh}, {IP: "10.0.0.1/24"}},
		{{IP: "0.0.0.0/0", Ports: ssh}},
	} {
		if err := ReplaceIPLists(f, IPListUpdate{Allow: allow}, now); err == nil {
			t.Fatalf("%v accepted", allow)
		}
	}
	if len(f.ops) != 0 {
		t.Fatalf("refused swap wrote %v", f.ops)
	}
}

// Re-adding the escape hatch with ports that miss SSH removes it; under a
// wildcard block the local API refuses that. Scoping it to SSH keeps it.
func TestLocalAllowlistNarrowingRefusedUnderWildcardBlock(t *testing.T) {
	state := fakeFirewallState{
		cfg:    &FullConfigAPI{Global: GlobalConfigAPI{EnableConntrack: true}},
		policy: &PortPolicyConfigAPI{DefaultIngress: "allow", DefaultEgress: "allow"},
		allow:  []AllowlistEntry{{IP: "198.51.100.7"}},
		block:  []BlocklistEntry{{IP: "0.0.0.0/0"}},
		env:    HostFirewallEnv{Exemptions: true, SSHPorts: []uint16{22}},
	}
	narrow := localFirewallChange{allowAdd: []IPEntry{{IP: "198.51.100.7", Ports: []PortScope{ps("tcp", 5432, 0)}}}}
	if _, err := validateLocalFirewallChange(state, narrow); !errors.Is(err, ErrWildcardBlockNeedsAllowlist) {
		t.Fatalf("narrowing the only escape hatch: %v", err)
	}
	keep := localFirewallChange{allowAdd: []IPEntry{{IP: "198.51.100.7", Ports: []PortScope{ps("tcp", 22, 0), ps("tcp", 5432, 0)}}}}
	if _, err := validateLocalFirewallChange(state, keep); err != nil {
		t.Fatalf("scoping the escape hatch to SSH: %v", err)
	}
	// The live entry is already scoped to SSH (ListAllowlist returns ports):
	// re-adding it for 5432 only is refused as well.
	state.allow = []AllowlistEntry{{IP: "198.51.100.7", Ports: []PortScope{ps("tcp", 22, 0)}}}
	if _, err := validateLocalFirewallChange(state, narrow); !errors.Is(err, ErrWildcardBlockNeedsAllowlist) {
		t.Fatalf("narrowing a scoped escape hatch: %v", err)
	}
	// A scoped /0 is refused by the guard.
	wild := localFirewallChange{allowAdd: []IPEntry{{IP: "0.0.0.0/0", Ports: []PortScope{ps("tcp", 22, 0)}}}}
	if _, err := validateLocalFirewallChange(state, wild); !errors.Is(err, ErrAllowlistWildcardScoped) {
		t.Fatalf("scoped /0: %v", err)
	}
	// A live value that allows nothing makes the state unjudgeable: refused.
	state.allow = []AllowlistEntry{{IP: "198.51.100.7"}, {IP: "203.0.113.1", Ports: []PortScope{{Proto: portProtoNone}}}}
	if _, err := validateLocalFirewallChange(state, localFirewallChange{allowAdd: []IPEntry{{IP: "192.0.2.1"}}}); !errors.Is(err, ErrInvalidPorts) {
		t.Fatalf("none sentinel in the live list: %v", err)
	}
}
