package agent

import (
	"encoding/json"
	"errors"
	"testing"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
)

// Port-scoped allowlist entries on the host agent: the allowlist_scoped key
// joins the allowlist only when the attached object matches scopes; otherwise
// every scoped entry is left out before the lockout check and counted, so an
// entry the dataplane never enforces cannot be the escape hatch.

const scopedState = `{
  "config": {"global": {"enabled": true, "enable_conntrack": true}},
  "blocklist": [{"ip": "0.0.0.0/0"}],
  "allowlist": [{"ip": "203.0.113.9"}],
  "allowlist_scoped": [
    {"ip": "198.51.100.7", "ports": [{"proto": "tcp", "from": 22}]},
    {"ip": "198.51.100.8", "ports": [{"proto": "udp", "from": 53}]}
  ]
}`

func decodeScopedState(t *testing.T, raw string) *ebpfDesiredState {
	t.Helper()
	var s ebpfDesiredState
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestMergeScopedAllowlist(t *testing.T) {
	s := decodeScopedState(t, scopedState)
	if n := mergeScopedAllowlist(s, true); n != 0 {
		t.Fatalf("supported: skipped %d", n)
	}
	if len(s.Allowlist) != 3 || s.AllowlistScoped != nil {
		t.Fatalf("supported: allowlist %+v scoped %+v", s.Allowlist, s.AllowlistScoped)
	}
	scoped := 0
	for _, e := range s.Allowlist {
		if len(e.Ports) > 0 {
			scoped++
		}
	}
	if scoped != 2 {
		t.Fatalf("supported: %d scoped entries kept their ports", scoped)
	}

	s = decodeScopedState(t, scopedState)
	if n := mergeScopedAllowlist(s, false); n != 2 {
		t.Fatalf("old object: skipped %d want 2", n)
	}
	if len(s.Allowlist) != 1 || s.Allowlist[0].IP != "203.0.113.9" || len(s.Allowlist[0].Ports) != 0 {
		t.Fatalf("old object: allowlist %+v", s.Allowlist)
	}

	// An entry with ports under "allowlist" is scoped as well; an entry
	// under "allowlist_scoped" without ports is malformed and dropped, never
	// enforced as an entry for every port.
	s = decodeScopedState(t, `{"allowlist": [{"ip": "192.0.2.1", "ports": [{"proto": "tcp", "from": 443}]}],
		"allowlist_scoped": [{"ip": "192.0.2.2"}]}`)
	if n := mergeScopedAllowlist(s, false); n != 2 || len(s.Allowlist) != 0 || s.Allowlist == nil {
		t.Fatalf("old object, misplaced entries: skipped %d allowlist %#v", n, s.Allowlist)
	}
	s = decodeScopedState(t, `{"allowlist": [], "allowlist_scoped": [{"ip": "192.0.2.2"}]}`)
	if n := mergeScopedAllowlist(s, true); n != 1 || len(s.Allowlist) != 0 {
		t.Fatalf("new object, scoped entry without ports: skipped %d allowlist %+v", n, s.Allowlist)
	}

	// No allowlist at all stays absent (ReplaceIPLists leaves a nil list).
	s = decodeScopedState(t, `{"blocklist": []}`)
	if n := mergeScopedAllowlist(s, false); n != 0 || s.Allowlist != nil {
		t.Fatalf("absent allowlist: skipped %d allowlist %#v", n, s.Allowlist)
	}
}

// The SSH-scoped entry is the only escape hatch for the wildcard block: an
// agent whose object cannot enforce it must refuse the state (and keep its
// last good policy), not accept it on the strength of an entry it skips.
func TestSkippedScopedEntryIsNoEscapeHatch(t *testing.T) {
	raw := `{
  "config": {"global": {"enabled": true, "enable_conntrack": true}},
  "blocklist": [{"ip": "0.0.0.0/0"}],
  "allowlist": [],
  "allowlist_scoped": [{"ip": "198.51.100.7", "ports": [{"proto": "tcp", "from": 22}]}]
}`
	env := firewallEnv{exemptions: true, sshPorts: []uint16{22}}

	s := decodeScopedState(t, raw)
	mergeScopedAllowlist(s, false)
	_, err := validateEBPFStateWith(s, env)
	if !errors.Is(err, wafebpf.ErrWildcardBlockNeedsAllowlist) {
		t.Fatalf("old object: %v", err)
	}

	s = decodeScopedState(t, raw)
	mergeScopedAllowlist(s, true)
	if _, err := validateEBPFStateWith(s, env); err != nil {
		t.Fatalf("new object: %v", err)
	}
}
