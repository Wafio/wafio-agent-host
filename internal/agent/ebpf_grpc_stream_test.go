package agent

import (
	"fmt"
	"strings"
	"testing"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
)

func TestHostBundleRejectsUnavailableOrInvalidState(t *testing.T) {
	for _, payload := range []string{`{}`, `null`, `{"trace_policies":null}`, `{"ebpf_state":null}`, `{"trace_policies":[]}`, `{"ebpf_state":{"config":{}}}`} {
		if err := applyEBPFBundle([]byte(payload), 0); err == nil {
			t.Errorf("%s reported success without application", payload)
		}
	}
}

// A control plane older than kill_acknowledged never sends it: a broad kill in
// its bundle is downgraded to alert instead of failing validation for the
// whole bundle (here the bundle then stops at the missing trace manager, not
// at the kill acknowledgement).
func TestHostBundleDowngradesUnacknowledgedBroadKill(t *testing.T) {
	payload := `{"trace_policies":[{"id":7,"name":"broad","enabled":true,"action":"kill","event_types":["execve"]},` +
		`{"id":8,"name":"narrow","enabled":true,"action":"kill","match_comm":"nc"}]}`
	err := applyEBPFBundle([]byte(payload), 0)
	if err == nil || strings.Contains(err.Error(), "kill_acknowledged") {
		t.Fatalf("broad kill must not reject the bundle: %v", err)
	}
}

func TestHostSnapshotValidationBeforeMutation(t *testing.T) {
	// Prefixes are stored natively, so a /16 allow, a /8 block and an
	// IPv6 /64 egress block are one map entry each — no longer refused as
	// "exceeds map capacity".
	for _, state := range []ebpfDesiredState{
		{Allowlist: []wafebpf.AllowlistEntry{{IP: "10.0.0.0/16"}}},
		{Blocklist: []wafebpf.BlocklistEntry{{IP: "10.0.0.0/8"}}},
		{EgressBlocklist: []wafebpf.EgressBlocklistEntry{{IP: "2001:db8::/64"}}},
	} {
		if err := validateEBPFState(&state); err != nil {
			t.Fatalf("representable snapshot refused: %v", err)
		}
	}
	// Still refused before any map changes: entries that are not addresses,
	// CIDRs or IPv4 ranges, and more prefixes than the map holds.
	many := make([]wafebpf.AllowlistEntry, 0, 10001)
	for i := 0; i < 10001; i++ {
		many = append(many, wafebpf.AllowlistEntry{IP: fmt.Sprintf("10.%d.%d.1", i/250, i%250)})
	}
	for _, state := range []ebpfDesiredState{
		{Blocklist: []wafebpf.BlocklistEntry{{IP: "10.0.0.0/33"}}},
		{EgressBlocklist: []wafebpf.EgressBlocklistEntry{{IP: "2001:db8::1-2001:db8::9"}}},
		{Allowlist: many},
	} {
		if err := validateEBPFState(&state); err == nil {
			t.Fatal("unrepresentable snapshot accepted")
		}
	}
}

func TestHostSnapshotRejectsIngressDenyWithoutAllow(t *testing.T) {
	for _, policies := range [][]wafebpf.PortPolicyAPI{
		nil,
		{{Port: 443, Proto: "tcp", Direction: "ingress", Action: "drop"}},
		{{Port: 443, Proto: "tcp", Direction: "egress", Action: "allow"}},
	} {
		state := &ebpfDesiredState{
			Config:           &wafebpf.FullConfigAPI{Global: wafebpf.GlobalConfigAPI{EnableConntrack: true}},
			PortPolicyConfig: &wafebpf.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"},
			PortPolicies:     policies,
		}
		if err := validateEBPFState(state); err == nil {
			t.Fatalf("unsafe port policy accepted: %+v", policies)
		}
	}
}

func TestHostSnapshotAcceptsRepresentableIPv6DesiredState(t *testing.T) {
	if err := validateEBPFState(&ebpfDesiredState{EgressBlocklist: []wafebpf.EgressBlocklistEntry{{IP: "::1"}}}); err != nil {
		t.Fatal(err)
	}
}
