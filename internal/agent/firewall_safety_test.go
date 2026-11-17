package agent

import (
	"errors"
	"strings"
	"testing"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

func tracked() *wafebpf.FullConfigAPI {
	return &wafebpf.FullConfigAPI{Global: wafebpf.GlobalConfigAPI{EnableConntrack: true}}
}

// On the agent: egress Deny All and wildcard blocklists rely on
// the reply and control-plane exemptions; objects without them must refuse
// the state instead of enforcing a lockout.
func TestHostSnapshotEgressDenyNeedsExemptingDataplane(t *testing.T) {
	egressDeny := &ebpfDesiredState{
		Config:           tracked(),
		PortPolicyConfig: &wafebpf.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "allow", DefaultEgress: "deny"},
		PortPolicies: []wafebpf.PortPolicyAPI{
			{Port: 443, Proto: "tcp", Direction: "egress", Action: "allow"},
			{Port: 53, Proto: "udp", Direction: "egress", Action: "allow"},
		},
	}
	wildcard := &ebpfDesiredState{
		Config:    tracked(),
		Blocklist: []wafebpf.BlocklistEntry{{IP: "0.0.0.0/0"}},
		Allowlist: []wafebpf.AllowlistEntry{{IP: "203.0.113.7"}},
	}
	for name, state := range map[string]*ebpfDesiredState{"egress deny": egressDeny, "wildcard block": wildcard} {
		if _, err := validateEBPFStateWith(state, firewallEnv{exemptions: false}); !errors.Is(err, wafebpf.ErrDataplaneLacksExemptions) {
			t.Fatalf("%s accepted on an old dataplane: %v", name, err)
		}
		if _, err := validateEBPFStateWith(state, firewallEnv{exemptions: true}); err != nil {
			t.Fatalf("%s rejected on the current dataplane: %v", name, err)
		}
	}
	warnings, _ := validateEBPFStateWith(egressDeny, firewallEnv{exemptions: true, controlPlanePort: 9443})
	if len(warnings) != 1 || warnings[0].Code != hostpolicy.WarnEgressControlPlaneRuleMissing || !strings.Contains(warnings[0].Message, "9443/tcp") {
		t.Fatalf("egress deny without the control-plane rule must warn with the configured port: %+v", warnings)
	}
	// Ingress Deny All alone never depended on the new objects.
	ingressOnly := &ebpfDesiredState{
		Config:           tracked(),
		PortPolicyConfig: &wafebpf.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"},
		PortPolicies:     []wafebpf.PortPolicyAPI{{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"}},
	}
	if _, err := validateEBPFStateWith(ingressOnly, firewallEnv{}); err != nil {
		t.Fatal(err)
	}
}

func TestHostSnapshotSSHGuardUsesDetectedPort(t *testing.T) {
	state := &ebpfDesiredState{
		Config:           tracked(),
		PortPolicyConfig: &wafebpf.PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"},
		PortPolicies:     []wafebpf.PortPolicyAPI{{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"}},
	}
	if _, err := validateEBPFStateWith(state, firewallEnv{sshPorts: []uint16{2222}, exemptions: true}); !errors.Is(err, hostpolicy.ErrIngressDenyNeedsAllow) {
		t.Fatalf("22 accepted while sshd listens on 2222: %v", err)
	}
	if _, err := validateEBPFStateWith(state, firewallEnv{sshPorts: []uint16{22, 2222}, exemptions: true}); err != nil {
		t.Fatal(err)
	}
}

// A threshold an older control plane stored above the dataplane limit is
// lowered to the limit instead of refusing the whole bundle.
func TestHostSnapshotNormalisesPortScanThreshold(t *testing.T) {
	state := &ebpfDesiredState{Config: tracked()}
	state.Config.PortScan = wafebpf.PortScanConfigAPI{Enabled: true, WindowMs: 10_000, MaxUniquePorts: 128}
	if _, err := validateEBPFStateWith(state, firewallEnv{exemptions: true}); err == nil {
		t.Fatal("threshold 128 passed validation without normalisation")
	}
	normalizeEBPFState(state)
	if state.Config.PortScan.MaxUniquePorts != wafebpf.MaxPortScanUniquePorts {
		t.Fatalf("threshold not lowered: %d", state.Config.PortScan.MaxUniquePorts)
	}
	if _, err := validateEBPFStateWith(state, firewallEnv{exemptions: true}); err != nil {
		t.Fatalf("normalised state refused: %v", err)
	}
}

// "Allow" used to reach the map as DROP.
func TestHostSnapshotRejectsUnknownPortAction(t *testing.T) {
	state := &ebpfDesiredState{PortPolicies: []wafebpf.PortPolicyAPI{{Port: 22, Proto: "tcp", Direction: "ingress", Action: "Allow"}}}
	if err := validateEBPFState(state); !errors.Is(err, hostpolicy.ErrInvalidPortPolicy) {
		t.Fatalf("unknown action accepted: %v", err)
	}
}
