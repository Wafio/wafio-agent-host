package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/agentcore"
)

// Last good firewall policy. BPF maps are not pinned: a
// restarted agent starts from the monitor-mode defaults and waits for the
// control plane's push. If that push is refused — or the control plane is
// unreachable — the host would run without its firewall. The agent keeps the
// last desired state it applied successfully, with the control-plane
// endpoints it was reaching, and re-applies it at start before the stream
// exists; a refused bundle never replaces it.

// envFirewallStateFile overrides where the last good state is kept.
const envFirewallStateFile = "WAFIO_FIREWALL_STATE_FILE"

// defaultFirewallStateFiles: the systemd StateDirectory (survives reboots),
// then the RuntimeDirectory (survives service restarts) for units installed
// before StateDirectory=wafio-host-agent existed (ProtectSystem=strict keeps
// /var/lib read-only for them). On load the newer record wins.
var defaultFirewallStateFiles = []string{
	"/var/lib/wafio-host-agent/firewall-last-good.json",
	"/run/wafio/host-agent-firewall-last-good.json",
}

func firewallStateFiles() []string {
	if p := strings.TrimSpace(os.Getenv(envFirewallStateFile)); p != "" {
		return []string{p}
	}
	return defaultFirewallStateFiles
}

// savedFirewall is the on-disk record.
type savedFirewall struct {
	Version    int       `json:"version"`
	Generation int64     `json:"generation"` // desired-state generation from the control plane
	SavedAt    time.Time `json:"saved_at"`
	// ControlPlane: the endpoints written to wafio_cp_endpoints when saved
	// (and refreshed when they change), to seed the dataplane at start when
	// the control plane cannot be resolved.
	ControlPlane []string        `json:"control_plane,omitempty"`
	State        json.RawMessage `json:"ebpf_state"`
}

func (r *savedFirewall) newerThan(o *savedFirewall) bool {
	if o == nil {
		return true
	}
	if r.Generation != o.Generation {
		return r.Generation > o.Generation
	}
	return r.SavedAt.After(o.SavedAt)
}

func (r *savedFirewall) endpoints() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(r.ControlPlane))
	for _, s := range r.ControlPlane {
		if ap, err := netip.ParseAddrPort(s); err == nil && ap.Port() != 0 {
			out = append(out, ap)
		}
		if len(out) == agentcore.MaxControlPlaneEndpoints {
			break
		}
	}
	return out
}

func endpointStrings(eps []netip.AddrPort) []string {
	out := make([]string, 0, len(eps))
	for _, ep := range eps {
		out = append(out, ep.String())
	}
	return out
}

// saveLastGoodFirewall stores the ebpf_state section of a bundle that was
// applied successfully, with its generation and the pinned control-plane
// endpoints (0600, atomic rename).
func saveLastGoodFirewall(raw json.RawMessage, generation int64) {
	rec := savedFirewall{Version: 1, Generation: generation, SavedAt: time.Now().UTC(), State: raw}
	if p := pinnedCPEndpoints.Load(); p != nil {
		rec.ControlPlane = endpointStrings(*p)
	}
	writeSavedFirewall(&rec, "")
}

// writeSavedFirewall writes rec to prefer (when set) or the first location
// that accepts it.
func writeSavedFirewall(rec *savedFirewall, prefer string) {
	data, err := json.Marshal(rec)
	if err != nil {
		log.Printf("[ebpf-grpc] last good firewall policy not saved: %v", err)
		return
	}
	paths := firewallStateFiles()
	if prefer != "" {
		paths = append([]string{prefer}, paths...)
	}
	var errs []error
	for _, path := range paths {
		err := writeFileAtomic(path, data)
		if err == nil {
			return
		}
		errs = append(errs, err)
	}
	log.Printf("[ebpf-grpc] last good firewall policy not saved: %v", errors.Join(errs...))
}

// updateSavedControlPlane records new pinned endpoints in the saved record.
func updateSavedControlPlane(eps []netip.AddrPort) {
	rec, path, err := loadLastGoodFirewall()
	if err != nil || rec == nil {
		return
	}
	want := endpointStrings(eps)
	if slices.Equal(rec.ControlPlane, want) {
		return
	}
	rec.ControlPlane = want
	writeSavedFirewall(rec, path)
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".firewall-last-good-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// loadLastGoodFirewall returns the newest usable record across the
// locations (higher generation, then later save). A location that cannot be
// read or parsed is skipped, and reported only if none is usable.
func loadLastGoodFirewall() (*savedFirewall, string, error) {
	var best *savedFirewall
	bestPath := ""
	var errs []error
	for _, path := range firewallStateFiles() {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: path comes from firewallStateFiles, the agent's own state locations
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
				errs = append(errs, err)
			}
			continue
		}
		var rec savedFirewall
		if err := json.Unmarshal(raw, &rec); err != nil || rec.Version != 1 || len(rec.State) == 0 {
			errs = append(errs, fmt.Errorf("%s: not a saved firewall record", path))
			continue
		}
		if rec.newerThan(best) {
			best, bestPath = &rec, path
		}
	}
	if best != nil {
		return best, bestPath, nil
	}
	return nil, "", errors.Join(errs...)
}

// Policy source reported to the control plane on connect (bundle_status
// "source"): "saved" — restored from disk, "default" — nothing restored,
// "live" — applied from a control-plane push.
type policySourceInfo struct {
	Source     string    `json:"source"`
	Generation int64     `json:"generation,omitempty,string"`
	SavedAt    time.Time `json:"saved_at,omitzero"`
	// DNSRelaxed: the saved egress Deny All runs with DNS allowed because no
	// control-plane endpoint could be pinned at start.
	DNSRelaxed bool `json:"dns_relaxed,omitempty"`
}

// policySourceCommandID is the CommandAck id carrying policySourceInfo
// (JSON in the error field, like ebpf:telemetry).
const policySourceCommandID = "ebpf:policy_source"

var currentPolicySource atomic.Pointer[policySourceInfo]

func setPolicySource(info policySourceInfo) { currentPolicySource.Store(&info) }

func policySourceJSON() string {
	info := currentPolicySource.Load()
	if info == nil {
		info = &policySourceInfo{Source: "default"}
	}
	b, _ := json.Marshal(info)
	return string(b)
}

// restoredRelaxed: the saved policy was applied with DNS egress allowed
// because no control-plane endpoint was known; re-apply it as saved once
// the endpoints are pinned.
var restoredRelaxed atomic.Bool

// restoreLastGoodFirewall re-applies the stored state through the normal
// bundle path (lockout guard, snapshot and rollback), without re-saving.
// Called once at start, before the control-plane stream. The control-plane
// endpoints come first: resolved now, while the dataplane
// still has its open defaults, else seeded from the record; with neither,
// an egress Deny All in the record is applied with DNS allowed until the
// endpoints are pinned.
func restoreLastGoodFirewall(ctx context.Context, serverAddr string) {
	rec, path, err := loadLastGoodFirewall()
	if err != nil {
		log.Printf("[ebpf-grpc] last good firewall policy unreadable: %v", err)
	}
	if rec == nil {
		setPolicySource(policySourceInfo{Source: "default"})
		return
	}
	pinned := refreshControlPlaneEndpoints(ctx, serverAddr)
	if len(pinned) == 0 {
		pinned = seedControlPlaneEndpoints(rec.endpoints())
	}
	state := rec.State
	relaxed := false
	if len(pinned) == 0 {
		state, relaxed = relaxEgressForDNS(rec.State)
	}
	if err := applySavedState(state, rec.Generation); err != nil {
		log.Printf("[ebpf-grpc] last good firewall policy (%s) not restored: %v", path, err)
		setPolicySource(policySourceInfo{Source: "default"})
		return
	}
	restoredRelaxed.Store(relaxed)
	setPolicySource(policySourceInfo{Source: "saved", Generation: rec.Generation, SavedAt: rec.SavedAt, DNSRelaxed: relaxed})
	log.Printf("[ebpf-grpc] last good firewall policy restored from %s (generation %d, dns_relaxed=%t)", path, rec.Generation, relaxed)
}

// reapplyUnrelaxed restores the saved policy as saved once the control
// plane is pinned, if the start-up restore had to relax it.
func reapplyUnrelaxed() {
	if !restoredRelaxed.Swap(false) {
		return
	}
	rec, _, err := loadLastGoodFirewall()
	if err != nil || rec == nil {
		return
	}
	if err := applySavedState(rec.State, rec.Generation); err != nil {
		restoredRelaxed.Store(true) // still relaxed; try again on the next dial
		log.Printf("[ebpf-grpc] saved firewall policy not re-applied after pinning: %v", err)
		return
	}
	if info := currentPolicySource.Load(); info != nil && info.Source == "saved" {
		setPolicySource(policySourceInfo{Source: "saved", Generation: rec.Generation, SavedAt: rec.SavedAt})
	}
	log.Printf("[ebpf-grpc] saved firewall policy re-applied without the DNS relaxation")
}

func applySavedState(state json.RawMessage, generation int64) error {
	bundle, err := json.Marshal(map[string]json.RawMessage{"ebpf_state": state})
	if err != nil {
		return err
	}
	return applyEBPFBundleWith(bundle, generation, false)
}

// relaxEgressForDNS adds permanent egress ALLOW rules for DNS (53/udp,
// 53/tcp) when state enables egress Deny All; the rules are appended, so
// they win their map slots.
func relaxEgressForDNS(state json.RawMessage) (json.RawMessage, bool) {
	var s ebpfDesiredState
	if err := json.Unmarshal(state, &s); err != nil || s.PortPolicyConfig == nil ||
		!s.PortPolicyConfig.Enabled || s.PortPolicyConfig.DefaultEgress != "deny" {
		return state, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(state, &fields); err != nil {
		return state, false
	}
	rules := append(slices.Clone(s.PortPolicies),
		wafebpf.PortPolicyAPI{Port: 53, Proto: "udp", Direction: "egress", Action: "allow"},
		wafebpf.PortPolicyAPI{Port: 53, Proto: "tcp", Direction: "egress", Action: "allow"})
	encoded, err := json.Marshal(rules)
	if err != nil {
		return state, false
	}
	fields["port_policies"] = encoded
	out, err := json.Marshal(fields)
	if err != nil {
		return state, false
	}
	return out, true
}

// applyRefusedPrefix starts the acknowledgement error of a bundle the agent
// refused before changing anything; the control plane shows it as
// "refused" with the code (agentserver.recordHostBundleAck).
const applyRefusedPrefix = "apply refused ("

// refuseApply wraps a validation error: nothing was applied and the
// previous (last good) policy stays in force.
func refuseApply(err error) error {
	code, ok := wafebpf.FirewallErrorCode(err)
	if !ok {
		code = "STATE_INVALID"
	}
	return fmt.Errorf("%s%s): %w; the previous firewall policy stays in force", applyRefusedPrefix, code, err)
}
