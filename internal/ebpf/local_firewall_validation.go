package ebpf

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// Local-API firewall writes run the same lockout guard as the gRPC
// desired-state path and the control plane (ValidateHostFirewall): it
// judges the whole state the write would produce — live config, port-policy
// config and rules, allowlist and live wildcard blocks, with the change
// applied — plus the host's SSH listeners and dataplane capabilities. A write
// that would lock the host out is refused before it touches a map.

// localPortPolicyScan bounds the rule read; it matches the desired-state
// snapshot limit (validateEBPFState) and the port policy map capacity.
const localPortPolicyScan = 4096

// localAllowlistScan bounds the allowlist read: both families' tries
// (MAX_ALLOW_PREFIXES each), so IPv6 escape hatches are seen behind a full
// IPv4 trie.
const localAllowlistScan = 2 * maxAllowPrefixes

// firewallStateReader is the slice of *Manager the lockout check reads.
type firewallStateReader interface {
	GetFullConfig() (*FullConfigAPI, error)
	GetPortPolicyConfig() (*PortPolicyConfigAPI, error)
	ListPortPolicies(limit int) ([]PortPolicyAPI, error)
	ListAllowlist(limit int) ([]AllowlistEntry, error)
	LiveBlocks() ([]BlocklistEntry, []EgressBlocklistEntry, error)
	HostFirewallEnv() HostFirewallEnv
}

// localFirewallChange is one local write. Nil fields keep the live value.
type localFirewallChange struct {
	config      *FullConfigAPI
	policy      *PortPolicyConfigAPI
	upserts     []PortPolicyAPI // added or replaced rules, same key = replace
	remove      *PortPolicyAPI  // key (port/proto/direction) of a removed rule
	blockAdd    []IPEntry       // ingress blocklist additions
	egressAdd   []IPEntry       // egress blocklist additions
	allowAdd    []IPEntry       // allowlist additions with their ports (same prefix = replace)
	allowRemove []string        // allowlist removals
}

// validateLocalFirewallChange refuses a local write that would lock the host
// out and returns the lockout-check warnings of an accepted one. Reading the
// live state fails closed: an unreadable state refuses the write rather than
// skipping the check.
func validateLocalFirewallChange(r firewallStateReader, ch localFirewallChange) ([]FirewallWarning, error) {
	policy := ch.policy
	if policy == nil {
		live, err := r.GetPortPolicyConfig()
		if err != nil {
			return nil, err
		}
		policy = live
	}
	cfg := ch.config
	if cfg == nil {
		live, err := r.GetFullConfig()
		if err != nil {
			return nil, err
		}
		cfg = live
	}
	rules, err := r.ListPortPolicies(localPortPolicyScan)
	if err != nil {
		return nil, err
	}
	rules = applyPortPolicyChange(rules, ch.upserts, ch.remove)
	allow, err := r.ListAllowlist(localAllowlistScan)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	// The allowlist lists one entry per prefix, with its ports:
	// removed and re-added entries are matched by the prefixes they occupy.
	// A re-add replaces the prefix's deadline and ports, so re-adding the
	// escape hatch with a TTL, or scoped to ports that miss SSH, is judged as
	// the entry it becomes (it used to skip the check).
	if len(ch.allowRemove) > 0 || len(ch.allowAdd) > 0 {
		gone := map[string]bool{}
		for _, ip := range ch.allowRemove {
			keys, err := IPListKeys(ip)
			if err != nil {
				gone[strings.TrimSpace(ip)] = true
				continue
			}
			for _, k := range keys {
				gone[k] = true
			}
		}
		for _, e := range ch.allowAdd {
			keys, err := IPListKeys(e.IP)
			if err != nil {
				return nil, err
			}
			for _, k := range keys {
				gone[k] = true
			}
		}
		kept := allow[:0:0]
		for _, e := range allow {
			if !gone[canonicalIPKey(e.IP)] {
				kept = append(kept, e)
			}
		}
		for _, e := range ch.allowAdd {
			kept = append(kept, AllowlistEntry{IP: e.IP, ExpiresAt: ttlExpiry(e.TTLMs, now), Ports: e.Ports})
		}
		allow = kept
	}
	block, egress, err := r.LiveBlocks()
	if err != nil {
		return nil, err
	}
	for _, e := range ch.blockAdd {
		block = append(block, BlocklistEntry{IP: e.IP, ExpiresAt: ttlExpiry(e.TTLMs, now)})
	}
	for _, e := range ch.egressAdd {
		egress = append(egress, EgressBlocklistEntry{IP: e.IP, ExpiresAt: ttlExpiry(e.TTLMs, now)})
	}
	env := r.HostFirewallEnv()
	in := FirewallSafetyInput{
		Config:               cfg,
		PortPolicyConfig:     policy,
		PortPolicies:         rules,
		Blocklist:            block,
		Allowlist:            allow,
		EgressBlocklist:      egress,
		SSHPorts:             env.SSHPorts,
		ControlPlanePort:     env.ControlPlanePort,
		ControlPlaneUnpinned: env.ControlPlaneUnpinned,
		Now:                  now,
	}
	// The live geo mode comes from the control plane (the local API cannot
	// switch it); a live allow mode was acknowledged when it was applied,
	// and a local write must not take away what it relies on (conntrack).
	if g, ok := r.(geoStateReader); ok {
		geo := g.GeoState()
		in.GeoMode = geo.Mode
		in.GeoAllowed = geo.Countries
		in.GeoAllowAcknowledged = true
	}
	return ValidateHostFirewall(in, env.Exemptions)
}

// geoStateReader is the optional part of firewallStateReader that reports
// the live geo mode (*Manager implements it).
type geoStateReader interface {
	GeoState() GeoRangeState
}

func ttlExpiry(ttlMs int64, now time.Time) *time.Time {
	if ttlMs <= 0 {
		return nil
	}
	exp := now.Add(time.Duration(ttlMs) * time.Millisecond)
	return &exp
}

type portPolicyMapKey struct {
	port      uint16
	proto     string
	direction string
}

// portPolicyKey mirrors the BPF map key: unknown protocols collapse to "any"
// and unknown directions to "ingress", exactly as AddPortPolicy stores them
// (protoStringToNum / directionStringToNum in manager.go).
func portPolicyKey(p PortPolicyAPI) portPolicyMapKey {
	k := portPolicyMapKey{port: p.Port, proto: "any", direction: "ingress"}
	switch p.Proto {
	case "tcp", "udp":
		k.proto = p.Proto
	}
	switch p.Direction {
	case "egress", "both":
		k.direction = p.Direction
	}
	return k
}

func applyPortPolicyChange(rules, upserts []PortPolicyAPI, remove *PortPolicyAPI) []PortPolicyAPI {
	out := make([]PortPolicyAPI, 0, len(rules)+len(upserts))
	drop := map[portPolicyMapKey]bool{}
	for _, u := range upserts {
		drop[portPolicyKey(u)] = true
	}
	if remove != nil {
		drop[portPolicyKey(*remove)] = true
	}
	for _, r := range rules {
		if !drop[portPolicyKey(r)] {
			out = append(out, r)
		}
	}
	// A later upsert with the same key wins, as sequential map updates do.
	last := map[portPolicyMapKey]int{}
	for i, u := range upserts {
		last[portPolicyKey(u)] = i
	}
	for i, u := range upserts {
		if last[portPolicyKey(u)] == i {
			out = append(out, u)
		}
	}
	return out
}

// firewallWriteMu serialises firewall writes that validate against live
// state and then apply: the local API and the gRPC desired-state apply both
// hold it across check + write, so no write lands between another write's
// lockout check and its apply.
var firewallWriteMu sync.Mutex

// LockFirewallWrites takes the firewall write lock and returns its release.
func LockFirewallWrites() func() {
	firewallWriteMu.Lock()
	return firewallWriteMu.Unlock
}

// maxPortPolicies is the port policy map capacity (MAX_PORT_POLICIES in
// bpf/wafio_common.h).
const maxPortPolicies = 4096

// ErrPortPolicyBatch reports a port policy batch that was not applied: it
// would overflow the map, or a rule write failed and the batch was rolled
// back.
var ErrPortPolicyBatch = errors.New("port policy batch not applied")

// portPolicyWriter is the slice of *Manager a local port policy batch uses.
type portPolicyWriter interface {
	firewallStateReader
	AddPortPolicy(api PortPolicyAPI) error
	RemovePortPolicy(port uint16, proto, direction string) error
}

// applyLocalPortPolicies writes a batch of port policy rules all-or-nothing.
// Under the firewall write lock it runs the lockout check on the resulting
// state, checks map capacity, writes allow rules before the others (so a
// failure can never leave a deny without the allow written with it), and on
// any write failure restores every rule it already changed. Returns the
// number of rules written.
func applyLocalPortPolicies(w portPolicyWriter, upserts []PortPolicyAPI) (int, error) {
	defer LockFirewallWrites()()
	if len(upserts) == 0 {
		return 0, nil
	}
	// One write per map key, the last in the request (as sequential map
	// updates would): the allow-first write order below must not change
	// which rule a key ends up with (a batch "drop 22, allow
	// 22" was validated as allow but written allow-then-drop).
	upserts = lastPerKey(upserts)
	if _, err := validateLocalFirewallChange(w, localFirewallChange{upserts: upserts}); err != nil {
		return 0, err
	}
	live, err := w.ListPortPolicies(maxPortPolicies + 1)
	if err != nil {
		return 0, err
	}
	prev := make(map[portPolicyMapKey]PortPolicyAPI, len(live))
	for _, r := range live {
		prev[portPolicyKey(r)] = r
	}
	newKeys := map[portPolicyMapKey]bool{}
	for _, u := range upserts {
		if _, ok := prev[portPolicyKey(u)]; !ok {
			newKeys[portPolicyKey(u)] = true
		}
	}
	if len(live)+len(newKeys) > maxPortPolicies {
		return 0, fmt.Errorf("%w: port policy map would exceed %d rules", ErrPortPolicyBatch, maxPortPolicies)
	}

	// Allow rules first; the relative order within each group is kept, so a
	// later rule for the same key still wins.
	ordered := make([]PortPolicyAPI, 0, len(upserts))
	for _, u := range upserts {
		if u.Action == "allow" {
			ordered = append(ordered, u)
		}
	}
	for _, u := range upserts {
		if u.Action != "allow" {
			ordered = append(ordered, u)
		}
	}
	var touched []portPolicyMapKey
	seen := map[portPolicyMapKey]bool{}
	for _, u := range ordered {
		if err := w.AddPortPolicy(u); err != nil {
			rollbackPortPolicies(w, touched, prev)
			return 0, fmt.Errorf("%w: rule %d/%s/%s: %v", ErrPortPolicyBatch, u.Port, u.Proto, u.Direction, err)
		}
		if k := portPolicyKey(u); !seen[k] {
			seen[k] = true
			touched = append(touched, k)
		}
	}
	return len(ordered), nil
}

// lastPerKey keeps, for each map key, the last rule of the request, in
// request order.
func lastPerKey(upserts []PortPolicyAPI) []PortPolicyAPI {
	last := make(map[portPolicyMapKey]int, len(upserts))
	for i, u := range upserts {
		last[portPolicyKey(u)] = i
	}
	out := make([]PortPolicyAPI, 0, len(last))
	for i, u := range upserts {
		if last[portPolicyKey(u)] == i {
			out = append(out, u)
		}
	}
	return out
}

// rollbackPortPolicies restores each touched key to its state before the
// batch: the previous rule (remaining TTL kept) or no rule.
func rollbackPortPolicies(w portPolicyWriter, touched []portPolicyMapKey, prev map[portPolicyMapKey]PortPolicyAPI) {
	// Restore in reverse so allow rules (written first) are restored last.
	for i := len(touched) - 1; i >= 0; i-- {
		k := touched[i]
		old, existed := prev[k]
		var err error
		if existed {
			old.TTLMs = 0
			if old.ExpiresAt != "" {
				if exp, perr := time.Parse(time.RFC3339, old.ExpiresAt); perr == nil {
					old.TTLMs = max(time.Until(exp).Milliseconds(), 1)
				}
			}
			err = w.AddPortPolicy(old)
		} else {
			err = w.RemovePortPolicy(k.port, k.proto, k.direction)
		}
		if err != nil {
			log.Printf("[ebpf] local API: port policy rollback %d/%s/%s failed: %v", k.port, k.proto, k.direction, err)
		}
	}
}

// portPolicyReplacer is the slice of *Manager ReplacePortPolicies uses.
type portPolicyReplacer interface {
	ListPortPolicies(limit int) ([]PortPolicyAPI, error)
	AddPortPolicy(api PortPolicyAPI) error
	RemovePortPolicy(port uint16, proto, direction string) error
}

// ReplacePortPolicies makes the port policy table equal to desired without a
// window in which a rule that stays is missing. Removing every rule
// and adding the new set back — what the push used to do — left the default
// deny on with no allow rules for the length of the swap, so a new SYN to an
// allowed port, or an established session that no conntrack entry covers,
// was dropped mid-push. Here:
//
//  1. every rule is validated before any write (nothing changes on an
//     invalid one);
//  2. desired rules are upserted in place (a map update keeps hit_count),
//     allow rules before the others;
//  3. stale rules that do not allow (drop, log) go next, and only then the
//     stale allow rules, so a deny switched on by this push never meets a
//     hole where its allow used to be, and a deny that only changes key
//     (80/tcp/ingress -> 80/any/both) is covered by its successor before its
//     predecessor goes;
//  4. only when the table has no room for the new keys beside the stale rules
//     (peak above the cap) do the stale non-allow rules go first, which only
//     loosens the policy.
//
// An upsert error returns at once and keeps the stale allow rules. The caller
// holds LockFirewallWrites (the agent's applyEBPFState does) and applies the
// port policy config after this returns.
func (m *Manager) ReplacePortPolicies(desired []PortPolicyAPI) error {
	return replacePortPolicies(m, desired)
}

func replacePortPolicies(w portPolicyReplacer, desired []PortPolicyAPI) error {
	desired = lastPerKey(desired)
	for _, d := range desired {
		if err := ValidatePortPolicyRule(d); err != nil {
			return err
		}
	}
	live, err := w.ListPortPolicies(maxPortPolicies + 1)
	if err != nil {
		return err
	}
	if len(live) > maxPortPolicies {
		return fmt.Errorf("%w: port policy map holds more than %d rules", ErrPortPolicyBatch, maxPortPolicies)
	}
	want := make(map[portPolicyMapKey]bool, len(desired))
	for _, d := range desired {
		want[portPolicyKey(d)] = true
	}
	var staleDeny, staleAllow []PortPolicyAPI
	liveKeys := make(map[portPolicyMapKey]bool, len(live))
	for _, r := range live {
		k := portPolicyKey(r)
		liveKeys[k] = true
		switch {
		case want[k]:
		case r.Action == "allow":
			staleAllow = append(staleAllow, r)
		default:
			staleDeny = append(staleDeny, r)
		}
	}
	newKeys := 0
	for k := range want {
		if !liveKeys[k] {
			newKeys++
		}
	}
	// With every stale rule still in place the table peaks at live + new
	// keys; when that does not fit, the stale non-allow rules go first (the
	// only loosening step) and the peak is what remains after them.
	staleDenyFirst := len(live)+newKeys > maxPortPolicies
	if staleDenyFirst && len(live)-len(staleDeny)+newKeys > maxPortPolicies {
		return fmt.Errorf("%w: port policy map would exceed %d rules", ErrPortPolicyBatch, maxPortPolicies)
	}

	remove := func(rules []PortPolicyAPI) error {
		for _, r := range rules {
			if err := w.RemovePortPolicy(r.Port, r.Proto, r.Direction); err != nil && !isKeyNotExist(err) {
				return err
			}
		}
		return nil
	}
	if staleDenyFirst {
		if err := remove(staleDeny); err != nil {
			return err
		}
	}
	for _, d := range desired {
		if d.Action == "allow" {
			if err := w.AddPortPolicy(d); err != nil {
				return err
			}
		}
	}
	for _, d := range desired {
		if d.Action != "allow" {
			if err := w.AddPortPolicy(d); err != nil {
				return err
			}
		}
	}
	if !staleDenyFirst {
		if err := remove(staleDeny); err != nil {
			return err
		}
	}
	return remove(staleAllow)
}
