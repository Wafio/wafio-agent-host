package agent

import (
	"encoding/json"
	"hash/fnv"
	"time"
)

// ruleStatsFullInterval is how often a stream resends every rule list even
// when no hit count changed, so a report lost unconfirmed is repaired.
const ruleStatsFullInterval = 5 * time.Minute

// ruleStatsDelta keeps a stream's rule hit-count reports to the lists that
// changed. The control plane merges each reported entry's
// count into the stored desired state and leaves entries absent from a
// report unchanged (MergeFirewallRuleHits, every version). It sums the
// counts of all live prefixes of one stored entry (a range is several
// prefixes), so a list is sent whole or not at all: never only the prefix
// that changed. Every list goes on the stream's first report and every
// ruleStatsFullInterval. Used by one goroutine only.
type ruleStatsDelta struct {
	sent     [5]uint64 // FNV-1a of each list's JSON as last sent
	lastFull time.Time
}

// filter returns the lists of s to send now, or nil when none changed.
func (d *ruleStatsDelta) filter(s *RuleStatsSnapshot, now time.Time) *RuleStatsSnapshot {
	if s == nil {
		return nil
	}
	full := d.lastFull.IsZero() || now.Sub(d.lastFull) >= ruleStatsFullInterval
	if full {
		d.lastFull = now
	}
	out := &RuleStatsSnapshot{}
	changed := false
	keep := func(i int, list any) bool {
		b, err := json.Marshal(list)
		if err != nil {
			return true // send it; the encoder reports the error
		}
		h := fnv.New64a()
		_, _ = h.Write(b) // hash.Hash never fails
		sum := h.Sum64()
		if !full && sum == d.sent[i] {
			return false
		}
		d.sent[i] = sum
		return true
	}
	if keep(0, s.Blocklist) {
		out.Blocklist, changed = s.Blocklist, true
	}
	if keep(1, s.Allowlist) {
		out.Allowlist, changed = s.Allowlist, true
	}
	if keep(2, s.PortPolicies) {
		out.PortPolicies, changed = s.PortPolicies, true
	}
	if keep(3, s.EgressBlocklist) {
		out.EgressBlocklist, changed = s.EgressBlocklist, true
	}
	if keep(4, s.TracePolicies) {
		out.TracePolicies, changed = s.TracePolicies, true
	}
	if !changed {
		return nil
	}
	return out
}
