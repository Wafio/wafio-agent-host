package ebpf

import (
	"fmt"
	"strings"
	"time"
)

// Diff-based IP list swap. A push used to delete every allowlist,
// blocklist and egress-blocklist entry and add the desired set back: blocked
// addresses passed during the loop, and an allowlisted administrator lost the
// bypass under a wildcard block (or geo allow mode) for its length.
// ReplaceIPLists makes the maps equal to the desired lists the way
// ReplacePortPolicies does for port rules: nothing that stays is ever
// absent from its map.

// ipListStore is the slice of *Manager ReplaceIPLists uses.
type ipListStore interface {
	ListAllowlist(limit int) ([]AllowlistEntry, error)
	ListBlocklist(limit int) ([]BlocklistEntry, error)
	ListEgressBlocklist(limit int) ([]EgressBlocklistEntry, error)
	AddToAllowlistPorts(ip string, ttl time.Duration, ports []PortScope) error
	AddToBlocklist(ip string, ttl time.Duration) error
	AddToEgressBlocklist(ip string, ttl time.Duration) error
	RemoveFromAllowlist(ip string) error
	RemoveFromBlocklist(ip string) error
	RemoveFromEgressBlocklist(ip string) error
}

// IPListUpdate is the desired content of the IP lists. A nil list is left as
// it is (the desired state did not carry it); an empty one is cleared.
type IPListUpdate struct {
	Allow  []AllowlistEntry
	Block  []BlocklistEntry
	Egress []EgressBlocklistEntry
}

// ipListKeys returns the map keys (prefixes) one list entry occupies, in
// the spelling the manager lists them.
func ipListKeys(entry string) ([]string, error) { return IPListKeys(entry) }

// canonicalIPKey spells a listed key the way ipListKeys does.
func canonicalIPKey(s string) string {
	if keys, err := IPListKeys(s); err == nil && len(keys) == 1 {
		return keys[0]
	}
	return strings.TrimSpace(s)
}

// ipListSide is one list of a swap.
type ipListSide struct {
	name     string
	capacity int
	desired  map[string]time.Time // key -> deadline; zero = permanent
	live     map[string]time.Time
	// desiredPorts / livePorts: allowlist port scopes per key (absent =
	// every port); a key whose ports differ is rewritten in place.
	desiredPorts map[string][]PortScope
	livePorts    map[string][]PortScope
	put          func(key string, ttl time.Duration, ports []PortScope) error
	del          func(key string) error
	// allow: removing a stale entry early would tighten the policy, so an
	// overflowing swap is refused instead (lockout safety).
	allow bool
}

// desiredKeys merges the entries of a list into map keys. A key named by
// several entries keeps the latest deadline, a permanent one above all: the
// key is present as long as any entry asks for it, which is also how the
// lockout guard reads the list (a permanent entry is an escape hatch).
// Expired entries are left out.
func desiredKeys[E any](entries []E, ipOf func(E) string, expiryOf func(E) *time.Time, capacity int, now time.Time) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(entries))
	for _, e := range entries {
		var deadline time.Time
		if exp := expiryOf(e); exp != nil {
			if !exp.After(now) {
				continue
			}
			deadline = *exp
		}
		keys, err := ipListKeys(ipOf(e))
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			prev, seen := out[k]
			switch {
			case !seen:
				out[k] = deadline
			case prev.IsZero() || deadline.IsZero():
				out[k] = time.Time{}
			case deadline.After(prev):
				out[k] = deadline
			}
		}
		if len(out) > capacity {
			return nil, fmt.Errorf("%w: more than %d entries", ErrIPListCapacity, capacity)
		}
	}
	return out, nil
}

// splitByMap divides a list into the maps its keys land in (classify names
// the map of a canonical key), each side with that map's capacity, so a swap
// is planned per map: the IPv4 and IPv6 tries of a list, and the egress hash
// and tries, fill up independently.
func splitByMap(s *ipListSide, classify func(key string) string, order []string, caps map[string]int) []*ipListSide {
	parts := make(map[string]*ipListSide, len(order))
	for _, m := range order {
		parts[m] = &ipListSide{name: s.name + " (" + m + ")", capacity: caps[m], desired: map[string]time.Time{},
			live: map[string]time.Time{}, desiredPorts: s.desiredPorts, livePorts: s.livePorts,
			put: s.put, del: s.del, allow: s.allow}
	}
	for k, d := range s.desired {
		if part := parts[classify(k)]; part != nil {
			part.desired[k] = d
		}
	}
	for k, d := range s.live {
		if part := parts[classify(k)]; part != nil {
			part.live[k] = d
		}
	}
	out := make([]*ipListSide, 0, len(order))
	for _, m := range order {
		out = append(out, parts[m])
	}
	return out
}

// keyFamily classifies an ingress list key by the trie it lands in.
func keyFamily(key string) string {
	if p, err := IPListPrefixes(key); err == nil && len(p) == 1 && p[0].Addr().Is6() {
		return "IPv6"
	}
	return "IPv4"
}

// egressKeyMap classifies an egress key: addresses and the family-wide
// entries live in the hash, other prefixes in the tries.
func egressKeyMap(key string) string {
	p, err := IPListPrefixes(key)
	if err != nil || len(p) != 1 || p[0].Bits() == 0 || p[0].Bits() == p[0].Addr().BitLen() {
		return "hash"
	}
	if p[0].Addr().Is6() {
		return "IPv6 prefixes"
	}
	return "IPv4 prefixes"
}

// sameDeadline: a live entry already enforces the desired deadline. Live
// deadlines come back through the boot-time offset, so a second of slack
// keeps an unchanged entry from being rewritten on every push.
func sameDeadline(live, want time.Time) bool {
	if live.IsZero() || want.IsZero() {
		return live.IsZero() == want.IsZero()
	}
	d := live.Sub(want)
	return d > -time.Second && d < time.Second
}

// desiredAllowPorts resolves the port scopes of each allowlist key (the
// prefixes of every live entry). Entries that name one prefix must agree on
// its ports (ValidateAllowlistPorts refuses the state otherwise).
func desiredAllowPorts(entries []AllowlistEntry, now time.Time) (map[string][]PortScope, error) {
	out := map[string][]PortScope{}
	seen := map[string]string{}
	for _, e := range entries {
		if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
			continue
		}
		ports, err := NormalizePortScopes(e.Ports)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", clip(e.IP), err)
		}
		keys, err := ipListKeys(e.IP)
		if err != nil {
			return nil, err
		}
		sig := PortScopesKey(ports)
		for _, k := range keys {
			if prev, ok := seen[k]; ok && prev != sig {
				return nil, fmt.Errorf("%w: %s is named by two allowlist entries with different ports", ErrInvalidPorts, k)
			}
			seen[k] = sig
			if len(ports) > 0 {
				if prefixes, err := IPListPrefixes(k); err == nil && len(prefixes) == 1 && prefixes[0].Bits() == 0 {
					return nil, ErrAllowlistWildcardScoped
				}
				out[k] = ports
			}
		}
	}
	return out, nil
}

// liveAllowPorts maps each listed allowlist key to its ports.
func liveAllowPorts(entries []AllowlistEntry) map[string][]PortScope {
	out := map[string][]PortScope{}
	for _, e := range entries {
		if len(e.Ports) > 0 {
			out[canonicalIPKey(e.IP)] = e.Ports
		}
	}
	return out
}

func liveKeys[E any](entries []E, ipOf func(E) string, expiryOf func(E) *time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(entries))
	for _, e := range entries {
		var deadline time.Time
		if exp := expiryOf(e); exp != nil {
			deadline = *exp
		}
		out[canonicalIPKey(ipOf(e))] = deadline
	}
	return out
}

// ReplaceIPLists makes the allowlist, blocklist and egress blocklist maps
// equal to u without a window in which an entry that stays is missing:
//
//  1. every desired list is resolved and checked against its capacity
//     before any write;
//  2. allowlist additions and changes are written first, then blocklist and
//     egress additions and changes (an update replaces a key in place, so a
//     changed entry is never absent);
//  3. stale blocklist and egress entries are removed next, and stale
//     allowlist entries last, so a block this push keeps never meets a hole
//     in the allowlist and an allowlist entry that moves (an address change)
//     is added before its predecessor goes;
//  4. only when a block map has no room for the new keys beside the stale
//     ones do its stale entries go first (that only loosens the policy). An
//     allowlist map that would overflow sheds only its lapsed stale entries
//     first (they allow nothing any more); if that is not room enough the
//     swap is refused: removing live stale entries first could leave the new
//     escape hatch absent for a moment.
//
// Capacity is planned per map (both tries of a list, the egress hash and
// tries), the way the kernel fills them.
//
// The caller holds LockFirewallWrites and has the lockout guard's verdict on
// the desired state; on an error it rolls back from its snapshot.
func ReplaceIPLists(st ipListStore, u IPListUpdate, now time.Time) error {
	var sides []*ipListSide
	if u.Allow != nil {
		desired, err := desiredKeys(u.Allow, func(e AllowlistEntry) string { return e.IP }, func(e AllowlistEntry) *time.Time { return e.ExpiresAt }, allowlistCapacity, now)
		if err != nil {
			return err
		}
		desiredPorts, err := desiredAllowPorts(u.Allow, now)
		if err != nil {
			return err
		}
		live, err := st.ListAllowlist(2*maxAllowPrefixes + 1)
		if err != nil {
			return err
		}
		sides = append(sides, splitByMap(&ipListSide{name: "allowlist", desired: desired,
			live:         liveKeys(live, func(e AllowlistEntry) string { return e.IP }, func(e AllowlistEntry) *time.Time { return e.ExpiresAt }),
			desiredPorts: desiredPorts, livePorts: liveAllowPorts(live),
			put: st.AddToAllowlistPorts, del: st.RemoveFromAllowlist, allow: true},
			keyFamily, []string{"IPv4", "IPv6"}, map[string]int{"IPv4": maxAllowPrefixes, "IPv6": maxAllowPrefixes})...)
	}
	if u.Block != nil {
		desired, err := desiredKeys(u.Block, func(e BlocklistEntry) string { return e.IP }, func(e BlocklistEntry) *time.Time { return e.ExpiresAt }, blocklistCapacity, now)
		if err != nil {
			return err
		}
		live, err := st.ListBlocklist(2*maxBlockPrefixes + 1)
		if err != nil {
			return err
		}
		sides = append(sides, splitByMap(&ipListSide{name: "blocklist", desired: desired,
			live: liveKeys(live, func(e BlocklistEntry) string { return e.IP }, func(e BlocklistEntry) *time.Time { return e.ExpiresAt }),
			put:  ignorePorts(st.AddToBlocklist), del: st.RemoveFromBlocklist},
			keyFamily, []string{"IPv4", "IPv6"}, map[string]int{"IPv4": maxBlockPrefixes, "IPv6": maxBlockPrefixes})...)
	}
	if u.Egress != nil {
		desired, err := desiredKeys(u.Egress, func(e EgressBlocklistEntry) string { return e.IP }, func(e EgressBlocklistEntry) *time.Time { return e.ExpiresAt }, egressBlocklistCapacity, now)
		if err != nil {
			return err
		}
		live, err := st.ListEgressBlocklist(egressBlocklistCapacity + egressSubnetV4Capacity + egressSubnetV6Capacity + 1)
		if err != nil {
			return err
		}
		sides = append(sides, splitByMap(&ipListSide{name: "egress blocklist", desired: desired,
			live: liveKeys(live, func(e EgressBlocklistEntry) string { return e.IP }, func(e EgressBlocklistEntry) *time.Time { return e.ExpiresAt }),
			put:  ignorePorts(st.AddToEgressBlocklist), del: st.RemoveFromEgressBlocklist},
			egressKeyMap, []string{"hash", "IPv4 prefixes", "IPv6 prefixes"},
			map[string]int{"hash": egressBlocklistCapacity, "IPv4 prefixes": egressSubnetV4Capacity, "IPv6 prefixes": egressSubnetV6Capacity})...)
	}

	// Capacity: with every stale key still in place a map peaks at live +
	// new keys. The live read covers every map of a list (both families'
	// tries, the egress hash and tries), so stale entries written past the
	// desired-state capacity (local API) are found and removed too.
	staleFirst := map[*ipListSide]bool{}
	lapsedFirst := map[*ipListSide]bool{}
	for _, s := range sides {
		newKeys, stale, lapsed := 0, 0, 0
		for k := range s.desired {
			if _, ok := s.live[k]; !ok {
				newKeys++
			}
		}
		for k, d := range s.live {
			if _, ok := s.desired[k]; !ok {
				stale++
				if !d.IsZero() && !d.After(now) {
					lapsed++
				}
			}
		}
		switch {
		case len(s.live)+newKeys <= s.capacity:
		case s.allow && len(s.live)-lapsed+newKeys <= s.capacity:
			lapsedFirst[s] = true
		case !s.allow && len(s.live)-stale+newKeys <= s.capacity:
			staleFirst[s] = true
		default:
			return fmt.Errorf("%w: the %s holds %d entries (%d stale, %d lapsed) and needs room for %d new ones (capacity %d)",
				ErrIPListBatch, s.name, len(s.live), stale, lapsed, newKeys, s.capacity)
		}
	}

	upsert := func(s *ipListSide) error {
		for k, deadline := range s.desired {
			if live, ok := s.live[k]; ok && sameDeadline(live, deadline) &&
				PortScopesKey(s.livePorts[k]) == PortScopesKey(s.desiredPorts[k]) {
				continue
			}
			var ttl time.Duration
			if !deadline.IsZero() {
				if ttl = time.Until(deadline); ttl <= 0 {
					continue // lapsed during the swap: the stale pass removes it
				}
			}
			if err := s.put(k, ttl, s.desiredPorts[k]); err != nil {
				return fmt.Errorf("%s %s: %w", s.name, k, err)
			}
		}
		return nil
	}
	removeStale := func(s *ipListSide) error {
		for k := range s.live {
			deadline, keep := s.desired[k]
			if keep && (deadline.IsZero() || deadline.After(time.Now())) {
				continue
			}
			if err := s.del(k); err != nil && !isKeyNotExist(err) {
				return fmt.Errorf("%s %s: %w", s.name, k, err)
			}
		}
		return nil
	}

	for _, s := range sides {
		if lapsedFirst[s] {
			for k, d := range s.live {
				if _, keep := s.desired[k]; keep || d.IsZero() || d.After(now) {
					continue
				}
				if err := s.del(k); err != nil && !isKeyNotExist(err) {
					return fmt.Errorf("%s %s: %w", s.name, k, err)
				}
			}
		}
		if staleFirst[s] {
			if err := removeStale(s); err != nil {
				return err
			}
		}
	}
	for _, s := range sides { // allowlist first: it is first in sides
		if err := upsert(s); err != nil {
			return err
		}
	}
	for _, s := range sides { // blocks before the allowlist
		if !s.allow && !staleFirst[s] {
			if err := removeStale(s); err != nil {
				return err
			}
		}
	}
	for _, s := range sides {
		if s.allow {
			if err := removeStale(s); err != nil {
				return err
			}
		}
	}
	return nil
}

// ignorePorts adapts a block list writer to the swap's put signature.
func ignorePorts(put func(ip string, ttl time.Duration) error) func(string, time.Duration, []PortScope) error {
	return func(ip string, ttl time.Duration, _ []PortScope) error { return put(ip, ttl) }
}
