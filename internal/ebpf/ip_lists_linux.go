//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// IP list storage. Ingress allowlist and blocklist entries are prefixes
// in LPM tries, one trie per list and family (wafio_allow4/6,
// wafio_block4/6); nothing is expanded into single addresses. The egress
// blocklist keeps addresses and the family-wide entries in its hash (TC reads
// the 0xFD/0xFE sentinels there) and every other prefix in the egress tries.
// None of these maps evicts: a full map refuses the write.

// ErrListMapsMissing: the attached XDP object predates the prefix tries.
var ErrListMapsMissing = errors.New("the attached XDP object predates prefix IP lists (wafio_allow4/wafio_block4); update the eBPF objects with the agent")

func u32FromU64Sat(v uint64) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// listTries returns the two tries of an ingress list.
func (m *Manager) listTries(allow bool) (v4, v6 *ebpf.Map) {
	if allow {
		return m.allow4Map, m.allow6Map
	}
	return m.block4Map, m.block6Map
}

func v4Key(p netip.Prefix) SubnetV4Key {
	return SubnetV4Key{PrefixLen: u32FromInt(p.Bits()), Addr: p.Addr().As4()}
}

func v6Key(p netip.Prefix) SubnetV6Key {
	return SubnetV6Key{PrefixLen: u32FromInt(p.Bits()), Addr: p.Addr().As16()}
}

// trieKey picks the trie of p's family and its key.
func trieKey(v4, v6 *ebpf.Map, p netip.Prefix) (*ebpf.Map, any) {
	if p.Addr().Is4() {
		return v4, v4Key(p)
	}
	return v6, v6Key(p)
}

// putListPrefix writes one ingress list prefix (hit count kept). ports
// (allowlist only) scope the entry; empty = every port and protocol.
func (m *Manager) putListPrefix(allow bool, p netip.Prefix, ttl time.Duration, ports []PortScope) error {
	v4, v6 := m.listTries(allow)
	if v4 == nil || v6 == nil {
		return ErrListMapsMissing
	}
	if allow && len(ports) > 0 && !m.allowlistPortsSupportedLocked() {
		// An object without scope matching treats a scoped value as never
		// deciding; refusing keeps the lockout guard's view (it counts
		// SSH-covering scopes as an escape hatch) equal to the dataplane.
		return ErrAllowlistPortsUnsupported
	}
	trie, key := trieKey(v4, v6, p)
	now := m.ktimeNow()
	var expires uint64
	if ttl > 0 {
		expires = now + durationNs(ttl)
	}
	plen := u32FromInt(p.Bits())
	if allow {
		val := AllowVal{AddedNs: now, ExpiresNs: expires, PrefixLen: plen}
		if err := allowValScopes(&val, ports); err != nil {
			return err
		}
		var old AllowVal
		if err := trie.Lookup(key, &old); err == nil {
			val.HitCount = old.HitCount
		}
		return listWriteErr(trie.Update(key, &val, ebpf.UpdateAny), "allowlist", p)
	}
	val := BlockVal{AddedNs: now, ExpiresNs: expires, PrefixLen: plen}
	var old BlockVal
	if err := trie.Lookup(key, &old); err == nil {
		val.HitCount = old.HitCount
	}
	return listWriteErr(trie.Update(key, &val, ebpf.UpdateAny), "blocklist", p)
}

// listWriteErr names a full map (the tries never evict, they refuse).
func listWriteErr(err error, list string, p netip.Prefix) error {
	if err == nil {
		return nil
	}
	// LPM tries refuse a full map with ENOSPC, hash maps with E2BIG.
	if errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.E2BIG) {
		return fmt.Errorf("%w: %s map full, %s not added", ErrIPListCapacity, list, PrefixKey(p))
	}
	return fmt.Errorf("%s %s: %w", list, PrefixKey(p), err)
}

func (m *Manager) deleteListPrefix(allow bool, p netip.Prefix) error {
	v4, v6 := m.listTries(allow)
	if v4 == nil || v6 == nil {
		return ErrListMapsMissing
	}
	trie, key := trieKey(v4, v6, p)
	return trie.Delete(key)
}

// addListEntry writes every prefix of an entry (an address, a CIDR, a
// range); ports as putListPrefix.
func (m *Manager) addListEntry(allow bool, entry string, ttl time.Duration, ports []PortScope) error {
	prefixes, err := IPListPrefixes(entry)
	if err != nil {
		return err
	}
	if len(ports) > 0 {
		for _, p := range prefixes {
			if p.Bits() == 0 {
				return ErrAllowlistWildcardScoped
			}
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range prefixes {
		if err := m.putListPrefix(allow, p, ttl, ports); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) removeListEntry(allow bool, entry string) error {
	prefixes, err := IPListPrefixes(entry)
	if err != nil {
		return err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var errs []error
	for _, p := range prefixes {
		if err := m.deleteListPrefix(allow, p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// listEntries reads an ingress list, IPv4 first, up to limit entries
// (limit <= 0: 1000). Expired entries are included (the XDP walk skips them;
// a push removes or rewrites them). Allowlist entries carry their ports.
func (m *Manager) listEntries(allow bool, limit int) ([]AllowlistEntry, error) {
	if limit <= 0 {
		limit = 1000
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	v4, v6 := m.listTries(allow)
	if v4 == nil || v6 == nil {
		return nil, ErrListMapsMissing
	}
	var out []AllowlistEntry
	add := func(p netip.Prefix, added, expires, hits uint64, ports []PortScope) {
		e := AllowlistEntry{IP: PrefixKey(p), AddedAt: m.bpfTimeToWall(added), HitCount: u32FromU64Sat(hits), Ports: ports}
		if expires != 0 {
			t := m.bpfTimeToWall(expires)
			e.ExpiresAt = &t
		}
		out = append(out, e)
	}
	var k4 SubnetV4Key
	var k6 SubnetV6Key
	if allow {
		var v AllowVal
		iter := v4.Iterate()
		for len(out) < limit && iter.Next(&k4, &v) {
			add(netip.PrefixFrom(netip.AddrFrom4(k4.Addr), int(k4.PrefixLen)), v.AddedNs, v.ExpiresNs, v.HitCount, portScopesOfAllowVal(v))
		}
		if err := iter.Err(); err != nil {
			return out, err
		}
		iter = v6.Iterate()
		for len(out) < limit && iter.Next(&k6, &v) {
			add(netip.PrefixFrom(netip.AddrFrom16(k6.Addr), int(k6.PrefixLen)), v.AddedNs, v.ExpiresNs, v.HitCount, portScopesOfAllowVal(v))
		}
		return out, iter.Err()
	}
	var v BlockVal
	iter := v4.Iterate()
	for len(out) < limit && iter.Next(&k4, &v) {
		add(netip.PrefixFrom(netip.AddrFrom4(k4.Addr), int(k4.PrefixLen)), v.AddedNs, v.ExpiresNs, v.HitCount, nil)
	}
	if err := iter.Err(); err != nil {
		return out, err
	}
	iter = v6.Iterate()
	for len(out) < limit && iter.Next(&k6, &v) {
		add(netip.PrefixFrom(netip.AddrFrom16(k6.Addr), int(k6.PrefixLen)), v.AddedNs, v.ExpiresNs, v.HitCount, nil)
	}
	return out, iter.Err()
}

// AddToBlocklist adds an address, CIDR or IPv4 range to the ingress
// blocklist with an optional TTL.
func (m *Manager) AddToBlocklist(ipStr string, ttl time.Duration) error {
	return m.addListEntry(false, ipStr, ttl, nil)
}

// RemoveFromBlocklist removes the prefixes of an entry from the blocklist.
func (m *Manager) RemoveFromBlocklist(ipStr string) error { return m.removeListEntry(false, ipStr) }

// ListBlocklist returns the ingress blocklist (one entry per prefix).
func (m *Manager) ListBlocklist(limit int) ([]BlocklistEntry, error) {
	entries, err := m.listEntries(false, limit)
	out := make([]BlocklistEntry, len(entries))
	for i, e := range entries {
		out[i] = BlocklistEntry{IP: e.IP, AddedAt: e.AddedAt, ExpiresAt: e.ExpiresAt, HitCount: e.HitCount}
	}
	return out, err
}

// AddToAllowlist adds an address, CIDR or IPv4 range to the ingress
// allowlist with an optional TTL (every port and protocol: ALLOW_F_ALL).
func (m *Manager) AddToAllowlist(ipStr string, ttl time.Duration) error {
	return m.addListEntry(true, ipStr, ttl, nil)
}

// AddToAllowlistPorts is AddToAllowlist scoped to ports (empty = every
// port). Scoped entries need an object that matches scopes
// (ErrAllowlistPortsUnsupported) and never name a /0 prefix.
func (m *Manager) AddToAllowlistPorts(ipStr string, ttl time.Duration, ports []PortScope) error {
	return m.addListEntry(true, ipStr, ttl, ports)
}

// RemoveFromAllowlist removes the prefixes of an entry from the allowlist.
func (m *Manager) RemoveFromAllowlist(ipStr string) error { return m.removeListEntry(true, ipStr) }

// ListAllowlist returns the ingress allowlist (one entry per prefix, with
// its ports).
func (m *Manager) ListAllowlist(limit int) ([]AllowlistEntry, error) {
	return m.listEntries(true, limit)
}

// ── Egress blocklist ────────────────────────────────────────────────────────

// egressIPv6 reports an attached TC egress object that filters IPv6 (the
// condition Status reports as egress_ipv6_supported).
func (m *Manager) egressIPv6() bool {
	attached := m.tcEgressLink != nil || m.legacyTC != nil && m.legacyTC.attached(netlink.HANDLE_MIN_EGRESS)
	return attached && m.tcColl != nil && m.tcColl.Maps["wafio_packet_abi"] != nil
}

// egressHashKey: the hash key of an address or a family-wide prefix; false
// for any other prefix (it goes to the egress tries).
func egressHashKey(p netip.Prefix) (IPKey, bool) {
	switch p.Bits() {
	case 0:
		if p.Addr().Is4() {
			return IPKeyWildcard("0.0.0.0/0"), true
		}
		return IPKeyWildcard("::/0"), true
	case p.Addr().BitLen():
		return IPKeyFromIP(net.IP(p.Addr().AsSlice())), true
	}
	return IPKey{}, false
}

// AddToEgressBlocklist adds an address, CIDR or IPv4 range to the egress
// blocklist.
func (m *Manager) AddToEgressBlocklist(ipStr string, ttl time.Duration) error {
	prefixes, err := IPListPrefixes(ipStr)
	if err != nil {
		return err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.egressBlocklistMap == nil {
		return fmt.Errorf("egress blocklist map not loaded")
	}
	now := m.ktimeNow()
	var expires uint64
	if ttl > 0 {
		expires = now + durationNs(ttl)
	}
	for _, p := range prefixes {
		if p.Addr().Is6() && !m.egressIPv6() {
			return fmt.Errorf("IPv6 egress filtering unavailable on attached object")
		}
		if key, ok := egressHashKey(p); ok {
			val := IPListVal{AddedNs: now, ExpiresNs: expires, RuleType: 1}
			var old IPListVal
			if err := m.egressBlocklistMap.Lookup(key, &old); err == nil {
				val.HitCount = old.HitCount
			}
			if err := listWriteErr(m.egressBlocklistMap.Update(key, &val, ebpf.UpdateAny), "egress blocklist", p); err != nil {
				return err
			}
			continue
		}
		trie, key := trieKey(m.egressSubnetV4Map, m.egressSubnetV6Map, p)
		if trie == nil {
			return fmt.Errorf("egress subnet map not loaded")
		}
		val := SubnetVal{AddedNs: now, ExpiresNs: expires, RuleType: 1}
		var old SubnetVal
		if err := trie.Lookup(key, &old); err == nil {
			val.HitCount = old.HitCount
		}
		if err := listWriteErr(trie.Update(key, &val, ebpf.UpdateAny), "egress blocklist", p); err != nil {
			return err
		}
	}
	return nil
}

// RemoveFromEgressBlocklist removes the prefixes of an entry.
func (m *Manager) RemoveFromEgressBlocklist(ipStr string) error {
	prefixes, err := IPListPrefixes(ipStr)
	if err != nil {
		return err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.egressBlocklistMap == nil {
		return fmt.Errorf("egress blocklist map not loaded")
	}
	var errs []error
	for _, p := range prefixes {
		if key, ok := egressHashKey(p); ok {
			if err := m.egressBlocklistMap.Delete(key); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		trie, key := trieKey(m.egressSubnetV4Map, m.egressSubnetV6Map, p)
		if trie == nil {
			errs = append(errs, fmt.Errorf("egress subnet map not loaded"))
			continue
		}
		if err := trie.Delete(key); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ListEgressBlocklist returns the egress blocklist: hash entries (addresses
// and family-wide entries), then the egress tries.
func (m *Manager) ListEgressBlocklist(limit int) ([]EgressBlocklistEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.egressBlocklistMap == nil {
		return nil, fmt.Errorf("egress blocklist map not loaded")
	}
	if limit <= 0 {
		limit = 1000
	}
	var out []EgressBlocklistEntry
	add := func(ip string, added, expires uint64, hits uint32) {
		e := EgressBlocklistEntry{IP: ip, AddedAt: m.bpfTimeToWall(added), HitCount: hits}
		if expires != 0 {
			t := m.bpfTimeToWall(expires)
			e.ExpiresAt = &t
		}
		out = append(out, e)
	}
	var key IPKey
	var val IPListVal
	iter := m.egressBlocklistMap.Iterate()
	for len(out) < limit && iter.Next(&key, &val) {
		ip := key.ToIP().String()
		if key.IsWildcard() {
			ip = "0.0.0.0/0"
			if key.Family == 0xFE {
				ip = "::/0"
			}
		}
		add(ip, val.AddedNs, val.ExpiresNs, val.HitCount)
	}
	if err := iter.Err(); err != nil {
		return out, err
	}
	var sv SubnetVal
	if m.egressSubnetV4Map != nil {
		var k4 SubnetV4Key
		iter = m.egressSubnetV4Map.Iterate()
		for len(out) < limit && iter.Next(&k4, &sv) {
			add(PrefixKey(netip.PrefixFrom(netip.AddrFrom4(k4.Addr), int(k4.PrefixLen))), sv.AddedNs, sv.ExpiresNs, sv.HitCount)
		}
		if err := iter.Err(); err != nil {
			return out, err
		}
	}
	if m.egressSubnetV6Map != nil {
		var k6 SubnetV6Key
		iter = m.egressSubnetV6Map.Iterate()
		for len(out) < limit && iter.Next(&k6, &sv) {
			add(PrefixKey(netip.PrefixFrom(netip.AddrFrom16(k6.Addr), int(k6.PrefixLen))), sv.AddedNs, sv.ExpiresNs, sv.HitCount)
		}
		if err := iter.Err(); err != nil {
			return out, err
		}
	}
	return out, nil
}

// LiveBlocks returns every live ingress and egress blocklist entry (lapsed
// ones left out) for the local API's lockout check. Since prefixes are
// stored natively the guard needs all of them, not only the /0 keys: a
// set of local writes such as 0.0.0.0/2 + 64.0.0.0/2 covers half a family
// without ever adding a /0 (broadFamilies).
func (m *Manager) LiveBlocks() ([]BlocklistEntry, []EgressBlocklistEntry, error) {
	block, err := m.ListBlocklist(2 * maxBlockPrefixes)
	if err != nil {
		return nil, nil, err
	}
	egress, err := m.ListEgressBlocklist(egressBlocklistCapacity + egressSubnetV4Capacity + egressSubnetV6Capacity)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	liveB := block[:0]
	for _, e := range block {
		if e.ExpiresAt == nil || e.ExpiresAt.After(now) {
			liveB = append(liveB, e)
		}
	}
	liveE := egress[:0]
	for _, e := range egress {
		if e.ExpiresAt == nil || e.ExpiresAt.After(now) {
			liveE = append(liveE, e)
		}
	}
	return liveB, liveE, nil
}
