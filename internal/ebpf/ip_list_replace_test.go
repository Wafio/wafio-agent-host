package ebpf

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakeListStore is an in-memory ipListStore. After every write it runs probe,
// standing in for the packets the dataplane looks up meanwhile.
type fakeListStore struct {
	lists map[string]map[string]time.Time // "allow" | "block" | "egress" -> key -> deadline
	ports map[string][]PortScope          // allowlist key -> ports (absent = every port)
	ops   []string                        // "put allow 10.0.0.1", "del block 0.0.0.0/0"
	probe func(op string)
}

func newFakeListStore() *fakeListStore {
	return &fakeListStore{lists: map[string]map[string]time.Time{"allow": {}, "block": {}, "egress": {}},
		ports: map[string][]PortScope{}}
}

func (f *fakeListStore) put(list, key string, ttl time.Duration) error {
	var deadline time.Time
	if ttl > 0 {
		deadline = time.Now().Add(ttl)
	}
	f.lists[list][key] = deadline
	op := "put " + list + " " + key
	f.ops = append(f.ops, op)
	if f.probe != nil {
		f.probe(op)
	}
	return nil
}

func (f *fakeListStore) del(list, key string) error {
	delete(f.lists[list], key)
	if list == "allow" {
		delete(f.ports, key)
	}
	op := "del " + list + " " + key
	f.ops = append(f.ops, op)
	if f.probe != nil {
		f.probe(op)
	}
	return nil
}

func listOf[E any](f *fakeListStore, list string, mk func(ip string, exp *time.Time) E) []E {
	var out []E
	for k, d := range f.lists[list] {
		var exp *time.Time
		if !d.IsZero() {
			d := d
			exp = &d
		}
		out = append(out, mk(k, exp))
	}
	return out
}

func (f *fakeListStore) ListAllowlist(int) ([]AllowlistEntry, error) {
	return listOf(f, "allow", func(ip string, exp *time.Time) AllowlistEntry {
		return AllowlistEntry{IP: ip, ExpiresAt: exp, Ports: f.ports[ip]}
	}), nil
}
func (f *fakeListStore) ListBlocklist(int) ([]BlocklistEntry, error) {
	return listOf(f, "block", func(ip string, exp *time.Time) BlocklistEntry { return BlocklistEntry{IP: ip, ExpiresAt: exp} }), nil
}
func (f *fakeListStore) ListEgressBlocklist(int) ([]EgressBlocklistEntry, error) {
	return listOf(f, "egress", func(ip string, exp *time.Time) EgressBlocklistEntry {
		return EgressBlocklistEntry{IP: ip, ExpiresAt: exp}
	}), nil
}
func (f *fakeListStore) AddToAllowlistPorts(ip string, ttl time.Duration, ports []PortScope) error {
	if len(ports) > 0 {
		f.ports[ip] = ports
	} else {
		delete(f.ports, ip)
	}
	return f.put("allow", ip, ttl)
}
func (f *fakeListStore) AddToBlocklist(ip string, ttl time.Duration) error {
	return f.put("block", ip, ttl)
}
func (f *fakeListStore) AddToEgressBlocklist(ip string, ttl time.Duration) error {
	return f.put("egress", ip, ttl)
}
func (f *fakeListStore) RemoveFromAllowlist(ip string) error       { return f.del("allow", ip) }
func (f *fakeListStore) RemoveFromBlocklist(ip string) error       { return f.del("block", ip) }
func (f *fakeListStore) RemoveFromEgressBlocklist(ip string) error { return f.del("egress", ip) }

func keysOf(m map[string]time.Time) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func at(t time.Time) *time.Time { return &t }

// An entry that stays is present at every moment of the swap, the
// allowlist grows before the blocks change and shrinks last, and the maps end
// equal to the desired lists.
func TestReplaceIPListsNeverDropsRetainedEntries(t *testing.T) {
	now := time.Now()
	f := newFakeListStore()
	f.lists["allow"]["203.0.113.7"] = time.Time{}        // admin, stays
	f.lists["allow"]["198.51.100.9"] = time.Time{}       // old admin address, goes
	f.lists["block"]["0.0.0.0/0"] = time.Time{}          // wildcard block, stays
	f.lists["block"]["192.0.2.66"] = time.Time{}         // stays, TTL added
	f.lists["block"]["192.0.2.67"] = time.Time{}         // goes
	f.lists["egress"]["198.18.0.1"] = now.Add(time.Hour) // stays
	retained := map[string][]string{
		"allow":  {"203.0.113.7"},
		"block":  {"0.0.0.0/0", "192.0.2.66"},
		"egress": {"198.18.0.1"},
	}
	newAllow := "198.51.100.10" // the admin's new address
	newAllowSeen := false
	f.probe = func(op string) {
		for list, keys := range retained {
			for _, k := range keys {
				if _, ok := f.lists[list][k]; !ok {
					t.Fatalf("after %q: retained %s entry %s missing", op, list, k)
				}
			}
		}
		if _, ok := f.lists["allow"][newAllow]; ok {
			newAllowSeen = true
		}
		if op == "del allow 198.51.100.9" && !newAllowSeen {
			t.Fatalf("old admin address removed before the new one was added")
		}
	}
	err := ReplaceIPLists(f, IPListUpdate{
		Allow:  []AllowlistEntry{{IP: "203.0.113.7"}, {IP: newAllow}},
		Block:  []BlocklistEntry{{IP: "0.0.0.0/0"}, {IP: "192.0.2.66", ExpiresAt: at(now.Add(time.Hour))}, {IP: "192.0.2.70"}},
		Egress: []EgressBlocklistEntry{{IP: "198.18.0.1", ExpiresAt: at(now.Add(time.Hour))}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	// Order: every allowlist write precedes every block write; every stale
	// block removal precedes every stale allowlist removal.
	lastAllowPut, firstBlockPut, lastBlockDel, firstAllowDel := -1, -1, -1, -1
	for i, op := range f.ops {
		switch {
		case strings.HasPrefix(op, "put allow"):
			lastAllowPut = i
		case strings.HasPrefix(op, "put block") && firstBlockPut < 0:
			firstBlockPut = i
		case strings.HasPrefix(op, "del block"):
			lastBlockDel = i
		case strings.HasPrefix(op, "del allow") && firstAllowDel < 0:
			firstAllowDel = i
		}
	}
	if lastAllowPut > firstBlockPut || lastBlockDel > firstAllowDel {
		t.Fatalf("write order: %v", f.ops)
	}
	if got := strings.Join(keysOf(f.lists["allow"]), ","); got != "198.51.100.10,203.0.113.7" {
		t.Fatalf("allowlist %s", got)
	}
	if got := strings.Join(keysOf(f.lists["block"]), ","); got != "0.0.0.0/0,192.0.2.66,192.0.2.70" {
		t.Fatalf("blocklist %s", got)
	}
	if f.lists["block"]["192.0.2.66"].IsZero() {
		t.Fatal("changed TTL not applied")
	}
	// The unchanged egress entry and the unchanged allow/block keys were not
	// rewritten.
	for _, op := range f.ops {
		if op == "put egress 198.18.0.1" || op == "put allow 203.0.113.7" || op == "put block 0.0.0.0/0" {
			t.Fatalf("unchanged entry rewritten: %s", op)
		}
	}
}

// An expired desired entry is never written (never permanent), and a live one
// is removed; a key named twice keeps the longest deadline, permanent first.
func TestReplaceIPListsExpiryAndDuplicates(t *testing.T) {
	now := time.Now()
	f := newFakeListStore()
	f.lists["block"]["192.0.2.1"] = time.Time{}
	err := ReplaceIPLists(f, IPListUpdate{
		Block: []BlocklistEntry{
			{IP: "192.0.2.1", ExpiresAt: at(now.Add(-time.Second))},
			{IP: "192.0.2.2", ExpiresAt: at(now)},
			{IP: "192.0.2.8", ExpiresAt: at(now.Add(time.Minute))},
			{IP: "192.0.2.8/32"},
			{IP: "::ffff:192.0.2.9", ExpiresAt: at(now.Add(time.Minute))},
			{IP: "192.0.2.9", ExpiresAt: at(now.Add(time.Hour))},
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keysOf(f.lists["block"]), ","); got != "192.0.2.8,192.0.2.9" {
		t.Fatalf("blocklist %s", got)
	}
	if !f.lists["block"]["192.0.2.8"].IsZero() {
		t.Fatal("permanent spelling of a key lost to an expiring one")
	}
	if d := f.lists["block"]["192.0.2.9"].Sub(now); d < 59*time.Minute {
		t.Fatalf("mapped and plain spellings did not merge to the later deadline: %v", d)
	}
}

func TestReplaceIPListsLeavesAbsentListsAlone(t *testing.T) {
	f := newFakeListStore()
	f.lists["allow"]["203.0.113.7"] = time.Time{}
	f.lists["egress"]["198.18.0.1"] = time.Time{}
	if err := ReplaceIPLists(f, IPListUpdate{Block: []BlocklistEntry{}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(f.ops) != 0 || len(f.lists["allow"]) != 1 || len(f.lists["egress"]) != 1 {
		t.Fatalf("lists outside the update changed: %v", f.ops)
	}
}

// An allowlist that would overflow while swapped is refused before any write;
// an overflowing blocklist sheds its stale entries first.
func TestReplaceIPListsCapacity(t *testing.T) {
	now := time.Now()
	f := newFakeListStore()
	for i := 0; i < allowlistCapacity; i++ {
		f.lists["allow"][fmt.Sprintf("10.%d.%d.1", i/250, i%250)] = time.Time{}
	}
	err := ReplaceIPLists(f, IPListUpdate{Allow: []AllowlistEntry{{IP: "203.0.113.7"}}}, now)
	if !errors.Is(err, ErrIPListBatch) || len(f.ops) != 0 {
		t.Fatalf("overflowing allowlist swap: err=%v ops=%d", err, len(f.ops))
	}

	f = newFakeListStore()
	for i := 0; i < blocklistCapacity; i++ {
		f.lists["block"][fmt.Sprintf("10.%d.%d.%d", i/62500, i/250%250, i%250)] = time.Time{}
	}
	if err := ReplaceIPLists(f, IPListUpdate{Block: []BlocklistEntry{{IP: "203.0.113.66"}}}, now); err != nil {
		t.Fatal(err)
	}
	if len(f.lists["block"]) != 1 || !strings.HasPrefix(f.ops[0], "del block") {
		t.Fatalf("overflowing blocklist swap did not shed stale entries first: %d left, first op %q", len(f.lists["block"]), f.ops[0])
	}
	// Planned per map: a full IPv4 allow trie leaves room in
	// the IPv6 one, and lapsed stale allowlist entries (they allow nothing)
	// make room before anything else.
	f = newFakeListStore()
	for i := 0; i < allowlistCapacity; i++ {
		f.lists["allow"][fmt.Sprintf("10.%d.%d.1", i/250, i%250)] = time.Time{}
	}
	keep := make([]AllowlistEntry, 0, allowlistCapacity+1)
	for k := range f.lists["allow"] {
		keep = append(keep, AllowlistEntry{IP: k})
	}
	if err := ReplaceIPLists(f, IPListUpdate{Allow: append(keep[:allowlistCapacity-1:allowlistCapacity-1], AllowlistEntry{IP: "2001:db8::1"})}, now); err != nil {
		t.Fatalf("IPv6 entry beside a full IPv4 trie: %v", err)
	}
	f = newFakeListStore()
	lapsed := now.Add(-time.Hour)
	for i := 0; i < allowlistCapacity; i++ {
		f.lists["allow"][fmt.Sprintf("10.%d.%d.1", i/250, i%250)] = lapsed
	}
	f.lists["allow"]["203.0.113.7"] = time.Time{}
	delete(f.lists["allow"], "10.0.0.1")
	if err := ReplaceIPLists(f, IPListUpdate{Allow: []AllowlistEntry{{IP: "203.0.113.7"}, {IP: "198.51.100.7"}}}, now); err != nil {
		t.Fatalf("lapsed stale entries did not make room: %v", err)
	}
	if got := strings.Join(keysOf(f.lists["allow"]), ","); got != "198.51.100.7,203.0.113.7" {
		t.Fatalf("allowlist %s", got)
	}
	// Egress: more IPv4 prefixes than the egress trie holds, replaced by a
	// disjoint set, shed the stale ones first instead of failing mid-swap.
	f = newFakeListStore()
	var fresh []EgressBlocklistEntry
	for i := 0; i < egressSubnetV4Capacity; i++ {
		f.lists["egress"][fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)] = time.Time{}
		fresh = append(fresh, EgressBlocklistEntry{IP: fmt.Sprintf("172.%d.%d.0/24", 16+i/256%16, i%256)})
	}
	if err := ReplaceIPLists(f, IPListUpdate{Egress: fresh[:egressSubnetV4Capacity/2]}, now); err != nil {
		t.Fatalf("egress prefixes swap: %v", err)
	}
	if !strings.HasPrefix(f.ops[0], "del egress") {
		t.Fatalf("full egress trie did not shed stale prefixes first: %q", f.ops[0])
	}

	if _, err := desiredKeys([]BlocklistEntry{{IP: "10.0.0.1"}, {IP: "10.0.0.2"}, {IP: "10.0.0.3"}, {IP: "10.0.0.4"}},
		func(e BlocklistEntry) string { return e.IP }, func(e BlocklistEntry) *time.Time { return e.ExpiresAt }, 3, now); !errors.Is(err, ErrIPListCapacity) {
		t.Fatalf("desired list above capacity: %v", err)
	}
}
