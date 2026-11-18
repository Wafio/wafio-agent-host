//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// The jail: addresses the WAF agent jails after repeated L7 blocks
// live in wafio_jail, apart from the operator lists. A push
// replaces the operator lists only (ReplaceIPLists), and the rollback
// snapshot leaves the jail out, so a jailed address stays jailed for its
// TTL; the dashboard reads the jail from the host status (Status.Jail).

// ErrJailUnavailable: the attached XDP object has no wafio_jail.
var ErrJailUnavailable = errors.New("the attached XDP object has no jail map; update the eBPF objects with the agent")

// statusJailEntries bounds the jail entries carried in Status (the status
// payload goes to the control plane every few seconds).
const statusJailEntries = 100

// AddToJail jails one address for ttl (> 0). Prefixes and ranges are
// refused: the jail holds the sources the WAF agent saw, one by one.
func (m *Manager) AddToJail(ipStr string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("a jail entry needs a TTL")
	}
	a, err := netip.ParseAddr(ipStr)
	if err != nil || a.Zone() != "" {
		return fmt.Errorf("%w: the jail takes single addresses, not %q", ErrInvalidIPEntry, clip(ipStr))
	}
	a = a.Unmap()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.jailMap == nil {
		return ErrJailUnavailable
	}
	key := IPKeyFromIP(net.IP(a.AsSlice()))
	now := m.ktimeNow()
	val := IPListVal{AddedNs: now, ExpiresNs: now + durationNs(ttl), RuleType: 1}
	var old IPListVal
	if err := m.jailMap.Lookup(key, &old); err == nil {
		val.HitCount = old.HitCount
	}
	err = m.jailMap.Update(key, &val, ebpf.UpdateAny)
	if errors.Is(err, unix.E2BIG) && m.claimJailSweep(time.Now()) {
		// Full: the entries past their TTL still hold slots until XDP meets
		// the address again. Free them and try once more.
		m.deleteExpiredJailLocked(now)
		err = m.jailMap.Update(key, &val, ebpf.UpdateAny)
	}
	if errors.Is(err, unix.E2BIG) {
		m.jailFull.Add(1)
		return fmt.Errorf("%w: %s not jailed", ErrJailFull, a)
	}
	return err
}

// jailSweepEvery spaces the sweeps of a full jail. A sweep reads every entry,
// and during an attack the WAF agent may jail many addresses a second: with
// the jail full of live entries, a sweep per request would cost a CPU.
const jailSweepEvery = time.Second

// claimJailSweep reports whether a full jail may be swept now: the first call
// after jailSweepEvery since the last sweep wins.
func (m *Manager) claimJailSweep(now time.Time) bool {
	last := m.jailSweptAt.Load()
	return now.UnixNano()-last >= int64(jailSweepEvery) && m.jailSweptAt.CompareAndSwap(last, now.UnixNano())
}

// deleteExpiredJailLocked removes the jail entries whose TTL ended before now
// (bpf_ktime_get_ns() nanoseconds). The caller holds m.mu.
func (m *Manager) deleteExpiredJailLocked(now uint64) {
	var expired []IPKey
	var key IPKey
	var val IPListVal
	iter := m.jailMap.Iterate()
	for iter.Next(&key, &val) {
		if val.ExpiresNs != 0 && val.ExpiresNs <= now {
			expired = append(expired, key)
		}
	}
	for _, k := range expired {
		if err := m.jailMap.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return
		}
	}
}

// listJailLocked returns up to limit live jail entries (latest expiry first)
// and how many are live in all. The caller holds m.mu.
func (m *Manager) listJailLocked(limit int) ([]BlocklistEntry, int, error) {
	if m.jailMap == nil {
		return nil, 0, ErrJailUnavailable
	}
	now := m.ktimeNow()
	var out []BlocklistEntry
	total := 0
	var key IPKey
	var val IPListVal
	iter := m.jailMap.Iterate()
	for iter.Next(&key, &val) {
		if val.ExpiresNs != 0 && val.ExpiresNs <= now {
			continue
		}
		total++
		e := BlocklistEntry{IP: key.ToIP().String(), AddedAt: m.bpfTimeToWall(val.AddedNs), HitCount: val.HitCount}
		if val.ExpiresNs != 0 {
			t := m.bpfTimeToWall(val.ExpiresNs)
			e.ExpiresAt = &t
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].ExpiresAt, out[j].ExpiresAt
		if a == nil || b == nil {
			return a == nil && b != nil
		}
		return a.After(*b)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, total, iter.Err()
}
