//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sort"

	cebpf "github.com/cilium/ebpf"
)

// snapshotTable is one map a desired-state apply writes.
type snapshotTable struct {
	name string
	m    *cebpf.Map
}

// mutableFirewallMaps lists the maps a desired-state apply writes, in the
// order a rollback removes what the failed apply added: maps that drop or
// limit first, the allowlist last. The connection-tracking table is not
// here: an apply never writes it, and restoring it deleted the flows
// opened while the apply ran — a new SSH session among them. The geo tries
// and mode record are not here either: the geo snapshot (captureGeoLocked)
// restores them by diff, in an order that never unlists an allowed source.
func (m *Manager) mutableFirewallMaps() []snapshotTable {
	return []snapshotTable{
		{"config", m.configMap}, {"rate_config", m.rateConfigMap}, {"anomaly_config", m.anomalyConfigMap},
		{"portscan_config", m.portscanCfgMap}, {"port_policy_config", m.portPolicyCfgMap},
		{"block4", m.block4Map}, {"block6", m.block6Map},
		{"egress_blocklist", m.egressBlocklistMap}, {"egress_subnet4", m.egressSubnetV4Map}, {"egress_subnet6", m.egressSubnetV6Map},
		{"geo_blocked", m.geoBlockedMap},
		{"port_policy", m.portPolicyMap},
		{"allow4", m.allow4Map}, {"allow6", m.allow6Map},
	}
}

func (m *Manager) CaptureFirewallState() (*FirewallSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snapshot := &FirewallSnapshot{tables: make(map[string][]firewallMapEntry)}
	for _, t := range m.mutableFirewallMaps() {
		if t.m == nil {
			continue
		}
		entries := make([]firewallMapEntry, 0)
		key, value := make([]byte, t.m.KeySize()), make([]byte, t.m.ValueSize())
		iter := t.m.Iterate()
		for iter.Next(&key, &value) {
			entries = append(entries, firewallMapEntry{key: append([]byte(nil), key...), value: append([]byte(nil), value...)})
		}
		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", t.name, err)
		}
		snapshot.tables[t.name] = entries
	}
	geo, err := m.captureGeoLocked()
	if err != nil {
		return nil, err
	}
	snapshot.geo = geo
	return snapshot, nil
}

// restoreWriteOrder is the order a rollback writes the captured entries
// back in: what lets traffic in first (allowlist, port rules with allow
// rules ahead), then what drops it, the switches (config, port-policy
// config with its default deny) last — the forward apply's "rules first,
// switch last".
var restoreWriteOrder = []string{
	"allow4", "allow6", "port_policy",
	"block4", "block6", "egress_blocklist", "egress_subnet4", "egress_subnet6",
	"geo_blocked",
	"portscan_config", "rate_config", "anomaly_config", "config", "port_policy_config",
}

// RestoreFirewallState puts the captured entries back without a moment in
// which one of them is missing: every captured entry is first written
// over the live one (an update replaces a key in place) in restoreWriteOrder,
// the geo snapshot is restored by diff, and only then are the keys the failed
// apply added removed — table by table in mutableFirewallMaps order, so the
// allowlist shrinks last, and port rules that drop before the allow rules.
func (m *Manager) RestoreFirewallState(snapshot *FirewallSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var failures []error
	tables := m.mutableFirewallMaps()
	byName := make(map[string]*cebpf.Map, len(tables))
	for _, t := range tables {
		byName[t.name] = t.m
	}
	for name := range snapshot.tables {
		if byName[name] == nil {
			failures = append(failures, fmt.Errorf("rollback map %s unavailable", name))
		}
	}
	order := append([]string(nil), restoreWriteOrder...)
	for _, t := range tables { // a table missing from the order still comes back, last
		if !slices.Contains(order, t.name) {
			order = append(order, t.name)
		}
	}
	for _, name := range order {
		entries, ok := snapshot.tables[name]
		table := byName[name]
		if !ok || table == nil {
			continue
		}
		if name == "port_policy" {
			// Allow rules ahead of the rules that drop or log.
			sort.SliceStable(entries, func(i, j int) bool { return isAllowRule(entries[i].value) && !isAllowRule(entries[j].value) })
		}
		for _, entry := range entries {
			if err := table.Update(entry.key, entry.value, cebpf.UpdateAny); err != nil {
				failures = append(failures, fmt.Errorf("rollback restore %s: %w", name, err))
			}
		}
	}
	// Geo (mode record and tries) by diff, after the allowlist and the port
	// rules are back and before anything the failed apply added is removed.
	if err := m.restoreGeoLocked(snapshot.geo); err != nil {
		failures = append(failures, err)
	}
	for _, t := range tables {
		entries, ok := snapshot.tables[t.name]
		if !ok || t.m == nil || t.m.Type() == cebpf.Array || t.m.Type() == cebpf.PerCPUArray {
			continue // arrays cannot lose keys: the writes above restored them
		}
		keep := make(map[string]bool, len(entries))
		for _, e := range entries {
			keep[string(e.key)] = true
		}
		var extra, extraAllow [][]byte
		key, value := make([]byte, t.m.KeySize()), make([]byte, t.m.ValueSize())
		iter := t.m.Iterate()
		for iter.Next(&key, &value) {
			if keep[string(key)] {
				continue
			}
			k := append([]byte(nil), key...)
			if t.name == "port_policy" && isAllowRule(value) {
				extraAllow = append(extraAllow, k)
			} else {
				extra = append(extra, k)
			}
		}
		if err := iter.Err(); err != nil {
			failures = append(failures, fmt.Errorf("rollback enumerate %s: %w", t.name, err))
			continue
		}
		for _, k := range append(extra, extraAllow...) {
			if err := t.m.Delete(k); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
				failures = append(failures, fmt.Errorf("rollback clear %s: %w", t.name, err))
			}
		}
	}
	return errors.Join(failures...)
}

// isAllowRule: a port_policy_val whose action is ACTION_ALLOW (0).
func isAllowRule(value []byte) bool {
	return len(value) >= 4 && binary.LittleEndian.Uint32(value[:4]) == 0
}
