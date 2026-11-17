package ebpf

// FirewallSnapshot retains exact mutable map entries, including monotonic expiry.
// It supports rollback; it does not provide an atomic dataplane map swap.
// The geo tries and mode record are kept apart (geo) and restored by diff
// (syncGeo): clearing and refilling them would unlist every allowed source
// while allow mode is on, and the mode record must come back with them.
type FirewallSnapshot struct {
	tables map[string][]firewallMapEntry
	geo    *GeoSnapshot
}
type firewallMapEntry struct{ key, value []byte }
