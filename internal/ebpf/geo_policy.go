package ebpf

import (
	"fmt"
	"net/netip"
	"slices"
)

// geoModeName is the API name of a geo_config mode value.
func geoModeName(v uint32) string {
	if v == geoModeAllowValue {
		return GeoModeAllow
	}
	return GeoModeBlock
}

// GeoRangeState is what the dataplane enforces after ApplyGeoRanges.
type GeoRangeState struct {
	Mode      string   `json:"mode"`
	Countries []string `json:"countries"`
	RangesV4  int      `json:"ranges_v4"`
	RangesV6  int      `json:"ranges_v6"`
}

// geoRangeStore is the slice of the dataplane the geo sync writes: the two
// geo LPM tries and the mode record. Tests use a fake.
type geoRangeStore interface {
	listGeoRanges() (map[netip.Prefix]uint8, error)
	putGeoRange(p netip.Prefix, value uint8) error
	deleteGeoRange(p netip.Prefix) error
	// geoConfig reads wafio_geo_config; ok false when the object has none.
	geoConfig() (cfg GeoConfig, ok bool, err error)
	setGeoConfig(cfg GeoConfig) error
	// ktimeNow is bpf_ktime_get_ns() now (CLOCK_MONOTONIC).
	ktimeNow() uint64
}

// applyGeoRanges makes the geo tries hold exactly prefixes (merged) with the
// value of mode and switches the mode (syncGeo orders the writes). Switching
// from block to allow stamps allow_since_ns with the current time; staying
// in allow keeps the stamp, so connections open before the first switch
// stay exempt across list changes.
func applyGeoRanges(s geoRangeStore, mode string, prefixes []netip.Prefix) (v4, v6 int, err error) {
	allow := mode == GeoModeAllow
	cur, hasMode, err := s.geoConfig()
	if err != nil {
		return 0, 0, err
	}
	if allow && !hasMode {
		return 0, 0, ErrGeoAllowUnsupported
	}
	m4, m6, err := GeoRangesFit(prefixes)
	if err != nil {
		return 0, 0, err
	}
	value := geoCIDRBlocked
	cfg := GeoConfig{Mode: geoModeBlockValue}
	if allow {
		value = geoCIDRAllowed
		cfg = cur
		if cur.Mode != geoModeAllowValue {
			cfg = GeoConfig{Mode: geoModeAllowValue, AllowSinceNs: s.ktimeNow()}
		}
	}
	desired := make(map[netip.Prefix]uint8, len(m4)+len(m6))
	for _, p := range append(m4, m6...) {
		desired[p] = value
	}
	if err := syncGeo(s, desired, cfg, hasMode); err != nil {
		return 0, 0, err
	}
	return len(m4), len(m6), nil
}

// GeoSnapshot is the geo part of a firewall snapshot: the tries' entries and
// the mode record, restored by syncGeo (never cleared and refilled), plus
// the manager's bookkeeping of the last apply.
type GeoSnapshot struct {
	ranges  map[netip.Prefix]uint8
	cfg     GeoConfig
	hasMode bool
	state   GeoRangeState
}

func captureGeo(s geoRangeStore) (*GeoSnapshot, error) {
	ranges, err := s.listGeoRanges()
	if err != nil {
		return nil, err
	}
	cfg, hasMode, err := s.geoConfig()
	if err != nil {
		return nil, err
	}
	return &GeoSnapshot{ranges: ranges, cfg: cfg, hasMode: hasMode}, nil
}

// syncGeo makes the geo tries hold exactly desired and the mode record cfg,
// in an order that never drops a source the old or the new policy lets
// through:
//
//   - to allow: the desired ranges are written first (block mode ignores
//     allowed ranges), then the mode record, then the old ranges go — so an
//     allowed source is never unlisted while allow mode is on;
//   - to block: the mode record first (allowed ranges then mean nothing),
//     then the blocked ranges are written and the old ones go.
//
// When the old and the new ranges together do not fit a trie, the old ones
// go before the new are written: block ranges vanish early (a moment of
// fail-open), allowed ranges of a country leaving the list early (it is
// being dropped anyway). The same routine restores a snapshot, so a
// rollback never clears and refills the tries while allow mode is live.
func syncGeo(s geoRangeStore, desired map[netip.Prefix]uint8, cfg GeoConfig, hasMode bool) error {
	existing, err := s.listGeoRanges()
	if err != nil {
		return err
	}
	union4, union6 := 0, 0
	count := func(p netip.Prefix) {
		if p.Addr().Is4() {
			union4++
		} else {
			union6++
		}
	}
	for p := range desired {
		if _, ok := existing[p]; !ok {
			count(p)
		}
	}
	for p := range existing {
		count(p)
	}
	fits := union4 <= GeoCIDRCapacity && union6 <= GeoCIDRCapacity

	// Writes in address order: deterministic for tests and logs.
	keys := make([]netip.Prefix, 0, len(desired))
	for p := range desired {
		keys = append(keys, p)
	}
	slices.SortFunc(keys, comparePrefix)
	put := func() error {
		for _, p := range keys {
			if v, ok := existing[p]; ok && v == desired[p] {
				continue
			}
			if err := s.putGeoRange(p, desired[p]); err != nil {
				return fmt.Errorf("geo range %s: %w", p, err)
			}
		}
		return nil
	}
	drop := func() error {
		stale := make([]netip.Prefix, 0)
		for p := range existing {
			if _, ok := desired[p]; !ok {
				stale = append(stale, p)
			}
		}
		slices.SortFunc(stale, comparePrefix)
		for _, p := range stale {
			if err := s.deleteGeoRange(p); err != nil {
				return fmt.Errorf("geo range %s: %w", p, err)
			}
		}
		return nil
	}
	setMode := func() error {
		if !hasMode {
			return nil
		}
		return s.setGeoConfig(cfg)
	}

	allow := cfg.Mode == geoModeAllowValue
	var steps []func() error
	switch {
	case allow && fits:
		steps = []func() error{put, setMode, drop}
	case allow:
		steps = []func() error{drop, put, setMode}
	case fits:
		steps = []func() error{setMode, put, drop}
	default:
		steps = []func() error{setMode, drop, put}
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}
