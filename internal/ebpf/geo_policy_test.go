package ebpf

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

func TestNormalizeGeoMode(t *testing.T) {
	for in, want := range map[string]string{"": GeoModeBlock, "block": GeoModeBlock, " Allow ": GeoModeAllow} {
		if got, ok := NormalizeGeoMode(in); !ok || got != want {
			t.Errorf("NormalizeGeoMode(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"deny", "allowlist", "1"} {
		if _, ok := NormalizeGeoMode(bad); ok {
			t.Errorf("NormalizeGeoMode(%q) accepted", bad)
		}
	}
}

func TestNormalizeCountryCode(t *testing.T) {
	for in, want := range map[string]string{"id": "ID", " Sg ": "SG", "US": "US"} {
		if got, ok := NormalizeCountryCode(in); !ok || got != want {
			t.Errorf("NormalizeCountryCode(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "I", "IDN", "1D", "Ä1", "I-"} {
		if _, ok := NormalizeCountryCode(bad); ok {
			t.Errorf("NormalizeCountryCode(%q) accepted", bad)
		}
	}
}

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func TestMergeGeoPrefixes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     []string
		v4, v6 []string
	}{
		{"siblings", []string{"10.0.0.128/25", "10.0.0.0/25"}, []string{"10.0.0.0/24"}, nil},
		{"cascade", []string{"10.0.0.192/26", "10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26"}, []string{"10.0.0.0/24"}, nil},
		{"not siblings", []string{"10.0.0.128/25", "10.0.1.0/25"}, []string{"10.0.0.128/25", "10.0.1.0/25"}, nil},
		{"contained and duplicate", []string{"10.0.0.0/16", "10.0.3.0/24", "10.0.0.0/16", "10.1.0.0/24"}, []string{"10.0.0.0/16", "10.1.0.0/24"}, nil},
		{"unmasked input", []string{"10.0.0.7/24"}, []string{"10.0.0.0/24"}, nil},
		{"ipv4-mapped", []string{"::ffff:10.0.0.0/120"}, []string{"10.0.0.0/24"}, nil},
		{"ipv6 siblings", []string{"2001:db8::/33", "2001:db8:8000::/33", "2001:db9::/32"}, nil, []string{"2001:db8::/31"}},
		{"families split", []string{"2001:db8::/32", "192.0.2.0/24"}, []string{"192.0.2.0/24"}, []string{"2001:db8::/32"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6 := MergeGeoPrefixes(prefixes(t, tc.in...))
			if got := prefixStrings(v4); !slices.Equal(got, append([]string{}, tc.v4...)) && !(len(got) == 0 && len(tc.v4) == 0) {
				t.Errorf("v4 = %v, want %v", got, tc.v4)
			}
			if got := prefixStrings(v6); !slices.Equal(got, append([]string{}, tc.v6...)) && !(len(got) == 0 && len(tc.v6) == 0) {
				t.Errorf("v6 = %v, want %v", got, tc.v6)
			}
		})
	}
}

// fakeGeoStore records the dataplane writes of applyGeoRanges; onWrite lets
// a test check what the dataplane would do after every single write.
type fakeGeoStore struct {
	ranges  map[netip.Prefix]uint8
	n4, n6  int
	mode    *bool // nil: object without wafio_geo_config
	since   uint64
	clock   uint64
	ops     []string
	failPut int // fail the n-th put (1-based); 0 never
	puts    int
	// onWrite runs after every write, for invariant checks.
	onWrite func(s *fakeGeoStore)
}

func newFakeGeoStore(withMode bool) *fakeGeoStore {
	s := &fakeGeoStore{ranges: map[netip.Prefix]uint8{}}
	if withMode {
		s.mode = new(bool)
	}
	return s
}

func (s *fakeGeoStore) listGeoRanges() (map[netip.Prefix]uint8, error) {
	out := make(map[netip.Prefix]uint8, len(s.ranges))
	for p, v := range s.ranges {
		out[p] = v
	}
	return out, nil
}

func (s *fakeGeoStore) count(v6 bool) *int {
	if v6 {
		return &s.n6
	}
	return &s.n4
}

func (s *fakeGeoStore) putGeoRange(p netip.Prefix, v uint8) error {
	s.puts++
	if s.failPut != 0 && s.puts == s.failPut {
		return errors.New("injected")
	}
	if _, ok := s.ranges[p]; !ok {
		if *s.count(p.Addr().Is6()) >= GeoCIDRCapacity {
			return errors.New("map full") // the kernel's E2BIG/ENOSPC
		}
		*s.count(p.Addr().Is6())++
	}
	s.ranges[p] = v
	s.ops = append(s.ops, fmt.Sprintf("put %s=%d", p, v))
	if s.onWrite != nil {
		s.onWrite(s)
	}
	return nil
}

func (s *fakeGeoStore) deleteGeoRange(p netip.Prefix) error {
	if _, ok := s.ranges[p]; ok {
		*s.count(p.Addr().Is6())--
	}
	delete(s.ranges, p)
	s.ops = append(s.ops, "del "+p.String())
	if s.onWrite != nil {
		s.onWrite(s)
	}
	return nil
}

func (s *fakeGeoStore) geoConfig() (GeoConfig, bool, error) {
	if s.mode == nil {
		return GeoConfig{}, false, nil
	}
	cfg := GeoConfig{AllowSinceNs: s.since}
	if *s.mode {
		cfg.Mode = geoModeAllowValue
	}
	return cfg, true, nil
}

func (s *fakeGeoStore) setGeoConfig(cfg GeoConfig) error {
	if s.mode == nil {
		return nil
	}
	*s.mode = cfg.Mode == geoModeAllowValue
	s.since = cfg.AllowSinceNs
	s.ops = append(s.ops, fmt.Sprintf("mode allow=%v", *s.mode))
	if s.onWrite != nil {
		s.onWrite(s)
	}
	return nil
}

func (s *fakeGeoStore) ktimeNow() uint64 {
	s.clock += 1000
	return s.clock
}

// verdict mirrors the XDP lookup for one address: what the geo step does.
func (s *fakeGeoStore) dropped(addr netip.Addr) bool {
	var best netip.Prefix
	var val uint8
	found := false
	for p, v := range s.ranges {
		if p.Contains(addr) && (!found || p.Bits() > best.Bits()) {
			best, val, found = p, v, true
		}
	}
	if s.mode != nil && *s.mode {
		return !(found && val == geoCIDRAllowed)
	}
	return found && val == geoCIDRBlocked
}

func TestApplyGeoRangesTransitionsNeverDropWhatBothPoliciesAllow(t *testing.T) {
	id := prefixes(t, "36.64.0.0/11", "2001:df0::/32")  // the allowed country
	cn := prefixes(t, "1.80.0.0/13", "2400:da00::/32")  // a blocked country
	sg := prefixes(t, "8.128.0.0/10", "2401:7400::/32") // another one
	idAddr := []netip.Addr{netip.MustParseAddr("36.70.1.1"), netip.MustParseAddr("2001:df0::1")}
	cnAddr := []netip.Addr{netip.MustParseAddr("1.80.1.1"), netip.MustParseAddr("2400:da00::1")}
	for _, tc := range []struct {
		name          string
		fromMode      string
		from          []netip.Prefix
		toMode        string
		to            []netip.Prefix
		neverDropped  []netip.Addr // allowed by the old and the new policy
		alwaysDropped []netip.Addr // dropped by the old and the new policy
	}{
		{"block CN → allow ID", GeoModeBlock, cn, GeoModeAllow, id, idAddr, cnAddr},
		{"allow ID → allow ID+SG", GeoModeAllow, id, GeoModeAllow, append(slices.Clone(id), sg...), idAddr, cnAddr},
		{"allow ID+SG → allow ID", GeoModeAllow, append(slices.Clone(id), sg...), GeoModeAllow, id, idAddr, cnAddr},
		{"allow ID → block CN", GeoModeAllow, id, GeoModeBlock, cn, idAddr, nil},
		{"allow ID → block ID", GeoModeAllow, id, GeoModeBlock, id, nil, nil},
		{"block ID → allow ID", GeoModeBlock, id, GeoModeAllow, id, nil, nil},
		{"block CN → block CN+SG", GeoModeBlock, cn, GeoModeBlock, append(slices.Clone(cn), sg...), idAddr, cnAddr},
		{"allow ID → off", GeoModeAllow, id, GeoModeBlock, nil, idAddr, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeGeoStore(true)
			if _, _, err := applyGeoRanges(s, tc.fromMode, tc.from); err != nil {
				t.Fatal(err)
			}
			s.ops = nil
			s.onWrite = func(s *fakeGeoStore) {
				for _, a := range tc.neverDropped {
					if s.dropped(a) {
						t.Errorf("%s dropped mid-transition after %v", a, s.ops)
					}
				}
				for _, a := range tc.alwaysDropped {
					if !s.dropped(a) {
						t.Errorf("%s passed mid-transition after %v", a, s.ops)
					}
				}
			}
			v4, v6, err := applyGeoRanges(s, tc.toMode, tc.to)
			if err != nil {
				t.Fatal(err)
			}
			m4, m6 := MergeGeoPrefixes(tc.to)
			if v4 != len(m4) || v6 != len(m6) || len(s.ranges) != len(m4)+len(m6) {
				t.Fatalf("counts v4=%d v6=%d ranges=%d, want %d/%d", v4, v6, len(s.ranges), len(m4), len(m6))
			}
			want := geoCIDRBlocked
			if tc.toMode == GeoModeAllow {
				want = geoCIDRAllowed
			}
			for p, v := range s.ranges {
				if v != want {
					t.Errorf("%s = %d, want %d", p, v, want)
				}
			}
			if *s.mode != (tc.toMode == GeoModeAllow) {
				t.Errorf("mode allow=%v, want %s", *s.mode, tc.toMode)
			}
		})
	}
}

func TestApplyGeoRangesAllowOrder(t *testing.T) {
	s := newFakeGeoStore(true)
	if _, _, err := applyGeoRanges(s, GeoModeBlock, prefixes(t, "1.80.0.0/13")); err != nil {
		t.Fatal(err)
	}
	s.ops = nil
	if _, _, err := applyGeoRanges(s, GeoModeAllow, prefixes(t, "36.64.0.0/11")); err != nil {
		t.Fatal(err)
	}
	want := []string{"put 36.64.0.0/11=2", "mode allow=true", "del 1.80.0.0/13"}
	if !slices.Equal(s.ops, want) {
		t.Fatalf("ops %v, want %v", s.ops, want)
	}
	// Unchanged list and mode: nothing is written but the mode.
	s.ops = nil
	if _, _, err := applyGeoRanges(s, GeoModeAllow, prefixes(t, "36.64.0.0/11")); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.ops, []string{"mode allow=true"}) {
		t.Fatalf("re-apply ops %v", s.ops)
	}
}

// A failed write in the middle of a switch to allow leaves block mode on:
// the mode only switches once every allowed range is in.
func TestApplyGeoRangesAllowFailureKeepsBlockMode(t *testing.T) {
	s := newFakeGeoStore(true)
	if _, _, err := applyGeoRanges(s, GeoModeBlock, prefixes(t, "1.80.0.0/13")); err != nil {
		t.Fatal(err)
	}
	s.failPut = s.puts + 2
	if _, _, err := applyGeoRanges(s, GeoModeAllow, prefixes(t, "36.64.0.0/11", "8.128.0.0/10")); err == nil {
		t.Fatal("injected failure not reported")
	}
	if *s.mode {
		t.Fatal("allow mode switched on with part of the allow list")
	}
	if !s.dropped(netip.MustParseAddr("1.80.1.1")) {
		t.Fatal("blocked country no longer blocked after a failed switch")
	}
}

func TestApplyGeoRangesRefusals(t *testing.T) {
	old := newFakeGeoStore(false)
	if _, _, err := applyGeoRanges(old, GeoModeAllow, prefixes(t, "36.64.0.0/11")); !errors.Is(err, ErrGeoAllowUnsupported) {
		t.Fatalf("object without wafio_geo_config: %v", err)
	}
	if len(old.ops) != 0 {
		t.Fatalf("writes on refusal: %v", old.ops)
	}
	// Block mode still works on such an object (value 1, as before).
	if _, _, err := applyGeoRanges(old, GeoModeBlock, prefixes(t, "1.80.0.0/13")); err != nil {
		t.Fatal(err)
	}

	big := make([]netip.Prefix, 0, GeoCIDRCapacity+1)
	for i := 0; i <= GeoCIDRCapacity; i++ {
		// /32s two apart never merge.
		big = append(big, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 15), byte(i >> 7), byte(i<<1) & 0xfe}), 32))
	}
	s := newFakeGeoStore(true)
	_, _, err := applyGeoRanges(s, GeoModeAllow, big)
	if !errors.Is(err, ErrGeoRangesExceedCapacity) {
		t.Fatalf("over capacity: %v", err)
	}
	if code, _ := FirewallErrorCode(err); code != "GEO_RANGES_EXCEED_CAPACITY" {
		t.Fatalf("code %q", code)
	}
	if len(s.ops) != 0 {
		t.Fatalf("writes on refusal: %d", len(s.ops))
	}
}

// Old and new lists that only fit one at a time: the old ranges go first.
func TestApplyGeoRangesOverflowDropsOldFirst(t *testing.T) {
	half := GeoCIDRCapacity/2 + 10
	mk := func(base byte) []netip.Prefix {
		out := make([]netip.Prefix, 0, half)
		for i := 0; i < half; i++ {
			out = append(out, netip.PrefixFrom(netip.AddrFrom4([4]byte{base, byte(i >> 15), byte(i >> 7), byte(i<<1) & 0xfe}), 32))
		}
		return out
	}
	s := newFakeGeoStore(true)
	if _, _, err := applyGeoRanges(s, GeoModeBlock, mk(20)); err != nil {
		t.Fatal(err)
	}
	s.ops = nil
	if _, _, err := applyGeoRanges(s, GeoModeAllow, mk(30)); err != nil {
		t.Fatal(err)
	}
	if len(s.ops) == 0 || s.ops[0][:3] != "del" || s.ops[len(s.ops)-1] != "mode allow=true" {
		t.Fatalf("overflow order: first %q last %q", s.ops[0], s.ops[len(s.ops)-1])
	}
}

// allow_since_ns is stamped when allow mode goes live and kept while it
// stays on, so connections open before the first switch stay exempt across
// list changes, and none opened through an exempt path afterwards do.
func TestApplyGeoRangesAllowSince(t *testing.T) {
	s := newFakeGeoStore(true)
	if _, _, err := applyGeoRanges(s, GeoModeAllow, prefixes(t, "36.64.0.0/11")); err != nil {
		t.Fatal(err)
	}
	first := s.since
	if first == 0 {
		t.Fatal("allow_since_ns not stamped")
	}
	if _, _, err := applyGeoRanges(s, GeoModeAllow, prefixes(t, "36.64.0.0/11", "8.128.0.0/10")); err != nil {
		t.Fatal(err)
	}
	if s.since != first {
		t.Fatalf("list change restamped allow_since_ns: %d -> %d", first, s.since)
	}
	if _, _, err := applyGeoRanges(s, GeoModeBlock, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyGeoRanges(s, GeoModeAllow, prefixes(t, "36.64.0.0/11")); err != nil {
		t.Fatal(err)
	}
	if s.since <= first {
		t.Fatalf("a new switch to allow kept the old stamp %d", s.since)
	}
}

// A later step fails after the geo step and the bundle rolls
// back. The snapshot holds the tries and the mode record, and the rollback
// diffs back to them (syncGeo), in both directions, without dropping a
// source both policies let through and without restamping allow_since_ns.
func TestGeoSnapshotRollbackBothDirections(t *testing.T) {
	id := prefixes(t, "36.64.0.0/11", "2001:df0::/32")
	cn := prefixes(t, "1.80.0.0/13", "2400:da00::/32")
	idAddr := netip.MustParseAddr("36.70.1.1")
	cnAddr := netip.MustParseAddr("1.80.1.1")

	t.Run("block to allow rolled back", func(t *testing.T) {
		s := newFakeGeoStore(true)
		if _, _, err := applyGeoRanges(s, GeoModeBlock, cn); err != nil {
			t.Fatal(err)
		}
		snap, err := captureGeo(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := applyGeoRanges(s, GeoModeAllow, id); err != nil {
			t.Fatal(err)
		}
		s.onWrite = func(s *fakeGeoStore) {
			if s.dropped(idAddr) {
				t.Errorf("%s dropped mid-rollback after %v", idAddr, s.ops)
			}
		}
		if err := syncGeo(s, snap.ranges, snap.cfg, snap.hasMode); err != nil {
			t.Fatal(err)
		}
		if *s.mode || !s.dropped(cnAddr) || s.dropped(idAddr) || len(s.ranges) != len(cn) {
			t.Fatalf("after rollback: allow=%v ranges=%v", *s.mode, s.ranges)
		}
	})
	t.Run("allow to block rolled back", func(t *testing.T) {
		s := newFakeGeoStore(true)
		if _, _, err := applyGeoRanges(s, GeoModeAllow, id); err != nil {
			t.Fatal(err)
		}
		since := s.since
		snap, err := captureGeo(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := applyGeoRanges(s, GeoModeBlock, cn); err != nil {
			t.Fatal(err)
		}
		s.onWrite = func(s *fakeGeoStore) {
			if s.dropped(idAddr) {
				t.Errorf("%s dropped mid-rollback after %v", idAddr, s.ops)
			}
		}
		if err := syncGeo(s, snap.ranges, snap.cfg, snap.hasMode); err != nil {
			t.Fatal(err)
		}
		if !*s.mode || s.since != since || !s.dropped(cnAddr) || s.dropped(idAddr) || len(s.ranges) != len(id) {
			t.Fatalf("after rollback: allow=%v since=%d (want %d) ranges=%v", *s.mode, s.since, since, s.ranges)
		}
	})
}
