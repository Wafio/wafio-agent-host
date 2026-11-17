package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// fakeGeoDataplane logs the geo writes applyGeoState makes, in order.
type fakeGeoDataplane struct {
	log          []string
	blocked      []string
	failApply    error
	failRestore  error
	subnetWrites int
	code, state  string
	msg          string
}

func (f *fakeGeoDataplane) ListBlockedCountries() ([]string, error) {
	return slices.Clone(f.blocked), nil
}
func (f *fakeGeoDataplane) BlockCountry(code string) error {
	f.blocked = append(f.blocked, code)
	f.log = append(f.log, "block "+code)
	return nil
}
func (f *fakeGeoDataplane) UnblockCountry(code string) error {
	f.blocked = slices.DeleteFunc(f.blocked, func(c string) bool { return c == code })
	f.log = append(f.log, "unblock "+code)
	return nil
}
func (f *fakeGeoDataplane) ApplyGeoRanges(mode string, codes []string, prefixes []netip.Prefix) error {
	if f.failApply != nil {
		return f.failApply
	}
	f.log = append(f.log, fmt.Sprintf("ranges %s %s %d", mode, strings.Join(codes, ","), len(prefixes)))
	return nil
}
func (f *fakeGeoDataplane) CaptureGeo() (*wafebpf.GeoSnapshot, error) {
	f.log = append(f.log, "capture")
	return &wafebpf.GeoSnapshot{}, nil
}
func (f *fakeGeoDataplane) RestoreGeo(*wafebpf.GeoSnapshot) error {
	f.log = append(f.log, "restore")
	return f.failRestore
}
func (f *fakeGeoDataplane) SetGeoLocalSubnets(p []netip.Prefix) error {
	f.subnetWrites++
	f.log = append(f.log, fmt.Sprintf("subnets %d", len(p)))
	return nil
}
func (f *fakeGeoDataplane) SetGeoDegraded(code, state, message string) {
	f.code, f.state, f.msg = code, state, message
}

// fakeResolver returns n ranges per country, or err.
type fakeResolver struct {
	n   int
	err error
}

func (r fakeResolver) ResolveGeoRanges(codes []string) ([]netip.Prefix, error) {
	if r.err != nil {
		return nil, r.err
	}
	var out []netip.Prefix
	for i := range codes {
		for j := 0; j < r.n; j++ {
			// /32s two apart never merge.
			out = append(out, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(10 + i), byte(j >> 15), byte(j >> 7), byte(j<<1) & 0xfe}), 32))
		}
	}
	return out, nil
}

func geoState(mode string, enabled bool, blocked []string, allowed []string) *ebpfDesiredState {
	s := &ebpfDesiredState{
		Config:     &wafebpf.FullConfigAPI{Global: wafebpf.GlobalConfigAPI{EnableGeoblock: enabled, EnableConntrack: true}},
		GeoMode:    mode,
		GeoAllowed: allowed,
		GeoBlocked: []wafebpf.CountryEntry{},
	}
	for _, c := range blocked {
		s.GeoBlocked = append(s.GeoBlocked, wafebpf.CountryEntry{Code: c, Blocked: true})
	}
	return s
}

var fullGeoEnv = firewallEnv{exemptions: true, geoAllow: true}

// Geo reasons degrade geo only; they are resolved before any map write.
func TestPlanGeo(t *testing.T) {
	allow := geoState("allow", true, []string{"CN"}, []string{"ID"})
	for _, tc := range []struct {
		name  string
		s     *ebpfDesiredState
		env   firewallEnv
		src   geoRangeResolver
		code  string // degraded code; "" = applies
		apply bool
		n     int // resolved prefixes
	}{
		{"allow", allow, fullGeoEnv, fakeResolver{n: 3}, "", true, 3},
		{"allow on objects without the exemptions", allow, firewallEnv{geoAllow: true}, fakeResolver{n: 3}, "FIREWALL_DATAPLANE_OUTDATED", true, 0},
		{"allow without wafio_geo_config", allow, firewallEnv{exemptions: true}, fakeResolver{n: 3}, "GEO_ALLOW_UNSUPPORTED", true, 0},
		{"allow without dataset", allow, fullGeoEnv, nil, "GEO_ALLOW_NO_DATASET", true, 0},
		{"allow, country has no range", allow, fullGeoEnv, fakeResolver{n: 0}, "GEO_ALLOW_NO_RANGES", true, 0},
		{"allow, dataset unreadable", allow, fullGeoEnv, fakeResolver{err: fmt.Errorf("%w: open: no such file", ErrGeoDatasetUnreadable)}, "GEO_DATASET_UNREADABLE", true, 0},
		{"allow over capacity", allow, fullGeoEnv, fakeResolver{n: wafebpf.GeoCIDRCapacity + 1}, "GEO_RANGES_EXCEED_CAPACITY", true, 0},
		{"block", geoState("block", true, []string{"cn"}, nil), firewallEnv{}, fakeResolver{n: 2}, "", true, 2},
		{"block without dataset: reactive map only", geoState("block", true, []string{"CN"}, nil), firewallEnv{}, nil, "", true, 0},
		{"block over capacity", geoState("block", true, []string{"CN"}, nil), firewallEnv{}, fakeResolver{n: wafebpf.GeoCIDRCapacity + 1}, "GEO_RANGES_EXCEED_CAPACITY", true, 0},
		{"geo off needs nothing", geoState("allow", false, nil, []string{"ID"}), firewallEnv{}, nil, "", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := planGeo(tc.s, tc.env, tc.src)
			code := ""
			if p.degraded != nil {
				code = geoDegradedCode(p.degraded)
			}
			if code != tc.code || p.apply != tc.apply || len(p.prefixes) != tc.n {
				t.Fatalf("plan code %q apply %v prefixes %d (%v); want %q %v %d", code, p.apply, len(p.prefixes), p.degraded, tc.code, tc.apply, tc.n)
			}
		})
	}
	partial := geoState("block", true, nil, nil)
	partial.GeoBlocked = nil
	if p := planGeo(partial, firewallEnv{}, nil); p.apply || p.degraded != nil {
		t.Fatalf("a push without geo_blocked must leave geo alone: %+v", p)
	}
}

func TestApplyGeoStateOrder(t *testing.T) {
	subnets := func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, nil }
	for _, tc := range []struct {
		name   string
		before []string
		s      *ebpfDesiredState
		want   []string
	}{
		// The connected subnets and the allow list go live before the
		// blocked countries leave the reactive map.
		{"block to allow", []string{"CN"}, geoState("allow", true, []string{"CN"}, []string{"ID"}),
			[]string{"capture", "subnets 1", "ranges allow ID 2", "unblock CN"}},
		{"allow to block", nil, geoState("block", true, []string{"CN"}, []string{"ID"}),
			[]string{"capture", "block CN", "ranges block CN 2"}},
		{"geo off", []string{"CN"}, geoState("allow", false, nil, []string{"ID"}),
			[]string{"capture", "unblock CN", "ranges block  0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &fakeGeoDataplane{blocked: slices.Clone(tc.before), code: "OLD"}
			applyGeoState(dp, planGeo(tc.s, fullGeoEnv, fakeResolver{n: 2}), subnets)
			if !slices.Equal(dp.log, tc.want) {
				t.Fatalf("ops %q, want %q", dp.log, tc.want)
			}
			if dp.code != "" || dp.state != "" {
				t.Fatalf("degraded status not cleared: %q %q", dp.code, dp.state)
			}
		})
	}
}

// A degraded plan writes nothing: the previous geo state stays.
func TestApplyGeoStateDegradedKeepsPreviousGeo(t *testing.T) {
	dp := &fakeGeoDataplane{blocked: []string{"CN"}}
	applyGeoState(dp, planGeo(geoState("allow", true, nil, []string{"ID"}), firewallEnv{exemptions: true}, fakeResolver{n: 2}), nil)
	if len(dp.log) != 0 || dp.code != "GEO_ALLOW_UNSUPPORTED" || dp.state != geoStateKept || !slices.Equal(dp.blocked, []string{"CN"}) {
		t.Fatalf("ops %v code %q state %q blocked %v", dp.log, dp.code, dp.state, dp.blocked)
	}
}

// A block list that cannot be loaded still leaves allow mode: the mode the
// operator switched away from never stays live. The reactive country map
// takes the list, the ranges are cleared, and the status says why.
func TestApplyGeoStateDegradedBlockLeavesAllowMode(t *testing.T) {
	dp := &fakeGeoDataplane{}
	plan := planGeo(geoState("block", true, []string{"CN"}, []string{"ID"}), fullGeoEnv, fakeResolver{n: wafebpf.GeoCIDRCapacity + 1})
	applyGeoState(dp, plan, nil)
	want := []string{"capture", "block CN", "ranges block  0"}
	if !slices.Equal(dp.log, want) || dp.code != "GEO_RANGES_EXCEED_CAPACITY" || dp.state != geoStateRangesCleared {
		t.Fatalf("ops %q code %q state %q, want %q GEO_RANGES_EXCEED_CAPACITY ranges_cleared", dp.log, dp.code, dp.state, want)
	}
}

// A write failing half-way restores the geo snapshot (by diff, mode record
// included) and the reactive map, and degrades geo only.
func TestApplyGeoStateRollsBackFailedWrite(t *testing.T) {
	dp := &fakeGeoDataplane{blocked: []string{"CN"}, failApply: errors.New("map full")}
	applyGeoState(dp, planGeo(geoState("block", true, []string{"RU"}, nil), fullGeoEnv, fakeResolver{n: 2}), nil)
	if !slices.Contains(dp.log, "restore") || !slices.Equal(dp.blocked, []string{"CN"}) {
		t.Fatalf("no rollback: ops %v blocked %v", dp.log, dp.blocked)
	}
	if dp.code != "GEO_APPLY_FAILED" || dp.state != geoStateKept || !strings.Contains(dp.msg, "map full") {
		t.Fatalf("degraded %q %q %q", dp.code, dp.state, dp.msg)
	}

	// The rollback fails too: the status says the tables are mixed.
	dp = &fakeGeoDataplane{blocked: []string{"CN"}, failApply: errors.New("map full"), failRestore: errors.New("ENOMEM")}
	applyGeoState(dp, planGeo(geoState("block", true, []string{"RU"}, nil), fullGeoEnv, fakeResolver{n: 2}), nil)
	if dp.state != geoStateMixed || !strings.Contains(dp.msg, "rollback failed") {
		t.Fatalf("failed rollback reported as %q: %q", dp.state, dp.msg)
	}
}

// An unreadable interface fails the switch to allow (rolled
// back, reported) instead of loading an empty subnet table.
func TestApplyGeoStateSubnetReadFailureFailsTheSwitch(t *testing.T) {
	dp := &fakeGeoDataplane{blocked: []string{"CN"}}
	broken := func() ([]netip.Prefix, error) {
		return nil, fmt.Errorf("%w: eth0: permission denied", ErrGeoLocalSubnets)
	}
	applyGeoState(dp, planGeo(geoState("allow", true, nil, []string{"ID"}), fullGeoEnv, fakeResolver{n: 2}), broken)
	if dp.subnetWrites != 0 || slices.ContainsFunc(dp.log, func(op string) bool { return strings.HasPrefix(op, "ranges") }) {
		t.Fatalf("switched with an unreadable interface: %v", dp.log)
	}
	if dp.code != "GEO_LOCAL_SUBNETS_UNREADABLE" || dp.state != geoStateKept || !slices.Equal(dp.blocked, []string{"CN"}) {
		t.Fatalf("code %q state %q blocked %v", dp.code, dp.state, dp.blocked)
	}
	// A refresh while allow mode is live keeps the table on a read error.
	if err := refreshGeoSubnets(dp, broken); err == nil || dp.subnetWrites != 0 {
		t.Fatalf("refresh wrote a table after a read error: %v", err)
	}
}

// Only the interface XDP is attached to supplies subnets; a
// second interface (docker0) is never on-link for packets XDP sees, so its
// subnet must not be admitted.
func TestAttachedSubnetsOnlyFromTheXDPInterface(t *testing.T) {
	ipnet := func(s string) *net.IPNet {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	table := map[string][]net.Addr{
		"eth0":    {ipnet("198.51.100.10/24"), ipnet("10.1.2.5/24"), ipnet("fe80::1/64")},
		"docker0": {ipnet("172.17.0.1/16")},
		"lo":      {ipnet("127.0.0.1/8")},
	}
	addrs := func(name string) ([]net.Addr, error) {
		a, ok := table[name]
		if !ok {
			return nil, errors.New("no such interface")
		}
		return a, nil
	}
	got, err := subnetsOf("eth0", addrs)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("10.1.2.0/24"), netip.MustParsePrefix("fe80::/64")}
	if !slices.Equal(got, want) {
		t.Fatalf("eth0 subnets %v, want %v", got, want)
	}
	if slices.ContainsFunc(got, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr("172.17.0.2")) }) {
		t.Fatal("docker0's subnet admitted")
	}
	for _, name := range []string{"", "wg9"} {
		if _, err := subnetsOf(name, addrs); !errors.Is(err, ErrGeoLocalSubnets) {
			t.Fatalf("interface %q: %v", name, err)
		}
	}
	if code := geoDegradedCode(fmt.Errorf("%w: x", ErrGeoLocalSubnets)); code != "GEO_LOCAL_SUBNETS_UNREADABLE" {
		t.Fatalf("code %q", code)
	}
}

// Validation no longer refuses a whole state for a geo capability reason;
// the lockout rules still refuse an unsafe allow mode.
func TestValidateEBPFStateGeoAllow(t *testing.T) {
	s := geoState("allow", true, nil, []string{"ID"})
	s.GeoAllowAcknowledged = true
	for _, env := range []firewallEnv{{}, {exemptions: true}, fullGeoEnv} {
		if _, err := validateEBPFStateWith(s, env); err != nil {
			t.Fatalf("env %+v: %v (geo capability must degrade, not refuse)", env, err)
		}
	}
	s.GeoAllowAcknowledged = false
	if _, err := validateEBPFStateWith(s, fullGeoEnv); !errors.Is(err, hostpolicy.ErrGeoAllowUnacknowledged) {
		t.Fatalf("unacknowledged: %v", err)
	}
	if code, _ := wafebpf.FirewallErrorCode(hostpolicy.ErrGeoAllowUnacknowledged); !strings.HasPrefix(refuseApply(hostpolicy.ErrGeoAllowUnacknowledged).Error(), applyRefusedPrefix+code+")") {
		t.Fatal("refusal text")
	}
}

// An agent older than allow mode reads a new desired state: the allowed
// countries sit under their own key, so it sees no blocked country
// (fail open) instead of blocking the allowed ones.
func TestGeoAllowedKeyInvisibleToBlockList(t *testing.T) {
	raw := []byte(`{"config":{"global":{"enable_geoblock":true}},"geo_blocked":[],"geo_mode":"allow","geo_allowed":["ID"],"geo_allow_acknowledged":true}`)
	var old struct {
		GeoBlocked []wafebpf.CountryEntry `json:"geo_blocked"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	if len(old.GeoBlocked) != 0 {
		t.Fatalf("old agent would block %v", old.GeoBlocked)
	}
	var s ebpfDesiredState
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if s.GeoMode != "allow" || !slices.Equal(s.GeoAllowed, []string{"ID"}) || !s.GeoAllowAcknowledged {
		t.Fatalf("decoded %+v", s)
	}
}

func TestPrefixFromIPNet(t *testing.T) {
	for _, tc := range []struct {
		in   *net.IPNet
		want string
	}{
		{&net.IPNet{IP: net.IPv4(36, 64, 0, 0).To4(), Mask: net.CIDRMask(11, 32)}, "36.64.0.0/11"},
		{&net.IPNet{IP: net.IPv4(36, 64, 0, 0), Mask: net.CIDRMask(107, 128)}, "36.64.0.0/11"},
		{&net.IPNet{IP: net.ParseIP("2001:df0::"), Mask: net.CIDRMask(32, 128)}, "2001:df0::/32"},
		{&net.IPNet{IP: net.IPv4(36, 64, 0, 0), Mask: net.CIDRMask(11, 32)}, "36.64.0.0/11"},
	} {
		got, ok := wafebpf.GeoPrefixFromIPNet(tc.in)
		if !ok || got != netip.MustParsePrefix(tc.want) {
			t.Errorf("GeoPrefixFromIPNet(%v) = %v, %v; want %s", tc.in, got, ok, tc.want)
		}
	}
	if _, ok := wafebpf.GeoPrefixFromIPNet(nil); ok {
		t.Error("nil accepted")
	}
}
