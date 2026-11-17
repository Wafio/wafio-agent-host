package agent

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
)

// Geo is the last step of a desired-state apply and the only one that
// degrades instead of failing the bundle: a host whose objects
// or GeoIP dataset cannot enforce the desired geo policy keeps every other
// rule (blocklist, Deny All, port rules) and its previous geo state, and
// reports why in its status (geo_degraded_code). Refusing the whole state
// for a geo reason would leave the host on the open default policy at the
// next restart.

// geoRangeResolver turns country codes into their GeoIP ranges
// (*GeoIPEnricher).
type geoRangeResolver interface {
	ResolveGeoRanges(codes []string) ([]netip.Prefix, error)
}

// geoDataplane is the slice of *wafebpf.Manager the geo step writes.
type geoDataplane interface {
	ListBlockedCountries() ([]string, error)
	BlockCountry(code string) error
	UnblockCountry(code string) error
	ApplyGeoRanges(mode string, countries []string, prefixes []netip.Prefix) error
	CaptureGeo() (*wafebpf.GeoSnapshot, error)
	RestoreGeo(*wafebpf.GeoSnapshot) error
	SetGeoLocalSubnets([]netip.Prefix) error
	SetGeoDegraded(code, state, message string)
}

// Degraded geo states (status geo_degraded_state): what the dataplane holds
// when the desired geo policy is not enforced.
const (
	// geoStateKept: the previous geo state is enforced unchanged.
	geoStateKept = "kept"
	// geoStateRangesCleared: block mode with the reactive country map only;
	// the country address ranges are not loaded (block list unloadable).
	geoStateRangesCleared = "ranges_cleared"
	// geoStateMixed: a geo write failed and restoring the previous state
	// failed too; the geo tables may hold parts of both.
	geoStateMixed = "mixed"
)

// geoSubnets lists the subnets of the interface XDP is attached to.
type geoSubnets func() ([]netip.Prefix, error)

// geoPlan is the geo part of a desired state, resolved — ranges loaded from
// the dataset and checked against the tries' capacity — before any map is
// written.
type geoPlan struct {
	apply    bool     // false: the state says nothing about geo
	mode     string   // block or allow
	blocked  []string // reactive country map (block mode)
	codes    []string // countries whose ranges load
	prefixes []netip.Prefix
	// degraded: the desired geo policy cannot be enforced; the previous
	// geo state stays.
	degraded error
}

// ErrGeoDatasetUnreadable: the GeoIP country database could not be read
// while resolving the ranges.
var ErrGeoDatasetUnreadable = errors.New("the GeoIP country database could not be read")

// ErrGeoLocalSubnets: the addresses of the interface XDP is attached to
// could not be read, so allow mode cannot tell its own subnets apart.
var ErrGeoLocalSubnets = errors.New("the attached interface's subnets could not be read")

// geoDegradedCode is the status code of a degraded geo apply.
func geoDegradedCode(err error) string {
	if errors.Is(err, ErrGeoDatasetUnreadable) {
		return "GEO_DATASET_UNREADABLE"
	}
	if errors.Is(err, ErrGeoLocalSubnets) {
		return "GEO_LOCAL_SUBNETS_UNREADABLE"
	}
	if code, ok := wafebpf.FirewallErrorCode(err); ok {
		return code
	}
	return "GEO_APPLY_FAILED"
}

// planGeo resolves the geo part of s. Allow mode degrades when the
// dataplane lacks the reply exemptions (older objects) or
// wafio_geo_config, when no dataset is loaded, when the dataset has no
// range for the allowed countries or cannot be read, or when the ranges
// exceed the tries' capacity; block mode degrades on the last two. Geo
// switched off always applies (it needs neither objects nor data).
func planGeo(s *ebpfDesiredState, env firewallEnv, src geoRangeResolver) geoPlan {
	enabled := s.Config == nil || s.Config.Global.EnableGeoblock
	mode, ok := wafebpf.NormalizeGeoMode(s.GeoMode)
	if !ok {
		return geoPlan{degraded: wafebpf.ErrGeoModeInvalid}
	}
	if !enabled {
		return geoPlan{apply: true, mode: wafebpf.GeoModeBlock}
	}
	if mode == wafebpf.GeoModeBlock && s.GeoBlocked == nil {
		return geoPlan{} // an older control plane's partial state
	}
	p := geoPlan{apply: true, mode: mode}
	if mode == wafebpf.GeoModeAllow {
		for _, code := range s.GeoAllowed {
			if c, ok := wafebpf.NormalizeCountryCode(code); ok {
				p.codes = append(p.codes, c)
			}
		}
		switch {
		case !env.exemptions:
			p.degraded = wafebpf.ErrDataplaneLacksExemptions
		case !env.geoAllow:
			p.degraded = wafebpf.ErrGeoAllowUnsupported
		case src == nil:
			p.degraded = wafebpf.ErrGeoAllowNoDataset
		}
		if p.degraded != nil {
			return p
		}
	} else {
		p.blocked = geoBlockedCodes(s.GeoBlocked)
		p.codes = p.blocked
	}
	if src != nil && len(p.codes) > 0 {
		prefixes, err := src.ResolveGeoRanges(p.codes)
		if err != nil {
			p.degraded = err
			return p
		}
		if _, _, err := wafebpf.GeoRangesFit(prefixes); err != nil {
			p.degraded = err
			return p
		}
		p.prefixes = prefixes
	}
	if mode == wafebpf.GeoModeAllow && len(p.prefixes) == 0 {
		p.degraded = wafebpf.ErrGeoAllowNoRanges
	}
	return p
}

// applyGeoState applies a plan; it never fails the bundle. The status
// says which degraded state the dataplane is in (geo_degraded_state):
//
//   - kept: a degraded allow plan writes nothing, or a write that failed
//     half-way was rolled back (RestoreGeo: by diff, the mode record
//     included, and the reactive country map) — the previous geo state is
//     enforced;
//   - ranges_cleared: a degraded block plan (block → block too) still
//     leaves allow mode — a mode the operator switched away from never
//     stays live — with the reactive country map only and the ranges
//     cleared;
//   - mixed: the rollback of a failed write failed as well.
//
// A later complete apply clears the status.
func applyGeoState(dp geoDataplane, plan geoPlan, subnets geoSubnets) {
	if plan.degraded != nil {
		code := geoDegradedCode(plan.degraded)
		if !plan.apply || plan.mode != wafebpf.GeoModeBlock {
			dp.SetGeoDegraded(code, geoStateKept, plan.degraded.Error())
			log.Printf("[ebpf-grpc] geo policy not applied (%s): %v; the previous geo state stays, every other rule is applied", code, plan.degraded)
			return
		}
		log.Printf("[ebpf-grpc] geo block list not loaded (%s): %v; block mode with the reactive country map only", code, plan.degraded)
		fallback := plan
		fallback.prefixes, fallback.codes = nil, nil
		if mixed, err := commitGeo(dp, fallback, subnets); err != nil {
			dp.SetGeoDegraded(code, geoCommitState(mixed), fmt.Sprintf("%s; %v", plan.degraded.Error(), err))
			return
		}
		dp.SetGeoDegraded(code, geoStateRangesCleared, plan.degraded.Error())
		return
	}
	if !plan.apply {
		return
	}
	if mixed, err := commitGeo(dp, plan, subnets); err != nil {
		code := geoDegradedCode(err)
		dp.SetGeoDegraded(code, geoCommitState(mixed), err.Error())
		log.Printf("[ebpf-grpc] geo policy not applied (%s): %v", code, err)
		return
	}
	dp.SetGeoDegraded("", "", "")
}

func geoCommitState(mixed bool) string {
	if mixed {
		return geoStateMixed
	}
	return geoStateKept
}

// commitGeo writes a plan; on failure it restores the geo maps and the
// reactive country map as they were before it and returns the error, and
// mixed when that restore failed too.
func commitGeo(dp geoDataplane, plan geoPlan, subnets geoSubnets) (mixed bool, err error) {
	snap, err := dp.CaptureGeo()
	if err != nil {
		return false, err
	}
	previous, err := dp.ListBlockedCountries()
	if err != nil {
		return false, err
	}
	if err := writeGeo(dp, plan, subnets); err != nil {
		if rollback := errors.Join(dp.RestoreGeo(snap), syncCountrySet(dp, previous)); rollback != nil {
			return true, fmt.Errorf("%w; geo rollback failed: %v", err, rollback)
		}
		return false, err
	}
	return false, nil
}

// writeGeo writes a resolved plan:
//
//   - allow mode: the XDP interface's subnets first (private UDP sources), then
//     the allowed ranges and the mode switch (ApplyGeoRanges orders the
//     writes), then the reactive country map — which only block mode reads
//     — empties, so a blocked country stays blocked until allow is live;
//   - block mode: the reactive map, then the blocked ranges (the mode
//     switches to block first);
//   - geo off: the reactive map empties and the ranges go, mode block, so a
//     later enable never starts in allow mode with empty tables.
func writeGeo(dp geoDataplane, plan geoPlan, subnets geoSubnets) error {
	if plan.mode == wafebpf.GeoModeAllow {
		if subnets != nil {
			// An unreadable interface fails the switch (it is rolled back
			// and reported); an empty table would drop the LAN's UDP.
			list, err := subnets()
			if err != nil {
				return err
			}
			if err := dp.SetGeoLocalSubnets(list); err != nil {
				return err
			}
		}
		if err := dp.ApplyGeoRanges(plan.mode, plan.codes, plan.prefixes); err != nil {
			return err
		}
		return syncCountrySet(dp, nil)
	}
	if err := syncCountrySet(dp, plan.blocked); err != nil {
		return err
	}
	return dp.ApplyGeoRanges(wafebpf.GeoModeBlock, plan.codes, plan.prefixes)
}

// syncCountrySet makes the reactive blocked-country map hold exactly codes.
func syncCountrySet(dp geoDataplane, codes []string) error {
	existing, err := dp.ListBlockedCountries()
	if err != nil {
		return err
	}
	want := make(map[string]bool, len(codes))
	for _, c := range codes {
		want[c] = true
	}
	have := make(map[string]bool, len(existing))
	for _, c := range existing {
		have[c] = true
		if !want[c] {
			if err := dp.UnblockCountry(c); err != nil {
				return err
			}
		}
	}
	for _, c := range codes {
		if !have[c] {
			if err := dp.BlockCountry(c); err != nil {
				return err
			}
		}
	}
	return nil
}

// geoBlockedCodes returns the blocked country codes of a desired state.
func geoBlockedCodes(entries []wafebpf.CountryEntry) []string {
	var codes []string
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		code, ok := wafebpf.NormalizeCountryCode(e.Code)
		if !e.Blocked || !ok || seen[code] {
			continue
		}
		seen[code] = true
		codes = append(codes, code)
	}
	return codes
}

// attachedSubnets lists the subnets of ifName, the interface XDP is
// attached to (wafio_geo_local4/6): the only private sources allow mode
// admits for UDP and other protocols without a handshake. Subnets of other
// interfaces (docker0, br-*, cni0, wg0, a second NIC) are never on-link for
// packets XDP sees, so a source spoofed from them must not pass.
func attachedSubnets(ifName string) ([]netip.Prefix, error) {
	return subnetsOf(ifName, func(name string) ([]net.Addr, error) {
		ifc, err := net.InterfaceByName(name)
		if err != nil {
			return nil, err
		}
		return ifc.Addrs()
	})
}

// attachedSubnetsOf binds attachedSubnets to the interface mgr's XDP
// program is attached to, read at call time.
func attachedSubnetsOf(mgr interface{ InterfaceName() string }) geoSubnets {
	return func() ([]netip.Prefix, error) { return attachedSubnets(mgr.InterfaceName()) }
}

// subnetsOf reads ifName's addresses through addrs (tests inject a fake
// interface table). An unreadable interface is an error, never an empty
// list: the caller keeps the table it has.
func subnetsOf(ifName string, addrs func(string) ([]net.Addr, error)) ([]netip.Prefix, error) {
	if ifName == "" {
		return nil, fmt.Errorf("%w: no interface attached", ErrGeoLocalSubnets)
	}
	list, err := addrs(ifName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrGeoLocalSubnets, ifName, err)
	}
	var out []netip.Prefix
	for _, a := range list {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if p, ok := wafebpf.GeoPrefixFromIPNet(n); ok && !p.Addr().IsLoopback() {
			out = append(out, p)
		}
	}
	return out, nil
}

// refreshGeoSubnets re-reads the attached interface's subnets while allow
// mode is live; a read error keeps the table as it is.
func refreshGeoSubnets(dp interface{ SetGeoLocalSubnets([]netip.Prefix) error }, subnets geoSubnets) error {
	list, err := subnets()
	if err != nil {
		return err
	}
	return dp.SetGeoLocalSubnets(list)
}
