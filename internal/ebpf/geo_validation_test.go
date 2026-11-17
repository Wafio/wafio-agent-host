package ebpf

import (
	"testing"
)

func geoConfig(conntrack, geo, monitor bool) *FullConfigAPI {
	return &FullConfigAPI{Global: GlobalConfigAPI{EnableConntrack: conntrack, EnableGeoblock: geo, MonitorOnly: monitor}}
}

// Geo allow mode is a default deny for every public source outside the
// listed countries: the lockout guard refuses it without conntrack, without
// a country or without the operator's acknowledgement, and warns while it is
// enforced.
func TestValidateFirewallSafetyGeoAllow(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   FirewallSafetyInput
		code string
		warn string
	}{
		{"allow without conntrack", FirewallSafetyInput{Config: geoConfig(false, true, false), GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}, "CONNTRACK_REQUIRED", ""},
		{"allow without config", FirewallSafetyInput{GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}, "CONNTRACK_REQUIRED", ""},
		{"allow empty", FirewallSafetyInput{Config: geoConfig(true, true, false), GeoMode: "allow", GeoAllowAcknowledged: true}, "GEO_ALLOW_EMPTY", ""},
		{"allow unacknowledged", FirewallSafetyInput{Config: geoConfig(true, true, true), GeoMode: "allow", GeoAllowed: []string{"ID"}}, "GEO_ALLOW_UNACKNOWLEDGED", ""},
		{"invalid mode", FirewallSafetyInput{Config: geoConfig(true, true, false), GeoMode: "deny"}, "GEO_MODE_INVALID", ""},
		{"invalid country", FirewallSafetyInput{Config: geoConfig(true, true, false), GeoMode: "allow", GeoAllowed: []string{"IDN"}, GeoAllowAcknowledged: true}, "GEO_COUNTRY_INVALID", ""},
		{"allow enforced", FirewallSafetyInput{Config: geoConfig(true, true, false), GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}, "", WarnGeoAllowActive},
		{"allow monitor", FirewallSafetyInput{Config: geoConfig(true, true, true), GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}, "", ""},
		// Geo filtering off: allow mode is dormant and needs nothing.
		{"allow dormant", FirewallSafetyInput{Config: geoConfig(false, false, false), GeoMode: "allow"}, "", ""},
		{"block mode", FirewallSafetyInput{Config: geoConfig(false, true, false), GeoMode: "block"}, "", ""},
		{"absent mode", FirewallSafetyInput{Config: geoConfig(false, true, false)}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warnings, err := ValidateFirewallSafety(tc.in)
			if tc.code != "" {
				code, ok := FirewallErrorCode(err)
				if !ok || code != tc.code {
					t.Fatalf("err %v (code %q), want %s", err, code, tc.code)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got string
			for _, w := range warnings {
				if w.Code == WarnGeoAllowActive {
					got = w.Code
				}
			}
			if got != tc.warn {
				t.Fatalf("warnings %v, want %q", warnings, tc.warn)
			}
		})
	}
}

// Allow mode relies on the exemptions dataplane (replies to connections this
// host opens pass only with TC's CONN_OUTBOUND entries), but objects that
// predate it must not refuse the whole state for that: the agent degrades
// geo alone (planGeo) and applies every other rule.
func TestGeoAllowDoesNotRefuseWholeStateOnOldDataplane(t *testing.T) {
	in := FirewallSafetyInput{Config: geoConfig(true, true, false), GeoMode: "allow", GeoAllowed: []string{"ID"}, GeoAllowAcknowledged: true}
	if NeedsDataplaneExemptions(in) {
		t.Fatal("geo allow mode refuses the whole state on old objects")
	}
	if _, err := ValidateHostFirewall(in, false); err != nil {
		t.Fatalf("old dataplane: %v", err)
	}
}

// A local write that would take conntrack away from a live allow mode is
// refused (the local API reads the live geo mode from the manager).
func TestLocalWriteKeepsGeoAllowConntrack(t *testing.T) {
	r := geoFakeState{fakeFirewallState: fakeFirewallState{env: HostFirewallEnv{Exemptions: true}}, geo: GeoRangeState{Mode: GeoModeAllow, Countries: []string{"ID"}}}
	_, err := validateLocalFirewallChange(r, localFirewallChange{config: geoConfig(false, true, false)})
	if code, _ := FirewallErrorCode(err); code != "CONNTRACK_REQUIRED" {
		t.Fatalf("conntrack off under live allow mode: %v", err)
	}
	if _, err := validateLocalFirewallChange(r, localFirewallChange{config: geoConfig(true, true, false)}); err != nil {
		t.Fatal(err)
	}
}

type geoFakeState struct {
	fakeFirewallState
	geo GeoRangeState
}

func (f geoFakeState) GeoState() GeoRangeState { return f.geo }
