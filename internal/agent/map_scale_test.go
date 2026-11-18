package agent

import (
	"strings"
	"testing"
)

func TestLoadMapScale(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == EnvEBPFMapScale {
				return v
			}
			return ""
		}
	}
	const invalid = `invalid --ebpf-map-scale "1.5" (or WAFIO_EBPF_MAP_SCALE): want auto or a number above 0 and at most 1`
	for _, tc := range []struct {
		name    string
		flag    string // the flag value, as the command line parser leaves it
		flagSet bool
		env     string
		want    string
		wantErr string
	}{
		{"default", "auto", false, "", "auto", ""},
		{"the env applies when no flag was given", "auto", false, "0.25", "0.25", ""},
		{"a blank env is ignored", "auto", false, "  ", "auto", ""},
		{"the flag beats the env", "0.5", true, "0.25", "0.5", ""},
		{"an invalid env value stops the start", "auto", false, "1.5", "", invalid},
		{"an invalid flag stops the start", "1.5", true, "", "", invalid},
		{"an invalid env value is ignored behind a flag", "0.5", true, "1.5", "0.5", ""},
		{"zero is refused", "0", true, "", "", `invalid --ebpf-map-scale "0"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := HostConfig{EBPFMapScale: tc.flag}
			err := c.LoadMapScale(env(tc.env), tc.flagSet)
			if tc.wantErr != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || c.EBPFMapScale != tc.want {
				t.Fatalf("scale %q, error %v; want %q", c.EBPFMapScale, err, tc.want)
			}
		})
	}
}

// The seen cache of the GeoIP enricher is cleared when it reaches the size of
// the kernel map, so it never grows past it and an address the map evicted is
// looked up again.
func TestGeoIPEnricherReserveClearsAtLimit(t *testing.T) {
	e := &GeoIPEnricher{seen: map[string]string{}}
	const limit = 3
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if !e.reserve(ip, limit) {
			t.Fatalf("%s reported as known", ip)
		}
	}
	if e.reserve("192.0.2.2", limit) {
		t.Fatal("a cached address was looked up again")
	}
	if len(e.seen) != limit {
		t.Fatalf("cache holds %d entries, want %d", len(e.seen), limit)
	}
	// The fourth address finds the cache at the limit: it is cleared first and
	// holds only the new address, and an old one is looked up again.
	if !e.reserve("192.0.2.4", limit) {
		t.Fatal("new address refused")
	}
	if len(e.seen) != 1 {
		t.Fatalf("cache holds %d entries after the reset, want 1", len(e.seen))
	}
	if !e.reserve("192.0.2.1", limit) {
		t.Fatal("an evicted address was not looked up again")
	}
	// No limit (the map is not loaded): the cache only grows.
	e = &GeoIPEnricher{seen: map[string]string{}}
	for i := range 10 {
		e.reserve(strings.Repeat("a", i+1), 0)
	}
	if len(e.seen) != 10 {
		t.Fatalf("cache holds %d entries without a limit, want 10", len(e.seen))
	}
}
