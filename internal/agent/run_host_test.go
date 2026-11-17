package agent

import "testing"

// The host agent no longer reads config.yaml: the GeoIP database comes from
// the flag, then WAFIO_GEO_COUNTRY_DB_PATH, then the legacy WAFIO_GEOIP_DB_PATH.
func TestHostGeoIPPath(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, tc := range []struct {
		name string
		flag string
		env  map[string]string
		want string
	}{
		{"flag wins", " /f.mmdb ", map[string]string{"WAFIO_GEO_COUNTRY_DB_PATH": "/c.mmdb", "WAFIO_GEOIP_DB_PATH": "/l.mmdb"}, "/f.mmdb"},
		{"country env", "", map[string]string{"WAFIO_GEO_COUNTRY_DB_PATH": "/c.mmdb", "WAFIO_GEOIP_DB_PATH": "/l.mmdb"}, "/c.mmdb"},
		{"legacy env", "", map[string]string{"WAFIO_GEOIP_DB_PATH": "/l.mmdb"}, "/l.mmdb"},
		{"blank values", "  ", map[string]string{"WAFIO_GEO_COUNTRY_DB_PATH": " "}, ""},
	} {
		if got := hostGeoIPPath(tc.flag, env(tc.env)); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
