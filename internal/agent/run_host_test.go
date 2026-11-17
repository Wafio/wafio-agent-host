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

// The retired agent API key is refused only when it is the sole credential of
// the HTTP push. A host key or a complete gRPC setup lets the agent start, with
// the key ignored.
func TestCheckAgentAPIKey(t *testing.T) {
	base := func(edit func(*HostConfig)) HostConfig {
		c := HostConfig{AgentAPIKey: "old", ServerURL: "http://cp"}
		edit(&c)
		return c
	}
	grpc := func(c *HostConfig) {
		c.GRPCServer, c.GRPCClientCert, c.GRPCClientKey, c.GRPCCACert = "cp:9090", "c", "k", "ca"
	}
	for _, tc := range []struct {
		name    string
		cfg     HostConfig
		wantErr bool
	}{
		{"no key", base(func(c *HostConfig) { c.AgentAPIKey = "" }), false},
		{"key only, push to a server", base(func(*HostConfig) {}), true},
		{"key and host key", base(func(c *HostConfig) { c.HostKey = "wafh_x" }), false},
		{"key and gRPC", base(grpc), false},
		{"key and gRPC without a CA file", base(func(c *HostConfig) { grpc(c); c.GRPCCACert = "" }), true},
		{"key, no server to push to", base(func(c *HostConfig) { c.ServerURL = "" }), false},
	} {
		if err := checkAgentAPIKey(tc.cfg); (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, want error %t", tc.name, err, tc.wantErr)
		}
	}
}
