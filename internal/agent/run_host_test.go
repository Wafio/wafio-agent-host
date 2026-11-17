package agent

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

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

// The retired agent API key never stops the agent. When it is the sole credential
// of the HTTP push, the warning says how to fix that; otherwise the key is only
// reported as ignored.
func TestWarnAgentAPIKey(t *testing.T) {
	base := func(edit func(*HostConfig)) HostConfig {
		c := HostConfig{AgentAPIKey: "old", ServerURL: "http://cp"}
		edit(&c)
		return c
	}
	grpc := func(c *HostConfig) {
		c.GRPCServer, c.GRPCClientCert, c.GRPCClientKey, c.GRPCCACert = "cp:9090", "c", "k", "ca"
	}
	const sole, ignored = "only the retired agent API key is set", "is no longer used and is ignored"
	for _, tc := range []struct {
		name string
		cfg  HostConfig
		want string // substring of the log; empty means no log
	}{
		{"no key", base(func(c *HostConfig) { c.AgentAPIKey = "" }), ""},
		{"key only, push to a server", base(func(*HostConfig) {}), sole},
		{"key and host key", base(func(c *HostConfig) { c.HostKey = "wafh_x" }), ignored},
		{"key and gRPC", base(grpc), ignored},
		{"key and gRPC without a CA file", base(func(c *HostConfig) { grpc(c); c.GRPCCACert = "" }), sole},
		{"key, no server to push to", base(func(c *HostConfig) { c.ServerURL = "" }), ignored},
	} {
		var buf bytes.Buffer
		log.SetOutput(&buf)
		warnAgentAPIKey(tc.cfg)
		log.SetOutput(os.Stderr)
		got := buf.String()
		if tc.want == "" {
			if got != "" {
				t.Errorf("%s: logged %q, want nothing", tc.name, got)
			}
		} else if !strings.Contains(got, "WARNING") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: logged %q, want a WARNING with %q", tc.name, got, tc.want)
		}
	}
}
