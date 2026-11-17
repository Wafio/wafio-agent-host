package ebpf

import (
	"testing"

	"github.com/valyala/fasthttp"
)

func TestBlocklistEntryIsLocal(t *testing.T) {
	tests := []struct {
		entry string
		want  bool
	}{
		{"127.0.0.1", true},
		{"127.5.5.5", true},
		{"127.0.0.0/8", true},
		{"127.0.0.1/32", true},
		{"::1", true},
		{"::1/128", true},
		{"::ffff:127.0.0.1", true},
		{"0.0.0.0", true},
		{"0.0.0.0/8", true},
		{"::", true},
		{" 127.0.0.1 ", true},
		{"0.0.0.0/1", true},
		{"64.0.0.0/2", true}, // covers 127.0.0.0/8 from a non-loopback base
		{"128.0.0.0/1", false},
		{"::/1", true},
		{"::0/0", false},
		{"0:0::/0", false},
		{"0.0.0.0/0", false}, // wildcard feature, validated elsewhere
		{"::/0", false},
		{"203.0.113.7", false},
		{"203.0.113.0/24", false},
		{"2001:db8::7", false},
		{"10.0.0.5", false},
		{"not-an-ip", false}, // the manager reports malformed entries
	}
	for _, tc := range tests {
		if got := blocklistEntryIsLocal(tc.entry); got != tc.want {
			t.Errorf("blocklistEntryIsLocal(%q) = %v, want %v", tc.entry, got, tc.want)
		}
	}
}

func TestAddBlocklistRejectsLocalAddressWith400(t *testing.T) {
	h := &FastHTTPHandler{} // no manager: validation must answer before the dataplane check
	for _, ip := range []string{"127.0.0.1", "::1", "0.0.0.0", "127.0.0.0/8"} {
		var ctx fasthttp.RequestCtx
		ctx.Request.Header.SetMethod("POST")
		ctx.Request.SetRequestURI("/api/ebpf/blocklist")
		ctx.Request.SetBodyString(`{"entries":[{"ip":"203.0.113.7"},{"ip":"` + ip + `","ttl_ms":3600000}]}`)
		if !h.Handle(&ctx) {
			t.Fatalf("%s: not handled", ip)
		}
		if got := ctx.Response.StatusCode(); got != fasthttp.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400", ip, got)
		}
	}
	// A public entry passes validation and reaches the running check.
	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetRequestURI("/api/ebpf/blocklist")
	ctx.Request.SetBodyString(`{"entries":[{"ip":"203.0.113.7"}]}`)
	h.Handle(&ctx)
	if got := ctx.Response.StatusCode(); got != fasthttp.StatusServiceUnavailable {
		t.Fatalf("public entry: status %d, want 503 (not running)", got)
	}
}
