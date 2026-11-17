package ebpf

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

const testLocalToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// serveLocal runs handler on a loopback listener and returns a request helper.
func serveLocal(t *testing.T, handler fasthttp.RequestHandler) func(method, path, auth string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &fasthttp.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return func(method, path, auth string) int {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)
		req.Header.SetMethod(method)
		req.SetRequestURI("http://" + ln.Addr().String() + path)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if err := fasthttp.DoTimeout(req, resp, 2*time.Second); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode()
	}
}

// Every eBPF route, GET included, requires the local API token.
func TestLocalAPIRequiresTokenForGet(t *testing.T) {
	h := &FastHTTPHandler{AuthToken: testLocalToken}
	do := serveLocal(t, func(ctx *fasthttp.RequestCtx) { h.Handle(ctx) })

	routes := []struct{ method, path string }{
		{"GET", "/api/ebpf/status"},
		{"GET", "/api/ebpf/config"},
		{"GET", "/api/ebpf/blocklist"},
		{"GET", "/api/ebpf/connections"},
		{"HEAD", "/api/ebpf/status"},
		{"PUT", "/api/ebpf/config"},
		{"POST", "/api/ebpf/blocklist"},
		{"DELETE", "/api/ebpf/port-policies"},
		{"GET", "/api/ebpf/unknown"},
	}
	for _, r := range routes {
		for _, auth := range []string{"", "Bearer wrong", "Bearer " + testLocalToken[:len(testLocalToken)-1], "Basic " + testLocalToken, testLocalToken} {
			if code := do(r.method, r.path, auth); code != fasthttp.StatusUnauthorized {
				t.Errorf("%s %s auth=%q = %d, want 401", r.method, r.path, auth, code)
			}
		}
		if code := do(r.method, r.path, "Bearer "+testLocalToken); code == fasthttp.StatusUnauthorized {
			t.Errorf("%s %s with the token = 401, want past auth", r.method, r.path)
		}
	}
}

// Trace routes (full argv, enforcement log) and the SSE stream are gated.
func TestTraceRoutesRequireToken(t *testing.T) {
	trace := &TraceFastHTTPHandler{AuthToken: testLocalToken}
	sse := &SSEHandler{AuthToken: testLocalToken}
	do := serveLocal(t, func(ctx *fasthttp.RequestCtx) {
		if sse.Handle(ctx) {
			return
		}
		trace.Handle(ctx)
	})

	routes := []struct{ method, path string }{
		{"GET", "/api/ebpf/trace/status"},
		{"GET", "/api/ebpf/trace/events"},
		{"GET", "/api/ebpf/trace/events/process"},
		{"GET", "/api/ebpf/trace/policies"},
		{"GET", "/api/ebpf/trace/policies/1"},
		{"GET", "/api/ebpf/trace/enforcement-log"},
		{"DELETE", "/api/ebpf/trace/enforcement-log"},
		{"GET", "/api/ebpf/stream"},
		{"OPTIONS", "/api/ebpf/stream"},
	}
	for _, r := range routes {
		if code := do(r.method, r.path, ""); code != fasthttp.StatusUnauthorized {
			t.Errorf("%s %s without token = %d, want 401", r.method, r.path, code)
		}
		if code := do(r.method, r.path, "Bearer nope"); code != fasthttp.StatusUnauthorized {
			t.Errorf("%s %s wrong token = %d, want 401", r.method, r.path, code)
		}
	}
	// With the token the SSE preflight passes auth (no manager needed).
	if code := do("OPTIONS", "/api/ebpf/stream", "Bearer "+testLocalToken); code != fasthttp.StatusNoContent {
		t.Errorf("OPTIONS stream with token = %d, want 204", code)
	}
}

func TestLocalAuthorizedEdgeCases(t *testing.T) {
	check := func(token, header string) bool {
		var ctx fasthttp.RequestCtx
		if header != "" {
			ctx.Request.Header.Set("Authorization", header)
		}
		return LocalAuthorized(&ctx, token)
	}
	if check("", "Bearer ") {
		t.Error("empty token must never authorize")
	}
	if check("", "") {
		t.Error("empty token and header must not authorize")
	}
	if !check("abc", "bearer abc") {
		t.Error("scheme is case-insensitive")
	}
	if check("abc", "Bearer abcd") || check("abc", "Bearer ab") {
		t.Error("prefix/suffix tokens must not authorize")
	}
}

type fakeFirewallState struct {
	cfg    *FullConfigAPI
	policy *PortPolicyConfigAPI
	rules  []PortPolicyAPI
	allow  []AllowlistEntry
	block  []BlocklistEntry
	egress []EgressBlocklistEntry
	env    HostFirewallEnv
	err    error
}

func (f fakeFirewallState) GetFullConfig() (*FullConfigAPI, error) { return f.cfg, f.err }
func (f fakeFirewallState) GetPortPolicyConfig() (*PortPolicyConfigAPI, error) {
	return f.policy, f.err
}
func (f fakeFirewallState) ListPortPolicies(int) ([]PortPolicyAPI, error) { return f.rules, f.err }
func (f fakeFirewallState) ListAllowlist(int) ([]AllowlistEntry, error)   { return f.allow, f.err }
func (f fakeFirewallState) LiveBlocks() ([]BlocklistEntry, []EgressBlocklistEntry, error) {
	return f.block, f.egress, f.err
}
func (f fakeFirewallState) HostFirewallEnv() HostFirewallEnv { return f.env }

// Local firewall writes run the same guard as the gRPC
// desired-state path and the control plane (ValidateHostFirewall) against
// the state the write would produce.
func TestLocalConfigRunsLockoutValidation(t *testing.T) {
	conntrackOn := &FullConfigAPI{Global: GlobalConfigAPI{EnableConntrack: true}}
	conntrackOff := &FullConfigAPI{}
	denyAll := &PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"}
	allowAll := &PortPolicyConfigAPI{Enabled: false, DefaultIngress: "allow", DefaultEgress: "allow"}
	ssh := PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"}

	cases := []struct {
		name  string
		state fakeFirewallState
		ch    localFirewallChange
		want  error
	}{
		{"deny-all without allow rule", fakeFirewallState{cfg: conntrackOn, policy: allowAll},
			localFirewallChange{policy: denyAll}, ErrIngressDenyNeedsAllow},
		{"deny-all without conntrack", fakeFirewallState{cfg: conntrackOff, policy: allowAll, rules: []PortPolicyAPI{ssh}},
			localFirewallChange{policy: denyAll}, ErrIngressDenyNeedsConntrack},
		{"deny-all with ssh allow", fakeFirewallState{cfg: conntrackOn, policy: allowAll, rules: []PortPolicyAPI{ssh}},
			localFirewallChange{policy: denyAll}, nil},
		{"conntrack off under deny-all", fakeFirewallState{cfg: conntrackOn, policy: denyAll, rules: []PortPolicyAPI{ssh}},
			localFirewallChange{config: conntrackOff}, ErrIngressDenyNeedsConntrack},
		{"remove last allow under deny-all", fakeFirewallState{cfg: conntrackOn, policy: denyAll, rules: []PortPolicyAPI{ssh}},
			localFirewallChange{remove: &PortPolicyAPI{Port: 22, Proto: "tcp", Direction: "ingress"}}, ErrIngressDenyNeedsAllow},
		{"remove other rule keeps allow", fakeFirewallState{cfg: conntrackOn, policy: denyAll, rules: []PortPolicyAPI{ssh}},
			localFirewallChange{remove: &PortPolicyAPI{Port: 22, Proto: "udp", Direction: "ingress"}}, nil},
		{"replace allow with drop", fakeFirewallState{cfg: conntrackOn, policy: denyAll, rules: []PortPolicyAPI{ssh}},
			localFirewallChange{upserts: []PortPolicyAPI{{Port: 22, Proto: "tcp", Direction: "ingress", Action: "drop"}}}, ErrIngressDenyNeedsAllow},
		{"replace allow with expiring allow", fakeFirewallState{cfg: conntrackOn, policy: denyAll, rules: []PortPolicyAPI{ssh}},
			localFirewallChange{upserts: []PortPolicyAPI{{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow", TTLMs: 1000}}}, ErrIngressDenyNeedsAllow},
		{"batch drop then allow same key", fakeFirewallState{cfg: conntrackOn, policy: denyAll, rules: []PortPolicyAPI{ssh}},
			localFirewallChange{upserts: []PortPolicyAPI{
				{Port: 22, Proto: "tcp", Direction: "ingress", Action: "drop"},
				{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"},
			}}, nil},
		{"policy off skips check", fakeFirewallState{cfg: conntrackOff, policy: allowAll},
			localFirewallChange{config: conntrackOff}, nil},
		// The local path runs the same guard as the gRPC/control-plane path.
		{"batch allow then drop same key", fakeFirewallState{cfg: conntrackOn, policy: denyAll, rules: []PortPolicyAPI{ssh}},
			localFirewallChange{upserts: []PortPolicyAPI{
				{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"},
				{Port: 22, Proto: "tcp", Direction: "ingress", Action: "drop"},
			}}, ErrIngressDenyNeedsAllow},
		{"only 80/udp allowed", fakeFirewallState{cfg: conntrackOn, policy: allowAll, rules: []PortPolicyAPI{{Port: 80, Proto: "udp", Direction: "ingress", Action: "allow"}}},
			localFirewallChange{policy: denyAll}, ErrIngressDenyNeedsAllow},
		{"unknown action", fakeFirewallState{cfg: conntrackOn, policy: allowAll},
			localFirewallChange{upserts: []PortPolicyAPI{{Port: 22, Proto: "tcp", Direction: "ingress", Action: "Allow"}}}, ErrInvalidPortPolicy},
		{"wildcard block without allowlist", fakeFirewallState{cfg: conntrackOn, policy: allowAll, env: HostFirewallEnv{Exemptions: true}},
			localFirewallChange{blockAdd: []IPEntry{{IP: "0.0.0.0/0"}}}, ErrWildcardBlockNeedsAllowlist},
		{"wildcard block with allowlist", fakeFirewallState{cfg: conntrackOn, policy: allowAll, allow: []AllowlistEntry{{IP: "203.0.113.7"}}, env: HostFirewallEnv{Exemptions: true}},
			localFirewallChange{blockAdd: []IPEntry{{IP: "0.0.0.0/0"}}}, nil},
		{"remove last allowlist entry under wildcard", fakeFirewallState{cfg: conntrackOn, policy: allowAll, allow: []AllowlistEntry{{IP: "203.0.113.7"}},
			block: []BlocklistEntry{{IP: "0.0.0.0/0"}}, env: HostFirewallEnv{Exemptions: true}},
			localFirewallChange{allowRemove: []string{"203.0.113.7"}}, ErrWildcardBlockNeedsAllowlist},
		// The allowlist lists prefixes; a removal in another spelling
		// still removes the escape hatch, and a re-add with a TTL turns it
		// into an expiring entry (the add path used to skip the check).
		{"remove escape hatch by CIDR spelling", fakeFirewallState{cfg: conntrackOn, policy: allowAll, allow: []AllowlistEntry{{IP: "203.0.113.0/24"}},
			block: []BlocklistEntry{{IP: "0.0.0.0/0"}}, env: HostFirewallEnv{Exemptions: true}},
			localFirewallChange{allowRemove: []string{"203.0.113.9/24"}}, ErrWildcardBlockNeedsAllowlist},
		{"re-add escape hatch with ttl", fakeFirewallState{cfg: conntrackOn, policy: allowAll, allow: []AllowlistEntry{{IP: "203.0.113.7"}},
			block: []BlocklistEntry{{IP: "0.0.0.0/0"}}, env: HostFirewallEnv{Exemptions: true}},
			localFirewallChange{allowAdd: []IPEntry{{IP: "203.0.113.7/32", TTLMs: 60000}}}, ErrWildcardBlockNeedsAllowlist},
		// The local check sees every live block, so half a
		// family blocked in several local writes needs the escape hatch too.
		{"broad block split over writes", fakeFirewallState{cfg: conntrackOn, policy: allowAll, block: []BlocklistEntry{{IP: "0.0.0.0/2"}}, env: HostFirewallEnv{Exemptions: true}},
			localFirewallChange{blockAdd: []IPEntry{{IP: "64.0.0.0/2"}}}, ErrWildcardBlockNeedsAllowlist},
		{"broad egress block split over writes", fakeFirewallState{cfg: conntrackOn, policy: allowAll, egress: []EgressBlocklistEntry{{IP: "0.0.0.0/2"}}, env: HostFirewallEnv{Exemptions: true}},
			localFirewallChange{egressAdd: []IPEntry{{IP: "64.0.0.0/2"}}}, ErrEgressBlockTooBroad},
		{"remove escape hatch under a broad block", fakeFirewallState{cfg: conntrackOn, policy: allowAll, allow: []AllowlistEntry{{IP: "203.0.113.7"}},
			block: []BlocklistEntry{{IP: "0.0.0.0/1"}, {IP: "128.0.0.0/1"}}, env: HostFirewallEnv{Exemptions: true}},
			localFirewallChange{allowRemove: []string{"203.0.113.7"}}, ErrWildcardBlockNeedsAllowlist},
		{"add second escape hatch", fakeFirewallState{cfg: conntrackOn, policy: allowAll, allow: []AllowlistEntry{{IP: "203.0.113.7"}},
			block: []BlocklistEntry{{IP: "0.0.0.0/0"}}, env: HostFirewallEnv{Exemptions: true}},
			localFirewallChange{allowAdd: []IPEntry{{IP: "198.51.100.0/24", TTLMs: 60000}}}, nil},
		{"wildcard block on an old dataplane", fakeFirewallState{cfg: conntrackOn, policy: allowAll, allow: []AllowlistEntry{{IP: "203.0.113.7"}}},
			localFirewallChange{blockAdd: []IPEntry{{IP: "0.0.0.0/0"}}}, ErrDataplaneLacksExemptions},
		{"egress wildcard without conntrack", fakeFirewallState{cfg: conntrackOff, policy: allowAll, env: HostFirewallEnv{Exemptions: true}},
			localFirewallChange{egressAdd: []IPEntry{{IP: "::/0"}}}, ErrWildcardBlockNeedsConntrack},
		{"egress deny on an old dataplane", fakeFirewallState{cfg: conntrackOn, policy: allowAll},
			localFirewallChange{policy: &PortPolicyConfigAPI{Enabled: true, DefaultIngress: "allow", DefaultEgress: "deny"}}, ErrDataplaneLacksExemptions},
		{"ssh moved to 2222", fakeFirewallState{cfg: conntrackOn, policy: allowAll, env: HostFirewallEnv{SSHPorts: []uint16{2222}},
			rules: []PortPolicyAPI{ssh}}, localFirewallChange{policy: denyAll}, ErrIngressDenyNeedsAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := validateLocalFirewallChange(tc.state, tc.ch)
			if !errors.Is(got, tc.want) && got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}

	// Unreadable state fails closed.
	boom := errors.New("map not loaded")
	if _, err := validateLocalFirewallChange(fakeFirewallState{err: boom}, localFirewallChange{remove: &ssh}); !errors.Is(err, boom) {
		t.Fatalf("state read error = %v, want refusal", err)
	}

	// The handler maps a lockout error to 400 with the control plane's code
	// and a read failure to a generic 500; neither lets the write through.
	var ctx fasthttp.RequestCtx
	if writeLockoutResult(&ctx, ErrIngressDenyNeedsAllow) || ctx.Response.StatusCode() != fasthttp.StatusBadRequest ||
		!bytes.Contains(ctx.Response.Body(), []byte(`"code":"SSH_ALLOW_REQUIRED"`)) {
		t.Fatalf("lockout → %d %s, want 400 SSH_ALLOW_REQUIRED", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	ctx = fasthttp.RequestCtx{}
	if writeLockoutResult(&ctx, boom) || ctx.Response.StatusCode() != fasthttp.StatusInternalServerError {
		t.Fatalf("read failure → %d, want 500", ctx.Response.StatusCode())
	}
}
