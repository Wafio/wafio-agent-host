package agent

import (
	"bytes"
	"log"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/agentcore"
)

const testAgentToken = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// lockedBuffer is a log sink safe to read while server goroutines write.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// hostAgentHandler builds the host agent's local handler exactly as RunHost
// wires it: every sub-handler carries the token and the whole mux is wrapped.
func hostAgentHandler(token string) fasthttp.RequestHandler {
	ebpfHTTP := &wafebpf.FastHTTPHandler{AuthToken: token}
	traceHTTP := &wafebpf.TraceFastHTTPHandler{AuthToken: token}
	sseHTTP := &wafebpf.SSEHandler{AuthToken: token}
	return withLocalAPIAuth(token, agentHandler(ebpfHTTP, traceHTTP, sseHTTP))
}

func serveAgent(t *testing.T, h fasthttp.RequestHandler) func(method, path, auth string) (int, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &fasthttp.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return func(method, path, auth string) (int, string) {
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
		return resp.StatusCode(), string(resp.Body())
	}
}

// /healthz stays open; every other local route — eBPF, trace, SSE,
// unknown paths — needs the token. The routes the host agent no longer serves
// (analyze, /internal/config, /internal/telemetry) are unknown paths: 401
// without the token, 404 with it.
func TestLocalAPIHealthzStaysOpen(t *testing.T) {
	do := serveAgent(t, hostAgentHandler(testAgentToken))

	if code, _ := do("GET", "/healthz", ""); code != fasthttp.StatusOK {
		t.Fatalf("/healthz without token = %d, want 200", code)
	}
	if code, _ := do("GET", "/healthz", "Bearer wrong"); code != fasthttp.StatusOK {
		t.Fatalf("/healthz with wrong token = %d, want 200", code)
	}

	gated := []struct{ method, path string }{
		{"GET", "/internal/config"},
		{"GET", "/internal/telemetry"},
		{"GET", "/api/ebpf/status"},
		{"PUT", "/api/ebpf/config"},
		{"GET", "/api/ebpf/trace/events"},
		{"DELETE", "/api/ebpf/trace/enforcement-log"},
		{"GET", "/api/ebpf/stream"},
		{"POST", "/v1/analyze"},
		{"GET", "/v1/analyze-nginx"},
		{"GET", "/healthz/../internal/config"},
		{"GET", "/nope"},
	}
	for _, r := range gated {
		code, body := do(r.method, r.path, "")
		if code != fasthttp.StatusUnauthorized {
			t.Errorf("%s %s without token = %d, want 401", r.method, r.path, code)
		}
		if strings.Contains(body, testAgentToken) {
			t.Errorf("%s %s leaked the token in the body", r.method, r.path)
		}
	}
	for _, r := range []struct{ method, path string }{
		{"GET", "/internal/config"},
		{"GET", "/internal/telemetry"},
		{"POST", "/v1/analyze"},
		{"GET", "/v1/analyze-nginx"},
	} {
		if code, _ := do(r.method, r.path, "Bearer "+testAgentToken); code != fasthttp.StatusNotFound {
			t.Errorf("%s %s with token = %d, want 404: the host agent no longer serves it", r.method, r.path, code)
		}
	}
}

// Each local mutation is logged — method, path, outcome — never the token.
func TestLocalAPIMutationsLoggedWithoutToken(t *testing.T) {
	var buf lockedBuffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	do := serveAgent(t, hostAgentHandler(testAgentToken))
	do("DELETE", "/api/ebpf/trace/enforcement-log", "Bearer "+testAgentToken[:10])
	do("PUT", "/api/ebpf/config", "Bearer "+testAgentToken)
	do("GET", "/api/ebpf/status", "Bearer "+testAgentToken)

	out := buf.String()
	if !strings.Contains(out, `refused DELETE "/api/ebpf/trace/enforcement-log"`) {
		t.Errorf("refused mutation not logged: %q", out)
	}
	if !strings.Contains(out, `local API: PUT "/api/ebpf/config"`) {
		t.Errorf("accepted mutation not logged: %q", out)
	}
	if strings.Contains(out, "/api/ebpf/status") {
		t.Errorf("reads must not be logged as mutations: %q", out)
	}
	if strings.Contains(out, testAgentToken) || strings.Contains(out, testAgentToken[:10]) {
		t.Error("log output contains token material")
	}
}

// The host agent gets a fresh token at every start when it serves the local
// listener, whether or not eBPF or tracing started. No listener,
// nothing to gate.
func TestLocalAPITokenFor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "host-agent.token")
	listen := HostConfig{ListenAddr: "127.0.0.1:18089", LocalAPITokenFile: path}
	tok, err := localAPITokenFor(listen)
	if err != nil || len(tok) != 64 {
		t.Fatalf("token = %q, err = %v; want 64 hex chars", tok, err)
	}
	onDisk, err := agentcore.ReadLocalAPIToken(path)
	if err != nil || onDisk != tok {
		t.Fatalf("token file = %q (%v), want the served token", onDisk, err)
	}
	tok2, _ := localAPITokenFor(listen)
	if tok2 == tok {
		t.Fatal("each start must generate a new token")
	}

	// --listen "": nothing to gate, no file.
	if tok, err := localAPITokenFor(HostConfig{}); tok != "" || err != nil {
		t.Fatalf("no listener: token = %q, err = %v; want none", tok, err)
	}

	if got := localAPITokenPath(HostConfig{}); got != agentcore.DefaultLocalAPITokenFile {
		t.Errorf("default = %q, want %q", got, agentcore.DefaultLocalAPITokenFile)
	}
	if got := localAPITokenPath(HostConfig{LocalAPITokenFile: "/x"}); got != "/x" {
		t.Errorf("explicit file = %q", got)
	}

	// Unwritable path: the API stays gated by an in-memory token nobody has.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := agentcore.WriteLocalAPIToken(blocker, "x", ""); err != nil {
		t.Fatal(err)
	}
	tok, err = localAPITokenFor(HostConfig{ListenAddr: "127.0.0.1:18089", LocalAPITokenFile: filepath.Join(blocker, "sub", "t")})
	if err != nil || tok == "" {
		t.Fatalf("unwritable path: token = %q, err = %v; want in-memory token", tok, err)
	}
}

// An empty token (none could be generated) refuses everything except
// /healthz: the gate fails closed.
func TestLocalAPIEmptyTokenFailsClosed(t *testing.T) {
	do := serveAgent(t, withLocalAPIAuth("", agentHandler(nil, nil, &wafebpf.SSEHandler{})))
	for _, auth := range []string{"", "Bearer ", "Bearer x"} {
		if code, _ := do("GET", "/api/ebpf/status", auth); code != fasthttp.StatusUnauthorized {
			t.Errorf("/api/ebpf/status auth=%q with empty token = %d, want 401", auth, code)
		}
	}
	if code, _ := do("GET", "/healthz", ""); code != fasthttp.StatusOK {
		t.Errorf("/healthz = %d", code)
	}
}
