package agent

import (
	"log"
	"strings"

	"github.com/valyala/fasthttp"
	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/agentcore"
)

// servesLocalAPI reports whether RunHost starts the local HTTP listener
// (--listen).
func servesLocalAPI(cfg HostConfig) bool {
	return strings.TrimSpace(cfg.ListenAddr) != ""
}

// localAPITokenFor sets up the local API token for RunHost: a listener that
// carries firewall writes and trace events gets one. It is
// written whenever the listener runs, also when eBPF or tracing failed to
// start. An empty result means there is no local listener to gate.
func localAPITokenFor(cfg HostConfig) (string, error) {
	if !servesLocalAPI(cfg) {
		return "", nil
	}
	path := localAPITokenPath(cfg)
	token, published, err := agentcore.SetupLocalAPIToken(path, cfg.LocalAPITokenGroup)
	if token == "" {
		return "", err
	}
	if published {
		log.Printf("local API: token written to %s; every local route except /healthz requires it", path)
	} else {
		log.Printf("WARNING: local API: token not written to %s: %v; every local call except /healthz is refused until restart", path, err)
	}
	return token, nil
}

// localAPITokenPath is the token file RunHost writes: LocalAPITokenFile, else
// agentcore.DefaultLocalAPITokenFile.
func localAPITokenPath(cfg HostConfig) string {
	if cfg.LocalAPITokenFile != "" {
		return cfg.LocalAPITokenFile
	}
	return agentcore.DefaultLocalAPITokenFile
}

// withLocalAPIAuth gates the local listener and logs each local
// mutation — method, path, peer and status, never the token. /healthz is
// always open. Every other route — eBPF, trace, SSE, unknown paths — needs
// "Authorization: Bearer <local token>". An empty token matches nothing (fail
// closed).
func withLocalAPIAuth(token string, next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if string(ctx.Path()) == "/healthz" {
			next(ctx)
			return
		}
		mutation := isLocalMutation(ctx)
		if !wafebpf.LocalAuthorized(ctx, token) {
			wafebpf.WriteLocalUnauthorized(ctx)
			if mutation {
				log.Printf("local API: refused %s %q from %s: missing or invalid token",
					ctx.Method(), ctx.Path(), ctx.RemoteAddr())
			}
			return
		}
		next(ctx)
		if mutation {
			log.Printf("local API: %s %q from %s -> %d",
				ctx.Method(), ctx.Path(), ctx.RemoteAddr(), ctx.Response.StatusCode())
		}
	}
}

// isLocalMutation reports a state-changing call on the control API (/api/...).
func isLocalMutation(ctx *fasthttp.RequestCtx) bool {
	if !strings.HasPrefix(string(ctx.Path()), "/api/") {
		return false
	}
	switch string(ctx.Method()) {
	case fasthttp.MethodGet, fasthttp.MethodHead, fasthttp.MethodOptions:
		return false
	}
	return true
}
