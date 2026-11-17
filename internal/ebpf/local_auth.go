package ebpf

import (
	"crypto/subtle"
	"strings"

	"github.com/valyala/fasthttp"
)

// LocalAuthorized reports whether ctx carries "Authorization: Bearer <token>"
// matching token. The comparison is constant-time so response timing does not
// leak how much of a guessed token was right. An empty token never matches:
// callers decide whether an empty token means "gate disabled".
func LocalAuthorized(ctx *fasthttp.RequestCtx, token string) bool {
	if token == "" {
		return false
	}
	auth := string(ctx.Request.Header.Peek(fasthttp.HeaderAuthorization))
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return false
	}
	got := strings.TrimSpace(auth[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// WriteLocalUnauthorized answers a local API request that failed the bearer
// check. The body never says why, so it cannot be used as an oracle.
func WriteLocalUnauthorized(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	ctx.SetContentType("application/json")
	ctx.Response.Header.Set(fasthttp.HeaderWWWAuthenticate, `Bearer realm="wafio-host-agent"`)
	ctx.SetBodyString(`{"error":"unauthorized"}`)
}

// requireLocalToken gates one local handler. An empty token leaves the handler
// open; the host agent always sets one (agent.Run), so empty only happens
// where the handler is not mounted on a host-agent listener.
func requireLocalToken(ctx *fasthttp.RequestCtx, token string) bool {
	if token == "" || LocalAuthorized(ctx, token) {
		return true
	}
	WriteLocalUnauthorized(ctx)
	return false
}
