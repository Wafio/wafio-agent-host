package ebpf

import (
	"math"
	"strconv"
	"strings"

	"github.com/valyala/fasthttp"
)

// TraceFastHTTPHandler dispatches /api/ebpf/trace/* requests.
// All policy configuration is managed exclusively via the gRPC control plane.
// This handler exposes read-only diagnostics and enforcement log maintenance only.
type TraceFastHTTPHandler struct {
	Trace *TraceManager
	// AuthToken is the host-agent local API token; when non-empty
	// every trace route (events carry full argv) requires it.
	AuthToken string
}

// Handle dispatches trace API requests. Returns true if handled.
func (h *TraceFastHTTPHandler) Handle(ctx *fasthttp.RequestCtx) bool {
	path := string(ctx.Path())
	if !strings.HasPrefix(path, "/api/ebpf/trace") {
		return false
	}
	if !requireLocalToken(ctx, h.AuthToken) {
		return true
	}

	method := string(ctx.Method())

	switch {
	case path == "/api/ebpf/trace/status" && method == "GET":
		h.getStatus(ctx)
	case path == "/api/ebpf/trace/config" && method == "GET":
		h.getConfig(ctx)
	case path == "/api/ebpf/trace/events" && method == "GET":
		h.getEvents(ctx)
	case path == "/api/ebpf/trace/events/process" && method == "GET":
		h.getEventsByCategory(ctx, "process")
	case path == "/api/ebpf/trace/events/file" && method == "GET":
		h.getEventsByCategory(ctx, "file")
	case path == "/api/ebpf/trace/events/network" && method == "GET":
		h.getEventsByCategory(ctx, "network")
	case path == "/api/ebpf/trace/events/security" && method == "GET":
		h.getEventsByCategory(ctx, "security")
	case path == "/api/ebpf/trace/stats" && method == "GET":
		h.getStats(ctx)
	case path == "/api/ebpf/trace/types" && method == "GET":
		h.getEventTypes(ctx)

	// ── Enforcement Policy Endpoints (read-only) ──────────────────────────
	// Policies are pushed exclusively from the control plane via gRPC BundleUpdate.
	case path == "/api/ebpf/trace/policies" && method == "GET":
		h.listPolicies(ctx)
	case strings.HasPrefix(path, "/api/ebpf/trace/policies/") && method == "GET":
		h.getPolicy(ctx, path)

	// ── Enforcement Log Endpoints ─────────────────────────────────────────
	case path == "/api/ebpf/trace/enforcement-log" && method == "GET":
		h.getEnforcementLog(ctx)
	case path == "/api/ebpf/trace/enforcement-log" && method == "DELETE":
		h.clearEnforcementLog(ctx)

	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetBodyString(`{"error":"not found"}`)
	}
	return true
}

// ── GET /api/ebpf/trace/status ───────────────────────────────────────────

func (h *TraceFastHTTPHandler) getStatus(ctx *fasthttp.RequestCtx) {
	status := h.Trace.Status()
	writeJSON(ctx, fasthttp.StatusOK, status)
}

// ── GET /api/ebpf/trace/config ───────────────────────────────────────────

func (h *TraceFastHTTPHandler) getConfig(ctx *fasthttp.RequestCtx) {
	cfg, err := h.Trace.GetConfig()
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, cfg)
}

// ── GET /api/ebpf/trace/events ──────────────────────────────────────────

func (h *TraceFastHTTPHandler) getEvents(ctx *fasthttp.RequestCtx) {
	limit := traceQueryInt(ctx, "limit", 200)
	minSev := traceQuerySeverity(ctx, "min_severity")

	var events []TraceEvent
	if minSev > 0 {
		events = h.Trace.FilterRecentEvents("", minSev, limit)
	} else {
		events = h.Trace.DrainRecentTraceEvents(limit)
	}

	if events == nil {
		events = []TraceEvent{}
	}
	writeJSON(ctx, fasthttp.StatusOK, events)
}

// ── GET /api/ebpf/trace/events/{category} ──────────────────────────────

func (h *TraceFastHTTPHandler) getEventsByCategory(ctx *fasthttp.RequestCtx, category string) {
	limit := traceQueryInt(ctx, "limit", 200)
	minSev := traceQuerySeverity(ctx, "min_severity")

	events := h.Trace.FilterRecentEvents(category, minSev, limit)
	if events == nil {
		events = []TraceEvent{}
	}
	writeJSON(ctx, fasthttp.StatusOK, events)
}

// ── GET /api/ebpf/trace/stats ──────────────────────────────────────────

func (h *TraceFastHTTPHandler) getStats(ctx *fasthttp.RequestCtx) {
	stats, err := h.Trace.GetStats()
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, stats)
}

// ── GET /api/ebpf/trace/types ──────────────────────────────────────────

func (h *TraceFastHTTPHandler) getEventTypes(ctx *fasthttp.RequestCtx) {
	type eventTypeInfo struct {
		ID          uint32 `json:"id"`
		Name        string `json:"name"`
		Category    string `json:"category"`
		Description string `json:"description"`
	}

	var types []eventTypeInfo
	for id := uint32(1); id <= TraceEventMax; id++ {
		info := TraceEventTypes[id]
		types = append(types, eventTypeInfo{
			ID:          id,
			Name:        info.Name,
			Category:    categoryName(info.Category),
			Description: info.Description,
		})
	}
	writeJSON(ctx, fasthttp.StatusOK, types)
}

// ═══════════════════════════════════════════════════════════════════════════
//  ENFORCEMENT POLICY ENDPOINTS (read-only)
// ═══════════════════════════════════════════════════════════════════════════

// ── GET /api/ebpf/trace/policies ─────────────────────────────────────────

func (h *TraceFastHTTPHandler) listPolicies(ctx *fasthttp.RequestCtx) {
	policies := h.Trace.ListPolicies()
	if policies == nil {
		policies = []EnforcementPolicy{}
	}
	writeJSON(ctx, fasthttp.StatusOK, policies)
}

// ── GET /api/ebpf/trace/policies/:id ─────────────────────────────────────

func (h *TraceFastHTTPHandler) getPolicy(ctx *fasthttp.RequestCtx, path string) {
	id := extractPolicyID(path)
	if id == 0 {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid policy id"})
		return
	}
	p, err := h.Trace.GetPolicy(id)
	if err != nil {
		writeJSON(ctx, fasthttp.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, p)
}

// ═══════════════════════════════════════════════════════════════════════════
//  ENFORCEMENT LOG ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════

// ── GET /api/ebpf/trace/enforcement-log ──────────────────────────────────

func (h *TraceFastHTTPHandler) getEnforcementLog(ctx *fasthttp.RequestCtx) {
	limit := traceQueryInt(ctx, "limit", 200)
	entries := h.Trace.GetEnforcementLog(limit)
	if entries == nil {
		entries = []EnforcementLogEntry{}
	}
	writeJSON(ctx, fasthttp.StatusOK, entries)
}

// ── DELETE /api/ebpf/trace/enforcement-log ───────────────────────────────

func (h *TraceFastHTTPHandler) clearEnforcementLog(ctx *fasthttp.RequestCtx) {
	h.Trace.ClearEnforcementLog()
	writeJSON(ctx, fasthttp.StatusOK, map[string]string{"status": "cleared"})
}

// ── Helpers ─────────────────────────────────────────────────────────────

func traceQueryInt(ctx *fasthttp.RequestCtx, key string, def int) int {
	v := string(ctx.QueryArgs().Peek(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func traceQuerySeverity(ctx *fasthttp.RequestCtx, key string) uint32 {
	v := string(ctx.QueryArgs().Peek(key))
	switch strings.ToLower(v) {
	case "low":
		return SevLow
	case "medium":
		return SevMedium
	case "high":
		return SevHigh
	case "critical":
		return SevCritical
	default:
		return 0
	}
}

func extractPolicyID(path string) uint32 {
	prefix := "/api/ebpf/trace/policies/"
	if !strings.HasPrefix(path, prefix) {
		return 0
	}
	idStr := path[len(prefix):]
	n, err := strconv.Atoi(idStr)
	if err != nil || n <= 0 || uint64(n) > math.MaxUint32 {
		return 0 // out of range: an ID past uint32 must not wrap onto another policy
	}
	return uint32(n)
}
