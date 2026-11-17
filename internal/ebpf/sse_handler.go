package ebpf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

// ──────────────────────────────────────────────────────────────────────────────
// SSE (Server-Sent Events) Handler — Enterprise real-time streaming endpoint
// ──────────────────────────────────────────────────────────────────────────────
//
// Endpoint: GET /api/ebpf/stream?channels=metrics,events,connections,...
//
// Supported channels:
//   metrics      – eBPF firewall metrics          (1s interval)
//   events       – firewall perf events            (1s interval)
//   connections  – conntrack table                  (3s interval)
//   bandwidth    – per-IP bandwidth data            (3s interval)
//   status       – combined eBPF + trace status     (5s interval)
//   trace        – runtime security trace events    (1s interval)
//   stats        – trace aggregate statistics       (3s interval)
//   enforcement  – enforcement audit log            (1s interval)
//
// Protocol features:
//   • Multiplexed event types on single connection
//   • Monotonic sequence IDs (Last-Event-ID reconnection)
//   • Heartbeat keep-alive comments every tick
//   • Channel-based subscription via query params
//   • Graceful disconnect detection via flush errors
//   • Connection counting for observability
// ──────────────────────────────────────────────────────────────────────────────

// SSEHandler serves Server-Sent Events for real-time eBPF data streaming.
type SSEHandler struct {
	Manager *Manager
	Trace   *TraceManager
	// AuthToken is the host-agent local API token; when non-empty
	// the stream (and its preflight) requires it.
	AuthToken string

	activeConns atomic.Int64 // active SSE connection count
}

// ActiveConnections returns the number of active SSE connections.
func (h *SSEHandler) ActiveConnections() int64 {
	return h.activeConns.Load()
}

// Handle dispatches SSE requests. Returns true if handled.
func (h *SSEHandler) Handle(ctx *fasthttp.RequestCtx) bool {
	path := string(ctx.Path())
	if path != "/api/ebpf/stream" {
		return false
	}
	if !requireLocalToken(ctx, h.AuthToken) {
		return true
	}

	if string(ctx.Method()) == "OPTIONS" {
		ctx.SetStatusCode(fasthttp.StatusNoContent)
		setCORSHeaders(ctx)
		return true
	}

	if string(ctx.Method()) != "GET" {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		return true
	}

	channels := parseChannels(string(ctx.QueryArgs().Peek("channels")))
	if len(channels) == 0 {
		// default: subscribe to all available channels
		channels = allChannels(h.Manager != nil, h.Trace != nil)
	}

	// SSE response headers
	ctx.SetContentType("text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("X-Accel-Buffering", "no") // disable nginx buffering
	setCORSHeaders(ctx)

	h.activeConns.Add(1)

	ctx.SetBodyStreamWriter(func(w *bufio.Writer) {
		defer h.activeConns.Add(-1)
		h.streamLoop(w, channels)
	})

	return true
}

// ── Channel parsing ─────────────────────────────────────────────────────────

var validChannels = map[string]bool{
	"metrics": true, "events": true, "connections": true, "bandwidth": true,
	"status": true, "trace": true, "stats": true, "enforcement": true,
}

func parseChannels(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	out := make(map[string]bool)
	for _, ch := range strings.Split(raw, ",") {
		ch = strings.TrimSpace(strings.ToLower(ch))
		if validChannels[ch] {
			out[ch] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func allChannels(hasEBPF, hasTrace bool) map[string]bool {
	out := make(map[string]bool)
	if hasEBPF {
		out["metrics"] = true
		out["events"] = true
		out["connections"] = true
		out["bandwidth"] = true
	}
	if hasTrace {
		out["trace"] = true
		out["stats"] = true
		out["enforcement"] = true
	}
	out["status"] = true // always available
	return out
}

func setCORSHeaders(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	ctx.Response.Header.Set("Access-Control-Allow-Headers", "Cache-Control, Last-Event-ID")
}

// ── Stream loop ─────────────────────────────────────────────────────────────

func (h *SSEHandler) streamLoop(w *bufio.Writer, channels map[string]bool) {
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	var seq uint64

	// Send initial burst immediately
	h.sendInitialBurst(w, channels, &seq)
	if err := w.Flush(); err != nil {
		return
	}

	for range tick.C {
		seq++

		// ── Fast channels (every 1s) ──
		if channels["metrics"] && h.Manager != nil {
			h.sendMetrics(w, &seq)
		}
		if channels["events"] && h.Manager != nil {
			h.sendEvents(w, &seq)
		}
		if channels["trace"] && h.Trace != nil {
			h.sendTrace(w, &seq)
		}
		if channels["enforcement"] && h.Trace != nil {
			h.sendEnforcement(w, &seq)
		}

		// ── Medium channels (every 3s) ──
		if seq%3 == 0 {
			if channels["connections"] && h.Manager != nil {
				h.sendConnections(w, &seq)
			}
			if channels["bandwidth"] && h.Manager != nil {
				h.sendBandwidth(w, &seq)
			}
			if channels["stats"] && h.Trace != nil {
				h.sendStats(w, &seq)
			}
		}

		// ── Slow channels (every 5s) ──
		if seq%5 == 0 {
			if channels["status"] {
				h.sendStatus(w, &seq)
			}
		}

		// heartbeat comment (keep-alive)
		_, _ = fmt.Fprintf(w, ": hb %d\n\n", seq) // bufio errors are sticky; the flush reports a gone client

		if err := w.Flush(); err != nil {
			return // client disconnected
		}
	}
}

// sendInitialBurst pushes current snapshots for all subscribed channels immediately.
func (h *SSEHandler) sendInitialBurst(w *bufio.Writer, channels map[string]bool, seq *uint64) {
	if channels["status"] {
		h.sendStatus(w, seq)
	}
	if channels["metrics"] && h.Manager != nil {
		h.sendMetrics(w, seq)
	}
	if channels["events"] && h.Manager != nil {
		h.sendEvents(w, seq)
	}
	if channels["connections"] && h.Manager != nil {
		h.sendConnections(w, seq)
	}
	if channels["bandwidth"] && h.Manager != nil {
		h.sendBandwidth(w, seq)
	}
	if channels["trace"] && h.Trace != nil {
		h.sendTrace(w, seq)
	}
	if channels["stats"] && h.Trace != nil {
		h.sendStats(w, seq)
	}
	if channels["enforcement"] && h.Trace != nil {
		h.sendEnforcement(w, seq)
	}
}

// ── Channel senders ─────────────────────────────────────────────────────────

func (h *SSEHandler) sendMetrics(w *bufio.Writer, seq *uint64) {
	m, err := h.Manager.ReadMetrics()
	if err != nil {
		return
	}
	writeSSE(w, "metrics", seq, m)
}

func (h *SSEHandler) sendEvents(w *bufio.Writer, seq *uint64) {
	evts := h.Manager.DrainRecentEvents(200)
	if len(evts) == 0 {
		return // skip empty frames
	}
	writeSSE(w, "events", seq, map[string]interface{}{
		"events": evts,
		"count":  len(evts),
	})
}

func (h *SSEHandler) sendConnections(w *bufio.Writer, seq *uint64) {
	conns, err := h.Manager.ListConnections(200)
	if err != nil {
		return
	}
	writeSSE(w, "connections", seq, map[string]interface{}{
		"connections": conns,
		"count":       len(conns),
	})
}

func (h *SSEHandler) sendBandwidth(w *bufio.Writer, seq *uint64) {
	bw, err := h.Manager.ListBandwidth(200)
	if err != nil {
		return
	}
	writeSSE(w, "bandwidth", seq, map[string]interface{}{
		"entries": bw,
		"count":   len(bw),
	})
}

func (h *SSEHandler) sendStatus(w *bufio.Writer, seq *uint64) {
	payload := make(map[string]interface{})
	if h.Manager != nil {
		payload["ebpf"] = h.Manager.Status()
	}
	if h.Trace != nil {
		payload["trace"] = h.Trace.Status()
	}
	writeSSE(w, "status", seq, payload)
}

func (h *SSEHandler) sendTrace(w *bufio.Writer, seq *uint64) {
	evts := h.Trace.DrainRecentTraceEvents(500)
	if len(evts) == 0 {
		return
	}
	writeSSE(w, "trace", seq, evts)
}

func (h *SSEHandler) sendStats(w *bufio.Writer, seq *uint64) {
	s, err := h.Trace.GetStats()
	if err != nil {
		return
	}
	writeSSE(w, "stats", seq, s)
}

func (h *SSEHandler) sendEnforcement(w *bufio.Writer, seq *uint64) {
	log := h.Trace.GetEnforcementLog(500)
	if len(log) == 0 {
		return
	}
	writeSSE(w, "enforcement", seq, log)
}

// ── SSE wire format helpers ─────────────────────────────────────────────────

var jsonPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 4096)
	},
}

// writeSSE writes a single SSE event frame:
//
//	event: <type>
//	id: <seq>
//	data: <json>
//
// Increments *seq atomically.
func writeSSE(w *bufio.Writer, event string, seq *uint64, data interface{}) {
	*seq++

	buf := jsonPool.Get().([]byte)[:0]
	defer func() { jsonPool.Put(buf) }()

	var err error
	buf, err = json.Marshal(data)
	if err != nil {
		return
	}

	_, _ = fmt.Fprintf(w, "event: %s\nid: %d\ndata: ", event, *seq) // bufio errors are sticky; the flush reports a gone client
	_, _ = w.Write(buf)                                             // bufio errors are sticky; the flush reports a gone client
	_, _ = w.WriteString("\n\n")                                    // bufio errors are sticky; the flush reports a gone client
}
