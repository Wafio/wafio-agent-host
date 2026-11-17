package ebpf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var errInvalidJSON = errors.New("body is not valid JSON (expected object or array)")

// bytesTrimSpace trims ASCII whitespace from both ends of b without allocating.
func bytesTrimSpace(b []byte) []byte {
	return bytes.TrimSpace(b)
}

// FastHTTPHandler dispatches /api/ebpf/* requests using raw fasthttp.
// Returns true if the request was handled, false if the path was not recognized.
type FastHTTPHandler struct {
	Manager *Manager
	// AuthToken is the host-agent local API token. When non-empty,
	// every method — GET included — must carry "Authorization: Bearer
	// <token>". agent.Run always sets it on the host agent.
	AuthToken string
}

// Handle dispatches eBPF API requests. Returns true if handled (even with error),
// false if the path is not an eBPF API path and should be handled elsewhere.
func (h *FastHTTPHandler) Handle(ctx *fasthttp.RequestCtx) bool {
	path := string(ctx.Path())
	if !strings.HasPrefix(path, "/api/ebpf") {
		return false
	}
	if !requireLocalToken(ctx, h.AuthToken) {
		return true
	}

	method := string(ctx.Method())

	switch {
	case path == "/api/ebpf/status" && method == "GET":
		h.getStatus(ctx)
	case path == "/api/ebpf/metrics" && method == "GET":
		h.getMetrics(ctx)
	case path == "/api/ebpf/config" && method == "GET":
		h.getConfig(ctx)
	case path == "/api/ebpf/config" && method == "PUT":
		h.putConfig(ctx)
	case path == "/api/ebpf/blocklist" && method == "GET":
		h.listBlocklist(ctx)
	case path == "/api/ebpf/blocklist" && method == "POST":
		h.addBlocklist(ctx)
	case path == "/api/ebpf/blocklist" && method == "DELETE":
		h.deleteBlocklist(ctx)
	case path == "/api/ebpf/allowlist" && method == "GET":
		h.listAllowlist(ctx)
	case path == "/api/ebpf/allowlist" && method == "POST":
		h.addAllowlist(ctx)
	case path == "/api/ebpf/allowlist" && method == "DELETE":
		h.deleteAllowlist(ctx)
	case path == "/api/ebpf/geo/blocked" && method == "GET":
		h.listGeoBlocked(ctx)
	case path == "/api/ebpf/geo/blocked" && method == "PUT":
		h.updateGeoBlocked(ctx)
	case path == "/api/ebpf/connections" && method == "GET":
		h.listConnections(ctx)
	case path == "/api/ebpf/bandwidth" && method == "GET":
		h.listBandwidth(ctx)
	case path == "/api/ebpf/events" && method == "GET":
		h.getEvents(ctx)

	// ── Port Policies (enterprise ingress/egress port firewall) ──
	case path == "/api/ebpf/port-policies" && method == "GET":
		h.listPortPolicies(ctx)
	case path == "/api/ebpf/port-policies" && method == "POST":
		h.addPortPolicy(ctx)
	case path == "/api/ebpf/port-policies" && method == "DELETE":
		h.deletePortPolicy(ctx)
	case path == "/api/ebpf/port-policies/config" && method == "GET":
		h.getPortPolicyConfig(ctx)
	case path == "/api/ebpf/port-policies/config" && method == "PUT":
		h.updatePortPolicyConfig(ctx)

	// ── Egress IP Blocklist ──
	case path == "/api/ebpf/egress-blocklist" && method == "GET":
		h.listEgressBlocklist(ctx)
	case path == "/api/ebpf/egress-blocklist" && method == "POST":
		h.addEgressBlocklist(ctx)
	case path == "/api/ebpf/egress-blocklist" && method == "DELETE":
		h.deleteEgressBlocklist(ctx)

	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
	}
	return true
}

// ── helpers ──────────────────────────────────────────────────────────────────

func writeJSON(ctx *fasthttp.RequestCtx, status int, v any) {
	ctx.SetStatusCode(status)
	ctx.SetContentType("application/json")
	b, err := json.Marshal(v)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error":"json marshal failed"}`)
		return
	}
	ctx.SetBody(b)
}

func (h *FastHTTPHandler) requireLinux(ctx *fasthttp.RequestCtx) bool {
	if runtime.GOOS != "linux" {
		writeJSON(ctx, fasthttp.StatusServiceUnavailable, map[string]string{
			"error": "eBPF is only available on Linux",
			"code":  "EBPF_NOT_SUPPORTED",
		})
		return false
	}
	return true
}

func (h *FastHTTPHandler) requireRunning(ctx *fasthttp.RequestCtx) bool {
	if h.Manager == nil || !h.Manager.IsRunning() {
		writeJSON(ctx, fasthttp.StatusServiceUnavailable, map[string]string{
			"error": "eBPF dataplane is not running",
			"code":  "EBPF_NOT_RUNNING",
		})
		return false
	}
	return true
}

// checkLockout runs the firewall lockout validation for a local write and
// answers 400 when the write would lock the host out. Returns true when the
// write may proceed.
func (h *FastHTTPHandler) checkLockout(ctx *fasthttp.RequestCtx, ch localFirewallChange) bool {
	warnings, err := validateLocalFirewallChange(h.Manager, ch)
	for _, w := range warnings {
		log.Printf("[ebpf] local API firewall lockout check: %s: %s", w.Code, w.Message)
	}
	return writeLockoutResult(ctx, err)
}

// writeLockoutResult maps a lockout validation error to a response: 400
// with the same stable code the control plane uses (FirewallErrorCode).
func writeLockoutResult(ctx *fasthttp.RequestCtx, err error) bool {
	code, lockout := FirewallErrorCode(err)
	switch {
	case err == nil:
		return true
	case lockout:
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{
			"error": err.Error(),
			"code":  code,
		})
	default:
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{
			"error": "could not read firewall state for lockout validation",
		})
	}
	return false
}

func queryInt(ctx *fasthttp.RequestCtx, key string, def int) int {
	v := string(ctx.QueryArgs().Peek(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// ── endpoints ────────────────────────────────────────────────────────────────

func (h *FastHTTPHandler) getStatus(ctx *fasthttp.RequestCtx) {
	if !h.requireLinux(ctx) {
		return
	}
	if h.Manager == nil {
		writeJSON(ctx, fasthttp.StatusOK, Status{Running: false})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, h.Manager.Status())
}

func (h *FastHTTPHandler) getMetrics(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	m, err := h.Manager.ReadMetrics()
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, m)
}

func (h *FastHTTPHandler) getConfig(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	cfg, err := h.Manager.GetFullConfig()
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, cfg)
}

func (h *FastHTTPHandler) putConfig(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	var req FullConfigAPI
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	defer LockFirewallWrites()()
	if !h.checkLockout(ctx, localFirewallChange{config: &req}) {
		return
	}
	if err := h.Manager.UpdateFullConfig(req); err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]string{"status": "ok"})
}

func (h *FastHTTPHandler) listBlocklist(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	limit := queryInt(ctx, "limit", 1000)
	entries, err := h.Manager.ListBlocklist(limit)
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if entries == nil {
		entries = []BlocklistEntry{}
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

func (h *FastHTTPHandler) addBlocklist(ctx *fasthttp.RequestCtx) {
	var req struct {
		Entries []IPEntry `json:"entries"`
		// Origin "jail": the WAF agent's L7 → XDP jail. Its entries go
		// to the jail map, which a control-plane push never clears; older
		// host agents ignore the field and use the blocklist as before.
		Origin string `json:"origin,omitempty"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	for _, entry := range req.Entries {
		if blocklistEntryIsLocal(entry.IP) {
			// A loopback or unspecified address is never a blocklist
			// target (an L7 jail once dropped the load-test source that way).
			writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "loopback and unspecified addresses cannot be blocked", "code": "BLOCKLIST_LOCAL_ADDRESS"})
			return
		}
	}
	if !h.requireRunning(ctx) {
		return
	}
	if req.Origin == "jail" {
		h.addJail(ctx, req.Entries)
		return
	}
	defer LockFirewallWrites()()
	if !h.checkLockout(ctx, localFirewallChange{blockAdd: req.Entries}) {
		return
	}
	var errs []string
	added, full := 0, false
	for _, entry := range req.Entries {
		ttl := time.Duration(0)
		if entry.TTLMs > 0 {
			ttl = time.Duration(entry.TTLMs) * time.Millisecond
		}
		if err := h.Manager.AddToBlocklist(entry.IP, ttl); err != nil {
			errs = append(errs, entry.IP+": "+err.Error())
			full = full || errors.Is(err, ErrIPListCapacity)
		} else {
			added++
		}
	}
	resp := map[string]any{"added": added}
	if len(errs) > 0 {
		resp["errors"] = errs
	}
	if full { // the trie refused the entry; nothing was evicted for it
		resp["code"] = "IP_LIST_FULL"
	}
	writeJSON(ctx, fasthttp.StatusOK, resp)
}

// addJail jails single addresses for their TTL. The jail map is not part
// of the desired state, so no lockout check applies: an address the
// allowlist names passes despite a jail entry, and a single address never
// trips the family-wide guard.
func (h *FastHTTPHandler) addJail(ctx *fasthttp.RequestCtx, entries []IPEntry) {
	var errs []string
	added := 0
	for _, entry := range entries {
		if entry.TTLMs <= 0 {
			errs = append(errs, entry.IP+": a jail entry needs ttl_ms")
			continue
		}
		if err := h.Manager.AddToJail(entry.IP, time.Duration(entry.TTLMs)*time.Millisecond); err != nil {
			errs = append(errs, entry.IP+": "+err.Error())
		} else {
			added++
		}
	}
	resp := map[string]any{"added": added}
	if len(errs) > 0 {
		resp["errors"] = errs
	}
	writeJSON(ctx, fasthttp.StatusOK, resp)
}

// blocklistEntryIsLocal reports whether an ingress blocklist entry (single IP
// or CIDR) names, or covers, loopback or the unspecified address. A /0 prefix
// (any spelling of the 0.0.0.0/0 and ::/0 wildcards) is a distinct, validated
// feature and stays accepted; any other prefix is refused when it overlaps
// 127.0.0.0/8 or ::1 or has an unspecified base address.
func blocklistEntryIsLocal(entry string) bool {
	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return false // the manager reports malformed entries
		}
		if p.Bits() == 0 {
			return false
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			if p.Bits() == 0 {
				return false
			}
		}
		return p.Addr().IsUnspecified() ||
			p.Overlaps(netip.MustParsePrefix("127.0.0.0/8")) ||
			p.Overlaps(netip.MustParsePrefix("::1/128"))
	}
	a, err := netip.ParseAddr(entry)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || a.IsUnspecified()
}

func (h *FastHTTPHandler) deleteBlocklist(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	var req struct {
		Entries []IPEntry `json:"entries"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	removed := 0
	for _, entry := range req.Entries {
		if err := h.Manager.RemoveFromBlocklist(entry.IP); err == nil {
			removed++
		}
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{"removed": removed})
}

func (h *FastHTTPHandler) listAllowlist(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	limit := queryInt(ctx, "limit", 1000)
	entries, err := h.Manager.ListAllowlist(limit)
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if entries == nil {
		entries = []AllowlistEntry{}
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

func (h *FastHTTPHandler) addAllowlist(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	var req struct {
		Entries []IPEntry `json:"entries"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	// Ports: normalised here, refused when the attached object
	// cannot match them (it would treat the entry as allowing nothing while
	// the lockout check counted an SSH scope as an escape hatch).
	scoped := false
	for i := range req.Entries {
		ports, err := NormalizePortScopes(req.Entries[i].Ports)
		if err != nil {
			writeLockoutResult(ctx, fmt.Errorf("%s: %w", clip(req.Entries[i].IP), err))
			return
		}
		req.Entries[i].Ports = ports
		scoped = scoped || len(ports) > 0
	}
	if scoped && !h.Manager.AllowlistPortsSupported() {
		writeJSON(ctx, fasthttp.StatusConflict, map[string]string{
			"error": ErrAllowlistPortsUnsupported.Error(),
			"code":  "ALLOWLIST_PORTS_UNSUPPORTED",
		})
		return
	}
	// Re-adding an entry replaces its deadline and its ports: re-adding the
	// escape hatch with a TTL, or with ports that no longer cover SSH, would
	// close it, so the add runs the lockout check like every other local
	// write.
	defer LockFirewallWrites()()
	if !h.checkLockout(ctx, localFirewallChange{allowAdd: req.Entries}) {
		return
	}
	added, full := 0, false
	var errs []string
	for _, entry := range req.Entries {
		ttl := time.Duration(0)
		if entry.TTLMs > 0 {
			ttl = time.Duration(entry.TTLMs) * time.Millisecond
		}
		if err := h.Manager.AddToAllowlistPorts(entry.IP, ttl, entry.Ports); err != nil {
			errs = append(errs, entry.IP+": "+err.Error())
			full = full || errors.Is(err, ErrIPListCapacity)
		} else {
			added++
		}
	}
	resp := map[string]any{"added": added}
	if len(errs) > 0 {
		resp["errors"] = errs
	}
	if full {
		resp["code"] = "IP_LIST_FULL"
	}
	writeJSON(ctx, fasthttp.StatusOK, resp)
}

func (h *FastHTTPHandler) deleteAllowlist(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	var req struct {
		Entries []IPEntry `json:"entries"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	gone := make([]string, 0, len(req.Entries))
	for _, entry := range req.Entries {
		gone = append(gone, entry.IP)
	}
	defer LockFirewallWrites()()
	if !h.checkLockout(ctx, localFirewallChange{allowRemove: gone}) {
		return
	}
	removed := 0
	for _, entry := range req.Entries {
		if err := h.Manager.RemoveFromAllowlist(entry.IP); err == nil {
			removed++
		}
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{"removed": removed})
}

func (h *FastHTTPHandler) listGeoBlocked(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	countries, err := h.Manager.ListBlockedCountries()
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if countries == nil {
		countries = []string{}
	}
	geo := h.Manager.GeoState()
	allowed := geo.Countries
	if geo.Mode != GeoModeAllow || allowed == nil {
		allowed = []string{}
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{"countries": countries, "count": len(countries),
		"mode": geo.Mode, "allowed_countries": allowed})
}

func (h *FastHTTPHandler) updateGeoBlocked(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	var req struct {
		Countries []CountryEntry `json:"countries"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	// The local API edits the block-mode country set only. In allow mode
	// that set is not consulted, and the allow list and mode belong to the
	// control plane's desired state.
	if h.Manager.GeoState().Mode == GeoModeAllow {
		writeJSON(ctx, fasthttp.StatusConflict, map[string]string{
			"error": "geo allow mode is active; change countries from the control plane",
			"code":  "GEO_ALLOW_MODE_ACTIVE",
		})
		return
	}
	var errs []string
	for _, entry := range req.Countries {
		var err error
		if entry.Blocked {
			err = h.Manager.BlockCountry(entry.Code)
		} else {
			err = h.Manager.UnblockCountry(entry.Code)
		}
		if err != nil {
			errs = append(errs, entry.Code+": "+err.Error())
		}
	}
	resp := map[string]any{"status": "ok"}
	if len(errs) > 0 {
		resp["errors"] = errs
	}
	writeJSON(ctx, fasthttp.StatusOK, resp)
}

func (h *FastHTTPHandler) listConnections(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	limit := queryInt(ctx, "limit", 100)
	conns, err := h.Manager.ListConnections(limit)
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if conns == nil {
		conns = []Connection{}
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{"connections": conns, "count": len(conns)})
}

func (h *FastHTTPHandler) listBandwidth(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	limit := queryInt(ctx, "limit", 100)
	entries, err := h.Manager.ListBandwidth(limit)
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if entries == nil {
		entries = []BandwidthEntry{}
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

func (h *FastHTTPHandler) getEvents(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	limit := queryInt(ctx, "limit", 100)
	events := h.Manager.GetRecentEvents(limit)
	if events == nil {
		events = []Event{}
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{"events": events, "count": len(events)})
}

// ── Port Policies ────────────────────────────────────────────────────────────

func (h *FastHTTPHandler) listPortPolicies(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	limit := queryInt(ctx, "limit", 4096)
	policies, err := h.Manager.ListPortPolicies(limit)
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if policies == nil {
		policies = []PortPolicyAPI{}
	}
	cfg, _ := h.Manager.GetPortPolicyConfig()
	var cfgResp any = map[string]any{"enabled": false, "default_ingress": "allow", "default_egress": "allow"}
	if cfg != nil {
		cfgResp = cfg
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{
		"policies": policies,
		"count":    len(policies),
		"config":   cfgResp,
	})
}

func (h *FastHTTPHandler) addPortPolicy(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	policies, err := parsePortPolicyBody(ctx.PostBody())
	if err != nil {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return
	}
	if len(policies) == 0 {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{
			"error": "body must contain a port policy (single object, array, or {\"policies\":[...]})",
		})
		return
	}
	var (
		added int
		errs  []string
		valid []PortPolicyAPI
	)
	for _, req := range policies {
		if req.Port == 0 {
			errs = append(errs, "port is required")
			continue
		}
		if req.Proto == "" {
			req.Proto = "tcp"
		}
		if req.Direction == "" {
			req.Direction = "ingress"
		}
		if req.Action == "" {
			req.Action = "drop"
		}
		valid = append(valid, req)
	}
	// The valid rules are one all-or-nothing change: lockout-checked on the
	// resulting state, capacity-checked, rolled back on any write failure.
	added, err = applyLocalPortPolicies(h.Manager, valid)
	if errors.Is(err, ErrPortPolicyBatch) {
		writeJSON(ctx, fasthttp.StatusConflict, map[string]string{
			"error": err.Error(),
			"code":  "PORT_POLICY_BATCH_FAILED",
		})
		return
	}
	if !writeLockoutResult(ctx, err) {
		return
	}
	resp := map[string]any{"status": "ok", "added": added}
	if len(errs) > 0 {
		resp["errors"] = errs
	}
	writeJSON(ctx, fasthttp.StatusOK, resp)
}

// parsePortPolicyBody accepts three body shapes for ergonomics:
//  1. single object:   {"port":8080,"proto":"tcp",...}
//  2. bare array:      [{"port":8080,...}, ...]
//  3. wrapped array:   {"policies":[{"port":8080,...}, ...]}
//
// This mirrors the blocklist endpoint which uses {"entries":[...]}, and avoids
// surprising 400s when CLI users POST the same format they'd use for blocklists.
func parsePortPolicyBody(body []byte) ([]PortPolicyAPI, error) {
	body = bytesTrimSpace(body)
	if len(body) == 0 {
		return nil, nil
	}
	switch body[0] {
	case '[':
		var arr []PortPolicyAPI
		if err := json.Unmarshal(body, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	case '{':
		var wrapper struct {
			Policies []PortPolicyAPI `json:"policies"`
		}
		if err := json.Unmarshal(body, &wrapper); err == nil && len(wrapper.Policies) > 0 {
			return wrapper.Policies, nil
		}
		var single PortPolicyAPI
		if err := json.Unmarshal(body, &single); err != nil {
			return nil, err
		}
		return []PortPolicyAPI{single}, nil
	default:
		return nil, errInvalidJSON
	}
}

func (h *FastHTTPHandler) deletePortPolicy(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	// Accept port/proto/direction from either JSON body or query string.
	// Query params are handy for CLI users: `DELETE /api/ebpf/port-policies?port=8080&proto=tcp`.
	type delReq struct {
		Port      uint16 `json:"port"`
		Proto     string `json:"proto"`
		Direction string `json:"direction"`
	}
	var req delReq
	if body := bytesTrimSpace(ctx.PostBody()); len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
			return
		}
	}
	if req.Port == 0 {
		if p := queryInt(ctx, "port", 0); p > 0 && p <= 65535 {
			req.Port = uint16(p)
		}
	}
	if req.Proto == "" {
		req.Proto = string(ctx.QueryArgs().Peek("proto"))
	}
	if req.Direction == "" {
		req.Direction = string(ctx.QueryArgs().Peek("direction"))
	}
	if req.Port == 0 {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{
			"error": "port is required (via JSON body or ?port=<n>)",
		})
		return
	}
	if req.Proto == "" {
		req.Proto = "tcp"
	}
	if req.Direction == "" {
		req.Direction = "ingress"
	}
	removed := PortPolicyAPI{Port: req.Port, Proto: req.Proto, Direction: req.Direction}
	defer LockFirewallWrites()()
	if !h.checkLockout(ctx, localFirewallChange{remove: &removed}) {
		return
	}
	if err := h.Manager.RemovePortPolicy(req.Port, req.Proto, req.Direction); err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{
		"status":    "ok",
		"removed":   1,
		"port":      req.Port,
		"proto":     req.Proto,
		"direction": req.Direction,
	})
}

func (h *FastHTTPHandler) getPortPolicyConfig(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	cfg, err := h.Manager.GetPortPolicyConfig()
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if cfg == nil {
		cfg = &PortPolicyConfigAPI{Enabled: false, DefaultIngress: "allow", DefaultEgress: "allow"}
	}
	writeJSON(ctx, fasthttp.StatusOK, cfg)
}

func (h *FastHTTPHandler) updatePortPolicyConfig(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	var req PortPolicyConfigAPI
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return
	}
	defer LockFirewallWrites()()
	if !h.checkLockout(ctx, localFirewallChange{policy: &req}) {
		return
	}
	if err := h.Manager.UpdatePortPolicyConfig(req); err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]string{"status": "ok"})
}

// ── Egress Blocklist ─────────────────────────────────────────────────────────

func (h *FastHTTPHandler) listEgressBlocklist(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	limit := queryInt(ctx, "limit", 1000)
	entries, err := h.Manager.ListEgressBlocklist(limit)
	if err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if entries == nil {
		entries = []EgressBlocklistEntry{}
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

func (h *FastHTTPHandler) addEgressBlocklist(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	var req struct {
		IP    string `json:"ip"`
		TTLMs int64  `json:"ttl_ms,omitempty"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return
	}
	if req.IP == "" {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "ip is required"})
		return
	}
	defer LockFirewallWrites()()
	if !h.checkLockout(ctx, localFirewallChange{egressAdd: []IPEntry{{IP: req.IP, TTLMs: req.TTLMs}}}) {
		return
	}
	ttl := time.Duration(0)
	if req.TTLMs > 0 {
		ttl = time.Duration(req.TTLMs) * time.Millisecond
	}
	if err := h.Manager.AddToEgressBlocklist(req.IP, ttl); err != nil {
		if errors.Is(err, ErrIPListCapacity) {
			writeJSON(ctx, fasthttp.StatusConflict, map[string]string{"error": err.Error(), "code": "IP_LIST_FULL"})
			return
		}
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]string{"status": "ok"})
}

func (h *FastHTTPHandler) deleteEgressBlocklist(ctx *fasthttp.RequestCtx) {
	if !h.requireRunning(ctx) {
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, fasthttp.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return
	}
	if err := h.Manager.RemoveFromEgressBlocklist(req.IP); err != nil {
		writeJSON(ctx, fasthttp.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(ctx, fasthttp.StatusOK, map[string]string{"status": "ok"})
}
