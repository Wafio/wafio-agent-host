package agent

import (
	"errors"
	"log"
	"sync"
	"sync/atomic"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/tracefilter"
)

// Trace forwarding filter, agent side. A control plane that
// knows the feature sends, on this stream, the detection rules and
// correlation stages its ingest evaluates for this host
// (tracefilter.TraceForwardFilterCommandID). The agent then decides, with the
// control plane's own code (tracefilter.TraceForwardFilter), which trace
// events ingest would discard with no effect, does not send those, and
// reports the rule hits they carried in the next batch so the rule hit
// counts stay what they were.
//
// Fail open: the filter belongs to one stream. A new stream starts without
// one (an older control plane never sends it), and a filter that does not
// parse or was built for other ingest semantics (TraceForwardRevision)
// filters nothing. Every batch reports the digest the stream holds, so the
// control plane re-sends a filter that changed or never arrived.

// Forwarding filter states (trace status forward_filter).
const (
	traceForwardOff              = "off"
	traceForwardActive           = "active"
	traceForwardRevisionMismatch = "revision_mismatch"
	traceForwardInvalid          = "invalid"
	// traceForwardTooLarge: the control plane's filter for this host is
	// over tracefilter.TraceForwardFilterMaxBytes and was not sent; the
	// stream holds its marker and sends everything.
	traceForwardTooLarge = tracefilter.TraceForwardTooLarge
)

// traceForwardFilter is one stream's filter. The zero value and nil filter
// nothing.
type traceForwardFilter struct {
	mu     sync.Mutex
	filter *tracefilter.TraceForwardFilter // nil: send everything
	digest string                          // of the last filter received ("" = none or unreadable)
	state  string
	hits   map[string]int // rule hits of dropped events not yet reported
}

var (
	// traceForwardCurrent is the filter of the current stream, for the
	// trace status; nil when no stream runs.
	traceForwardCurrent atomic.Pointer[traceForwardFilter]
	// Events not sent since the agent started, by verdict.
	traceForwardSuppressed atomic.Uint64
	traceForwardUnstored   atomic.Uint64
)

// newTraceForwardFilter starts a stream's filter (none yet) and makes it
// the one the trace status reports.
func newTraceForwardFilter() *traceForwardFilter {
	f := &traceForwardFilter{state: traceForwardOff}
	traceForwardCurrent.Store(f)
	return f
}

// close ends the stream's filter; the status reads off until the next
// stream starts.
func (f *traceForwardFilter) close() {
	traceForwardCurrent.CompareAndSwap(f, nil)
}

// handle applies a tracefilter.TraceForwardFilterCommandID message. Anything but
// a filter of this binary's revision leaves the stream sending everything;
// a too-large marker's digest is reported so the control plane stops
// sending it.
func (f *traceForwardFilter) handle(msg []byte) {
	filter, digest, err := tracefilter.ParseTraceForwardFilter(msg)
	state := traceForwardActive
	switch {
	case err == nil:
	case errors.Is(err, tracefilter.ErrTraceForwardRevision):
		state = traceForwardRevisionMismatch
	case errors.Is(err, tracefilter.ErrTraceForwardTooLarge):
		state = traceForwardTooLarge
	default:
		state = traceForwardInvalid
	}
	f.mu.Lock()
	changed := f.state != state || f.digest != digest
	f.filter, f.digest, f.state = filter, digest, state
	f.mu.Unlock()
	if changed {
		log.Printf("[ebpf-grpc] trace forward filter %s digest=%q", state, digest)
	}
}

// drop reports whether the trace event encoded as event is one ingest
// would discard with no effect, and counts it and the rule hit it carries.
// It never drops without a filter or when the filter fails.
func (f *traceForwardFilter) drop(event []byte) (dropped bool) {
	if f == nil {
		return false
	}
	f.mu.Lock()
	filter := f.filter
	f.mu.Unlock()
	if filter == nil {
		return false
	}
	defer func() {
		if r := recover(); r != nil {
			// The control plane's ingest code panicked on this event:
			// send it and stop filtering on this stream.
			log.Printf("[ebpf-grpc] trace forward filter failed, sending every event: %v", r)
			f.mu.Lock()
			f.filter, f.state = nil, traceForwardInvalid
			f.mu.Unlock()
			dropped = false
		}
	}()
	verdict, ruleID := filter.Decide(event)
	switch verdict {
	case tracefilter.TraceForwardSuppressed:
		traceForwardSuppressed.Add(1)
	case tracefilter.TraceForwardUnstored:
		traceForwardUnstored.Add(1)
	default:
		return false
	}
	if ruleID != "" {
		f.mu.Lock()
		if f.hits == nil {
			f.hits = make(map[string]int)
		}
		f.hits[ruleID]++
		f.mu.Unlock()
	}
	return true
}

// report is the batch report: the digest the stream holds and the hits of
// the events dropped since the last report (taken). nil for nil.
func (f *traceForwardFilter) report() *tracefilter.TraceForwardReport {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &tracefilter.TraceForwardReport{Digest: f.digest, RuleHits: f.hits}
	f.hits = nil
	return r
}

// fillTraceForwardStatus sets the forwarding filter fields of the trace
// status the agent reports.
func fillTraceForwardStatus(st *wafebpf.TraceStatus) {
	st.ForwardFilter = traceForwardOff
	if f := traceForwardCurrent.Load(); f != nil {
		f.mu.Lock()
		st.ForwardFilter, st.ForwardFilterDigest = f.state, f.digest
		f.mu.Unlock()
	}
	st.ForwardFilteredSuppressed = traceForwardSuppressed.Load()
	st.ForwardFilteredUnstored = traceForwardUnstored.Load()
}

// hostAgentFeatures are the Hello features of the host agent's stream.
func hostAgentFeatures() []string {
	return []string{telemetryDemandFeature, tracefilter.TraceForwardFilterFeature}
}
