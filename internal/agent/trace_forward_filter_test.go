package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"testing"
	"time"

	gojson "github.com/goccy/go-json"
	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/tracefilter"
)

// Agent side: the stream filters only with a filter of its
// own revision from its own control plane, reports the digest it holds and
// the hits of what it kept back, and never counts that as loss.

func forwardTestFilter(t *testing.T) ([]byte, string) {
	t.Helper()
	msg, digest := tracefilter.BuildTraceForwardFilter([]tracefilter.DetectionRule{
		{ID: "quiet", Enabled: true, Action: tracefilter.RuleActionSuppress, Conditions: []tracefilter.RuleCondition{{Field: "comm", Op: "eq", Value: "quiet"}}},
		{ID: "tag-lib", Enabled: true, Action: tracefilter.RuleActionTag, Conditions: []tracefilter.RuleCondition{{Field: "filename", Op: "starts_with", Value: "/usr/lib/"}}},
	}, forwardTestChains())
	if msg == nil {
		t.Fatal("no filter built")
	}
	return msg, digest
}

// forwardTestChains is a one-chain stand-in for the control plane's built-in
// correlation chains (this package cannot import them): a file opened in a
// world-writable or web directory starts the chain the tests call "correlation
// stage".
func forwardTestChains() []*tracefilter.CorrelationRule {
	return []*tracefilter.CorrelationRule{{
		ID: "webshell-exec-chain", Name: "Web_Shell_Execution_Chain", Entity: "process", MaxSpan: 5 * time.Minute,
		Stages: []tracefilter.CorrelationStage{
			{Conditions: []tracefilter.CorrelationCondition{
				{Field: "event_name", Op: "eq", Value: "openat"},
				{Field: "filename", Op: "starts_with_any", Value: []string{"/dev/shm/", "/tmp/", "/var/tmp/", "/var/www/"}},
			}},
			{Within: time.Minute, Conditions: []tracefilter.CorrelationCondition{
				{Field: "event_name", Op: "in", Value: []string{"fchmodat", "chmod"}},
			}},
		},
	}}
}

func forwardEvent(t *testing.T, e wafebpf.TraceEvent) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTraceForwardFilterAppliesOnlyItsOwnFilter(t *testing.T) {
	noise := forwardEvent(t, wafebpf.TraceEvent{EventName: "openat", Category: "file", Comm: "app", Filename: "/usr/lib/libc.so.6"})
	suppressed := forwardEvent(t, wafebpf.TraceEvent{EventName: "execve", Category: "process", Comm: "quiet", Severity: 3})
	kept := forwardEvent(t, wafebpf.TraceEvent{EventName: "openat", Category: "file", Comm: "php", Filename: "/tmp/x.php"})

	var none *traceForwardFilter
	if none.drop(noise) || none.report() != nil {
		t.Fatal("nil filter (HTTP push) dropped or reported")
	}
	f := newTraceForwardFilter()
	defer f.close()
	if f.drop(noise) {
		t.Fatal("dropped before the control plane sent a filter")
	}
	if r := f.report(); r == nil || r.Digest != "" || r.RuleHits != nil {
		t.Fatalf("report before a filter = %+v, want empty digest", r)
	}

	msg, digest := forwardTestFilter(t)
	f.handle(msg)
	before := traceForwardSuppressed.Load() + traceForwardUnstored.Load()
	if !f.drop(noise) || !f.drop(noise) || !f.drop(suppressed) || f.drop(kept) {
		t.Fatal("verdicts: want noise and suppressed dropped, the correlation stage kept")
	}
	if got := traceForwardSuppressed.Load() + traceForwardUnstored.Load() - before; got != 3 {
		t.Fatalf("counted %d filtered events, want 3", got)
	}
	r := f.report()
	if r.Digest != digest || !maps.Equal(r.RuleHits, map[string]int{"tag-lib": 2, "quiet": 1}) {
		t.Fatalf("report %+v, want digest %s and hits tag-lib=2 quiet=1", r, digest)
	}
	if again := f.report(); again.Digest != digest || again.RuleHits != nil {
		t.Fatalf("hits reported twice: %+v", again)
	}
	var st wafebpf.TraceStatus
	fillTraceForwardStatus(&st)
	if st.ForwardFilter != traceForwardActive || st.ForwardFilterDigest != digest {
		t.Fatalf("status %q %q, want active %s", st.ForwardFilter, st.ForwardFilterDigest, digest)
	}

	// Built for other ingest semantics: digest kept (no resend loop), nothing dropped.
	var m struct {
		Revision int             `json:"revision"`
		Digest   string          `json:"digest"`
		Filter   json.RawMessage `json:"filter"`
	}
	if err := json.Unmarshal(msg, &m); err != nil {
		t.Fatal(err)
	}
	m.Revision = tracefilter.TraceForwardRevision + 1
	other, _ := json.Marshal(m) // digest no longer matches: unreadable
	f.handle(other)
	if f.drop(noise) || f.report().Digest != "" {
		t.Fatal("a filter whose digest does not match was applied or reported")
	}
	fillTraceForwardStatus(&st)
	if st.ForwardFilter != traceForwardInvalid {
		t.Fatalf("status %q, want invalid", st.ForwardFilter)
	}

	// A new stream starts without a filter; the old one closing later
	// does not touch it.
	g := newTraceForwardFilter()
	f.close()
	fillTraceForwardStatus(&st)
	if st.ForwardFilter != traceForwardOff || g.drop(noise) {
		t.Fatalf("new stream: status %q, want off and nothing dropped", st.ForwardFilter)
	}
	g.close()
	fillTraceForwardStatus(&st)
	if st.ForwardFilter != traceForwardOff || st.ForwardFilterDigest != "" {
		t.Fatalf("no stream: status %q %q, want off", st.ForwardFilter, st.ForwardFilterDigest)
	}
}

func TestTraceForwardFilterRevisionMismatchSendsEverything(t *testing.T) {
	f := newTraceForwardFilter()
	defer f.close()
	msg := otherRevisionFilter(t)
	f.handle(msg)
	noise := forwardEvent(t, wafebpf.TraceEvent{EventName: "openat", Category: "file", Comm: "app", Filename: "/usr/lib/x"})
	if f.drop(noise) {
		t.Fatal("applied a filter of another revision")
	}
	if r := f.report(); r.Digest == "" {
		t.Fatal("revision mismatch must still report the digest it received, or the control plane resends it every batch")
	}
	var st wafebpf.TraceStatus
	fillTraceForwardStatus(&st)
	if st.ForwardFilter != traceForwardRevisionMismatch {
		t.Fatalf("status %q, want revision_mismatch", st.ForwardFilter)
	}
}

// A filter too large to send arrives as a marker: an active filter is
// dropped, nothing is filtered, the marker's digest is reported (so the
// control plane stops sending it) and the status says too_large.
func TestTraceForwardTooLargeMarkerSendsEverything(t *testing.T) {
	f := newTraceForwardFilter()
	defer f.close()
	msg, _ := forwardTestFilter(t)
	f.handle(msg)
	noise := forwardEvent(t, wafebpf.TraceEvent{EventName: "openat", Category: "file", Comm: "app", Filename: "/usr/lib/x"})
	if !f.drop(noise) {
		t.Fatal("setup: the filter keeps noise")
	}
	names := make([]any, 60_000)
	for i := range names {
		names[i] = "/opt/app/file-" + strconv.Itoa(i)
	}
	marker, digest := tracefilter.BuildTraceForwardFilter([]tracefilter.DetectionRule{{ID: "big", Enabled: true, Action: tracefilter.RuleActionSuppress,
		Conditions: []tracefilter.RuleCondition{{Field: "filename", Op: "in", Value: names}}}}, nil)
	if len(marker) > 512 {
		t.Fatalf("control plane sent %d bytes, want the marker", len(marker))
	}
	f.handle(marker)
	if f.drop(noise) {
		t.Fatal("filtered after the too-large marker")
	}
	if r := f.report(); r.Digest != digest {
		t.Fatalf("reported digest %q, want the marker's %q", r.Digest, digest)
	}
	var st wafebpf.TraceStatus
	fillTraceForwardStatus(&st)
	if st.ForwardFilter != traceForwardTooLarge || st.ForwardFilterDigest != digest {
		t.Fatalf("status %q %q, want too_large %s", st.ForwardFilter, st.ForwardFilterDigest, digest)
	}
}

// otherRevisionFilter is a well-formed filter built for the next revision.
func otherRevisionFilter(t *testing.T) []byte {
	t.Helper()
	msg, _ := forwardTestFilter(t)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(msg, &m); err != nil {
		t.Fatal(err)
	}
	// The digest covers the revision and the filter bytes; the parser
	// checks it before the revision, so a wrong recipe fails below.
	rev := tracefilter.TraceForwardRevision + 1
	sum := sha256.Sum256(append([]byte(strconv.Itoa(rev)+"\n"), m["filter"]...))
	m["revision"], _ = json.Marshal(rev)
	m["digest"], _ = json.Marshal(hex.EncodeToString(sum[:16]))
	out, _ := json.Marshal(m)
	if _, _, err := tracefilter.ParseTraceForwardFilter(out); !errors.Is(err, tracefilter.ErrTraceForwardRevision) {
		t.Fatalf("crafted other-revision filter: %v", err)
	}
	return out
}

func TestPushPayloadCountsFilteredEvents(t *testing.T) {
	if !(&PushPayload{traceByClass: [3]int{100, 0, 0}, traceFiltered: 400}).fullBatch() {
		t.Fatal("events the filter kept back count toward a full drain")
	}
	p := &PushPayload{TraceForward: &tracefilter.TraceForwardReport{Digest: "d"}}
	if p.hasTraceForwardHits() {
		t.Fatal("a report without hits makes no batch")
	}
	p.TraceForward.RuleHits = map[string]int{"r": 1}
	if !p.hasTraceForwardHits() {
		t.Fatal("hits must be sent even in an otherwise empty batch")
	}
	// Filtered events are not trace events of the batch: a lost batch
	// reports only what it carried as delivery loss.
	if p.traceByClass != [3]int{} {
		t.Fatal("filtered events counted by class")
	}
}

// A batch built with a filter carries only what ingest uses; the rest
// counts toward a full drain and as hits in the report, and the control
// plane decodes the batch (gojson, as Prepare does) with the report intact.
func TestTraceForwardBatchAsIngestReadsIt(t *testing.T) {
	msg, digest := forwardTestFilter(t)
	f := newTraceForwardFilter()
	defer f.close()
	f.handle(msg)

	events := []wafebpf.TraceEvent{
		{EventName: "openat", Category: "file", Comm: "app", Filename: "/usr/lib/libc.so.6"}, // tag-lib hit, not stored
		{EventName: "execve", Category: "process", Comm: "quiet", Severity: 3},               // suppressed
		{EventName: "openat", Category: "file", Comm: "php", Filename: "/tmp/x.php"},         // correlation stage
		{EventName: "execve", Category: "process", Comm: "curl", Filename: "/usr/bin/curl"},  // stored (process)
	}
	p := &PushPayload{}
	for i := range events {
		if !p.addTraceEvent(&events[i], f) {
			t.Fatalf("event %d not encoded", i)
		}
	}
	p.TraceForward = f.report()
	if len(p.TraceEvents) != 2 || p.traceFiltered != 2 || p.traceUnencoded != 0 ||
		p.traceByClass[0]+p.traceByClass[1]+p.traceByClass[2] != 2 {
		t.Fatalf("batch: %d sent, %d filtered, by class %v; want 2 sent, 2 filtered", len(p.TraceEvents), p.traceFiltered, p.traceByClass)
	}

	body, err := json.Marshal(p) // as the stream encodes a batch
	if err != nil {
		t.Fatal(err)
	}
	// The control plane's HostTelemetryPayload, reduced to the keys this
	// test reads.
	var got struct {
		TraceEvents []struct {
			Filename string `json:"filename"`
		} `json:"trace_events"`
		TraceForward *tracefilter.TraceForwardReport `json:"trace_forward"`
	}
	if err := gojson.Unmarshal(body, &got); err != nil {
		t.Fatalf("ingest decode: %v", err)
	}
	if len(got.TraceEvents) != 2 || got.TraceEvents[0].Filename != "/tmp/x.php" || got.TraceEvents[1].Filename != "/usr/bin/curl" {
		t.Fatalf("ingest read events %+v, want /tmp/x.php then /usr/bin/curl", got.TraceEvents)
	}
	if got.TraceForward == nil || got.TraceForward.Digest != digest ||
		!maps.Equal(got.TraceForward.RuleHits, map[string]int{"tag-lib": 1, "quiet": 1}) {
		t.Fatalf("ingest read report %+v, want digest %s and hits tag-lib=1 quiet=1", got.TraceForward, digest)
	}

	// No filter (HTTP push): every event rides, no report is sent.
	var none *traceForwardFilter
	q := &PushPayload{}
	for i := range events {
		q.addTraceEvent(&events[i], none)
	}
	q.TraceForward = none.report()
	body, err = json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.TraceEvents) != len(events) || q.traceFiltered != 0 || bytes.Contains(body, []byte(`"trace_forward"`)) {
		t.Fatalf("HTTP batch: %d sent, %d filtered, report sent=%v", len(q.TraceEvents), q.traceFiltered, bytes.Contains(body, []byte(`"trace_forward"`)))
	}
}

// A filter whose ingest code panics on an event sends that event and stops
// filtering on the stream (fail open, status invalid).
func TestTraceForwardFilterPanicFailsOpen(t *testing.T) {
	f := newTraceForwardFilter()
	defer f.close()
	f.handle(otherRevisionFilter(t)) // digest held, nothing applied
	f.mu.Lock()
	f.filter, f.state = &tracefilter.TraceForwardFilter{}, traceForwardActive // zero filter: nil evaluator
	f.mu.Unlock()
	ev := forwardEvent(t, wafebpf.TraceEvent{EventName: "openat", Category: "file", Comm: "app", Filename: "/usr/lib/x"})
	if f.drop(ev) {
		t.Fatal("dropped an event the filter failed on")
	}
	var st wafebpf.TraceStatus
	fillTraceForwardStatus(&st)
	if f.drop(ev) || st.ForwardFilter != traceForwardInvalid {
		t.Fatalf("after a failure: status %q, want invalid and nothing dropped", st.ForwardFilter)
	}
}

func TestHostAgentHelloFeatures(t *testing.T) {
	got := hostAgentFeatures()
	for _, want := range []string{telemetryDemandFeature, tracefilter.TraceForwardFilterFeature} {
		if !slices.Contains(got, want) {
			t.Errorf("Hello features %v lack %s", got, want)
		}
	}
}
