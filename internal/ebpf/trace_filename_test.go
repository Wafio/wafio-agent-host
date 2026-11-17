package ebpf

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The event types whose hook writes evt->filename must be exactly the ones
// eventCarriesFilename keeps: a hook that starts writing one would otherwise
// lose it in userspace, and one missing from wafio_trace.c would let a stale
// per-CPU path through from an older object.
func TestEventCarriesFilenameMatchesBPF(t *testing.T) {
	header, err := os.ReadFile("bpf/wafio_trace.h")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("bpf/wafio_trace.c")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]uint32{}
	for _, m := range regexp.MustCompile(`(?m)^#define TRACE_EVENT_(\w+)\s+(\d+)`).FindAllStringSubmatch(string(header), -1) {
		if m[1] == "MAX" {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		ids[m[1]] = uint32(n)
	}
	src := string(source)
	writes := map[uint32]bool{}
	seen := map[uint32]bool{}
	writeRe := regexp.MustCompile(`\(&?evt->filename,`)
	for _, loc := range regexp.MustCompile(`new_event\(TRACE_EVENT_(\w+)`).FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		id, ok := ids[name]
		if !ok {
			t.Fatalf("unknown event %s", name)
		}
		body := src[loc[1]:]
		if end := strings.Index(body, "submit_event"); end >= 0 {
			body = body[:end]
		}
		seen[id] = true
		if writeRe.MatchString(body) {
			writes[id] = true
		}
	}
	if len(seen) < 25 {
		t.Fatalf("parsed %d event hooks, the source parser is broken", len(seen))
	}
	for id := range seen {
		if writes[id] != eventCarriesFilename(id) {
			t.Errorf("event type %d: hook writes filename=%v, eventCarriesFilename=%v", id, writes[id], eventCarriesFilename(id))
		}
	}
	newEvent := regexp.MustCompile(`(?s)new_event\(__u32 event_type, __u32 severity\)\n\{.*?\n\}`).FindString(src)
	if !strings.Contains(newEvent, "evt->filename[0] = 0;") {
		t.Error("new_event does not clear the per-CPU filename")
	}
}

// An event from an object that predates the clear carries the previous
// event's path: userspace drops it for event types that never write one.
func TestToTraceEventDropsStaleFilename(t *testing.T) {
	stale := func(eventType uint32) TraceEvent {
		var r RawTraceEvent
		r.EventType = eventType
		copy(r.Filename[:], "/etc/shadow")
		copy(r.Comm[:], "sudo")
		return r.ToTraceEvent(0)
	}
	for _, et := range []uint32{TraceSendto, TraceConnect, TraceConnExit, TraceSocket, TraceAccept, TraceSetuid, TraceSetgid, TraceKill, TraceBPFSyscall} {
		if got := stale(et).Filename; got != "" {
			t.Errorf("event type %d kept stale filename %q", et, got)
		}
	}
	if got := stale(TraceOpen).Filename; got != "/etc/shadow" {
		t.Errorf("openat lost its filename: %q", got)
	}
}
