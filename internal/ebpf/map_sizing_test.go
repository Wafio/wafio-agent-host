package ebpf

import (
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const gib = 1 << 30

// Every map gets a size between its floor and its ceiling, the ceiling from 8
// GiB up, and a bigger host never gets a smaller map. The ring is a power of
// two. An LRU map keeps at least 1024 entries a CPU.
func TestComputeMapSizesBounds(t *testing.T) {
	for _, cpus := range []int{1, 64} {
		prev := map[string]uint32{}
		for _, ram := range []uint64{1 * gib, 2 * gib, 4 * gib, 8 * gib, 16 * gib} {
			sz := ComputeMapSizes(ScaleForMemory(ram), cpus)
			for _, m := range sizedMaps {
				got, ok := sz.Size(m.name)
				if !ok {
					t.Fatalf("%d GiB, %d CPUs: no size for %s", ram/gib, cpus, m.name)
				}
				floor := m.floor
				if m.lru {
					floor = max(floor, uint32(min(uint64(m.ceiling), 1024*uint64(cpus))))
				}
				if got < floor || got > m.ceiling {
					t.Errorf("%d GiB, %d CPUs: %s = %d, want %d..%d", ram/gib, cpus, m.name, got, floor, m.ceiling)
				}
				if ram >= 8*gib && got != m.ceiling {
					t.Errorf("%d GiB: %s = %d, want the ceiling %d", ram/gib, m.name, got, m.ceiling)
				}
				if got < prev[m.name] {
					t.Errorf("%s shrank from %d to %d with more memory", m.name, prev[m.name], got)
				}
				prev[m.name] = got
			}
			ring := sz.Entries[traceMapEvents]
			if bits.OnesCount32(ring) != 1 || ring < traceRingMin || ring > traceRingMax {
				t.Errorf("%d GiB: trace_events = %d, want a power of two between 4 and 16 MiB", ram/gib, ring)
			}
		}
	}
}

// The ceilings are the sizes of today's objects, and the LRU floor follows the
// CPU count only where it is higher than the table floor.
func TestComputeMapSizesCeilingsAndCPUFloor(t *testing.T) {
	full := ComputeMapSizes(1, 1)
	for name, want := range map[string]uint32{
		mapConntrack: 500000, mapSynState: 200000, mapRateState: 100000, mapPortscan: 100000,
		mapBandwidth: 100000, mapGeoIP: 100000, mapJail: 65536, traceMapOpenPending: 2048, traceMapEvents: 16 << 20,
	} {
		if got := full.Entries[name]; got != want {
			t.Errorf("scale 1: %s = %d, want %d", name, got, want)
		}
	}
	small64 := ComputeMapSizes(0.001, 64)
	for name, want := range map[string]uint32{mapBandwidth: 65536, mapGeoIP: 65536, mapConntrack: 65536} {
		if got := small64.Entries[name]; got != want {
			t.Errorf("scale 0.001 with 64 CPUs: %s = %d, want the LRU CPU floor %d", name, got, want)
		}
	}
	// A hash map is not raised by the CPU count.
	if got := small64.Entries[mapSynState]; got != 16384 {
		t.Errorf("syn_state = %d with 64 CPUs, want its floor 16384", got)
	}
	small1 := ComputeMapSizes(0.001, 1)
	if got := small1.Entries[mapBandwidth]; got != 8192 {
		t.Errorf("bandwidth = %d with 1 CPU, want its floor 8192", got)
	}
	// The LRU CPU floor never passes the ceiling.
	if got := ComputeMapSizes(0.001, 4096).Entries[mapBandwidth]; got != 100000 {
		t.Errorf("bandwidth = %d with 4096 CPUs, want the ceiling 100000", got)
	}
}

// One formula for every map: half the memory of a full host is half the
// ceiling, truncated, with no tiers in between.
func TestComputeMapSizesIsProportional(t *testing.T) {
	sz := ComputeMapSizes(0.5, 1)
	if got := sz.Entries[mapConntrack]; got != 250000 {
		t.Errorf("conntrack at 0.5 = %d, want 250000", got)
	}
	if got := sz.Entries[mapSynState]; got != 100000 {
		t.Errorf("syn_state at 0.5 = %d, want 100000", got)
	}
	if got := sz.Entries[traceMapEvents]; got != 8<<20 {
		t.Errorf("trace_events at 0.5 = %d, want 8 MiB", got)
	}
	// 1962 MiB: the scale is 0.2395 and the sizes truncate, they do not round.
	demo := ComputeMapSizes(ScaleForMemory(1962<<20), 1)
	if demo.Entries[mapConntrack] != 119750 || demo.Entries[mapSynState] != 47900 || demo.Entries[traceMapEvents] != 4<<20 {
		t.Errorf("1962 MiB host: conntrack=%d syn_state=%d trace_events=%d", demo.Entries[mapConntrack], demo.Entries[mapSynState], demo.Entries[traceMapEvents])
	}
}

// A scale outside (0, 1] never reaches ComputeMapSizes from the agent, but a
// caller bug must not size a map above its ceiling or at zero.
func TestComputeMapSizesCoercesBadScale(t *testing.T) {
	for _, s := range []float64{0, -1, 1.5, math.NaN(), math.Inf(1)} {
		sz := ComputeMapSizes(s, 1)
		if sz.Entries[mapConntrack] != 500000 || sz.Scale != 1 {
			t.Errorf("scale %v: conntrack=%d scale=%v, want the ceiling at scale 1", s, sz.Entries[mapConntrack], sz.Scale)
		}
	}
}

func TestParseMapScale(t *testing.T) {
	for _, tc := range []struct {
		in     string
		scale  float64
		forced bool
	}{
		{"auto", 0, false}, {"AUTO", 0, false}, {"", 0, false}, {"  ", 0, false},
		{"1", 1, true}, {"1.0", 1, true}, {"0.5", 0.5, true}, {"0.001", 0.001, true}, {".25", 0.25, true},
	} {
		scale, forced, err := ParseMapScale(tc.in)
		if err != nil || scale != tc.scale || forced != tc.forced {
			t.Errorf("ParseMapScale(%q) = %v, %v, %v; want %v, %v", tc.in, scale, forced, err, tc.scale, tc.forced)
		}
	}
	for _, in := range []string{"0", "0.0", "-1", "1.5", "2", "abc", "NaN", "Inf", "+Inf", "1e-3", "0x1", "1,5", "0.5.1", "."} {
		if _, _, err := ParseMapScale(in); err == nil {
			t.Errorf("ParseMapScale(%q) accepted", in)
		}
	}
}

// fakeRoot writes the files MemoryBasis reads under a temporary root.
func fakeRoot(t *testing.T, meminfo, selfCgroup string, memoryMax map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if meminfo != "" {
		write("proc/meminfo", meminfo)
	}
	if selfCgroup != "" {
		write("proc/self/cgroup", selfCgroup)
	}
	for cg, v := range memoryMax {
		write(filepath.Join("sys/fs/cgroup", cg, "memory.max"), v)
	}
	return root
}

const meminfo2G = "MemTotal:        2009700 kB\nMemFree:          100000 kB\n"

func TestMemoryBasis(t *testing.T) {
	const total = 2009700 * 1024
	const unit = "0::/system.slice/wafio-host-agent.service\n"
	for _, tc := range []struct {
		name       string
		meminfo    string
		cgroup     string
		memoryMax  map[string]string
		wantBytes  uint64
		wantSource string
		wantErr    bool
	}{
		{"max on the whole path", meminfo2G, unit, map[string]string{
			"system.slice/wafio-host-agent.service": "max\n", "system.slice": "max\n", "": "max\n"}, total, "meminfo", false},
		{"a number on the unit", meminfo2G, unit, map[string]string{
			"system.slice/wafio-host-agent.service": "536870912\n"}, 536870912, "cgroup", false},
		{"a number on a parent, nested", meminfo2G, unit, map[string]string{
			"system.slice/wafio-host-agent.service": "max\n", "system.slice": "268435456\n"}, 268435456, "cgroup", false},
		{"the smallest limit on the path wins", meminfo2G, unit, map[string]string{
			"system.slice/wafio-host-agent.service": "1073741824\n", "system.slice": "536870912\n", "": "268435456\n"}, 268435456, "cgroup", false},
		{"a limit above MemTotal does not raise it", meminfo2G, unit, map[string]string{
			"system.slice/wafio-host-agent.service": "17179869184\n"}, total, "meminfo", false},
		{"memory.max missing", meminfo2G, unit, nil, total, "meminfo", false},
		{"in a cgroup namespace the root is the limit", meminfo2G, "0::/\n", map[string]string{"": "134217728\n"}, 134217728, "cgroup", false},
		{"cgroup v1 is ignored", meminfo2G, "4:memory:/system.slice/x.service\n1:name=systemd:/x\n", map[string]string{
			"system.slice/x.service": "134217728\n"}, total, "meminfo", false},
		{"no /proc/self/cgroup", meminfo2G, "", nil, total, "meminfo", false},
		{"a deleted cgroup", meminfo2G, "0::/system.slice/old.service (deleted)\n", map[string]string{
			"system.slice/old.service": "134217728\n"}, 134217728, "cgroup", false},
		{"no meminfo", "", unit, nil, 0, "", true},
		{"no MemTotal line", "MemFree: 1 kB\n", unit, nil, 0, "", true},
		{"MemTotal in a unit other than kB", "MemTotal: 2009700 MB\n", unit, nil, 0, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fakeRoot(t, tc.meminfo, tc.cgroup, tc.memoryMax)
			bytes, source, err := MemoryBasis(root)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error %v, want error %v", err, tc.wantErr)
			}
			if !tc.wantErr && (bytes != tc.wantBytes || source != tc.wantSource) {
				t.Errorf("MemoryBasis = %d %q, want %d %q", bytes, source, tc.wantBytes, tc.wantSource)
			}
		})
	}
}

func TestResolveMapSizes(t *testing.T) {
	root := fakeRoot(t, "MemTotal: 2009700 kB\n", "0::/u.service\n", map[string]string{"u.service": "max\n"})

	auto, err := ResolveMapSizes("auto", root, 1)
	if err != nil || auto.Source != MapScaleAuto || auto.MemorySource != "meminfo" || auto.MemoryBytes != 2009700*1024 || auto.Warning != "" {
		t.Fatalf("auto: %+v, %v", auto, err)
	}
	if want := ScaleForMemory(2009700 * 1024); auto.Scale != want {
		t.Errorf("auto scale %v, want %v", auto.Scale, want)
	}

	forced, err := ResolveMapSizes("0.001", root, 1)
	if err != nil || forced.Source != MapScaleForced || forced.Scale != 0.001 || forced.Entries[mapConntrack] != 65536 {
		t.Fatalf("forced: %+v, %v", forced, err)
	}

	if _, err := ResolveMapSizes("1.5", root, 1); err == nil {
		t.Error("an invalid setting was accepted")
	}

	// No readable memory: the objects' own sizes, and a warning for the log.
	none, err := ResolveMapSizes("", t.TempDir(), 1)
	if err != nil || none.Scale != 1 || none.Entries[mapConntrack] != 500000 || none.MemorySource != "unknown" || none.Warning == "" {
		t.Fatalf("unreadable memory: %+v, %v", none, err)
	}
	// A forced scale needs no memory and warns about none.
	forcedNoMem, err := ResolveMapSizes("0.5", t.TempDir(), 1)
	if err != nil || forcedNoMem.Scale != 0.5 || forcedNoMem.Warning != "" {
		t.Fatalf("forced without memory: %+v, %v", forcedNoMem, err)
	}
}

func TestLogLine(t *testing.T) {
	// 1962 MiB, the demo host of the specification.
	root := fakeRoot(t, "MemTotal: 2009088 kB\n", "", nil)
	sz, err := ResolveMapSizes("auto", root, 1)
	if err != nil {
		t.Fatal(err)
	}
	line := sz.LogLine()
	for _, want := range []string{
		"eBPF map sizing: scale=0.240 source=auto memory=1962MiB (meminfo) ",
		"wafio_conntrack=119750", "wafio_syn_state=47900", "wafio_rate_state=23950", "wafio_portscan=23950",
		"wafio_bandwidth=23950", "wafio_geoip=23950", "wafio_jail=16384", "trace_open_pending=512", "trace_events=4MiB", " est=",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log line lacks %q: %s", want, line)
		}
	}
	if strings.Contains(line, "\n") {
		t.Errorf("log line spans lines: %q", line)
	}
	// The estimate stays in the range of the memory the sizes preallocate.
	if est := sz.EstimatedBytes(); est < 38<<20 || est > 48<<20 {
		t.Errorf("estimate %d MiB for the 1962 MiB host", est>>20)
	}
}

func TestMapFullWarning(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	at := func(ago time.Duration) *time.Time { v := now.Add(-ago); return &v }
	sz := &MapSizing{Scale: 0.24, Source: MapScaleAuto, Maps: []MapCapacity{
		{Name: mapConntrack, LastFullAt: at(30 * time.Second)},
		{Name: mapSynState},
		{Name: mapRateState, LastFullAt: at(9*time.Minute + 59*time.Second)},
		{Name: mapPortscan, LastFullAt: at(10 * time.Minute)},
		{Name: mapJail, LastFullAt: at(time.Hour)},
	}}
	want := "eBPF maps full in the last 10 minutes: wafio_conntrack, wafio_rate_state. Map scale 0.24 (auto): raise WAFIO_EBPF_MAP_SCALE (at most 1) or look for a flood."
	if got := mapFullWarning(sz, now); got != want {
		t.Errorf("warning\n got %q\nwant %q", got, want)
	}
	if got := mapFullWarning(sz, now.Add(11*time.Minute)); got != "" {
		t.Errorf("warning after the window: %q", got)
	}
	if got := mapFullWarning(nil, now); got != "" {
		t.Errorf("warning without sizing: %q", got)
	}
	if got := mapFullWarning(&MapSizing{Maps: []MapCapacity{{Name: mapJail}}}, now); got != "" {
		t.Errorf("warning for a map never full: %q", got)
	}
	forced := &MapSizing{Scale: 0.001, Source: MapScaleForced, Maps: []MapCapacity{{Name: mapJail, LastFullAt: at(time.Second)}}}
	if got := mapFullWarning(forced, now); !strings.Contains(got, "Map scale 0.001 (forced)") {
		t.Errorf("forced warning %q", got)
	}
}

// A map that stays full logs one WARN per ten minutes, and last_full_at
// follows the last sample that found it full.
func TestMapFullTracker(t *testing.T) {
	var tr mapFullTracker
	t0 := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	if last, warn := tr.note("m", t0, false); !last.IsZero() || warn {
		t.Fatalf("a map never full: last=%v warn=%v", last, warn)
	}
	last, warn := tr.note("m", t0.Add(30*time.Second), true)
	if !warn || !last.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("first full sample: last=%v warn=%v", last, warn)
	}
	last, warn = tr.note("m", t0.Add(60*time.Second), true)
	if warn || !last.Equal(t0.Add(60*time.Second)) {
		t.Fatalf("still full: last=%v warn=%v, want no second WARN and the new time", last, warn)
	}
	// Not full any more: the last time stays.
	if last, warn = tr.note("m", t0.Add(90*time.Second), false); warn || !last.Equal(t0.Add(60*time.Second)) {
		t.Fatalf("emptied: last=%v warn=%v", last, warn)
	}
	// Ten minutes after the WARN it logs again.
	if _, warn = tr.note("m", t0.Add(30*time.Second+10*time.Minute), true); !warn {
		t.Fatal("no WARN ten minutes after the last one")
	}
	// Another map has its own state.
	if _, warn = tr.note("other", t0.Add(time.Minute), true); !warn {
		t.Fatal("another map shares the WARN limit")
	}
}

func TestMapFullTrackerCounter(t *testing.T) {
	var tr mapFullTracker
	t0 := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	if last, warn := tr.noteCounter("m", t0, 0); !last.IsZero() || warn {
		t.Fatalf("counter at zero: last=%v warn=%v", last, warn)
	}
	last, warn := tr.noteCounter("m", t0.Add(30*time.Second), 5)
	if !warn || !last.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("counter grew: last=%v warn=%v", last, warn)
	}
	// No growth: not full now, the last time stays, no WARN.
	if last, warn = tr.noteCounter("m", t0.Add(time.Minute), 5); warn || !last.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("counter flat: last=%v warn=%v", last, warn)
	}
	// Growth within ten minutes of the WARN: the time moves, no new WARN.
	if last, warn = tr.noteCounter("m", t0.Add(2*time.Minute), 9); warn || !last.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("counter grew again: last=%v warn=%v", last, warn)
	}
}

func TestSizedMapsCoverTheTable(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range sizedMaps {
		if seen[m.name] {
			t.Errorf("%s listed twice", m.name)
		}
		seen[m.name] = true
		if m.floor == 0 || m.floor > m.ceiling || m.entryBytes == 0 {
			t.Errorf("%s: floor %d ceiling %d entry %d", m.name, m.floor, m.ceiling, m.entryBytes)
		}
	}
	for name := range ComputeMapSizes(1, 1).Entries {
		if name != traceMapEvents && !seen[name] {
			t.Errorf("%s sized but not in the table", name)
		}
	}
	if mapDefaultSize(traceMapEvents) != 16<<20 || mapDefaultSize(mapConntrack) != 500000 || mapDefaultSize("nope") != 0 {
		t.Error("mapDefaultSize")
	}
}
