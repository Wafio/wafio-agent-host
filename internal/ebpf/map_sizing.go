package ebpf

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Map names that the sizing table and the objects share (must match the
// SEC(".maps") names in C).
const (
	mapConntrack = "wafio_conntrack"
	mapSynState  = "wafio_syn_state"
	mapRateState = "wafio_rate_state"
	mapPortscan  = "wafio_portscan"
	mapBandwidth = "wafio_bandwidth"
	mapGeoIP     = "wafio_geoip"
	mapJail      = "wafio_jail" // WAF-agent jail
	// mapStateFull counts the inserts the three per-source state maps refused
	// (slots stateFullRate, stateFullSyn, stateFullPortscan). Optional: older
	// objects lack it.
	mapStateFull = "wafio_state_full"

	traceMapEvents      = "trace_events"
	traceMapOpenPending = "trace_open_pending"
)

// ErrJailFull: the jail refused an address because every slot holds a live
// entry. The jail never evicts one. It wraps ErrIPListCapacity, so the local
// API answers it as IP_LIST_FULL.
var ErrJailFull = fmt.Errorf("%w: the jail is full", ErrIPListCapacity)

// Slots of wafio_state_full (STATE_FULL_* in wafio_xdp.c).
const (
	stateFullRate     uint32 = 0
	stateFullSyn      uint32 = 1
	stateFullPortscan uint32 = 2
)

// Map memory follows the host memory: the preallocated maps are sized once at
// load by one formula, never above the size the object declares.
const (
	// mapScaleFullMemory is the memory at which every map has its declared
	// size: scale = min(1, memory / mapScaleFullMemory).
	mapScaleFullMemory = 8 << 30
	// mapLRUFreeNodesPerCPU: each CPU keeps up to 128 free nodes of an LRU
	// map, so eviction starts before the map is full.
	mapLRUFreeNodesPerCPU = 128
	// mapFullWindow is how long a map counts as full after it last was.
	mapFullWindow = 10 * time.Minute
	// mapFullWarnEvery limits the WARN log of one full map.
	mapFullWarnEvery = 10 * time.Minute

	// Source values of MapSizing.Source.
	MapScaleAuto   = "auto"
	MapScaleForced = "forced"
	// Values of MapSizing.MemorySource.
	memorySourceMeminfo = "meminfo"
	memorySourceCgroup  = "cgroup"
	memorySourceUnknown = "unknown"

	traceRingMax = 16 << 20
	traceRingMin = 4 << 20
)

// sizedMap is one map the sizing formula scales: its declared size (ceiling,
// the #define in bpf/*.h and *.c), the smallest size the host still needs
// (floor), whether it is an LRU map and what an entry costs in kernel memory
// (key + value + about 64 bytes), for the memory estimate.
type sizedMap struct {
	name       string
	ceiling    uint32
	floor      uint32
	lru        bool
	entryBytes uint64
}

// sizedMaps is the sizing table. The floor of each map is what a small server
// still needs from it:
//   - wafio_conntrack: the concurrent flows of a small server plus headroom.
//     An evicted flow is tracked again, and a host-opened TCP flow recovers by
//     socket proof.
//   - wafio_syn_state, wafio_rate_state: the prune frees 4096 idle sources a
//     second and keeps each for two windows and a second, so about 12288
//     entries stand at that rate.
//   - wafio_portscan: with its 10 s window, about 780 new scanning sources a
//     second, sustained. A real scan needs a real address.
//   - wafio_bandwidth: accounting only, no verdict depends on it.
//   - wafio_geoip: a cache behind the geo CIDR tries, refilled after eviction.
//   - wafio_jail: the distinct L7 attackers jailed within one TTL.
//   - trace_open_pending: the open syscalls in flight at once.
//
// wafio_egress_blocklist is not here: it is allocated on insert instead.
var sizedMaps = []sizedMap{
	{mapConntrack, 500000, 65536, true, 152},
	{mapSynState, 200000, 16384, false, 132},
	{mapRateState, 100000, 16384, false, 124},
	{mapPortscan, 100000, 16384, false, 172},
	{mapBandwidth, 100000, 8192, true, 124},
	{mapGeoIP, 100000, 16384, true, 88},
	{mapJail, 65536, 16384, false, 108},
	{traceMapOpenPending, 2048, 512, false, 1512},
}

// MapSizes is the size chosen for each sized map, by map name: entries, except
// trace_events, which is in bytes. The zero value leaves every map at the size
// its object declares.
type MapSizes struct {
	Scale        float64
	Source       string // MapScaleAuto or MapScaleForced
	MemoryBytes  uint64 // the memory basis; 0 when unknown
	MemorySource string // meminfo, cgroup or unknown
	CPUs         int
	Entries      map[string]uint32
	// Warning is a problem the caller logs (the memory could not be read, so
	// the scale is 1).
	Warning string
}

// Size returns the chosen size of a map and whether one was chosen.
func (s MapSizes) Size(name string) (uint32, bool) {
	n, ok := s.Entries[name]
	return n, ok
}

var mapScaleSyntax = regexp.MustCompile(`^(\d+\.?\d*|\.\d+)$`)

// ParseMapScale reads the map scale setting: "auto" or empty (size by host
// memory) or a decimal above 0 and at most 1 (forced). forced is false for
// auto.
func ParseMapScale(setting string) (scale float64, forced bool, err error) {
	v := strings.TrimSpace(setting)
	if v == "" || strings.EqualFold(v, "auto") {
		return 0, false, nil
	}
	if mapScaleSyntax.MatchString(v) {
		if f, perr := strconv.ParseFloat(v, 64); perr == nil && f > 0 && f <= 1 {
			return f, true, nil
		}
	}
	return 0, false, errors.New("want auto or a number above 0 and at most 1")
}

// MemoryBasis is the memory the maps are sized from: MemTotal of
// <root>/proc/meminfo, lowered to the smallest numeric memory.max on the
// cgroup v2 path of the process up to the cgroup root. A cgroup limit counts
// because kernels from 5.11 charge map memory to the cgroup. source is
// "meminfo" or, when a limit lowered it, "cgroup". root is "/" on a host.
func MemoryBasis(root string) (bytes uint64, source string, err error) {
	data, err := os.ReadFile(filepath.Join(root, "proc/meminfo"))
	if err != nil {
		return 0, "", err
	}
	total, ok := parseMemTotal(string(data))
	if !ok {
		return 0, "", errors.New("MemTotal not found in meminfo")
	}
	bytes, source = total, memorySourceMeminfo
	// shortcut: cgroup v1 is ignored (only a "0::" line of /proc/self/cgroup
	// counts); add the v1 memory controller when a v1-only host matters.
	self, err := os.ReadFile(filepath.Join(root, "proc/self/cgroup"))
	if err != nil {
		return bytes, source, nil
	}
	path := ""
	for line := range strings.SplitSeq(string(self), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			path = strings.TrimSuffix(strings.TrimSpace(p), " (deleted)")
			break
		}
	}
	if path == "" {
		return bytes, source, nil
	}
	for p := filepath.Clean("/" + path); ; p = filepath.Dir(p) {
		raw, err := os.ReadFile(filepath.Join(root, "sys/fs/cgroup", p, "memory.max"))
		if err == nil {
			if limit, perr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); perr == nil && limit < bytes {
				bytes, source = limit, memorySourceCgroup
			}
		}
		if p == "/" {
			break
		}
	}
	return bytes, source, nil
}

// parseMemTotal reads the MemTotal line of /proc/meminfo, in bytes.
func parseMemTotal(meminfo string) (uint64, bool) {
	for line := range strings.SplitSeq(meminfo, "\n") {
		rest, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) != 2 || f[1] != "kB" {
			return 0, false
		}
		kb, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil || kb > math.MaxUint64/1024 {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

// ScaleForMemory is the automatic scale of a host with that much memory.
func ScaleForMemory(bytes uint64) float64 {
	return math.Min(1, float64(bytes)/mapScaleFullMemory)
}

// ComputeMapSizes sizes every map for the scale s (above 0, at most 1) on a
// host with cpus possible CPUs. A hash or LRU map gets trunc(ceiling * s),
// kept between its floor and its ceiling; the floor of an LRU map is raised
// to 1024 entries a CPU (at most the ceiling), because each CPU holds free
// nodes back. trace_events is the largest power of two at most 16 MiB * s,
// between 4 and 16 MiB. The kernel rounds the bucket count itself.
func ComputeMapSizes(s float64, cpus int) MapSizes {
	if !(s > 0) || s > 1 {
		s = 1
	}
	cpus = max(cpus, 1)
	out := MapSizes{Scale: s, CPUs: cpus, Entries: make(map[string]uint32, len(sizedMaps)+1)}
	for _, m := range sizedMaps {
		floor := m.floor
		if m.lru {
			floor = max(floor, uint32(min(uint64(m.ceiling), 1024*uint64(cpus))))
		}
		n := uint32(float64(m.ceiling) * s)
		out.Entries[m.name] = min(max(n, floor), m.ceiling)
	}
	ring := uint64(float64(traceRingMax) * s)
	if ring < traceRingMin {
		ring = traceRingMin
	} else {
		ring = 1 << (bits.Len64(ring) - 1)
	}
	out.Entries[traceMapEvents] = uint32(min(ring, traceRingMax))
	return out
}

// ResolveMapSizes turns the setting (see ParseMapScale) into sizes: forced
// scales as given, auto scales by the memory basis of root. When automatic
// sizing cannot read the memory the scale is 1, the sizes the objects declare,
// and Warning says so.
func ResolveMapSizes(setting, root string, cpus int) (MapSizes, error) {
	forced, isForced, err := ParseMapScale(setting)
	if err != nil {
		return MapSizes{}, err
	}
	mem, memSource, memErr := MemoryBasis(root)
	if memErr != nil {
		mem, memSource = 0, memorySourceUnknown
	}
	scale, source := forced, MapScaleForced
	warning := ""
	if !isForced {
		source = MapScaleAuto
		scale = 1
		if memErr != nil {
			warning = fmt.Sprintf("eBPF map sizing: host memory unreadable (%v): using scale 1, the sizes the objects declare", memErr)
		} else {
			scale = ScaleForMemory(mem)
		}
	}
	out := ComputeMapSizes(scale, cpus)
	out.Source, out.MemoryBytes, out.MemorySource, out.Warning = source, mem, memSource, warning
	return out, nil
}

// LogLine is the one line the agent logs at start: the scale, where it came
// from, the host memory and the size of every sized map, with an estimate of
// the memory they preallocate.
func (s MapSizes) LogLine() string {
	var b strings.Builder
	mem := "unknown"
	if s.MemoryBytes > 0 {
		mem = fmt.Sprintf("%dMiB (%s)", s.MemoryBytes>>20, s.MemorySource)
	}
	fmt.Fprintf(&b, "eBPF map sizing: scale=%.3f source=%s memory=%s", s.Scale, s.Source, mem)
	for _, m := range sizedMaps {
		if m.name != traceMapOpenPending {
			fmt.Fprintf(&b, " %s=%d", m.name, s.Entries[m.name])
		}
	}
	fmt.Fprintf(&b, " %s=%d %s=%dMiB est=%dMiB", traceMapOpenPending, s.Entries[traceMapOpenPending],
		traceMapEvents, s.Entries[traceMapEvents]>>20, s.EstimatedBytes()>>20)
	return b.String()
}

// EstimatedBytes is the memory the sized maps preallocate, estimated from the
// size of an entry (key, value and about 64 bytes of overhead).
func (s MapSizes) EstimatedBytes() uint64 {
	total := uint64(s.Entries[traceMapEvents])
	for _, m := range sizedMaps {
		total += uint64(s.Entries[m.name]) * m.entryBytes
	}
	return total
}

// ────────────────────────────────────────────────────────────────────────────
//  Status: how full each sized map is
// ────────────────────────────────────────────────────────────────────────────

// MapSizing is the map_sizing key of the firewall status (ebpf_status) and the
// trace status (trace_status): the scale the maps were sized with and how full
// each one is, so an operator sees when to raise the size.
type MapSizing struct {
	Scale        float64       `json:"scale"`
	Source       string        `json:"source"`
	MemoryBytes  uint64        `json:"memory_bytes,omitempty"`
	MemorySource string        `json:"memory_source"`
	SampledAt    *time.Time    `json:"sampled_at,omitempty"`
	Maps         []MapCapacity `json:"maps"`
}

// MapCapacity is one sized map. Entries is the live count (absent for the
// ring and before the first sample). FullCount is the number of inserts the map
// refused since start, absent for an LRU map, which evicts instead. LastFullAt
// is the last time FullCount grew; for an LRU map, the last sample that found
// it within one eviction margin of full.
type MapCapacity struct {
	Name              string     `json:"name"`
	MaxEntries        uint32     `json:"max_entries"`
	DefaultMaxEntries uint32     `json:"default_max_entries"`
	Entries           *uint64    `json:"entries,omitempty"`
	FullCount         *uint64    `json:"full_count,omitempty"`
	LastFullAt        *time.Time `json:"last_full_at,omitempty"`
}

// mapDefaultSize is the size the object declares for a sized map.
func mapDefaultSize(name string) uint32 {
	if name == traceMapEvents {
		return traceRingMax
	}
	for _, m := range sizedMaps {
		if m.name == name {
			return m.ceiling
		}
	}
	return 0
}

// mapFullWarning is the coverage warning for the maps that were full within
// the last mapFullWindow, or "" when none was.
func mapFullWarning(sz *MapSizing, now time.Time) string {
	if sz == nil {
		return ""
	}
	var names []string
	for _, m := range sz.Maps {
		if m.LastFullAt != nil && now.Sub(*m.LastFullAt) < mapFullWindow {
			names = append(names, m.Name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return fmt.Sprintf("eBPF maps full in the last %d minutes: %s. Map scale %.3g (%s): raise WAFIO_EBPF_MAP_SCALE (at most 1) or look for a flood.",
		int(mapFullWindow/time.Minute), strings.Join(names, ", "), sz.Scale, sz.Source)
}

// mapFullTracker follows when each sized map was last full and when its
// WARN was last logged.
type mapFullTracker struct {
	mu    sync.Mutex
	state map[string]*mapFullState
}

type mapFullState struct {
	counter  uint64
	lastFull time.Time
	lastWarn time.Time
}

// note records a sample of a map that was full when full is true. It returns
// the time the map was last full (zero for never) and whether the caller
// should log a WARN now: at most one per mapFullWarnEvery for each map.
func (t *mapFullTracker) note(name string, now time.Time, full bool) (last time.Time, warn bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == nil {
		t.state = make(map[string]*mapFullState)
	}
	st := t.state[name]
	if st == nil {
		st = &mapFullState{}
		t.state[name] = st
	}
	if full {
		st.lastFull = now
		if st.lastWarn.IsZero() || now.Sub(st.lastWarn) >= mapFullWarnEvery {
			st.lastWarn = now
			warn = true
		}
	}
	return st.lastFull, warn
}

// noteCounter is note for a map that counts its refused inserts: it was full
// since the last sample when the cumulative counter grew.
func (t *mapFullTracker) noteCounter(name string, now time.Time, counter uint64) (time.Time, bool) {
	t.mu.Lock()
	if t.state == nil {
		t.state = make(map[string]*mapFullState)
	}
	st := t.state[name]
	if st == nil {
		st = &mapFullState{}
		t.state[name] = st
	}
	grew := counter > st.counter
	st.counter = counter
	t.mu.Unlock()
	return t.note(name, now, grew)
}
