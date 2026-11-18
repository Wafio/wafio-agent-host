//go:build linux

package ebpf

import (
	"errors"
	"log"
	"reflect"
	"slices"
	"time"

	"github.com/cilium/ebpf"
)

const (
	// mapSampleEveryTicks: the capacity sampler runs on every 30th tick of
	// the metrics poller, every 30 s at the default poll interval.
	mapSampleEveryTicks = 30
	// mapCountChunk is the batch size of the entry count, lowered for a map
	// with large entries so that a buffer stays within mapCountBufferBytes.
	mapCountChunk       = 4096
	mapCountBufferBytes = 1 << 20
)

// applyMapSizes sets the size of every sized map the object has. A map the
// object lacks, or a name with no chosen size, is left alone.
func applyMapSizes(specs map[string]*ebpf.MapSpec, sizes MapSizes) {
	for name, n := range sizes.Entries {
		if ms := specs[name]; ms != nil {
			ms.MaxEntries = n
		}
	}
}

// entryCounter counts the entries of a map. Batch lookups run in chunks of
// mapCountChunk into buffers that are kept between samples; when the kernel
// refuses batch operations it walks the keys instead.
type entryCounter struct {
	keys, vals any
	keySize    uint32
	valSize    uint32
}

// buffers returns key and value buffers for the maps with these entry sizes,
// reallocating only when the sizes change.
func (c *entryCounter) buffers(keySize, valSize uint32) (keys, vals any) {
	if c.keys == nil || c.keySize != keySize || c.valSize != valSize {
		chunk := max(1, min(mapCountChunk, mapCountBufferBytes/int(keySize+valSize)))
		c.keys = newByteArrays(keySize, chunk)
		c.vals = newByteArrays(valSize, chunk)
		c.keySize, c.valSize = keySize, valSize
	}
	return c.keys, c.vals
}

// newByteArrays makes a slice of n arrays of size bytes: the shape
// BatchLookup needs for keys and values of that size.
func newByteArrays(size uint32, n int) any {
	elem := reflect.ArrayOf(int(size), reflect.TypeFor[byte]())
	return reflect.MakeSlice(reflect.SliceOf(elem), n, n).Interface()
}

// count returns the number of entries in a hash or LRU hash map.
func (c *entryCounter) count(m *ebpf.Map) (uint64, error) {
	keys, vals := c.buffers(m.KeySize(), m.ValueSize())
	if n, ok := batchCount(m, keys, vals, nil); ok {
		return n, nil
	}
	return countByIteration(m)
}

// batchCount counts the entries of m, read a chunk at a time into keys and
// vals (slices of one length), for which keep holds (nil: all). keep gets the
// index of the entry in keys and vals. ok is false when the kernel refuses
// batch lookups (kernels before 5.6, a bucket larger than the chunk): the
// caller walks the keys then.
func batchCount(m *ebpf.Map, keys, vals any, keep func(i int) bool) (total uint64, ok bool) {
	var cursor ebpf.MapBatchCursor
	for {
		n, err := m.BatchLookup(&cursor, keys, vals, nil)
		for i := range n {
			if keep == nil || keep(i) {
				total++
			}
		}
		switch {
		case err == nil && n > 0:
			continue
		case err == nil || errors.Is(err, ebpf.ErrKeyNotExist):
			return total, true
		default:
			return 0, false
		}
	}
}

// liveConnections counts the conntrack entries of flows that are still fresh
// (connectionFresh, as ListConnections). The table keeps the entries of ended
// flows until it needs their room, and evicts those first, so a busy host keeps
// it at capacity: only the fresh flows show how full it is.
func (m *Manager) liveConnections() (uint64, error) {
	now := m.ktimeNow()
	keys, vals := make([]ConnKey, mapCountChunk), make([]ConnVal, mapCountChunk)
	if n, ok := batchCount(m.conntrackMap, keys, vals, func(i int) bool {
		return connectionFresh(keys[i].Proto, vals[i].LastSeenNs, now)
	}); ok {
		return n, nil
	}
	var n uint64
	var key ConnKey
	var val ConnVal
	iter := m.conntrackMap.Iterate()
	for iter.Next(&key, &val) {
		if connectionFresh(key.Proto, val.LastSeenNs, now) {
			n++
		}
	}
	return n, iter.Err()
}

// countByIteration counts the keys one by one. The iterator stops with an
// error when a concurrent change makes it loop.
func countByIteration(m *ebpf.Map) (uint64, error) {
	key := make([]byte, m.KeySize())
	val := make([]byte, m.ValueSize())
	var n uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		n++
	}
	return n, iter.Err()
}

// capacityRef names a sized firewall map and where its full signal comes from.
type capacityRef struct {
	name string
	m    *ebpf.Map
	// slot is the wafio_state_full slot that counts the refused inserts of a
	// detection map; hasSlot says whether it has one.
	slot    uint32
	hasSlot bool
}

// capacityRefs lists the sized firewall maps of the loaded objects.
func (m *Manager) capacityRefs() []capacityRef {
	refs := []capacityRef{
		{name: mapConntrack, m: m.conntrackMap},
		{name: mapSynState, m: m.synStateMap, slot: stateFullSyn, hasSlot: true},
		{name: mapRateState, m: m.rateStateMap, slot: stateFullRate, hasSlot: true},
		{name: mapPortscan, m: m.portscanMap, slot: stateFullPortscan, hasSlot: true},
		{name: mapBandwidth, m: m.bandwidthMap},
		{name: mapGeoIP, m: m.geoipMap},
		{name: mapJail, m: m.jailMap},
	}
	return slices.DeleteFunc(refs, func(r capacityRef) bool { return r.m == nil })
}

// sampleMaps counts the entries of each sized firewall map and notes which
// were full since the last sample. It logs a WARN when a map becomes full, at
// most once per mapFullWarnEvery for each map, and keeps the result for Status.
func (m *Manager) sampleMaps(now time.Time) {
	if len(m.cfg.MapSizes.Entries) == 0 {
		return
	}
	refs := m.capacityRefs()
	out := make([]MapCapacity, 0, len(refs))
	for _, r := range refs {
		c := MapCapacity{Name: r.name, MaxEntries: r.m.MaxEntries(), DefaultMaxEntries: mapDefaultSize(r.name)}
		var n uint64
		var err error
		if r.name == mapConntrack {
			n, err = m.liveConnections()
		} else {
			n, err = m.counter.count(r.m)
		}
		if err == nil {
			c.Entries = &n
		}
		var last time.Time
		var warn bool
		switch {
		case r.name == mapConntrack:
			// Full: the fresh flows need the whole table, so the LRU evicts
			// flows that are still live.
			margin := uint64(mapLRUFreeNodesPerCPU) * uint64(max(m.cfg.MapSizes.CPUs, 1))
			full := c.Entries != nil && *c.Entries+margin >= uint64(c.MaxEntries)
			last, warn = m.fullTrack.note(r.name, now, full)
		case r.m.Type() == ebpf.LRUHash:
			// wafio_bandwidth and wafio_geoip are caches: they fill up and
			// evict by design, and their entries carry no age to tell a live
			// one from an old one. They never count as full.
		case r.hasSlot && m.stateFullMap != nil:
			v := sumPerCPU(m.stateFullMap, r.slot)
			c.FullCount = &v
			last, warn = m.fullTrack.noteCounter(r.name, now, v)
		case r.name == mapJail:
			v := m.jailFull.Load()
			c.FullCount = &v
			last, warn = m.fullTrack.noteCounter(r.name, now, v)
		}
		finishCapacity(m.log, m.cfg.MapSizes, &c, last, warn)
		out = append(out, c)
	}
	m.capMu.Lock()
	m.capSample, m.capAt = out, now
	m.capMu.Unlock()
}

// finishCapacity sets the last-full time of c and logs the WARN of a map that
// just became full.
func finishCapacity(l *log.Logger, sizes MapSizes, c *MapCapacity, last time.Time, warn bool) {
	if !last.IsZero() {
		c.LastFullAt = &last
	}
	if warn {
		l.Printf("WARN: eBPF map %s is full (%d entries). Map scale %.3g (%s): raise WAFIO_EBPF_MAP_SCALE (at most 1) or look for a flood",
			c.Name, c.MaxEntries, sizes.Scale, sizes.Source)
	}
}

// capacityStatus builds a map_sizing from the last sample, or from the sizes
// alone (base) before the first one.
func capacityStatus(sz MapSizes, sample []MapCapacity, at time.Time, base func() []MapCapacity) *MapSizing {
	if len(sz.Entries) == 0 {
		return nil
	}
	out := &MapSizing{Scale: sz.Scale, Source: sz.Source, MemoryBytes: sz.MemoryBytes, MemorySource: sz.MemorySource}
	out.Maps = slices.Clone(sample)
	if !at.IsZero() {
		out.SampledAt = &at
	}
	if out.Maps == nil {
		out.Maps = base()
	}
	return out
}

// mapSizingStatus is the map_sizing of Status, or nil when the maps were not
// sized. Before the first sample it lists the sizes only.
func (m *Manager) mapSizingStatus() *MapSizing {
	m.capMu.Lock()
	defer m.capMu.Unlock()
	return capacityStatus(m.cfg.MapSizes, m.capSample, m.capAt, func() []MapCapacity {
		out := []MapCapacity{}
		for _, r := range m.capacityRefs() {
			out = append(out, MapCapacity{Name: r.name, MaxEntries: r.m.MaxEntries(), DefaultMaxEntries: mapDefaultSize(r.name)})
		}
		return out
	})
}

// traceMapSampleEveryTicks: the trace map sampler runs on every 3rd tick of
// traceLossLoop, every 30 s.
const traceMapSampleEveryTicks = 3

// ringSize is the size of trace_events in bytes: the loaded map's, or the
// size the object declares while nothing is loaded.
func (tm *TraceManager) ringSize() uint64 {
	if tm.eventsMap != nil {
		return uint64(tm.eventsMap.MaxEntries())
	}
	return traceRingMax
}

// sampleMaps is the trace counterpart of Manager.sampleMaps. The ring has no
// entry count; it is full when the kernel could not reserve space in it.
func (tm *TraceManager) sampleMaps(now time.Time) {
	if len(tm.cfg.MapSizes.Entries) == 0 {
		return
	}
	var out []MapCapacity
	if tm.openPendingMap != nil {
		c := MapCapacity{Name: traceMapOpenPending, MaxEntries: tm.openPendingMap.MaxEntries(), DefaultMaxEntries: mapDefaultSize(traceMapOpenPending)}
		if n, err := tm.counter.count(tm.openPendingMap); err == nil {
			c.Entries = &n
		}
		v := sumPerCPU(tm.openStatsMap, traceOpenNoFull)
		c.FullCount = &v
		last, warn := tm.fullTrack.noteCounter(c.Name, now, v)
		finishCapacity(tm.log, tm.cfg.MapSizes, &c, last, warn)
		out = append(out, c)
	}
	if tm.eventsMap != nil {
		c := MapCapacity{Name: traceMapEvents, MaxEntries: tm.eventsMap.MaxEntries(), DefaultMaxEntries: mapDefaultSize(traceMapEvents)}
		v := sumPerCPU(tm.statsMap, 0)
		c.FullCount = &v
		last, warn := tm.fullTrack.noteCounter(c.Name, now, v)
		finishCapacity(tm.log, tm.cfg.MapSizes, &c, last, warn)
		out = append(out, c)
	}
	tm.capMu.Lock()
	tm.capSample, tm.capAt = out, now
	tm.capMu.Unlock()
}

// mapSizingStatus is the map_sizing of Status, or nil when the maps were not
// sized. The caller holds tm.mu.
func (tm *TraceManager) mapSizingStatus() *MapSizing {
	tm.capMu.Lock()
	defer tm.capMu.Unlock()
	return capacityStatus(tm.cfg.MapSizes, tm.capSample, tm.capAt, func() []MapCapacity {
		out := []MapCapacity{}
		if tm.openPendingMap != nil {
			out = append(out, MapCapacity{Name: traceMapOpenPending, MaxEntries: tm.openPendingMap.MaxEntries(), DefaultMaxEntries: mapDefaultSize(traceMapOpenPending)})
		}
		if tm.eventsMap != nil {
			out = append(out, MapCapacity{Name: traceMapEvents, MaxEntries: tm.eventsMap.MaxEntries(), DefaultMaxEntries: mapDefaultSize(traceMapEvents)})
		}
		return out
	})
}
