package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/geo"
)

// GeoIPEnricher periodically scans the eBPF connection table and populates
// the kernel `wafio_geoip` map with (source-IP → ISO country code) entries
// looked up via MaxMind (or any geo.GeoLookup).
//
// This lets the XDP dataplane make per-packet geo-blocking decisions without
// shipping a full MaxMind DB into the kernel. The userspace agent does the
// expensive prefix-tree lookup once per unique source IP, then installs the
// resolved country code in a fast hash map that XDP queries on the hot path.
type GeoIPEnricher struct {
	ebpfMgr  *wafebpf.Manager
	lookup   geo.GeoLookup
	interval time.Duration

	mu   sync.Mutex
	seen map[string]string // ip → country (or "" if negative-cached)
}

// NewGeoIPEnricher builds an enricher. interval <=0 defaults to 10s.
func NewGeoIPEnricher(ebpfMgr *wafebpf.Manager, lookup geo.GeoLookup, interval time.Duration) *GeoIPEnricher {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &GeoIPEnricher{
		ebpfMgr:  ebpfMgr,
		lookup:   lookup,
		interval: interval,
		seen:     make(map[string]string, 1024),
	}
}

// Run blocks until ctx is cancelled, periodically enriching connections.
func (e *GeoIPEnricher) Run(ctx context.Context) {
	if e.ebpfMgr == nil || e.lookup == nil {
		return
	}
	// Run an immediate pass so tests / fresh connections get enriched quickly.
	e.enrichOnce()

	t := time.NewTicker(e.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.enrichOnce()
		}
	}
}

// EnrichIP immediately resolves a single IP and pushes it to the geoip map.
// Safe to call from any goroutine. Caches both positive and negative lookups.
func (e *GeoIPEnricher) EnrichIP(ip string) {
	if ip == "" || e.lookup == nil || e.ebpfMgr == nil {
		return
	}
	e.mu.Lock()
	if _, ok := e.seen[ip]; ok {
		e.mu.Unlock()
		return
	}
	// optimistic mark so concurrent callers don't duplicate work
	e.seen[ip] = ""
	e.mu.Unlock()

	parsed := net.ParseIP(ip)
	if parsed == nil || isPrivateOrBogon(parsed) {
		return
	}
	country, err := e.lookup.Country(ip)
	if err != nil || len(country) != 2 {
		return
	}
	if err := e.ebpfMgr.LoadGeoIPEntry(parsed, country); err != nil {
		// couldn't push — clear cache so we retry on next tick
		e.mu.Lock()
		delete(e.seen, ip)
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	e.seen[ip] = country
	e.mu.Unlock()
}

// HasDataset reports whether a GeoIP country database is loaded, so the
// geo CIDR tries can be filled (allow mode depends on it).
func (e *GeoIPEnricher) HasDataset() bool {
	if e == nil {
		return false
	}
	mm, ok := e.lookup.(*geo.MaxMindLookup)
	return ok && mm != nil
}

// ResolveGeoRanges returns every GeoIP range of the given countries, read
// from the country database: the geo CIDR tries are filled from it, so the
// first packet from a listed country meets the policy without waiting for
// the reactive enricher. Errors: wafebpf.ErrGeoAllowNoDataset without a
// MaxMind-format database, ErrGeoDatasetUnreadable when it cannot be read.
func (e *GeoIPEnricher) ResolveGeoRanges(codes []string) ([]netip.Prefix, error) {
	if len(codes) == 0 {
		return nil, nil
	}
	mm, ok := e.lookup.(*geo.MaxMindLookup)
	if !ok || mm == nil {
		return nil, wafebpf.ErrGeoAllowNoDataset
	}
	var prefixes []netip.Prefix
	if err := mm.ForEachCountryCIDR(codes, func(network *net.IPNet) {
		if p, ok := wafebpf.GeoPrefixFromIPNet(network); ok {
			prefixes = append(prefixes, p)
		}
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGeoDatasetUnreadable, err)
	}
	return prefixes, nil
}

func (e *GeoIPEnricher) enrichOnce() {
	if !e.ebpfMgr.IsRunning() {
		return
	}
	// The attached interface's subnets change with DHCP; allow mode admits
	// a private UDP source only from them. A read error keeps the table.
	if e.ebpfMgr.GeoState().Mode == wafebpf.GeoModeAllow {
		subnets := attachedSubnetsOf(e.ebpfMgr)
		if err := refreshGeoSubnets(e.ebpfMgr, subnets); err != nil {
			log.Printf("geoip enricher: attached interface subnets not refreshed: %v", err)
		}
	}
	conns, err := e.ebpfMgr.ListConnections(2000)
	if err != nil {
		return
	}
	var added int
	for _, c := range conns {
		before := e.cacheHit(c.SrcIP)
		e.EnrichIP(c.SrcIP)
		if !before && e.cacheCountry(c.SrcIP) != "" {
			added++
		}
	}
	if added > 0 {
		log.Printf("geoip enricher: pushed %d new IP→country entries to eBPF map", added)
	}
}

func (e *GeoIPEnricher) cacheHit(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.seen[ip]
	return ok
}

func (e *GeoIPEnricher) cacheCountry(ip string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.seen[ip]
}

// isPrivateOrBogon skips RFC1918, loopback, link-local, multicast, etc.
// MaxMind doesn't map these, and inserting them just wastes map slots.
func isPrivateOrBogon(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1]&0xf0 == 16 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 100.64.0.0/10 (CGNAT)
		if ip4[0] == 100 && ip4[1]&0xc0 == 64 {
			return true
		}
	}
	return false
}
