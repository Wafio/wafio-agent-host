// Package ebpf provides an enterprise-grade eBPF dataplane for the Wafio WAF.
//
// It manages XDP (fast-path) and TC (slow-path) BPF programs that do
// wire-speed packet filtering, rate limiting, SYN-flood protection,
// geo-blocking, connection tracking, port-scan detection, and more.
//
// All types in this file are platform-independent so they can be imported
// by API handlers and UI code on any OS.

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
//  BPF map key / value types  (must match C structs in wafio_common.h)
// ────────────────────────────────────────────────────────────────────────────

// IPKey mirrors struct ip_key (20 bytes, packed).
type IPKey struct {
	Family uint8    // AF_INET=2, AF_INET6=10
	Pad    [3]uint8 //
	Addr   [16]byte // v4 in first 4 bytes, v6 in all 16
}

// IPKeyFromIP creates an IPKey from a net.IP.
func IPKeyFromIP(ip net.IP) IPKey {
	var k IPKey
	if v4 := ip.To4(); v4 != nil {
		k.Family = 2 // AF_INET
		copy(k.Addr[:4], v4)
	} else if v6 := ip.To16(); v6 != nil {
		k.Family = 10 // AF_INET6
		copy(k.Addr[:], v6)
	}
	return k
}

// IPKeyWildcard returns distinct sentinel keys for IPv4 and IPv6 /0 rules.
func IPKeyWildcard(cidr string) IPKey {
	if cidr == "::/0" {
		return IPKey{Family: 0xFE}
	}
	return IPKey{Family: 0xFD}
}

// IsWildcard reports whether the key is the "match all" sentinel.
func (k IPKey) IsWildcard() bool { return k.Family == 0xFD || k.Family == 0xFE }

// HostFirewallEnv is what the lockout guard needs from the running host.
type HostFirewallEnv struct {
	SSHPorts         []uint16 // detected SSH listeners; empty = 22 assumed
	ControlPlanePort uint16   // port of the configured control plane; 0 = 9090
	Exemptions       bool     // attached objects carry the reply and control-plane exemptions
	// ControlPlaneUnpinned: a control plane is configured but the dataplane
	// holds no endpoint for it yet, so reaching it may need DNS.
	ControlPlaneUnpinned bool
}

// maxCPEndpoints mirrors MAX_CP_ENDPOINTS in wafio_common.h.
const maxCPEndpoints = 16

// CPEndpointKey mirrors struct cp_endpoint_key (24 bytes, packed): one
// control-plane address:port the dataplane never cuts.
type CPEndpointKey struct {
	IP    IPKey
	Port  uint16 // network byte order in memory
	Proto uint8  // IPPROTO_TCP
	Pad   uint8
}

// CPEndpointKeyFrom builds the key for a TCP control-plane endpoint.
func CPEndpointKeyFrom(ap netip.AddrPort) CPEndpointKey {
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], ap.Port())
	return CPEndpointKey{
		IP:    IPKeyFromIP(net.IP(ap.Addr().Unmap().AsSlice())),
		Port:  binary.NativeEndian.Uint16(port[:]),
		Proto: 6,
	}
}

// ToIP converts an IPKey back to net.IP.
func (k IPKey) ToIP() net.IP {
	if k.Family == 2 {
		return net.IP(append([]byte{}, k.Addr[:4]...))
	}
	return net.IP(append([]byte{}, k.Addr[:16]...))
}

// IPListVal mirrors struct ip_list_val (24 bytes).
type IPListVal struct {
	AddedNs   uint64
	ExpiresNs uint64
	RuleType  uint32
	HitCount  uint32
}

// SubnetV4Key mirrors struct subnet_v4_key for BPF_MAP_TYPE_LPM_TRIE (8 bytes).
type SubnetV4Key struct {
	PrefixLen uint32
	Addr      [4]byte
}

// SubnetV6Key mirrors struct subnet_v6_key for BPF_MAP_TYPE_LPM_TRIE (20 bytes).
type SubnetV6Key struct {
	PrefixLen uint32
	Addr      [16]byte
}

// SubnetVal mirrors struct subnet_val (24 bytes).
type SubnetVal struct {
	AddedNs   uint64
	ExpiresNs uint64
	RuleType  uint32
	HitCount  uint32
}

// AllowScope mirrors struct allow_scope (6 bytes): one port range of a
// port-scoped allowlist entry (host order; Proto 0 = TCP and UDP).
type AllowScope struct {
	Lo    uint16
	Hi    uint16
	Proto uint8
	Pad   uint8
}

// AllowVal mirrors struct allow_val (88 bytes), the value of wafio_allow4 /
// wafio_allow6. An entry without ports is written with Flags =
// AllowFlagAll, NScopes = 0; a port-scoped one with Flags = 0 and its
// scopes (allowValScopes).
type AllowVal struct {
	AddedNs   uint64
	ExpiresNs uint64
	HitCount  uint64
	Flags     uint32
	NScopes   uint32
	PrefixLen uint32
	Scopes    [allowMaxScopes]AllowScope
	Pad       uint32
}

// BlockVal mirrors struct block_val (40 bytes), the value of wafio_block4 /
// wafio_block6.
type BlockVal struct {
	AddedNs   uint64
	ExpiresNs uint64
	HitCount  uint64
	Flags     uint32
	NScopes   uint32
	PrefixLen uint32
	Pad       uint32
}

// SubnetEntry represents a decoded CIDR rule for API/UI reporting.
type SubnetEntry struct {
	CIDR      string     `json:"cidr"`
	RuleType  string     `json:"rule_type"` // "block" or "allow"
	AddedAt   time.Time  `json:"added_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	HitCount  uint32     `json:"hit_count"`
}

// ParseCIDR parses an IPv4 or IPv6 CIDR (or bare IP) into SubnetV4Key or SubnetV6Key.
// If a bare IP is provided (without '/'), it assumes /32 for IPv4 and /128 for IPv6.
func ParseCIDR(cidrStr string) (isV6 bool, v4Key SubnetV4Key, v6Key SubnetV6Key, err error) {
	cidrStr = strings.TrimSpace(cidrStr)
	if !strings.Contains(cidrStr, "/") {
		ip := net.ParseIP(cidrStr)
		if ip == nil {
			return false, v4Key, v6Key, fmt.Errorf("invalid CIDR or IP address: %s", cidrStr)
		}
		if ip.To4() != nil {
			cidrStr += "/32"
		} else {
			cidrStr += "/128"
		}
	}

	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false, v4Key, v6Key, fmt.Errorf("parse CIDR %q: %w", cidrStr, err)
	}

	ones, _ := ipNet.Mask.Size()
	if v4 := ip.To4(); v4 != nil {
		v4Key.PrefixLen = u32FromInt(ones)
		copy(v4Key.Addr[:], ipNet.IP.To4())
		return false, v4Key, v6Key, nil
	}

	v6 := ip.To16()
	if v6 == nil {
		return false, v4Key, v6Key, fmt.Errorf("invalid IP address in CIDR: %s", cidrStr)
	}
	v6Key.PrefixLen = u32FromInt(ones)
	copy(v6Key.Addr[:], ipNet.IP.To16())
	return true, v4Key, v6Key, nil
}

// RateState mirrors struct rate_state (40 bytes).
type RateState struct {
	WindowStartNs uint64
	PktCount      uint64
	ByteCount     uint64
	SynCount      uint32
	Action        uint32
	Lock          uint32
	Pad           uint32
}

// RateConfig mirrors struct rate_config (40 bytes: 8 + 7×u32 + 4B tail pad
// from the __u64 alignment requirement).
type RateConfig struct {
	WindowNs       uint64
	MaxPPS         uint32
	MaxBPS         uint32
	MaxSynPPS      uint32
	BurstPPS       uint32
	BurstSyn       uint32
	Action         uint32
	SynPressurePPS uint32 // global SYN rate enabling pressure mode; 0 = off
	Pad            uint32
}

// ConnKey mirrors struct conn_key (48 bytes, packed).
type ConnKey struct {
	Src   IPKey
	Dst   IPKey
	Sport uint16 // network byte-order (big-endian)
	Dport uint16
	Proto uint8
	Pad   [3]uint8
}

// ConnVal mirrors struct conn_val (40 bytes).
type ConnVal struct {
	FirstSeenNs uint64
	LastSeenNs  uint64
	Packets     uint64
	Bytes       uint64
	TCPState    uint32 // 0=new, 1=established, 2=fin, 3=rst
	FlagsSeen   uint32
}

// ConnVal.FlagsSeen marks above the TCP flag bits (wafio_common.h).
const (
	ConnOutbound uint32 = 1 << 31 // CONN_OUTBOUND: TC entry of a flow this host opened
	ConnReply    uint32 = 1 << 30 // CONN_REPLY: XDP entry of the remote side of such a flow
	ConnVerified uint32 = 1 << 29 // CONN_VERIFIED: XDP entry TC confirmed as an inbound connection
	// ConnHostAcked: CONN_HOST_ACKED, the host sent a segment without SYN or
	// RST on the inbound connection (the rate-limit exemption).
	ConnHostAcked uint32 = 1 << 28
)

// SynState mirrors struct syn_state (48 bytes).
type SynState struct {
	WindowStartNs uint64
	SynCount      uint64
	SynAckCount   uint64
	AckCount      uint64
	DropCount     uint64
	Lock          uint32
	Pad           uint32
}

// PerfEventData mirrors struct perf_event_data (64 bytes, packed).
type PerfEventData struct {
	TimestampNs uint64
	SrcIP       IPKey
	DstIP       IPKey
	SrcPort     uint16 // big-endian from kernel
	DstPort     uint16 // big-endian from kernel
	Proto       uint8
	Action      uint8
	Reason      uint8
	TCPFlags    uint8
	PktLen      uint32
	RuleID      uint32
}

// GlobalConfig mirrors struct global_config (36 bytes).
type GlobalConfig struct {
	Enabled         uint32
	Mode            uint32 // 0=enforce, 1=monitor-only
	LogAllowed      uint32
	LogBlocked      uint32
	EnableConntrack uint32
	EnableSynflood  uint32
	EnableRatelimit uint32
	EnableGeoblock  uint32
	MaxPayloadBytes uint32
}

// MetricsVal mirrors struct metrics_val (160 bytes, 20×uint64).
type MetricsVal struct {
	RxPackets           uint64
	RxBytes             uint64
	TxPackets           uint64
	TxBytes             uint64
	DroppedPackets      uint64
	DroppedBytes        uint64
	RatelimitedPackets  uint64
	SynfloodDrops       uint64
	BlocklistDrops      uint64
	AllowlistPasses     uint64
	GeoblockDrops       uint64
	ConntrackEntries    uint64
	PortScanDrops       uint64
	PortPolicyDrops     uint64
	EgressIPDrops       uint64
	WouldDropPackets    uint64
	WouldDropBytes      uint64
	StateTableFull      uint64
	PacketParseFailures uint64
	SynPressureDrops    uint64
}

// GeoVal mirrors struct geo_val (4 bytes).
type GeoVal struct {
	CountryCode uint16
	Action      uint8
	Pad         uint8
}

// GeoConfig mirrors struct geo_config in wafio_xdp.c (16 bytes): the geo
// mode (geoModeBlockValue / geoModeAllowValue) and, in allow mode, the
// bpf_ktime_get_ns() at which it went live (connections first seen before
// it stay exempt).
type GeoConfig struct {
	Mode         uint32
	Pad          uint32
	AllowSinceNs uint64
}

// GeoCountryVal mirrors struct geo_country_val (4 bytes).
type GeoCountryVal struct {
	Blocked uint8
	Pad     [3]uint8
}

// BwState mirrors struct bw_state from wafio_tc.c (40 bytes).
type BwState struct {
	WindowStartNs  uint64
	IngressBytes   uint64
	EgressBytes    uint64
	IngressPackets uint64
	EgressPackets  uint64
}

// AnomalyConfig mirrors struct anomaly_config from wafio_tc.c (16 bytes).
type AnomalyConfig struct {
	DetectXmas    uint32
	DetectNull    uint32
	DetectFinOnly uint32
	Action        uint32
}

// PortScanConfig mirrors the portscan config struct in XDP (8 bytes).
type PortScanConfig struct {
	WindowNs       uint64
	MaxUniquePorts uint32
	Action         uint32 // 1=DROP 2=LOG
}

// ToAPI converts a BPF PortScanConfig to the API representation.
func (p *PortScanConfig) ToAPI() PortScanConfigAPI {
	return PortScanConfigAPI{
		Enabled:        p.MaxUniquePorts > 0,
		WindowMs:       p.WindowNs / 1_000_000,
		MaxUniquePorts: p.MaxUniquePorts,
		DropOnDetect:   p.Action == 1, // ACTION_DROP
	}
}

// FromAPI populates a BPF PortScanConfig from the API representation.
func (p *PortScanConfig) FromAPI(a PortScanConfigAPI) {
	if !a.Enabled {
		p.MaxUniquePorts = 0
		p.WindowNs = 0
		p.Action = 0
		return
	}
	p.WindowNs = a.WindowMs * 1_000_000
	p.MaxUniquePorts = a.MaxUniquePorts
	if a.DropOnDetect {
		p.Action = 1 // ACTION_DROP
	} else {
		p.Action = 2 // ACTION_LOG
	}
}

// ────────────────────────────────────────────────────────────────────────────
//  Port policy types (enterprise ingress/egress port firewall)
// ────────────────────────────────────────────────────────────────────────────

// Port direction constants (match C defines PORT_DIR_*)
const (
	PortDirIngress uint8 = 0
	PortDirEgress  uint8 = 1
	PortDirBoth    uint8 = 2
)

// PortPolicyKey mirrors struct port_policy_key (4 bytes, packed).
type PortPolicyKey struct {
	Port      uint16
	Proto     uint8
	Direction uint8
}

// PortPolicyVal mirrors struct port_policy_val (32 bytes with C alignment padding).
type PortPolicyVal struct {
	Action    uint32
	Pad_      uint32 // C compiler aligns next uint64 to 8-byte boundary
	HitCount  uint64
	AddedNs   uint64
	ExpiresNs uint64
}

// ────────────────────────────────────────────────────────────────────────────
//  Event-reason constants (match EVENT_REASON_* in wafio_common.h)
// ────────────────────────────────────────────────────────────────────────────

const (
	EventReasonBlocklist    uint8 = 1
	EventReasonRateLimitPPS uint8 = 2
	EventReasonRateLimitBPS uint8 = 3
	EventReasonSynflood     uint8 = 4
	EventReasonConntrack    uint8 = 5
	EventReasonGeoblock     uint8 = 6
	EventReasonPortScan     uint8 = 7
	EventReasonAllowlist    uint8 = 8
	EventReasonHTTPPattern  uint8 = 9
	EventReasonPayloadSize  uint8 = 10
	EventReasonPortPolicy   uint8 = 11
	EventReasonEgressIP     uint8 = 12
)

// ────────────────────────────────────────────────────────────────────────────
//  XDP attach modes
// ────────────────────────────────────────────────────────────────────────────

// XDPAttachMode controls how the XDP program is attached to the NIC.
type XDPAttachMode int

const (
	XDPModeAuto   XDPAttachMode = 0 // let kernel pick best mode
	XDPModeSKB    XDPAttachMode = 1 // generic / SKB (works everywhere)
	XDPModeDriver XDPAttachMode = 2 // native / driver (fast)
	XDPModeHW     XDPAttachMode = 3 // offloaded to NIC hardware
)

func (m XDPAttachMode) String() string {
	switch m {
	case XDPModeSKB:
		return "skb"
	case XDPModeDriver:
		return "driver"
	case XDPModeHW:
		return "hw"
	default:
		return "auto"
	}
}

// ────────────────────────────────────────────────────────────────────────────
//  High-level API types (JSON-friendly for HTTP handlers & UI)
// ────────────────────────────────────────────────────────────────────────────

// ManagerConfig holds startup configuration for the eBPF manager.
type ManagerConfig struct {
	Interface       string        `json:"interface" yaml:"interface"`             // e.g. "eth0"
	XDPObjectPath   string        `json:"xdp_object_path" yaml:"xdp_object_path"` // path to wafio_xdp.o
	TCObjectPath    string        `json:"tc_object_path" yaml:"tc_object_path"`   // path to wafio_tc.o
	PinPath         string        `json:"pin_path" yaml:"pin_path"`               // bpffs mount (default /sys/fs/bpf/wafio)
	XDPMode         XDPAttachMode `json:"xdp_mode" yaml:"xdp_mode"`
	EventBufferSize int           `json:"event_buffer_size" yaml:"event_buffer_size"` // perf ring pages (default 128)
	EventChanSize   int           `json:"event_chan_size" yaml:"event_chan_size"`     // Go channel buffer (default 4096)
	MetricsPollMs   int           `json:"metrics_poll_ms" yaml:"metrics_poll_ms"`     // metrics polling interval (default 1000)
}

// Status reports the runtime state of the eBPF subsystem.
type Status struct {
	PerfLostSamples     uint64                `json:"perf_lost_samples"`
	DecodeFailures      uint64                `json:"decode_failures"`
	QueueDropped        uint64                `json:"queue_dropped"`
	QueueDepth          int                   `json:"queue_depth"`
	EgressIPv6Supported bool                  `json:"egress_ipv6_supported"`
	CoverageWarnings    []string              `json:"coverage_warnings"`
	Running             bool                  `json:"running"`
	Interface           string                `json:"interface,omitempty"`
	InterfaceIdx        int                   `json:"interface_idx,omitempty"`
	XDPAttached         bool                  `json:"xdp_attached"`
	TCIngress           bool                  `json:"tc_ingress_attached"`
	TCEgress            bool                  `json:"tc_egress_attached"`
	XDPMode             string                `json:"xdp_mode,omitempty"`
	StartedAt           time.Time             `json:"started_at,omitempty"`
	UptimeSeconds       float64               `json:"uptime_seconds,omitempty"`
	PinPath             string                `json:"pin_path,omitempty"`
	KernelVersion       string                `json:"kernel_version,omitempty"`
	Config              *FullConfigAPI        `json:"config,omitempty"`
	PortPolicies        *PortPoliciesSnapshot `json:"port_policies,omitempty"`

	// LockoutExemptions: the attached XDP and TC objects carry the
	// reply and control-plane exemptions. Without them the agent
	// refuses egress Deny All and 0.0.0.0/0 or ::/0 blocklist entries.
	LockoutExemptions bool `json:"lockout_exemptions"`

	// Jail lists addresses the WAF agent jailed at XDP, latest expiry
	// first, at most 100; JailCount counts every live one. Read-only: a jail
	// lives in its own map, outside the desired state, until its TTL ends.
	Jail      []BlocklistEntry `json:"jail,omitempty"`
	JailCount int              `json:"jail_count"`

	// GeoAllowSupported: the XDP object can enforce geo allow mode
	// (wafio_geo_config). GeoMode is the live mode ("block"/"allow"), and
	// GeoRangesV4/V6 count the ranges the last geo apply loaded.
	GeoAllowSupported bool   `json:"geo_allow_supported"`
	GeoMode           string `json:"geo_mode,omitempty"`
	GeoRangesV4       int    `json:"geo_ranges_v4"`
	GeoRangesV6       int    `json:"geo_ranges_v6"`
	// AllowlistPortsSupported: the XDP object matches allowlist port scopes
	// (wafio_allow_scopes). AllowlistScopedSkipped counts the port-scoped
	// entries of the last applied desired state this agent did not write
	// because its object cannot enforce them (they are never written as
	// entries that allow every port).
	AllowlistPortsSupported bool `json:"allowlist_ports_supported"`
	AllowlistScopedSkipped  int  `json:"allowlist_scoped_skipped"`
	// GeoDegradedCode / GeoDegradedMessage: the desired geo policy is not
	// enforced (GEO_ALLOW_UNSUPPORTED, GEO_ALLOW_NO_DATASET, ...); the
	// previous geo state stays and every other rule was applied.
	GeoDegradedCode string `json:"geo_degraded_code,omitempty"`
	// GeoDegradedState: kept (the previous geo state is enforced),
	// ranges_cleared (block mode without the country ranges) or mixed (a
	// failed write could not be rolled back).
	GeoDegradedState   string `json:"geo_degraded_state,omitempty"`
	GeoDegradedMessage string `json:"geo_degraded_message,omitempty"`
}

// PortPoliciesSnapshot is the full port policy state included in status pushes.
type PortPoliciesSnapshot struct {
	Config   PortPolicyConfigAPI `json:"config"`
	Policies []PortPolicyAPI     `json:"policies"`
	Count    int                 `json:"count"`
}

// Metrics is the aggregated (summed across all CPUs) metrics snapshot.
type Metrics struct {
	RxPackets          uint64 `json:"rx_packets"`
	RxBytes            uint64 `json:"rx_bytes"`
	TxPackets          uint64 `json:"tx_packets"`
	TxBytes            uint64 `json:"tx_bytes"`
	DroppedPackets     uint64 `json:"dropped_packets"`
	DroppedBytes       uint64 `json:"dropped_bytes"`
	RatelimitedPackets uint64 `json:"ratelimited_packets"`
	SynfloodDrops      uint64 `json:"synflood_drops"`
	BlocklistDrops     uint64 `json:"blocklist_drops"`
	AllowlistPasses    uint64 `json:"allowlist_passes"`
	GeoblockDrops      uint64 `json:"geoblock_drops"`
	// ConntrackEntries counts connection-tracking entries created since the
	// programs loaded (XDP and TC, IPv4 and IPv6), not the live table size;
	// it used to count IPv4 packets.
	ConntrackEntries uint64 `json:"conntrack_entries"`
	PortScanDrops    uint64 `json:"port_scan_drops"`
	PortPolicyDrops  uint64 `json:"port_policy_drops"`
	EgressIPDrops    uint64 `json:"egress_ip_drops"`
	// Calculated rates
	PPS      float64 `json:"pps"`
	BPS      float64 `json:"bps"`
	DropRate float64 `json:"drop_rate_pct"`
	// Snapshot time
	Timestamp           time.Time `json:"timestamp"`
	WouldDropPackets    uint64    `json:"would_drop_packets"`
	WouldDropBytes      uint64    `json:"would_drop_bytes"`
	StateTableFull      uint64    `json:"state_table_full"`
	PacketParseFailures uint64    `json:"packet_parse_failures"`
	SynPressureDrops    uint64    `json:"syn_pressure_drops"`
}

// Event is a decoded perf event for API consumers.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Proto     string    `json:"proto"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
	TCPFlags  string    `json:"tcp_flags,omitempty"`
	PktLen    uint32    `json:"pkt_len"`
	RuleID    uint32    `json:"rule_id,omitempty"`
	// GeoMode names the geo mode that dropped a geoblock event ("block" or
	// "allow"; empty for other reasons and objects older than allow mode).
	GeoMode string `json:"geo_mode,omitempty"`
}

// Connection is a decoded conntrack table entry.
type Connection struct {
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Proto     string    `json:"proto"`
	State     string    `json:"state"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Packets   uint64    `json:"packets"`
	Bytes     uint64    `json:"bytes"`
}

// BandwidthEntry is a decoded bandwidth accounting entry (TC).
type BandwidthEntry struct {
	IP             string  `json:"ip"`
	IngressBytes   uint64  `json:"ingress_bytes"`
	EgressBytes    uint64  `json:"egress_bytes"`
	IngressPackets uint64  `json:"ingress_packets"`
	EgressPackets  uint64  `json:"egress_packets"`
	IngressBPS     float64 `json:"ingress_bps"`
	EgressBPS      float64 `json:"egress_bps"`
}

// ────────────────────────────────────────────────────────────────────────────
//  Conversion helpers
// ────────────────────────────────────────────────────────────────────────────

// PackCountry packs a 2-char ISO country code into a uint16.
func PackCountry(c0, c1 byte) uint16 {
	return uint16(c0)<<8 | uint16(c1)
}

// UnpackCountry unpacks a uint16 into a 2-char ISO country code.
func UnpackCountry(code uint16) string {
	return string([]byte{byte(code >> 8), byte(code & 0xff)})
}

func boolToU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func u32ToBool(v uint32) bool {
	return v != 0
}

// ToAPI converts a BPF GlobalConfig to the API representation.
func (g *GlobalConfig) ToAPI() GlobalConfigAPI {
	return GlobalConfigAPI{
		Enabled:         u32ToBool(g.Enabled),
		MonitorOnly:     u32ToBool(g.Mode),
		LogAllowed:      u32ToBool(g.LogAllowed),
		LogBlocked:      u32ToBool(g.LogBlocked),
		EnableConntrack: u32ToBool(g.EnableConntrack),
		EnableSynflood:  u32ToBool(g.EnableSynflood),
		EnableRatelimit: u32ToBool(g.EnableRatelimit),
		EnableGeoblock:  u32ToBool(g.EnableGeoblock),
		MaxPayloadBytes: g.MaxPayloadBytes,
	}
}

// FromAPI populates a BPF GlobalConfig from the API representation.
func (g *GlobalConfig) FromAPI(a GlobalConfigAPI) {
	g.Enabled = boolToU32(a.Enabled)
	g.Mode = boolToU32(a.MonitorOnly)
	g.LogAllowed = boolToU32(a.LogAllowed)
	g.LogBlocked = boolToU32(a.LogBlocked)
	g.EnableConntrack = boolToU32(a.EnableConntrack)
	g.EnableSynflood = boolToU32(a.EnableSynflood)
	g.EnableRatelimit = boolToU32(a.EnableRatelimit)
	g.EnableGeoblock = boolToU32(a.EnableGeoblock)
	g.MaxPayloadBytes = a.MaxPayloadBytes
}

// ToAPI converts a BPF RateConfig to the API representation.
func (r *RateConfig) ToAPI() RateConfigAPI {
	return RateConfigAPI{
		WindowMs:       r.WindowNs / 1_000_000, // ns → ms
		MaxPPS:         r.MaxPPS,
		MaxBPS:         r.MaxBPS,
		MaxSynPPS:      r.MaxSynPPS,
		BurstPPS:       r.BurstPPS,
		BurstSyn:       r.BurstSyn,
		DropOnLimit:    r.Action == 1, // ACTION_DROP
		SynPressurePPS: r.SynPressurePPS,
	}
}

// FromAPI populates a BPF RateConfig from the API representation.
func (r *RateConfig) FromAPI(a RateConfigAPI) {
	r.WindowNs = a.WindowMs * 1_000_000 // ms → ns
	r.MaxPPS = a.MaxPPS
	r.MaxBPS = a.MaxBPS
	r.MaxSynPPS = a.MaxSynPPS
	r.BurstPPS = a.BurstPPS
	r.BurstSyn = a.BurstSyn
	r.SynPressurePPS = a.SynPressurePPS
	if a.DropOnLimit {
		r.Action = 1 // ACTION_DROP
	} else {
		r.Action = 2 // ACTION_LOG
	}
}

// ToAPI converts a BPF AnomalyConfig to the API representation.
func (a *AnomalyConfig) ToAPI() AnomalyConfigAPI {
	return AnomalyConfigAPI{
		DetectXmas:    u32ToBool(a.DetectXmas),
		DetectNull:    u32ToBool(a.DetectNull),
		DetectFinOnly: u32ToBool(a.DetectFinOnly),
		DropOnDetect:  a.Action == 1, // ACTION_DROP
	}
}

// FromAPI populates a BPF AnomalyConfig from the API representation.
func (a *AnomalyConfig) FromAPI(api AnomalyConfigAPI) {
	a.DetectXmas = boolToU32(api.DetectXmas)
	a.DetectNull = boolToU32(api.DetectNull)
	a.DetectFinOnly = boolToU32(api.DetectFinOnly)
	if api.DropOnDetect {
		a.Action = 1 // ACTION_DROP
	} else {
		a.Action = 2 // ACTION_LOG
	}
}

// ────────────────────────────────────────────────────────────────────────────
//  Perf-event parsing helper
// ────────────────────────────────────────────────────────────────────────────

// ParsePerfEvent decodes raw perf ring bytes into a PerfEventData.
// The raw data is 64 bytes in native (little-endian) byte order,
// except src_port/dst_port which are big-endian (network order).
func ParsePerfEvent(raw []byte) (PerfEventData, error) {
	if len(raw) < 64 {
		return PerfEventData{}, fmt.Errorf("perf event too short: %d < 64", len(raw))
	}
	var ev PerfEventData
	le := binary.LittleEndian
	be := binary.BigEndian

	ev.TimestampNs = le.Uint64(raw[0:8])

	// src_ip (20 bytes at offset 8)
	ev.SrcIP.Family = raw[8]
	copy(ev.SrcIP.Pad[:], raw[9:12])
	copy(ev.SrcIP.Addr[:], raw[12:28])

	// dst_ip (20 bytes at offset 28)
	ev.DstIP.Family = raw[28]
	copy(ev.DstIP.Pad[:], raw[29:32])
	copy(ev.DstIP.Addr[:], raw[32:48])

	ev.SrcPort = be.Uint16(raw[48:50]) // network byte order
	ev.DstPort = be.Uint16(raw[50:52])
	ev.Proto = raw[52]
	ev.Action = raw[53]
	ev.Reason = raw[54]
	ev.TCPFlags = raw[55]
	ev.PktLen = le.Uint32(raw[56:60])
	ev.RuleID = le.Uint32(raw[60:64])
	return ev, nil
}

// ToEvent converts raw PerfEventData to a user-friendly Event.
func (ev *PerfEventData) ToEvent() Event {
	e := Event{
		Timestamp: time.Unix(0, i64FromU64(ev.TimestampNs)),
		SrcIP:     ev.SrcIP.ToIP().String(),
		DstIP:     ev.DstIP.ToIP().String(),
		SrcPort:   ev.SrcPort,
		DstPort:   ev.DstPort,
		Proto:     protoString(ev.Proto),
		Action:    actionString(ev.Action),
		Reason:    eventReasonString(ev.Reason),
		PktLen:    ev.PktLen,
		RuleID:    ev.RuleID,
	}
	if ev.Proto == 6 { // TCP
		e.TCPFlags = tcpFlagsString(ev.TCPFlags)
	}
	if ev.Reason == EventReasonGeoblock {
		switch ev.RuleID {
		case GeoEventRuleBlockMode:
			e.GeoMode = GeoModeBlock
		case GeoEventRuleAllowMode:
			e.GeoMode = GeoModeAllow
		}
	}
	return e
}

// ── string helpers ──

func eventReasonString(r uint8) string {
	switch r {
	case EventReasonBlocklist:
		return "blocklist"
	case EventReasonRateLimitPPS:
		return "ratelimit_pps"
	case EventReasonRateLimitBPS:
		return "ratelimit_bps"
	case EventReasonSynflood:
		return "synflood"
	case EventReasonConntrack:
		return "conntrack"
	case EventReasonGeoblock:
		return "geoblock"
	case EventReasonPortScan:
		return "port_scan"
	case EventReasonAllowlist:
		return "allowlist"
	case EventReasonHTTPPattern:
		return "http_pattern"
	case EventReasonPayloadSize:
		return "payload_size"
	case EventReasonPortPolicy:
		return "port_policy"
	case EventReasonEgressIP:
		return "egress_ip"
	case 13:
		return "packet_parse"
	default:
		return fmt.Sprintf("unknown_%d", r)
	}
}

func actionString(a uint8) string {
	switch a {
	case 4:
		return "would_drop"
	case 0:
		return "allow"
	case 1:
		return "drop"
	case 2:
		return "log"
	case 3:
		return "ratelimit"
	default:
		return fmt.Sprintf("unknown_%d", a)
	}
}

func protoString(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("proto_%d", p)
	}
}

func tcpFlagsString(flags uint8) string {
	var parts []string
	if flags&0x01 != 0 {
		parts = append(parts, "FIN")
	}
	if flags&0x02 != 0 {
		parts = append(parts, "SYN")
	}
	if flags&0x04 != 0 {
		parts = append(parts, "RST")
	}
	if flags&0x08 != 0 {
		parts = append(parts, "PSH")
	}
	if flags&0x10 != 0 {
		parts = append(parts, "ACK")
	}
	if flags&0x20 != 0 {
		parts = append(parts, "URG")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "|")
}

func tcpStateString(s uint32) string {
	switch s {
	case 0:
		return "new"
	case 1:
		return "established"
	case 2:
		return "fin"
	case 3:
		return "rst"
	default:
		return fmt.Sprintf("state_%d", s)
	}
}
