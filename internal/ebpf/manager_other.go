//go:build !linux

package ebpf

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"
)

// Manager stub for non-Linux platforms. All operations return ErrNotSupported.
type Manager struct{}

var ErrNotSupported = fmt.Errorf("eBPF is only supported on Linux")

func NewManager(_ ManagerConfig, _ *log.Logger) *Manager { return &Manager{} }

func (m *Manager) Start(_ context.Context) error                  { return ErrNotSupported }
func (m *Manager) Stop() error                                    { return nil }
func (m *Manager) IsRunning() bool                                { return false }
func (m *Manager) Status() Status                                 { return Status{} }
func (m *Manager) Events() <-chan Event                           { return make(chan Event) }
func (m *Manager) ReadMetrics() (*Metrics, error)                 { return nil, ErrNotSupported }
func (m *Manager) GetGlobalConfig() (*GlobalConfigAPI, error)     { return nil, ErrNotSupported }
func (m *Manager) UpdateGlobalConfig(_ GlobalConfigAPI) error     { return ErrNotSupported }
func (m *Manager) GetRateConfig() (*RateConfigAPI, error)         { return nil, ErrNotSupported }
func (m *Manager) UpdateRateConfig(_ RateConfigAPI) error         { return ErrNotSupported }
func (m *Manager) GetAnomalyConfig() (*AnomalyConfigAPI, error)   { return nil, ErrNotSupported }
func (m *Manager) UpdateAnomalyConfig(_ AnomalyConfigAPI) error   { return ErrNotSupported }
func (m *Manager) GetFullConfig() (*FullConfigAPI, error)         { return nil, ErrNotSupported }
func (m *Manager) UpdateFullConfig(_ FullConfigAPI) error         { return ErrNotSupported }
func (m *Manager) AddToBlocklist(_ string, _ time.Duration) error { return ErrNotSupported }
func (m *Manager) RemoveFromBlocklist(_ string) error             { return ErrNotSupported }
func (m *Manager) ListBlocklist(_ int) ([]BlocklistEntry, error)  { return nil, ErrNotSupported }
func (m *Manager) AddToAllowlistPorts(_ string, _ time.Duration, _ []PortScope) error {
	return ErrNotSupported
}
func (m *Manager) AllowlistPortsSupported() bool                 { return false }
func (m *Manager) SetAllowlistScopedSkipped(_ int)               {}
func (m *Manager) RemoveFromAllowlist(_ string) error            { return ErrNotSupported }
func (m *Manager) ListAllowlist(_ int) ([]AllowlistEntry, error) { return nil, ErrNotSupported }
func (m *Manager) AddToJail(_ string, _ time.Duration) error     { return ErrNotSupported }
func (m *Manager) BlockCountry(_ string) error                   { return ErrNotSupported }
func (m *Manager) UnblockCountry(_ string) error                 { return ErrNotSupported }
func (m *Manager) ListBlockedCountries() ([]string, error)       { return nil, ErrNotSupported }
func (m *Manager) ListConnections(_ int) ([]Connection, error)   { return nil, ErrNotSupported }
func (m *Manager) ListBandwidth(_ int) ([]BandwidthEntry, error) { return nil, ErrNotSupported }
func (m *Manager) DrainRecentEvents(_ int) []Event               { return nil }
func (m *Manager) PendingEvents() int                            { return 0 }
func (m *Manager) GetRecentEvents(_ int) []Event                 { return nil }
func (m *Manager) LoadGeoIPEntry(_ net.IP, _ string) error       { return ErrNotSupported }
func (m *Manager) GeoIPMaxEntries() uint32                       { return 0 }
func (m *Manager) GeoAllowSupported() bool                       { return false }
func (m *Manager) GeoState() GeoRangeState                       { return GeoRangeState{Mode: GeoModeBlock} }
func (m *Manager) CaptureGeo() (*GeoSnapshot, error)             { return nil, nil }
func (m *Manager) RestoreGeo(_ *GeoSnapshot) error               { return nil }
func (m *Manager) SetGeoLocalSubnets(_ []netip.Prefix) error     { return nil }
func (m *Manager) SetGeoDegraded(_, _, _ string)                 {}
func (m *Manager) InterfaceName() string                         { return "" }
func (m *Manager) ApplyGeoRanges(mode string, _ []string, _ []netip.Prefix) error {
	if mode == GeoModeAllow {
		return ErrGeoAllowUnsupported
	}
	return nil
}

// Port policy stubs
func (m *Manager) AddPortPolicy(_ PortPolicyAPI) error                { return ErrNotSupported }
func (m *Manager) RemovePortPolicy(_ uint16, _, _ string) error       { return ErrNotSupported }
func (m *Manager) ListPortPolicies(_ int) ([]PortPolicyAPI, error)    { return nil, ErrNotSupported }
func (m *Manager) GetPortPolicyConfig() (*PortPolicyConfigAPI, error) { return nil, ErrNotSupported }
func (m *Manager) UpdatePortPolicyConfig(_ PortPolicyConfigAPI) error { return ErrNotSupported }

// Egress blocklist stubs
func (m *Manager) AddToEgressBlocklist(_ string, _ time.Duration) error { return ErrNotSupported }
func (m *Manager) RemoveFromEgressBlocklist(_ string) error             { return ErrNotSupported }
func (m *Manager) ListEgressBlocklist(_ int) ([]EgressBlocklistEntry, error) {
	return nil, ErrNotSupported
}

func (m *Manager) SetControlPlaneEndpoints(_ []netip.AddrPort) error { return ErrNotSupported }
func (m *Manager) ExpectControlPlane()                               {}
func (m *Manager) HostFirewallEnv() HostFirewallEnv {
	return HostFirewallEnv{SSHPorts: DetectSSHDPorts()}
}
func (m *Manager) LiveBlocks() ([]BlocklistEntry, []EgressBlocklistEntry, error) {
	return nil, nil, ErrNotSupported
}
