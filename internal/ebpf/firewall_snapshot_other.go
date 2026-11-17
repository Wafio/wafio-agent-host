//go:build !linux

package ebpf

import "fmt"

func (m *Manager) CaptureFirewallState() (*FirewallSnapshot, error) {
	return nil, fmt.Errorf("firewall snapshots require Linux")
}
func (m *Manager) RestoreFirewallState(_ *FirewallSnapshot) error {
	return fmt.Errorf("firewall snapshots require Linux")
}
