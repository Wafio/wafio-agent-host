//go:build !linux

package ebpf

import (
	"context"
	"fmt"
	"log"
)

// TraceManager stub for non-Linux platforms.
type TraceManager struct{}

var ErrTraceNotSupported = fmt.Errorf("eBPF tracing is only supported on Linux")

func NewTraceManager(_ TraceManagerConfig, _ *log.Logger) *TraceManager {
	return &TraceManager{}
}

func (tm *TraceManager) Start(_ context.Context) error                             { return ErrTraceNotSupported }
func (tm *TraceManager) Stop() error                                               { return nil }
func (tm *TraceManager) IsRunning() bool                                           { return false }
func (tm *TraceManager) Status() TraceStatus                                       { return TraceStatus{} }
func (tm *TraceManager) DrainRecentTraceEvents(_ int) []TraceEvent                 { return nil }
func (tm *TraceManager) NoteDeliveryLoss(_ [3]int)                                 {}
func (tm *TraceManager) TelemetryUrgent() bool                                     { return false }
func (tm *TraceManager) QueuedEvents() int                                         { return 0 }
func (tm *TraceManager) FilterRecentEvents(_ string, _ uint32, _ int) []TraceEvent { return nil }
func (tm *TraceManager) GetConfig() (*TraceConfigAPI, error)                       { return nil, ErrTraceNotSupported }
func (tm *TraceManager) UpdateConfig(_ TraceConfigAPI) error                       { return ErrTraceNotSupported }
func (tm *TraceManager) AddFilteredPID(_ uint32) error                             { return ErrTraceNotSupported }
func (tm *TraceManager) RemoveFilteredPID(_ uint32) error                          { return ErrTraceNotSupported }
func (tm *TraceManager) GetStats() (*TraceStats, error)                            { return nil, ErrTraceNotSupported }

// Enforcement stubs
func (tm *TraceManager) AddPolicy(_ EnforcementPolicy) (*EnforcementPolicy, error) {
	return nil, ErrTraceNotSupported
}
func (tm *TraceManager) UpdatePolicy(_ uint32, _ EnforcementPolicy) (*EnforcementPolicy, error) {
	return nil, ErrTraceNotSupported
}
func (tm *TraceManager) DeletePolicy(_ uint32) error { return ErrTraceNotSupported }
func (tm *TraceManager) GetPolicy(_ uint32) (*EnforcementPolicy, error) {
	return nil, ErrTraceNotSupported
}
func (tm *TraceManager) ListPolicies() []EnforcementPolicy               { return nil }
func (tm *TraceManager) GetEnforcementLog(_ int) []EnforcementLogEntry   { return nil }
func (tm *TraceManager) DrainEnforcementLog(_ int) []EnforcementLogEntry { return nil }
func (tm *TraceManager) ClearEnforcementLog()                            {}

func (tm *TraceManager) ReplacePolicies(_ []EnforcementPolicy) error { return ErrTraceNotSupported }
func (tm *TraceManager) IsLSMActive() bool                           { return false }
func (tm *TraceManager) BlockBinaryPath(_ string, _ uint32) error    { return ErrTraceNotSupported }
func (tm *TraceManager) UnblockBinaryPath(_ string) error            { return ErrTraceNotSupported }
func (tm *TraceManager) ListBlockedBinaryPaths() ([]string, error)   { return nil, ErrTraceNotSupported }
