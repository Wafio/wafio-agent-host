package agent

import (
	"github.com/wafio/wafio-cp-backend/shared/agentcore"
	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

// RegisterHostMetrics adds the host (eBPF) agent series to reg.
func RegisterHostMetrics(reg *metrics.Registry) {
	agentcore.RegisterProcessMetrics(reg)
	reg.Counter("wafio_host_telemetry_send_failures", "Host telemetry batches that could not be marshalled or sent.",
		func() float64 { return agentcore.U64(ebpfTelemetrySendFailures.Load()) })
	reg.GaugeVec("wafio_host_telemetry_pending", "Host telemetry retained until the control plane acknowledges it.",
		func() []metrics.Sample {
			d := ebpfTelemetryRetention.snapshot()
			return []metrics.Sample{
				{Labels: []metrics.Label{{Name: "unit", Value: "batches"}}, Value: float64(d.PendingBatches)},
				{Labels: []metrics.Label{{Name: "unit", Value: "bytes"}}, Value: float64(d.PendingBytes)},
			}
		})
	reg.CounterVec("wafio_host_telemetry_dropped", "Host telemetry discarded before acknowledgement (expired or retention full).",
		func() []metrics.Sample {
			d := ebpfTelemetryRetention.snapshot()
			return []metrics.Sample{
				{Labels: []metrics.Label{{Name: "unit", Value: "batches"}}, Value: agentcore.U64(d.DroppedBatches)},
				{Labels: []metrics.Label{{Name: "unit", Value: "events"}}, Value: agentcore.U64(d.DroppedEvents)},
			}
		})
}
