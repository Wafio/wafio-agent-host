package ebpf

import (
	"math"
	"os"
	"time"
)

// Bounds-checked integer conversions for values that cross the Go ↔ BPF
// boundary. Each saturates instead of wrapping, so an out-of-range input can
// never turn into a small or negative number (gosec G115).

// u64FromInt converts a count or length to uint64; negative values become 0.
func u64FromInt(v int) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// u64FromInt64 converts a non-negative int64 (nanoseconds, a clock reading)
// to uint64; negative values become 0.
func u64FromInt64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// durationNs is a positive TTL in nanoseconds; zero or negative is 0.
func durationNs(d time.Duration) uint64 {
	return u64FromInt64(d.Nanoseconds())
}

// i64FromU64 converts a kernel nanosecond counter to int64, saturating at
// math.MaxInt64 (≈ 292 years of uptime).
func i64FromU64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// u32FromInt converts a length, prefix length or descriptor to uint32,
// clamping to [0, math.MaxUint32].
func u32FromInt(v int) uint32 {
	if v < 0 {
		return 0
	}
	if uint64(v) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// u16FromInt converts a port to uint16, clamping to [0, math.MaxUint16].
func u16FromInt(v int) uint16 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(v)
}

// i32FromInt converts a count to int32, clamping to [math.MinInt32, math.MaxInt32].
func i32FromInt(v int) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	if v < math.MinInt32 {
		return math.MinInt32
	}
	return int32(v)
}

// agentPID is this process's PID as the kernel's u32 tgid. Linux PIDs are
// bounded by pid_max (at most 2^22), so the value always fits.
func agentPID() uint32 {
	return u32FromInt(os.Getpid())
}
