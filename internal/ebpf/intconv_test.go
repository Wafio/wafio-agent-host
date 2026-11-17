package ebpf

import (
	"math"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestIntConvSaturates(t *testing.T) {
	if got := u64FromInt(-3); got != 0 {
		t.Fatalf("u64FromInt(-3) = %d, want 0", got)
	}
	if got := u64FromInt(7); got != 7 {
		t.Fatalf("u64FromInt(7) = %d", got)
	}
	if got := u64FromInt64(math.MinInt64); got != 0 {
		t.Fatalf("u64FromInt64(min) = %d, want 0", got)
	}
	if got := durationNs(-time.Second); got != 0 {
		t.Fatalf("durationNs(-1s) = %d, want 0", got)
	}
	if got := durationNs(2 * time.Second); got != uint64(2*time.Second) {
		t.Fatalf("durationNs(2s) = %d", got)
	}
	if got := i64FromU64(math.MaxUint64); got != math.MaxInt64 {
		t.Fatalf("i64FromU64(max) = %d, want MaxInt64", got)
	}
	if got := i64FromU64(42); got != 42 {
		t.Fatalf("i64FromU64(42) = %d", got)
	}
	if got := u32FromInt(-1); got != 0 {
		t.Fatalf("u32FromInt(-1) = %d, want 0", got)
	}
	if got := u32FromInt(math.MaxInt64); got != math.MaxUint32 {
		t.Fatalf("u32FromInt(max) = %d, want MaxUint32", got)
	}
	if got := u32FromInt(128); got != 128 {
		t.Fatalf("u32FromInt(128) = %d", got)
	}
	if got := i32FromInt(math.MaxInt64); got != math.MaxInt32 {
		t.Fatalf("i32FromInt(max) = %d", got)
	}
	if got := i32FromInt(math.MinInt64); got != math.MinInt32 {
		t.Fatalf("i32FromInt(min) = %d", got)
	}
	if got := agentPID(); int(got) != os.Getpid() {
		t.Fatalf("agentPID() = %d, want %d", got, os.Getpid())
	}
}

func TestExtractPolicyIDRejectsOutOfRange(t *testing.T) {
	const prefix = "/api/ebpf/trace/policies/"
	cases := map[string]uint32{
		prefix + "12": 12,
		prefix + strconv.FormatUint(math.MaxUint32, 10): math.MaxUint32,
		// 2^32 + 5 used to wrap to policy 5.
		prefix + strconv.FormatUint(1<<32+5, 10): 0,
		prefix + "0":                             0,
		prefix + "-4":                            0,
		prefix + "x":                             0,
		"/other/12":                              0,
	}
	for path, want := range cases {
		if got := extractPolicyID(path); got != want {
			t.Errorf("extractPolicyID(%q) = %d, want %d", path, got, want)
		}
	}
}
