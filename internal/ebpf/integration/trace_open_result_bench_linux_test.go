//go:build linux

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/wafio/wafio-agent-host/internal/ebpf"
)

// BenchmarkTraceOpenCost is the time of an open and close of an existing file
// without tracing and with the trace manager attached, at a pace of about
// 200k opens a second so the reader keeps up and the kernel does not shed. Run
// it with the object of this build and with the object of a build before open
// results: the second is not armed, so the difference is what waiting for the
// result costs.
//
//	sudo env WAFIO_EBPF_INTEGRATION=1 WAFIO_TRACE_OBJECT=<wafio_trace.o> \
//	  ./integration.test -test.run '^$' -test.bench TraceOpenCost -test.benchtime 2000000x
func BenchmarkTraceOpenCost(b *testing.B) {
	file := filepath.Join(b.TempDir(), "bench-fixture")
	if err := os.WriteFile(file, []byte("inert fixture"), 0o600); err != nil {
		b.Fatal(err)
	}
	const batch = 500
	run := func(b *testing.B, tm *ebpf.TraceManager) {
		for done := 0; done < b.N; {
			n := min(batch, b.N-done)
			for i := 0; i < n; i++ {
				fd, err := unix.Open(file, unix.O_RDONLY, 0)
				if err != nil {
					b.Fatal(err)
				}
				_ = unix.Close(fd)
			}
			done += n
			b.StopTimer()
			time.Sleep(2 * time.Millisecond)
			if tm != nil {
				tm.DrainRecentTraceEvents(1 << 20)
			}
			b.StartTimer()
		}
	}
	b.Run("untraced", func(b *testing.B) { run(b, nil) })
	tm := traceLabWithout(b, func(probe string) bool { return strings.HasPrefix(probe, "sys_exit_open") || probe == "sys_exit_creat" })
	b.Run("traced", func(b *testing.B) {
		before := tm.Status()
		run(b, tm)
		after := tm.Status()
		b.Logf("armed=%v with result=%d without=%d shed=%d", after.OpenResult,
			after.OpenResultKnown-before.OpenResultKnown, after.OpenResultUnknown-before.OpenResultUnknown,
			after.KernelEventsShed-before.KernelEventsShed)
	})
}
