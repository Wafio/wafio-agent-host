package ebpf

import "testing"

// TestLSMNetReportRateLimit compiles the per-CPU report limiter of
// wafio_lsm.c natively: at most LSM_NET_REPORTS_PER_SEC
// connect/send deny reports per CPU per second reach the ring, the rest are
// counted as suppressed; a new window (or a clock that went backwards)
// starts over. The denial itself is decided before and never limited.
func TestLSMNetReportRateLimit(t *testing.T) {
	src := `typedef uint32_t __u32; typedef uint64_t __u64;
` + bpfSourceDefines(t, "wafio_lsm.c", "LSM_NET_REPORTS_PER_SEC", "LSM_REPORT_WINDOW_NS") +
		bpfSourceStruct(t, "wafio_lsm.c", "lsm_report_window") + `
static int wafio_lsm_report_window, wafio_lsm_reports_suppressed;
static struct lsm_report_window win; static __u64 suppressed;
static void *bpf_map_lookup_elem(void *map, const void *key) {
  (void)key;
  if (map == &wafio_lsm_report_window) return &win;
  if (map == &wafio_lsm_reports_suppressed) return &suppressed;
  return NULL;
}
` + bpfSourceHelper(t, "wafio_lsm.c", "lsm_net_report_allowed") + `
static int burst(__u64 now, int n) { int ok = 0; for (int i = 0; i < n; i++) ok += lsm_net_report_allowed(now); return ok; }
/* The burst runs before suppressed is read: C leaves the order in which
 * printf's arguments are evaluated unspecified (gcc on x86-64 read the
 * counter first). */
static void report(const char *name, __u64 now, int n) {
  int ok = burst(now, n);
  printf("%s %d suppressed=%llu\n", name, ok, (unsigned long long)suppressed);
}
int main(void) {
  __u64 t0 = 5000000000ULL;
  report("first", t0, 40);
  report("same_window", t0 + 999999999ULL, 5);
  report("next_window", t0 + 1000000000ULL, 40);
  printf("clock_back %d\n", burst(t0 - 1, 1));
  return 0;
}
`
	got := runNativeC(t, "lsm_report_limit", src)
	want := `first 32 suppressed=8
same_window 0 suppressed=13
next_window 32 suppressed=21
clock_back 1
`
	if got != want {
		t.Fatalf("LSM network report limiter:\n got:\n%s\nwant:\n%s", got, want)
	}
}
