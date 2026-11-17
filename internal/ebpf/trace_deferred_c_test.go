package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTraceDeferredSignalLifecycle compiles check_deferred_signal of
// wafio_trace.c natively and checks the request lifecycle without the
// compare-and-swap it used to need: a pending request for the right
// process is signalled once and completed with its result; a completed or
// claimed request is left alone; a protected process, another process with
// the PID, or an expired request complete with -1 / -3 / -110 and no signal.
func TestTraceDeferredSignalLifecycle(t *testing.T) {
	src := `typedef uint8_t __u8; typedef uint32_t __u32; typedef uint64_t __u64; typedef int32_t __s32;
#define BPF_CORE_READ(t, f) ((t)->f)
struct task_struct { struct task_struct *group_leader; __u64 start_boottime; };
` + bpfSourceStruct(t, "wafio_trace.h", "trace_config") +
		bpfSourceStruct(t, "wafio_trace.c", "deferred_signal") +
		bpfSourceDefines(t, "wafio_trace.c", "TRACE_NSEC_PER_USER_HZ_TICK", "TRACE_DEFERRED_PENDING", "TRACE_WRITE_ONCE") + `
static int trace_deferred_signals, trace_protected_tgids;
static struct deferred_signal req; static int have_req;
static __u32 prot_tgid; static __u64 prot_ticks;
static void *bpf_map_lookup_elem(void *map, const void *key) {
  __u32 k = *(const __u32 *)key;
  if (map == &trace_deferred_signals) return have_req && k == 4242 ? (void *)&req : NULL;
  if (map == &trace_protected_tgids) return prot_tgid && k == prot_tgid ? (void *)&prot_ticks : NULL;
  return NULL;
}
static __u64 cur_pid_tgid = (__u64)4242 << 32 | 4243, now_ns = 1000;
static struct task_struct leader = { &leader, 5000000000ULL }, thread = { &leader, 0 };
static int signals;
static __u64 bpf_get_current_pid_tgid(void) { return cur_pid_tgid; }
static void *bpf_get_current_task(void) { return &thread; }
static __u64 bpf_ktime_get_ns(void) { return now_ns; }
static int reuse_during_signal;
static long bpf_send_signal(__u32 sig) {
  signals += sig == 9;
  /* Another thread completed the request, the agent deleted it and the
   * preallocated element now holds pid 5151's request. */
  if (reuse_during_signal) { req.tgid = 5151; req.expires_ns = 9999; req.state = 0; req.result = TRACE_DEFERRED_PENDING; }
  return 0;
}
` + bpfSourceHelper(t, "wafio_trace.c", "is_protected_tgid") +
		bpfSourceHelper(t, "wafio_trace.c", "check_deferred_signal") + `
static int failures;
#define EXPECT(cond, msg) do { if (!(cond)) { printf("%s\n", msg); failures++; } } while (0)
static struct trace_config cfg = { .agent_pid = 7 };
static void request(__u64 start, __u64 expires) {
  memset(&req, 0, sizeof req); have_req = 1;
  req.process_start_ns = start; req.expires_ns = expires; req.result = TRACE_DEFERRED_PENDING; req.tgid = 4242;
}
int main(void) {
  request(5000000000ULL, 2000);
  check_deferred_signal(&cfg);
  EXPECT(signals == 1 && req.state == 2 && req.result == 0, "pending request not signalled and completed");
  check_deferred_signal(&cfg);
  EXPECT(signals == 1, "completed request signalled again");

  request(5000000000ULL, 2000); req.state = 1; /* another thread claimed it */
  check_deferred_signal(&cfg);
  EXPECT(signals == 1 && req.state == 1, "claimed request touched");

  request(5000000000ULL, 2000); prot_tgid = 4242; prot_ticks = 500;
  check_deferred_signal(&cfg);
  EXPECT(signals == 1 && req.state == 2 && req.result == -1, "protected process signalled");
  prot_tgid = 0;

  request(4000000000ULL, 2000); /* PID reused by another process */
  check_deferred_signal(&cfg);
  EXPECT(signals == 1 && req.state == 2 && req.result == -3, "identity mismatch signalled");

  request(5000000000ULL, 1000); /* expired */
  check_deferred_signal(&cfg);
  EXPECT(signals == 1 && req.state == 2 && req.result == -110, "expired request signalled");

  /* The element under this pid's key holds another pid's request (reused
   * at once after a delete): never touched. */
  request(5000000000ULL, 2000); req.tgid = 5151;
  check_deferred_signal(&cfg);
  EXPECT(signals == 1 && req.state == 0 && req.result == TRACE_DEFERRED_PENDING, "another pid's request touched");

  /* Reused while this thread was signalling: its completion is not written
   * into the other pid's request. */
  request(5000000000ULL, 2000); reuse_during_signal = 1;
  check_deferred_signal(&cfg);
  reuse_during_signal = 0;
  EXPECT(signals == 2 && req.tgid == 5151 && req.state == 0 && req.result == TRACE_DEFERRED_PENDING,
         "late thread completed another pid's request");

  cur_pid_tgid = (__u64)7 << 32 | 7; request(5000000000ULL, 2000); /* the agent itself */
  check_deferred_signal(&cfg);
  EXPECT(signals == 2 && req.state == 0, "agent request touched");
  printf("size=%zu\n", sizeof(struct deferred_signal));
  printf("ok\n");
  return failures != 0;
}
`
	if out := runNativeC(t, "trace_deferred", src); !strings.Contains(out, "size=40\nok") {
		t.Fatal(out)
	}
}

// TestBPFSourcesAvoid512Atomics guards the atomics limit at the source: every
// BPF object must load on Linux 5.8. BPF cmpxchg/xchg and fetch-returning
// atomics are accepted from 5.12 only, and clang emits them for
// __sync_*_compare_and_swap, __sync_lock_test_and_set, any __atomic_* builtin,
// and a __sync_fetch_and_* whose result is used. Only a bare statement
// `__sync_fetch_and_add(p, v);` (plain XADD) is allowed. Compile at -mcpu=v1
// to be sure (kernel lab).
func TestBPFSourcesAvoid512Atomics(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("bpf", "*.[ch]"))
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`__sync_\w+|__atomic_\w+`)
	bareAdd := regexp.MustCompile(`^\s*(if \([^;]*\)\s*)?__sync_fetch_and_add\([^;]*\);\s*(/\*.*\*/|//.*)?$`)
	for _, f := range files {
		if filepath.Base(f) == "vmlinux.h" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			if strings.HasPrefix(strings.TrimSpace(code), "*") || strings.HasPrefix(strings.TrimSpace(code), "/*") {
				continue // comment block
			}
			if call.MatchString(code) && !bareAdd.MatchString(code) {
				t.Errorf("%s:%d: atomic needs Linux 5.12 (only a bare __sync_fetch_and_add statement is 5.8-safe): %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
