package ebpf

import (
	"strconv"
	"strings"
	"testing"
)

// tracePriorityHarness is the export path of wafio_trace.c (priority-ring
// helpers + submit_event_routed) compiled natively, with the maps and
// bpf_ringbuf_output mocked as tiny fixed-capacity rings. Ring sizes, the
// verifier and real tracepoints are covered in the kernel lab.
func tracePriorityHarness(t *testing.T, body string) string {
	t.Helper()
	src := `typedef uint8_t __u8; typedef uint16_t __u16; typedef uint32_t __u32; typedef uint64_t __u64;
typedef int32_t __s32; typedef int64_t __s64;
` + bpfSourceDefines(t, "wafio_trace.h", "TRACE_ACTION_", "SEV_", "TRACE_PRIO_", "TRACE_FNV64_", "TRACE_FILENAME_LEN", "TRACE_EVENT_OPEN", "TRACE_SHED_", "TRACE_NOISE_TYPES", "TRACE_KEEP_", "TRACE_EVT_", "TRACE_OPEN_", "TRACE_ERESTART_") +
		bpfSourceDefines(t, "wafio_trace.c", "TRACE_ROUTE_") +
		bpfSourceStruct(t, "wafio_trace.h", "trace_config") +
		bpfSourceStruct(t, "wafio_trace.h", "trace_priority_rule") +
		bpfSourceStruct(t, "wafio_trace.h", "trace_priority_ctl") +
		bpfSourceStruct(t, "wafio_trace.h", "trace_open_ctl") + `
/* Only the fields the export path reads. */
struct wafio_event { __u32 event_type, severity, action, flags; char filename[TRACE_FILENAME_LEN]; __s64 ret_val; __u32 proc_flags, aux; };

/* Maps: identity tokens dispatched by address. */
static int trace_config_map, trace_priority_rules, trace_stats, trace_priority_stats, trace_priority_ctl, trace_priority_names, trace_shed_stats, trace_keep_names;
static int trace_open_pending, trace_open_ctl, trace_open_stats;
static struct trace_config cfg0;
static struct trace_priority_rule rules[32];
static struct trace_priority_ctl ctl0;
static struct trace_open_ctl open_ctl0;
static __u64 stats[32], prio[TRACE_PRIO_STATS], shed[32], open_stats[TRACE_OPEN_STATS];
static __u64 names[8]; static int nnames; static __u8 one = 1;
static __u64 keep[16]; static __u8 keepval[16]; static int nkeep;
/* trace_open_pending: a hash map of PENDING_CAP elements; the thread the
 * programs run as is current_tid. */
#define PENDING_CAP 3
#define BPF_ANY 0
static struct { int used; __u64 key; struct wafio_event ev; } pending[PENDING_CAP];
static __u64 current_tid = 100;
static __u64 bpf_get_current_pid_tgid(void) { return current_tid; }
static int pending_count(void) { int n = 0; for (int i = 0; i < PENDING_CAP; i++) n += pending[i].used; return n; }
static void *bpf_map_lookup_elem(void *map, const void *key) {
  if (map == &trace_open_pending) {
    for (int i = 0; i < PENDING_CAP; i++) if (pending[i].used && pending[i].key == *(const __u64 *)key) return &pending[i].ev;
    return NULL;
  }
  if (map == &trace_open_ctl) return *(const __u32 *)key == 0 ? (void *)&open_ctl0 : NULL;
  if (map == &trace_open_stats) return *(const __u32 *)key < TRACE_OPEN_STATS ? (void *)&open_stats[*(const __u32 *)key] : NULL;
  if (map == &trace_priority_names) {
    for (int i = 0; i < nnames; i++) if (names[i] == *(const __u64 *)key) return &one;
    return NULL;
  }
  if (map == &trace_keep_names) {
    for (int i = 0; i < nkeep; i++) if (keep[i] == *(const __u64 *)key) return &keepval[i];
    return NULL;
  }
  __u32 k = *(const __u32 *)key;
  if (map == &trace_config_map) return k == 0 ? (void *)&cfg0 : NULL;
  if (map == &trace_priority_rules) return k < 32 ? (void *)&rules[k] : NULL;
  if (map == &trace_priority_ctl) return k == 0 ? (void *)&ctl0 : NULL;
  if (map == &trace_stats) return k < 32 ? (void *)&stats[k] : NULL;
  if (map == &trace_priority_stats) return k < TRACE_PRIO_STATS ? (void *)&prio[k] : NULL;
  if (map == &trace_shed_stats) return k < 32 ? (void *)&shed[k] : NULL;
  return NULL;
}
static long bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags) {
  (void)flags;
  if (map != &trace_open_pending) return -22;
  int free = -1;
  for (int i = 0; i < PENDING_CAP; i++) {
    if (pending[i].used && pending[i].key == *(const __u64 *)key) { pending[i].ev = *(const struct wafio_event *)value; return 0; }
    if (!pending[i].used && free < 0) free = i;
  }
  if (free < 0) return -7; /* E2BIG: full */
  pending[free].used = 1; pending[free].key = *(const __u64 *)key; pending[free].ev = *(const struct wafio_event *)value;
  return 0;
}
static long bpf_map_delete_elem(void *map, const void *key) {
  if (map != &trace_open_pending) return -22;
  for (int i = 0; i < PENDING_CAP; i++) if (pending[i].used && pending[i].key == *(const __u64 *)key) { pending[i].used = 0; return 0; }
  return -2;
}
struct ring { int cap, n; __u32 sev[256]; __s64 ret[256]; __u32 flags[256]; __u32 aux[256]; };
static struct ring trace_events = { 3, 0, {0}, {0}, {0}, {0} }, trace_priority_events = { 2, 0, {0}, {0}, {0}, {0} };
static long bpf_ringbuf_output(void *ringp, void *data, __u64 size, __u64 flags) {
  struct ring *r = ringp; const struct wafio_event *e = data; (void)size; (void)flags;
  if (r->n >= r->cap) return -28; /* full */
  if (r->n < 256) { r->sev[r->n] = e->severity; r->ret[r->n] = e->ret_val; r->flags[r->n] = e->proc_flags; r->aux[r->n] = e->aux; }
  r->n++;
  return 0;
}
/* Fill level in records: 100 bytes per record, capacity cap records. */
#define BPF_RB_AVAIL_DATA 0
#define BPF_RB_RING_SIZE 1
static __u64 bpf_ringbuf_query(void *ringp, __u64 flags) {
  struct ring *r = ringp;
  return flags == BPF_RB_RING_SIZE ? (__u64)r->cap * 100 : (__u64)r->n * 100;
}
` + bpfSourceHelper(t, "wafio_trace.c", "trace_prio_stat") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_prio_ctl") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_is_kill_candidate") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_name_hash_byte") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_open_name_candidate") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_open_keep") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_shed_wanted") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_shed_count") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_route") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_export") +
		bpfSourceHelper(t, "wafio_trace.c", "submit_event_routed") +
		bpfSourceHelper(t, "wafio_trace.c", "submit_event") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_open_count") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_open_leave") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_open_release") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_open_release_stale") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_open_submit") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_open_exit") +
		bpfSourceHelper(t, "wafio_trace.c", "trace_open_flush") + `
static int failures;
#define EXPECT(cond, msg) do { if (!(cond)) { printf("%s\n", msg); failures++; } } while (0)
static void emit(__u32 type, __u32 sev, __u32 action) { struct wafio_event e = { type, sev, action, 0, "" }; submit_event(&e); }
static void emit_open_flags(const char *path, __u32 sev, __u32 flags) {
  struct wafio_event e = { TRACE_EVENT_OPEN, sev, TRACE_ACTION_MONITOR, flags, "" };
  strncpy(e.filename, path, TRACE_FILENAME_LEN - 1);
  submit_event_routed(&e, 1);
}
static void emit_open(const char *path, __u32 sev) { emit_open_flags(path, sev, 0); }
/* The agent's name hash, from the kernel's per-byte step. */
static __u64 name_hash(const char *name) {
  __u64 h = TRACE_FNV64_OFFSET;
  for (; *name; name++) h = trace_name_hash_byte(h, (__u8)*name);
  return h;
}
static void reset(void) {
  memset(stats, 0, sizeof stats); memset(prio, 0, sizeof prio); memset(shed, 0, sizeof shed);
  memset(open_stats, 0, sizeof open_stats); memset(pending, 0, sizeof pending);
  trace_events.n = 0; trace_priority_events.n = 0;
}
` + body
	return runNativeC(t, "trace_priority", src)
}

// TestTracePriorityRouting replays the priority-ring scenario: a process
// floods openat until the shared ring is full, then makes the access a Kill
// policy is waiting for. Before the priority ring that event met the same full
// ring and was only counted as dropped, so the kill never happened.
func TestTracePriorityRouting(t *testing.T) {
	out := tracePriorityHarness(t, `
int main(void) {
  cfg0.enabled = 1; cfg0.event_mask_lo = 0xffffffffu; cfg0.min_severity = SEV_INFO;
  ctl0.attached = 1;
  /* userspace Kill policy: openat of /etc/shadow (HIGH in-kernel) */
  rules[3].enabled = 1; rules[3].min_severity = SEV_HIGH;

  /* The flood fills the shared ring and overflows it (MEDIUM: an INFO
   * flood is shed before the ring is full, TestTraceShedHeadroom). */
  for (int i = 0; i < 6; i++) emit(3, SEV_MEDIUM, TRACE_ACTION_MONITOR);
  EXPECT(trace_events.n == 3 && stats[0] == 3, "flood did not fill the shared ring");
  EXPECT(trace_priority_events.n == 0, "a non-candidate took the priority ring");

  /* The kill-candidate event still reaches userspace. */
  emit(3, SEV_HIGH, TRACE_ACTION_MONITOR);
  EXPECT(trace_priority_events.n == 1 && prio[TRACE_PRIO_ROUTED] == 1, "kill candidate lost behind the flood");
  EXPECT(stats[0] == 3, "kill candidate counted as a shared-ring drop");

  /* An event the kernel already killed for keeps its record on the priority ring. */
  emit(4, SEV_INFO, TRACE_ACTION_KILL);
  EXPECT(trace_priority_events.n == 2, "kernel kill record not on the priority ring");

  /* Priority ring full + shared ring full: counted as a lost candidate. */
  emit(3, SEV_CRITICAL, TRACE_ACTION_MONITOR);
  EXPECT(prio[TRACE_PRIO_FULL] == 1 && prio[TRACE_PRIO_LOST] == 1 && stats[0] == 4, "lost candidate not counted");

  /* Shared ring has room again: an overflowing candidate falls back to it. */
  trace_events.n = 0;
  emit(3, SEV_HIGH, TRACE_ACTION_MONITOR);
  EXPECT(trace_events.n == 1 && prio[TRACE_PRIO_FULL] == 2 && prio[TRACE_PRIO_LOST] == 1, "no fallback to the shared ring");

  /* Below the rule's severity, or a type without a rule: shared ring. */
  trace_priority_events.n = 0;
  emit(3, SEV_MEDIUM, TRACE_ACTION_MONITOR);
  emit(5, SEV_CRITICAL, TRACE_ACTION_MONITOR);
  EXPECT(trace_priority_events.n == 0 && trace_events.n == 3, "non-candidate routed to the priority ring");

  /* A disabled rule routes nothing. */
  rules[3].enabled = 0; trace_events.n = 0;
  emit(3, SEV_CRITICAL, TRACE_ACTION_MONITOR);
  EXPECT(trace_priority_events.n == 0 && trace_events.n == 1, "disabled rule still routes");

  /* The trace config filter still applies to monitor events before routing. */
  rules[3].enabled = 1; cfg0.event_mask_lo = ~(1u << 2); trace_events.n = 0;
  emit(3, SEV_CRITICAL, TRACE_ACTION_MONITOR);
  EXPECT(trace_priority_events.n == 0 && trace_events.n == 0, "masked event exported");
  printf("routed=%llu full=%llu lost=%llu shared_lost=%llu\n", (unsigned long long)prio[TRACE_PRIO_ROUTED],
         (unsigned long long)prio[TRACE_PRIO_FULL], (unsigned long long)prio[TRACE_PRIO_LOST], (unsigned long long)stats[0]);
  return failures != 0;
}
`)
	if !strings.Contains(out, "routed=2 full=2 lost=1 shared_lost=4") {
		t.Fatalf("unexpected counters: %s", out)
	}
}

// Nothing goes to the priority ring while no agent reads it (an older agent,
// or a reader that failed to open): not even kernel-kill records.
func TestTracePriorityNeedsAttachedReader(t *testing.T) {
	out := tracePriorityHarness(t, `
int main(void) {
  cfg0.enabled = 1; cfg0.event_mask_lo = 0xffffffffu;
  rules[3].enabled = 1; rules[3].min_severity = SEV_HIGH;
  names[nnames++] = 0; /* any */
  ctl0.attached = 0; ctl0.open_names = 1;
  emit(4, SEV_INFO, TRACE_ACTION_KILL);
  emit(3, SEV_HIGH, TRACE_ACTION_MONITOR);
  EXPECT(trace_priority_events.n == 0 && trace_events.n == 2, "routed to a ring nobody reads");
  ctl0.attached = 1;
  emit(4, SEV_INFO, TRACE_ACTION_KILL);
  EXPECT(trace_priority_events.n == 1, "attached reader not used");
  printf("ok\n");
  return failures != 0;
}
`)
	if !strings.Contains(out, "ok") {
		t.Fatal(out)
	}
}

// A Kill policy on openat of /etc/shadow at HIGH. The kernel
// raises severity on the exact path only; /etc/./shadow and "shadow" opened
// from /etc reach it at INFO and used to take the shared ring, so behind a
// flood they were dropped (and alerted as MEDIUM, not as a lost kill
// candidate). Their final component now routes them.
func TestTracePriorityOpenNameRoute(t *testing.T) {
	out := tracePriorityHarness(t, `
int main(void) {
  cfg0.enabled = 1; cfg0.event_mask_lo = 0xffffffffu; cfg0.min_severity = SEV_INFO;
  ctl0.attached = 1;
  rules[3].enabled = 1; rules[3].min_severity = SEV_HIGH;
  names[nnames++] = name_hash("shadow"); ctl0.open_names = 1;

  for (int i = 0; i < 6; i++) emit_open("/tmp/junk", SEV_MEDIUM);         /* flood */
  EXPECT(trace_events.n == 3 && trace_priority_events.n == 0, "flood took the priority ring");
  emit_open("/etc/./shadow", SEV_INFO);
  emit_open("shadow", SEV_INFO);
  EXPECT(trace_priority_events.n == 2 && stats[0] == 3, "uncleaned or relative shadow lost behind the flood");
  reset();
  emit_open("/etc/SHADOW", SEV_INFO);        /* case-insensitive like MatchFilename */
  emit_open("/etc/gshadow", SEV_INFO);       /* another name */
  emit_open("/etc/shadow/", SEV_INFO);       /* trailing slash: empty name */
  emit_open("/etc/shadow.bak", SEV_INFO);
  EXPECT(trace_priority_events.n == 1 && trace_events.n == 3, "name route matched the wrong names");
  /* No names listed: the scan is skipped. */
  reset(); ctl0.open_names = 0;
  emit_open("/etc/./shadow", SEV_INFO);
  EXPECT(trace_priority_events.n == 0, "routed with no names listed");
  /* Hashes for the Go side to compare. */
  const char *names_[] = { "shadow", "Shadow", "sudoers.d", "passwd", "" };
  for (int i = 0; i < 5; i++) printf("%s %016llx\n", names_[i], (unsigned long long)name_hash(names_[i]));
  return failures != 0;
}
`)
	want := goNameHashes("shadow", "Shadow", "sudoers.d", "passwd", "")
	if !strings.HasSuffix(out, want) {
		t.Fatalf("kernel and agent name hashes differ:\n got:\n%s\nwant suffix:\n%s", out, want)
	}
}

// Directory Kill terms (/etc/sudoers.d/, /proc/): the agent raises a file
// below them only when it is opened for writing, and /etc/./sudoers.d/evil
// reaches the kernel at INFO. An openat opened for writing is routed when any
// component is listed; a read (the common /proc case) is not.
func TestTracePriorityOpenDirectoryRoute(t *testing.T) {
	out := tracePriorityHarness(t, `
int main(void) {
  cfg0.enabled = 1; cfg0.event_mask_lo = 0xffffffffu; cfg0.min_severity = SEV_INFO;
  ctl0.attached = 1;
  rules[3].enabled = 1; rules[3].min_severity = SEV_MEDIUM;
  names[nnames++] = name_hash("sudoers.d"); names[nnames++] = name_hash("proc"); ctl0.open_names = 2;
  trace_events.cap = 16; trace_priority_events.cap = 16;

  emit_open_flags("/etc/./sudoers.d/evil", SEV_INFO, 1);          /* O_WRONLY */
  emit_open_flags("sudoers.d/evil", SEV_INFO, 2);                 /* O_RDWR, relative to /etc */
  emit_open_flags("/./proc/sys/kernel/core_pattern", SEV_INFO, 01001); /* O_WRONLY|O_TRUNC */
  emit_open_flags("/etc/sudoers.d/x", SEV_INFO, 01000);           /* O_TRUNC only */
  EXPECT(trace_priority_events.n == 4 && trace_events.n == 0, "written file below a listed directory not routed");
  printf("routed_writes=%d\n", (int)prio[TRACE_PRIO_ROUTED]);

  reset();
  emit_open_flags("/proc/self/stat", SEV_INFO, 0);                /* read below /proc */
  emit_open_flags("/etc/sudoers.d/x", SEV_INFO, 0);               /* read */
  emit_open_flags("/tmp/sudoers.d.bak/x", SEV_INFO, 1);           /* another name */
  emit_open_flags("/tmp/procfs/x", SEV_INFO, 1);
  EXPECT(trace_priority_events.n == 0 && prio[TRACE_PRIO_FULL] == 0 && trace_events.n == 4, "read or unlisted directory routed");
  /* The final component alone still routes a read. */
  emit_open_flags("/etc/./sudoers.d", SEV_INFO, 0);
  EXPECT(trace_priority_events.n == 1, "open of the listed directory itself not routed");
  printf("ok\n");
  return failures != 0;
}
`)
	if !strings.Contains(out, "routed_writes=4") || !strings.Contains(out, "ok") {
		t.Fatalf("directory route: %s", out)
	}
}

// TestTraceShedHeadroom: with the shared ring 6/8 full, file and network
// events below MEDIUM are shed (counted per type), from 7/8 every event below
// MEDIUM; MEDIUM+ events, enforced events and kill candidates still reach a
// ring, so the last part of the ring stays for them while the reader is
// behind. Before the shed, an INFO openat burst filled the ring and the next
// HIGH event was dropped.
func TestTraceShedHeadroom(t *testing.T) {
	out := tracePriorityHarness(t, `
int main(void) {
  cfg0.enabled = 1; cfg0.event_mask_lo = 0xffffffffu; cfg0.min_severity = SEV_INFO;
  ctl0.attached = 1;
  rules[3].enabled = 1; rules[3].min_severity = SEV_HIGH;
  trace_events.cap = 16; trace_priority_events.cap = 4;

  /* Below 6/8 (12 of 16) nothing is shed. */
  for (int i = 0; i < 12; i++) emit(3, SEV_INFO, TRACE_ACTION_MONITOR);
  EXPECT(trace_events.n == 12 && shed[3] == 0, "shed below the noise threshold");

  /* 6/8: INFO/LOW openat and connect shed, process INFO (execve) kept. */
  emit(3, SEV_INFO, TRACE_ACTION_MONITOR);
  emit(4, SEV_LOW, TRACE_ACTION_MONITOR);
  EXPECT(trace_events.n == 12 && shed[3] == 1 && shed[4] == 1, "noise not shed at 6/8");
  emit(1, SEV_INFO, TRACE_ACTION_MONITOR);
  emit(11, SEV_LOW, TRACE_ACTION_MONITOR);   /* chmod: file|security, always stored */
  EXPECT(trace_events.n == 14 && shed[1] == 0 && shed[11] == 0, "non-noise type shed at 6/8");

  /* 7/8 (14 of 16): every event below MEDIUM is shed. */
  emit(1, SEV_INFO, TRACE_ACTION_MONITOR);
  EXPECT(trace_events.n == 14 && shed[1] == 1, "process INFO not shed at 7/8");

  /* Never shed: MEDIUM+, enforced (kernel alert), kill candidates. */
  emit(3, SEV_MEDIUM, TRACE_ACTION_MONITOR);
  emit(3, SEV_INFO, TRACE_ACTION_ALERT);
  EXPECT(trace_events.n == 16, "MEDIUM or enforced event shed");
  emit(3, SEV_HIGH, TRACE_ACTION_MONITOR);
  EXPECT(trace_priority_events.n == 1 && prio[TRACE_PRIO_ROUTED] == 1, "kill candidate shed");
  EXPECT(stats[0] == 0, "an event was dropped instead of shed");

  /* Ring full: a MEDIUM event is a real drop, never counted as shed. */
  emit(5, SEV_MEDIUM, TRACE_ACTION_MONITOR);
  EXPECT(stats[0] == 1 && shed[5] == 0, "full-ring drop miscounted");
  /* A candidate that overflows the priority ring is not shed either. */
  trace_priority_events.n = trace_priority_events.cap; trace_events.n = 13;
  emit(3, SEV_HIGH, TRACE_ACTION_MONITOR);
  EXPECT(trace_events.n == 14 && prio[TRACE_PRIO_FULL] == 1, "overflowing candidate shed");
  printf("shed open=%llu connect=%llu execve=%llu\n", (unsigned long long)shed[3], (unsigned long long)shed[4], (unsigned long long)shed[1]);
  return failures != 0;
}
`)
	if !strings.Contains(out, "shed open=1 connect=1 execve=1") {
		t.Fatalf("shed counters: %s", out)
	}
}

// TestTraceShedKeepsRaisableEvents: under shedding pressure
// an attacker floods LOW openat events, then acts. Before this fix the
// kernel shed every openat below MEDIUM at 6/8 fill, including the ones the
// agent raises after the ring (a non-canonical /etc//shadow, a relative
// write it resolves into /etc/sudoers.d), the ones ingest raises (credential
// and auth file names, kept through trace_keep_names) and credential changes
// (setuid/setgid LOW) at 7/8. Now those are exported; ordinary low-value
// events are still shed.
func TestTraceShedKeepsRaisableEvents(t *testing.T) {
	out := tracePriorityHarness(t, `
static void fill(int n) { for (int i = 0; i < n; i++) emit(3, SEV_MEDIUM, TRACE_ACTION_MONITOR); }
int main(void) {
  cfg0.enabled = 1; cfg0.event_mask_lo = 0xffffffffu; cfg0.min_severity = SEV_INFO;
  ctl0.attached = 1;
  trace_events.cap = 128; trace_priority_events.cap = 4;
  fill(96); /* 6/8 */
  int n = trace_events.n;

  emit_open("/tmp/flood", SEV_INFO);
  EXPECT(trace_events.n == n && shed[3] == 1, "plain openat not shed at 6/8");

  /* Non-canonical absolute paths: the agent cleans them and re-derives severity. */
  const char *noncanon[] = { "/etc//shadow", "/etc/./shadow", "/tmp/../etc/sudoers.d/x", "/etc/shadow/",
                             "/proc/self/.", "/.", "/etc/..", "//etc/shadow" };
  for (int i = 0; i < 8; i++) emit_open_flags(noncanon[i], SEV_INFO, 1);
  EXPECT(trace_events.n == n + 8, "non-canonical path shed");
  n = trace_events.n;
  /* Canonical paths, odd but canonical dot names: still shed. */
  const char *canon[] = { "/etc/passwd", "/", "/a/b.c/..d", "/a/.../b", "/a/.b/c", "/proc/self/stat" };
  for (int i = 0; i < 6; i++) emit_open(canon[i], SEV_INFO);
  EXPECT(trace_events.n == n && shed[3] == 7, "canonical path kept");

  /* Relative paths: a write is kept (resolved by the agent), a read shed. */
  emit_open_flags("x", SEV_INFO, 1);
  emit_open_flags("evil", SEV_INFO, 01000);
  EXPECT(trace_events.n == n + 2, "relative write shed");
  n = trace_events.n;
  emit_open("x", SEV_INFO);
  emit_open("./x", SEV_INFO);
  EXPECT(trace_events.n == n && shed[3] == 9, "relative read kept without a listed name");

  /* trace_keep_names: NAME = final component (any component of a write),
   * DIR = any component. */
  keep[nkeep] = name_hash("shadow"); keepval[nkeep++] = TRACE_KEEP_NAME;
  keep[nkeep] = name_hash("sudoers.d"); keepval[nkeep++] = TRACE_KEEP_DIR;
  keep[nkeep] = name_hash(".ssh"); keepval[nkeep++] = TRACE_KEEP_NAME;
  emit_open("shadow", SEV_INFO);                       /* relative, final listed */
  emit_open("/etc/sudoers.d/x", SEV_INFO);             /* read below a DIR entry */
  emit_open("../sudoers.d/y", SEV_INFO);
  emit_open_flags("/root/.ssh/authorized_keys2", SEV_INFO, 1); /* write below a NAME entry */
  emit_open("/root/.SSH", SEV_INFO);                   /* final, ASCII case folded */
  EXPECT(trace_events.n == n + 5, "listed name shed");
  n = trace_events.n;
  emit_open("/home/u/shadow.txt", SEV_INFO);
  emit_open("/var/shadow/x", SEV_INFO);                /* NAME entry, inner, read */
  emit_open("/root/.ssh/known_hosts", SEV_INFO);
  EXPECT(trace_events.n == n && shed[3] == 12, "unlisted or inner-read name kept");
  /* WRITE: a read of /etc/hosts is shed, a write kept. */
  keep[nkeep] = name_hash("hosts"); keepval[nkeep++] = TRACE_KEEP_WRITE;
  emit_open("/etc/hosts", SEV_INFO);
  emit_open_flags("/etc/hosts", SEV_INFO, 2);
  EXPECT(trace_events.n == n + 1 && shed[3] == 13, "write-only entry");

  /* 7/8: every event below MEDIUM is shed, except credential changes. */
  trace_events.n = 112; n = 112;
  emit(13, SEV_LOW, TRACE_ACTION_MONITOR);  /* setuid to a non-root uid */
  emit(14, SEV_INFO, TRACE_ACTION_MONITOR); /* setgid */
  EXPECT(trace_events.n == n + 2 && shed[13] == 0 && shed[14] == 0, "credential change shed");
  emit(1, SEV_INFO, TRACE_ACTION_MONITOR);
  EXPECT(shed[1] == 1, "execve INFO not shed at 7/8");

  /* A Kill policy name still routes first; nothing is shed or kept twice. */
  n = trace_events.n;
  rules[3].enabled = 1; rules[3].min_severity = SEV_HIGH;
  names[nnames++] = name_hash("passwd"); ctl0.open_names = 1;
  emit_open("/etc//passwd", SEV_INFO);
  emit_open("/etc/passwd", SEV_INFO);
  EXPECT(trace_priority_events.n == 2 && trace_events.n == n, "kill-name route lost under pressure");
  emit_open("/etc//group", SEV_INFO);                  /* kept, not routed */
  emit_open("/tmp/flood", SEV_INFO);                   /* shed with names listed */
  EXPECT(trace_priority_events.n == 2 && trace_events.n == n + 1 && shed[3] == 14, "route/keep mixed up");
  EXPECT(stats[0] == 0, "an event was dropped");
  printf("shed open=%llu execve=%llu\n", (unsigned long long)shed[3], (unsigned long long)shed[1]);
  return failures != 0;
}
`)
	if !strings.Contains(out, "shed open=14 execve=1") {
		t.Fatalf("shed exemptions: %s", out)
	}
}

// TestTraceNoiseTypesMatchIngest: TRACE_NOISE_TYPES (wafio_trace.h) lists
// exactly the event types whose category is file and/or network only - the
// ones the control plane's noise filter (storeTraceEvent) does not store
// below MEDIUM. Process and security categories are always stored, so the
// kernel must not shed them at the first threshold.
func TestTraceNoiseTypesMatchIngest(t *testing.T) {
	out := runNativeC(t, "trace_noise_types", bpfSourceDefines(t, "wafio_trace.h", "TRACE_NOISE_TYPES")+`
int main(void) { printf("%u\n", (unsigned)TRACE_NOISE_TYPES); return 0; }
`)
	var want uint64
	for et, info := range TraceEventTypes {
		if info.Category&(CatFile|CatNetwork) != 0 && info.Category&(CatProcess|CatSecurity) == 0 {
			want |= 1 << et
		}
	}
	if got := strings.TrimSpace(out); got != strconv.FormatUint(want, 10) {
		t.Fatalf("TRACE_NOISE_TYPES = %s, want %d (file/network-only types)", got, want)
	}
}
