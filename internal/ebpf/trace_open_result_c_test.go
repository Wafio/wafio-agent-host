package ebpf

import (
	"strings"
	"testing"
)

// The open event waits for its result (trace_open_submit, trace_open_exit,
// trace_open_release of wafio_trace.c), compiled natively with the maps and the
// rings mocked: pending map of three elements, shared ring of three records,
// kill-candidate ring of two. The verifier and the kernel are covered in the
// lab.
func TestTraceOpenResultPending(t *testing.T) {
	out := tracePriorityHarness(t, `
static void enter_open_kind(const char *path, __u32 sev, __u32 action, __u32 kind) {
  struct wafio_event e = { TRACE_EVENT_OPEN, sev, action, 0, "" };
  strncpy(e.filename, path, TRACE_FILENAME_LEN - 1);
  trace_open_release_stale(); /* the first step of trace_open_path */
  trace_open_submit(&e, kind);
}
static void enter_open(const char *path, __u32 sev) {
  enter_open_kind(path, sev, TRACE_ACTION_MONITOR, TRACE_OPEN_KIND_OPENAT);
}
static void setup(int defer) {
  reset();
  cfg0.enabled = 1; cfg0.event_mask_lo = 0xffffffffu; cfg0.min_severity = SEV_INFO;
  memset(&ctl0, 0, sizeof ctl0); memset(rules, 0, sizeof rules);
  open_ctl0.defer = defer; current_tid = 100;
}
int main(void) {
  /* One event per open, leaving when the open returns, with its result. */
  setup(1);
  enter_open("/etc/hostname", SEV_INFO);
  EXPECT(trace_events.n == 0 && pending_count() == 1, "an open was exported before it returned");
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, 7);
  EXPECT(trace_events.n == 1 && trace_events.ret[0] == 7, "result of a successful open lost");
  EXPECT(trace_events.flags[0] & TRACE_EVT_OPEN_RESULT, "result not marked");
  EXPECT(trace_events.aux[0] == 0, "the kind of the open leaked into the event");
  EXPECT(pending_count() == 0 && open_stats[TRACE_OPEN_RESULT] == 1, "pending open not released");
  enter_open("/etc/shadow", SEV_INFO);
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, -13);
  EXPECT(trace_events.n == 2 && trace_events.ret[1] == -13 && (trace_events.flags[1] & TRACE_EVT_OPEN_RESULT), "denied open lost its errno");
  enter_open("/home/u/.ssh/id_rsa", SEV_INFO);
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, -2);
  EXPECT(trace_events.n == 3 && trace_events.ret[2] == -2 && (trace_events.flags[2] & TRACE_EVT_OPEN_RESULT), "open of a missing file lost its errno");
  /* A thread with nothing pending (an open traced before the agent armed, or
   * one the kernel shed) exports nothing at exit. */
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, 3);
  EXPECT(trace_events.n == 3, "an exit without an open exported an event");

  /* Not armed (older agent, an exit probe that failed to attach): the event
   * leaves at entry as before, without a result. */
  setup(0);
  enter_open("/etc/hostname", SEV_INFO);
  EXPECT(trace_events.n == 1 && pending_count() == 0, "unarmed open was held");
  EXPECT(trace_events.ret[0] == 0 && !(trace_events.flags[0] & TRACE_EVT_OPEN_RESULT), "unarmed open claims a result");
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, 5);
  EXPECT(trace_events.n == 1, "exit probe exported an unarmed open twice");

  /* The map is full: the open leaves at entry without a result, the ones
   * already waiting still leave once, with theirs. */
  setup(1);
  for (current_tid = 1; current_tid <= 3; current_tid++) enter_open("/tmp/a", SEV_INFO);
  EXPECT(pending_count() == 3 && trace_events.n == 0, "pending map not filled");
  current_tid = 4;
  enter_open("/tmp/b", SEV_INFO);
  EXPECT(trace_events.n == 1 && trace_events.ret[0] == 0 && !(trace_events.flags[0] & TRACE_EVT_OPEN_RESULT), "open refused by a full map was not exported at entry");
  EXPECT(trace_events.aux[0] == 0, "refused open kept its kind");
  EXPECT(open_stats[TRACE_OPEN_NO_FULL] == 1, "full map not counted");
  trace_events.n = 0;
  for (current_tid = 1; current_tid <= 3; current_tid++) trace_open_exit(TRACE_OPEN_KIND_OPENAT, 10 + (__s64)current_tid);
  EXPECT(trace_events.n == 3 && pending_count() == 0, "waiting opens lost behind a full map");
  EXPECT(trace_events.ret[0] == 11 && trace_events.ret[2] == 13, "waiting opens got another thread's result");
  current_tid = 4; trace_open_exit(TRACE_OPEN_KIND_OPENAT, 9);
  EXPECT(trace_events.n == 3, "the open that left at entry left again at exit");

  /* The thread opens again before its exit probe ran: the older open leaves
   * first, without a result, and the new one waits. */
  setup(1);
  enter_open("/tmp/first", SEV_INFO);
  enter_open("/tmp/second", SEV_INFO);
  EXPECT(trace_events.n == 1 && trace_events.ret[0] == 0 && !(trace_events.flags[0] & TRACE_EVT_OPEN_RESULT), "older open not flushed");
  EXPECT(pending_count() == 1 && open_stats[TRACE_OPEN_NO_NEXT] == 1, "older open not counted");
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, 4);
  EXPECT(trace_events.n == 2 && trace_events.ret[1] == 4 && (trace_events.flags[1] & TRACE_EVT_OPEN_RESULT), "newer open lost its result");

  /* The next open of the thread is dropped (shed here) after its exit probe
   * missed the first: the first must leave at that entry, so the result of an
   * open nobody recorded cannot land on it. */
  setup(1);
  enter_open("/tmp/first", SEV_INFO);
  trace_events.n = 3; /* shared ring full: INFO file events are shed from here */
  enter_open("/tmp/noise", SEV_INFO);
  EXPECT(shed[TRACE_EVENT_OPEN] == 1, "second open not shed");
  EXPECT(pending_count() == 0 && open_stats[TRACE_OPEN_NO_NEXT] == 1, "stale open kept by a dropped next open");
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, 6);
  EXPECT(open_stats[TRACE_OPEN_RESULT] == 0, "result of a dropped open attached to the stale one");

  /* An exit of another kind than the waiting open: the open lost its exit,
   * the result is not its own. */
  setup(1);
  enter_open_kind("/tmp/x", SEV_INFO, TRACE_ACTION_MONITOR, TRACE_OPEN_KIND_OPENAT);
  trace_open_exit(TRACE_OPEN_KIND_CREAT, 8);
  EXPECT(trace_events.n == 1 && trace_events.ret[0] == 0 && !(trace_events.flags[0] & TRACE_EVT_OPEN_RESULT), "result of another syscall attached");
  EXPECT(pending_count() == 0 && open_stats[TRACE_OPEN_NO_NEXT] == 1, "open of another kind not released");
  for (__u32 kind = TRACE_OPEN_KIND_OPENAT; kind <= TRACE_OPEN_KIND_CREAT; kind++) {
    setup(1);
    enter_open_kind("/tmp/x", SEV_INFO, TRACE_ACTION_MONITOR, kind);
    trace_open_exit(kind, 21);
    EXPECT(trace_events.n == 1 && trace_events.ret[0] == 21 && (trace_events.flags[0] & TRACE_EVT_OPEN_RESULT), "exit of its own kind lost");
  }

  /* A full map and a repeated open together: the stale element is released
   * first, so the new open still waits. */
  setup(1);
  for (current_tid = 1; current_tid <= 3; current_tid++) enter_open("/tmp/a", SEV_INFO);
  current_tid = 2; enter_open("/tmp/again", SEV_INFO);
  EXPECT(trace_events.n == 1 && pending_count() == 3 && open_stats[TRACE_OPEN_NO_FULL] == 0, "repeated open on a full map");

  /* The thread exits inside the open: it leaves without a result. */
  setup(1);
  enter_open("/tmp/blocked", SEV_INFO);
  trace_open_flush();
  EXPECT(trace_events.n == 1 && !(trace_events.flags[0] & TRACE_EVT_OPEN_RESULT) && pending_count() == 0, "open of an exiting thread lost");
  EXPECT(open_stats[TRACE_OPEN_NO_EXIT] == 1, "thread exit not counted");
  trace_open_flush();
  EXPECT(trace_events.n == 1, "a thread with nothing pending exported at exit");

  /* A signal ended the open and the kernel runs it again: the exit probe
   * sees a restart code, which is not a result. The open leaves as an attempt
   * and the restart enters as a new open. */
  for (__s64 code = -TRACE_ERESTART_FIRST; code >= -TRACE_ERESTART_LAST; code--) {
    setup(1);
    enter_open("/etc/shadow", SEV_HIGH);
    trace_open_exit(TRACE_OPEN_KIND_OPENAT, code);
    EXPECT(trace_events.n == 1 && trace_events.ret[0] == 0 && !(trace_events.flags[0] & TRACE_EVT_OPEN_RESULT), "restart code reported as a result");
    EXPECT(pending_count() == 0 && open_stats[TRACE_OPEN_NO_RESTART] == 1 && open_stats[TRACE_OPEN_RESULT] == 0, "restarted open not counted");
    enter_open("/etc/shadow", SEV_HIGH);
    trace_open_exit(TRACE_OPEN_KIND_OPENAT, 5);
    EXPECT(trace_events.n == 2 && trace_events.ret[1] == 5 && (trace_events.flags[1] & TRACE_EVT_OPEN_RESULT), "restarted open lost its real result");
  }
  /* Errnos next to the restart codes are results. */
  setup(1);
  enter_open("/tmp/x", SEV_INFO);
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, -(__s64)(TRACE_ERESTART_FIRST - 1));
  EXPECT(trace_events.n == 1 && (trace_events.flags[0] & TRACE_EVT_OPEN_RESULT) && trace_events.ret[0] == -511, "errno below the restart codes dropped");
  setup(1);
  enter_open("/tmp/x", SEV_INFO);
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, -(__s64)(TRACE_ERESTART_LAST + 1));
  EXPECT(trace_events.n == 1 && (trace_events.flags[0] & TRACE_EVT_OPEN_RESULT) && trace_events.ret[0] == -517, "errno above the restart codes dropped");

  /* A kill candidate does not wait: a userspace Kill policy must be able to
   * act while a slow open is still blocked. It leaves on the priority ring at
   * entry, without a result. */
  setup(1);
  ctl0.attached = 1; rules[3].enabled = 1; rules[3].min_severity = SEV_HIGH;
  enter_open("/etc/shadow", SEV_HIGH);
  EXPECT(trace_priority_events.n == 1 && trace_events.n == 0 && pending_count() == 0, "candidate held for its result");
  EXPECT(!(trace_priority_events.flags[0] & TRACE_EVT_OPEN_RESULT) && trace_priority_events.ret[0] == 0, "candidate claims a result");
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, -2);
  EXPECT(trace_priority_events.n == 1 && trace_events.n == 0, "candidate exported again at exit");
  /* below the policy's severity it is an ordinary open and waits */
  enter_open("/etc/hostname", SEV_INFO);
  EXPECT(trace_priority_events.n == 1 && pending_count() == 1, "ordinary open not held next to a Kill policy");
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, 3);
  EXPECT(trace_events.n == 1 && trace_events.ret[0] == 3, "ordinary open lost its result next to a Kill policy");

  /* A kernel Kill acts at entry and the process dies when the syscall ends:
   * the event leaves at once, without a result, with or without the priority
   * ring (the signal is accepted or refused either way). */
  for (int attached = 0; attached <= 1; attached++) {
    setup(1);
    ctl0.attached = attached;
    enter_open_kind("/etc/shadow", SEV_HIGH, TRACE_ACTION_KILL, TRACE_OPEN_KIND_OPENAT);
    EXPECT(pending_count() == 0 && trace_priority_events.n + trace_events.n == 1, "kernel Kill open held for its result");
    __u32 fl = attached ? trace_priority_events.flags[0] : trace_events.flags[0];
    __s64 rv = attached ? trace_priority_events.ret[0] : trace_events.ret[0];
    EXPECT(!(fl & TRACE_EVT_OPEN_RESULT) && rv == 0, "kernel Kill open claims a result");
    trace_open_exit(TRACE_OPEN_KIND_OPENAT, 3);
    EXPECT(trace_priority_events.n + trace_events.n == 1, "kernel Kill open exported again at exit");
  }
  /* The other actions wait: a Block shows the errno the LSM returned. */
  setup(1);
  enter_open_kind("/etc/shadow", SEV_HIGH, TRACE_ACTION_BLOCK, TRACE_OPEN_KIND_OPENAT);
  EXPECT(pending_count() == 1, "blocked open not held");
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, -1);
  EXPECT(trace_events.n == 1 && trace_events.ret[0] == -1 && (trace_events.flags[0] & TRACE_EVT_OPEN_RESULT), "blocked open lost its errno");

  /* kind 0: the exit probe of this open will not run (x32 task on a kprobe
   * twin). It leaves at entry like an unarmed open, and does not disturb a
   * later open of the thread. */
  setup(1);
  enter_open_kind("/tmp/x32", SEV_INFO, TRACE_ACTION_MONITOR, 0);
  EXPECT(trace_events.n == 1 && pending_count() == 0, "open without an exit probe was held");
  EXPECT(!(trace_events.flags[0] & TRACE_EVT_OPEN_RESULT) && trace_events.ret[0] == 0, "open without an exit probe claims a result");
  enter_open("/tmp/native", SEV_INFO);
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, 4);
  EXPECT(trace_events.n == 2 && trace_events.ret[1] == 4, "open after an x32 open lost its result");

  /* What the kernel dropped before stays dropped: never held, never exported. */
  setup(1);
  trace_events.n = 3; /* shared ring full: INFO file events are shed */
  enter_open("/tmp/noise", SEV_INFO);
  EXPECT(pending_count() == 0 && shed[TRACE_EVENT_OPEN] == 1, "shed open was held");
  trace_open_exit(TRACE_OPEN_KIND_OPENAT, 3);
  EXPECT(trace_events.n == 3, "shed open exported at exit");
  setup(1);
  cfg0.event_mask_lo = ~(1u << (TRACE_EVENT_OPEN - 1));
  enter_open("/tmp/masked", SEV_INFO);
  EXPECT(pending_count() == 0 && trace_events.n == 0, "masked open was held");
  printf("ok\n");
  return failures != 0;
}
`)
	if !strings.Contains(out, "ok") {
		t.Fatal(out)
	}
}

// The first thing an open entry does is release the open its thread left
// waiting; a drop decision before that would keep the stale event alive for the
// next open that is traced.
func TestTraceOpenPathReleasesStaleFirst(t *testing.T) {
	body := bpfSourceHelper(t, "wafio_trace.c", "trace_open_path")
	release := strings.Index(body, "trace_open_release_stale()")
	for _, drop := range []string{"should_trace(", "new_event(", "trace_open_submit("} {
		at := strings.Index(body, drop)
		if at < 0 {
			t.Fatalf("trace_open_path no longer calls %s", drop)
		}
		if release < 0 || release > at {
			t.Errorf("trace_open_path reaches %s before releasing the thread's waiting open", drop)
		}
	}
}
