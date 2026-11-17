package ebpf

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestTraceProtectedInheritance compiles the kernel-side protected-set
// helpers of wafio_trace.c natively, with only the BPF helpers and maps
// mocked, and checks the kernel-side lifecycle: a child forked by a protected
// process is protected at once, exec keeps the protection only for a
// protected image, and the leader's exit drops the entry. Verifier acceptance
// and the real tracepoints are covered on the Linux lab, not here.
func TestTraceProtectedInheritance(t *testing.T) {
	source, err := os.ReadFile("bpf/wafio_trace.c")
	if err != nil {
		t.Fatal(err)
	}
	var c strings.Builder
	c.WriteString(`typedef uint32_t __u32; typedef uint64_t __u64; typedef uint8_t __u8; typedef int64_t __s64;
#define BPF_ANY 0
#define BPF_CORE_READ(t, f) ((t)->f)
struct signal_struct { struct { int counter; } live; };
struct task_struct { __u32 pid, tgid; struct task_struct *group_leader; __u64 start_boottime; struct signal_struct *signal; };
struct protected_comm_key { char comm[16]; };

/* A tiny map: linear table of fixed-size keys and values. */
struct mockmap { unsigned ksz, vsz, n; unsigned char k[64][16]; _Alignas(8) unsigned char v[64][8]; };
static struct mockmap trace_protected_tgids = { 4, 8 }, trace_protected_comms = { 16, 1 }, trace_protected_budget = { 4, 8 };
static int slot(struct mockmap *m, const void *key) { for (unsigned i = 0; i < m->n; i++) if (!memcmp(m->k[i], key, m->ksz)) return (int)i; return -1; }
static void *bpf_map_lookup_elem(void *map, const void *key) { struct mockmap *m = map; int i = slot(m, key); return i < 0 ? NULL : m->v[i]; }
static long bpf_map_update_elem(void *map, const void *key, const void *val, __u64 flags) { struct mockmap *m = map; (void)flags; int i = slot(m, key); if (i < 0) { i = (int)m->n++; memcpy(m->k[i], key, m->ksz); } memcpy(m->v[i], val, m->vsz); return 0; }
static long bpf_map_delete_elem(void *map, const void *key) { struct mockmap *m = map; int i = slot(m, key); if (i < 0) return -2; m->n--; memmove(m->k[i], m->k[m->n], m->ksz); memmove(m->v[i], m->v[m->n], m->vsz); return 0; }

static __u64 cur_pid_tgid, cur_uid_gid; static char cur_comm[16]; static struct task_struct *cur_task;
static __u64 bpf_get_current_pid_tgid(void) { return cur_pid_tgid; }
static __u64 bpf_get_current_uid_gid(void) { return cur_uid_gid; }
static long bpf_get_current_comm(void *buf, __u32 size) { memset(buf, 0, size); strncpy(buf, cur_comm, size - 1); return 0; }
static void *bpf_get_current_task(void) { return cur_task; }
`)
	for _, line := range strings.Split(string(source), "\n") {
		if strings.HasPrefix(line, "#define TRACE_NSEC_PER_USER_HZ_TICK") || strings.HasPrefix(line, "#define TRACE_PROTECTED_") {
			c.WriteString(line + "\n")
		}
	}
	for _, name := range []string{"is_protected_tgid", "protected_inherit_refused", "protected_inherit_take", "protect_forked_child", "protect_on_exec", "protect_on_exit"} {
		body := regexp.MustCompile(`(?s)static __always_inline \w+\s*\n?` + name + `\(.*?\n\}`).FindString(string(source))
		if body == "" {
			t.Fatalf("missing helper %s", name)
		}
		c.WriteString(body + "\n")
	}
	c.WriteString(`static int failures;
#define EXPECT(cond, msg) do { if (!(cond)) { fprintf(stderr, "%s\n", msg); failures++; } } while (0)
static int has(__u32 tgid) { return bpf_map_lookup_elem(&trace_protected_tgids, &tgid) != NULL; }
static void protect(__u32 tgid, __u64 start_ns) { __u64 ticks = start_ns / TRACE_NSEC_PER_USER_HZ_TICK; bpf_map_update_elem(&trace_protected_tgids, &tgid, &ticks, BPF_ANY); }
static void comm(const char *name, __u8 flags) { struct protected_comm_key k; memset(&k, 0, sizeof k); strncpy(k.comm, name, 15); bpf_map_update_elem(&trace_protected_comms, &k, &flags, BPF_ANY); }
static struct signal_struct alive = { { 1 } }, dead = { { 0 } };
static struct task_struct mk_task(__u32 pid, __u32 tgid, __u64 start) { struct task_struct t = { pid, tgid, NULL, start, &alive }; return t; }
static __s64 budget_slot(__u32 slot) { __s64 *v = bpf_map_lookup_elem(&trace_protected_budget, &slot); return v ? *v : -999; }
static void set_budget(__s64 n) { __u32 slot = TRACE_PROTECTED_BUDGET_SLOT; bpf_map_update_elem(&trace_protected_budget, &slot, &n, BPF_ANY); }
static void run_exec(__u32 tgid, const char *name, __u32 uid) { cur_pid_tgid = ((__u64)tgid << 32) | tgid; strncpy(cur_comm, name, 15); cur_uid_gid = uid; protect_on_exec(); }

int main(void) {
  comm("sshd", TRACE_PROTECTED_COMM_ROOT); comm("sshd-session", TRACE_PROTECTED_COMM_ROOT); comm("agentd", 0);
  { __s64 zero = 0; __u32 refused = TRACE_PROTECTED_REFUSED_SLOT; bpf_map_update_elem(&trace_protected_budget, &refused, &zero, BPF_ANY); }

  /* No budget (before the first refresh, or an agent that never writes it):
   * nothing is inherited, and the refusal is counted. */
  set_budget(0);
  {
    struct task_struct p = mk_task(1, 1, 1); p.group_leader = &p;
    struct task_struct c = mk_task(150, 150, 5500000000ULL); c.group_leader = &c;
    protect_forked_child(&p, &c);
    EXPECT(!has(150), "inherited without budget");
    EXPECT(budget_slot(TRACE_PROTECTED_REFUSED_SLOT) == 1, "refused insert not counted");
    EXPECT(budget_slot(TRACE_PROTECTED_BUDGET_SLOT) == 0, "empty budget went negative");
  }
  set_budget(3);

  /* sshd (100) is protected; its forked child (200) is protected at once. */
  struct task_struct sshd = mk_task(100, 100, 5000000000ULL); sshd.group_leader = &sshd;
  protect(100, sshd.start_boottime);
  struct task_struct child = mk_task(200, 200, 6000000000ULL); child.group_leader = &child;
  protect_forked_child(&sshd, &child);
  EXPECT(has(200), "child of a protected process not inherited");
  EXPECT(is_protected_tgid(200, child.start_boottime), "inherited entry does not carry the child's start ticks");

  /* A new thread of the protected process adds nothing. */
  struct task_struct thread = mk_task(101, 100, 5000000000ULL); thread.group_leader = &sshd;
  protect_forked_child(&sshd, &thread);
  EXPECT(!has(101), "thread TID inserted as a process");

  /* An unprotected parent, or a stale entry for the parent's PID, grants nothing. */
  struct task_struct bash = mk_task(300, 300, 7000000000ULL); bash.group_leader = &bash;
  struct task_struct bash_child = mk_task(301, 301, 7100000000ULL); bash_child.group_leader = &bash_child;
  protect_forked_child(&bash, &bash_child);
  EXPECT(!has(301), "child of an unprotected parent inherited protection");
  protect(300, 1000000000ULL); /* PID 300 was a protected process that exited */
  protect_forked_child(&bash, &bash_child);
  EXPECT(!has(301), "stale parent entry (start time mismatch) was inherited");

  /* PID 1 is guarded by number; its children run init's image until exec. */
  struct task_struct init = mk_task(1, 1, 1); init.group_leader = &init;
  struct task_struct svc = mk_task(400, 400, 8000000000ULL); svc.group_leader = &svc;
  protect_forked_child(&init, &svc);
  EXPECT(has(400), "child of PID 1 not inherited");

  /* The budget (3) is spent by the inserts above (200, 400) plus one; the
   * next fork of a protected parent is refused and counted. */
  struct task_struct svc2 = mk_task(401, 401, 8100000000ULL); svc2.group_leader = &svc2;
  protect_forked_child(&init, &svc2);
  EXPECT(has(401), "third insert within budget refused");
  struct task_struct svc3 = mk_task(402, 402, 8200000000ULL); svc3.group_leader = &svc3;
  protect_forked_child(&init, &svc3);
  EXPECT(!has(402), "insert beyond the budget accepted");
  EXPECT(budget_slot(TRACE_PROTECTED_REFUSED_SLOT) == 2, "refusal beyond the budget not counted");

  /* exec: a protected image as root keeps the entry ... */
  run_exec(200, "sshd-session", 0);
  EXPECT(has(200), "exec of sshd-session as root dropped the protection");
  /* ... the user's shell loses it, */
  run_exec(200, "bash", 0);
  EXPECT(!has(200), "exec of bash kept the inherited protection");
  /* a protected name as non-root loses it, */
  run_exec(400, "sshd", 1000);
  EXPECT(!has(400), "non-root exec of a root-only protected name kept protection");
  /* and a configured exe basename without the root requirement keeps it. */
  protect(500, 9000000000ULL);
  run_exec(500, "agentd", 1000);
  EXPECT(has(500), "exec of a configured non-root protected binary dropped protection");
  /* exec of a process that was never protected inserts nothing. */
  run_exec(600, "sshd", 0);
  EXPECT(!has(600), "exec inserted an entry");

  /* exit: only when the whole thread group is gone, and only for the
   * entry's own process. */
  struct task_struct leader = mk_task(500, 500, 9000000000ULL); leader.group_leader = &leader;
  struct task_struct worker = mk_task(501, 500, 9000000000ULL); worker.group_leader = &leader;
  cur_task = &leader; cur_pid_tgid = ((__u64)500 << 32) | 500; protect_on_exit();
  EXPECT(has(500), "the leader's exit (pthread_exit from main) dropped a live process's entry");
  cur_task = &worker; cur_pid_tgid = ((__u64)500 << 32) | 501; protect_on_exit();
  EXPECT(has(500), "a thread's exit dropped a live process's entry");
  struct task_struct other = mk_task(500, 500, 9900000000ULL); other.group_leader = &other; other.signal = &dead;
  cur_task = &other; cur_pid_tgid = ((__u64)500 << 32) | 500; protect_on_exit();
  EXPECT(has(500), "exit of a different process with the same PID dropped the entry");
  leader.signal = &dead; worker.signal = &dead;
  cur_task = &worker; cur_pid_tgid = ((__u64)500 << 32) | 501; protect_on_exit();
  EXPECT(!has(500), "the last thread's exit left the entry behind");
  return failures != 0;
}
`)
	runNativeC(t, "protected_set_lifecycle", c.String())
}
