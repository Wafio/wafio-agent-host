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
// process is protected at once, exec keeps the protection only for an image
// listed by its file identity (never by comm), and the leader's exit drops the
// entry. Verifier acceptance and the real tracepoints are covered on the Linux
// lab, not here.
func TestTraceProtectedInheritance(t *testing.T) {
	source, err := os.ReadFile("bpf/wafio_trace.c")
	if err != nil {
		t.Fatal(err)
	}
	var c strings.Builder
	c.WriteString(`typedef uint32_t __u32; typedef uint64_t __u64; typedef uint8_t __u8; typedef int64_t __s64;
#define BPF_ANY 0
/* A read through a null pointer yields zero, as bpf_probe_read does. */
#define BPF_CORE_READ(t, f) ((t) ? (t)->f : 0)
#define TRACE_COMM_LEN 16
struct signal_struct { struct { int counter; } live; };
struct super_block { __u32 s_dev; };
struct inode { __u64 i_ino; struct super_block *i_sb; __u32 i_generation; };
struct file { struct inode *f_inode; };
struct mm_struct { struct file *exe_file; };
struct task_struct { __u32 pid, tgid; struct task_struct *group_leader; __u64 start_boottime; struct signal_struct *signal; struct mm_struct *mm; };
`)
	c.WriteString(bpfSourceStruct(t, "wafio_trace.c", "protected_image_key"))
	c.WriteString(`
/* A tiny map: linear table of fixed-size keys and values. */
struct mockmap { unsigned ksz, vsz, n; unsigned char k[64][16]; _Alignas(8) unsigned char v[64][8]; };
static struct mockmap trace_protected_tgids = { 4, 8 }, trace_protected_images = { 16, 1 }, trace_protected_budget = { 4, 8 };
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
	for _, name := range []string{"is_protected_tgid", "protected_inherit_refused", "protected_inherit_take", "protect_forked_child", "exec_image_key", "protect_on_exec", "protect_on_exit"} {
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
static void image(__u64 ino, __u32 dev, __u32 gen, __u8 flags) { struct protected_image_key k = { ino, dev, gen }; bpf_map_update_elem(&trace_protected_images, &k, &flags, BPF_ANY); }
static struct signal_struct alive = { { 1 } }, dead = { { 0 } };
static struct task_struct mk_task(__u32 pid, __u32 tgid, __u64 start) { struct task_struct t = { pid, tgid, NULL, start, &alive }; return t; }
static __s64 budget_slot(__u32 slot) { __s64 *v = bpf_map_lookup_elem(&trace_protected_budget, &slot); return v ? *v : -999; }
static void set_budget(__s64 n) { __u32 slot = TRACE_PROTECTED_BUDGET_SLOT; bpf_map_update_elem(&trace_protected_budget, &slot, &n, BPF_ANY); }
/* The task that execs: its mm->exe_file is the file with this identity. The
 * comm is what the process calls itself; the kernel code must not read it. */
static struct super_block exec_sb; static struct inode exec_inode; static struct file exec_file; static struct mm_struct exec_mm; static struct task_struct exec_task;
static void run_exec(__u32 tgid, __u64 ino, __u32 dev, __u32 gen, const char *comm, __u32 uid) {
  exec_sb.s_dev = dev; exec_inode.i_ino = ino; exec_inode.i_sb = &exec_sb; exec_inode.i_generation = gen;
  exec_file.f_inode = &exec_inode; exec_mm.exe_file = &exec_file; exec_task.mm = &exec_mm; cur_task = &exec_task;
  cur_pid_tgid = ((__u64)tgid << 32) | tgid; strncpy(cur_comm, comm, 15); cur_uid_gid = uid; protect_on_exec();
}

int main(void) {
  /* Device 259:2 (0x10300002), one inode generation per file. */
  const __u32 DEV = 0x10300002, OTHER_DEV = 0x10300003;
  const __u64 SSHD_SESSION = 1001, AGENT = 1002, NETWORKD = 1003, EXECUTOR = 1004;
  image(SSHD_SESSION, DEV, 7, TRACE_PROTECTED_IMAGE_ROOT); image(AGENT, DEV, 8, 0); image(NETWORKD, DEV, 9, 0); image(EXECUTOR, DEV, 10, TRACE_PROTECTED_IMAGE_ROOT);
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

  /* exec: a listed image as root keeps the entry ... */
  run_exec(200, SSHD_SESSION, DEV, 7, "sshd-session", 0);
  EXPECT(has(200), "exec of a root-only image as root dropped the protection");
  /* ... a file that is not listed loses it, whatever it calls itself, */
  const char *names[] = { "nginx", "sshd", "sshd-session", "wafio-waf-agent", "systemd-network", "23", "1", "" };
  for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++) {
    protect(210, 6500000000ULL);
    run_exec(210, 5000, DEV, 1, names[i], 0);
    EXPECT(!has(210), "exec of an unlisted image kept the entry because of its comm");
  }
  /* the same inode on another device, the same device with another inode, and
   * the same device and inode with another generation are other files, */
  protect(220, 6600000000ULL); run_exec(220, SSHD_SESSION, OTHER_DEV, 7, "sshd-session", 0);
  EXPECT(!has(220), "same inode on another device kept the entry");
  protect(220, 6600000000ULL); run_exec(220, SSHD_SESSION + 1, DEV, 7, "sshd-session", 0);
  EXPECT(!has(220), "same device with another inode kept the entry");
  protect(220, 6600000000ULL); run_exec(220, SSHD_SESSION, DEV, 8, "sshd-session", 0);
  EXPECT(!has(220), "same device and inode with another generation kept the entry");
  /* a root-only image as another user loses it, */
  run_exec(400, SSHD_SESSION, DEV, 7, "sshd-session", 998);
  EXPECT(!has(400), "non-root exec of a root-only image kept protection");
  /* and an image without the root requirement keeps it at any UID. */
  protect(500, 9000000000ULL);
  run_exec(500, AGENT, DEV, 8, "agentd", 998);
  EXPECT(has(500), "exec of a non-root image as a service account dropped protection");
  /* exec of a process that was never protected inserts nothing. */
  run_exec(600, SSHD_SESSION, DEV, 7, "sshd-session", 0);
  EXPECT(!has(600), "exec inserted an entry");

  /* systemd 255 and later: PID 1's child execs systemd-executor as
   * /proc/self/fd/<n>, so its comm is a number. The executor file is listed
   * like any other image, and the exec of the service binary decides next. */
  protect(700, 9100000000ULL);
  run_exec(700, EXECUTOR, DEV, 10, "16", 0);
  EXPECT(has(700), "root exec of the systemd-executor image dropped the entry");
  run_exec(700, 4242, DEV, 3, "systemd-network", 998);
  EXPECT(!has(700), "a fake systemd-network as a service account kept the entry");
  protect(701, 9200000000ULL);
  run_exec(701, EXECUTOR, DEV, 10, "17", 0);
  run_exec(701, NETWORKD, DEV, 9, "systemd-network", 998);
  EXPECT(has(701), "the real systemd-networkd image as its service account dropped the entry");
  /* A unit that runs a file with a numeric name as root is not the executor. */
  protect(702, 9300000000ULL);
  run_exec(702, 4243, DEV, 3, "1", 0);
  EXPECT(!has(702), "a root exec of an unlisted file with a numeric comm kept the entry");
  protect(702, 9300000000ULL);
  run_exec(702, EXECUTOR, DEV, 10, "2a", 998);
  EXPECT(!has(702), "the executor image as a non-root user kept the entry");

  /* A read that fails leaves a zero key: nothing matches it, not even an
   * image the table holds. */
  protect(710, 9400000000ULL);
  { struct task_struct t = mk_task(710, 710, 9400000000ULL); cur_task = &t; cur_pid_tgid = ((__u64)710 << 32) | 710; cur_uid_gid = 0; protect_on_exec(); }
  EXPECT(!has(710), "an exec whose image could not be read kept the entry");

  /* An empty table drops everything. */
  trace_protected_images.n = 0;
  protect(720, 9500000000ULL);
  run_exec(720, SSHD_SESSION, DEV, 7, "sshd-session", 0);
  EXPECT(!has(720), "an exec kept the entry with no image listed");
  image(SSHD_SESSION, DEV, 7, TRACE_PROTECTED_IMAGE_ROOT);

  /* A forked child that changes its UID without exec keeps its entry: it still
   * runs the verified binary's code, and the refresh decides. */
  struct task_struct priv = mk_task(800, 800, 9600000000ULL); priv.group_leader = &priv;
  protect(800, 9600000000ULL);
  struct task_struct dropped = mk_task(801, 801, 9700000000ULL); dropped.group_leader = &dropped;
  set_budget(2);
  protect_forked_child(&priv, &dropped);
  EXPECT(has(801), "child of a protected process not inherited");
  cur_uid_gid = 1000; /* setuid without exec: no kernel hook looks at it */
  EXPECT(has(801), "a UID change dropped the inherited entry");

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

	// A fork child keeps its entry through a UID change (the dropped child of
	// sshd-session still runs that binary): nothing but fork, exec and exit may
	// write the map, so no setuid hook can drop an entry.
	for _, write := range []string{"bpf_map_update_elem(&trace_protected_tgids", "bpf_map_delete_elem(&trace_protected_tgids"} {
		inHelpers := 0
		for _, name := range []string{"protect_forked_child", "protect_on_exec", "protect_on_exit"} {
			inHelpers += strings.Count(bpfSourceHelper(t, "wafio_trace.c", name), write)
		}
		if total := strings.Count(string(source), write); total != inHelpers {
			t.Errorf("%s: %d writes in wafio_trace.c, %d in the fork, exec and exit helpers", write, total, inHelpers)
		}
	}
}
