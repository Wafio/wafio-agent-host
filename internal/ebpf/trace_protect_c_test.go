package ebpf

import (
	"os"
	"strings"
	"testing"
)

// TestTraceProtectedInheritance compiles the kernel-side protected-set
// helpers of wafio_trace.c natively, with only the BPF helpers, maps and kernel
// structures mocked, and checks the kernel-side lifecycle: a child forked by a
// protected process is protected at once, exec keeps the protection only for an
// image listed by its file identity (never by comm) and only when the task meets
// the condition of that image (root, or the systemd unit), a task that gives up
// root without exec keeps it only under the same condition (a child of PID 1
// is left to its exec), the leader's exit drops the entry, and every entry the
// kernel drops gives its budget unit back.
// Verifier acceptance and the real tracepoints are covered on the Linux lab,
// not here.
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
/* A kernel without a field has the guard say so. */
static int missing_field;
#define bpf_core_field_exists(f) (!missing_field)
#define TRACE_COMM_LEN 16
struct signal_struct { struct { int counter; } live; };
struct super_block { __u32 s_dev; };
struct inode { __u64 i_ino; struct super_block *i_sb; __u32 i_generation; };
struct file { struct inode *f_inode; };
struct mm_struct { struct file *exe_file; };
struct kernfs_node { const char *name; };
struct cgroup;
struct cgroup_subsys_state { struct cgroup *cgroup; struct cgroup_subsys_state *parent; };
struct cgroup { struct cgroup_subsys_state self; int level; struct kernfs_node *kn; };
struct css_set { struct cgroup *dfl_cgrp; };
struct task_struct { __u32 pid, tgid; struct task_struct *group_leader; __u64 start_boottime; struct signal_struct *signal; struct mm_struct *mm; struct css_set *cgroups; struct task_struct *real_parent; };
`)
	c.WriteString(bpfSourceDefines(t, "wafio_trace.c", "TRACE_NSEC_PER_USER_HZ_TICK", "TRACE_PROTECTED_", "TRACE_UNIT_NAME_LEN"))
	c.WriteString(bpfSourceStruct(t, "wafio_trace.c", "protected_image_key"))
	c.WriteString(bpfSourceStruct(t, "wafio_trace.c", "protected_image"))
	c.WriteString(`
/* A tiny map: linear table of fixed-size keys and values. */
struct mockmap { unsigned ksz, vsz, n; unsigned char k[64][16]; _Alignas(8) unsigned char v[64][64]; };
static struct mockmap trace_protected_tgids = { 4, 8 }, trace_protected_images = { 16, sizeof(struct protected_image) }, trace_protected_budget = { 4, 8 };
static int fail_update, fail_delete;
static int slot(struct mockmap *m, const void *key) { for (unsigned i = 0; i < m->n; i++) if (!memcmp(m->k[i], key, m->ksz)) return (int)i; return -1; }
static void *bpf_map_lookup_elem(void *map, const void *key) { struct mockmap *m = map; int i = slot(m, key); return i < 0 ? NULL : m->v[i]; }
static long bpf_map_update_elem(void *map, const void *key, const void *val, __u64 flags) { struct mockmap *m = map; (void)flags; if (fail_update) return -7; int i = slot(m, key); if (i < 0) { i = (int)m->n++; memcpy(m->k[i], key, m->ksz); } memcpy(m->v[i], val, m->vsz); return 0; }
static long bpf_map_delete_elem(void *map, const void *key) { struct mockmap *m = map; int i = slot(m, key); if (i < 0 || fail_delete) return -2; m->n--; memmove(m->k[i], m->k[m->n], m->ksz); memmove(m->v[i], m->v[m->n], m->vsz); return 0; }

static __u64 cur_pid_tgid, cur_uid_gid; static char cur_comm[16]; static struct task_struct *cur_task;
static __u64 bpf_get_current_pid_tgid(void) { return cur_pid_tgid; }
static __u64 bpf_get_current_uid_gid(void) { return cur_uid_gid; }
static long bpf_get_current_comm(void *buf, __u32 size) { memset(buf, 0, size); strncpy(buf, cur_comm, size - 1); return 0; }
static void *bpf_get_current_task(void) { return cur_task; }
/* Copies like the helper: at most size - 1 bytes, always NUL terminated, the
 * length with the NUL on success. */
static int fail_str_read;
static long bpf_probe_read_kernel_str(void *dst, __u32 size, const void *src) { if (fail_str_read || !src) return -14; strncpy(dst, src, size - 1); ((char *)dst)[size - 1] = 0; return (long)strlen(dst) + 1; }
`)
	for _, name := range []string{"is_protected_tgid", "protected_inherit_refused", "protected_inherit_take", "protected_inherit_give", "protect_forked_child", "exec_image_key", "cgroup_dir_name", "task_in_unit", "protected_image_keeps", "protect_on_exec", "protect_on_setuid", "protect_on_exit"} {
		c.WriteString(bpfSourceHelper(t, "wafio_trace.c", name) + "\n")
	}
	c.WriteString(protectedLifecycleC)
	runNativeC(t, "protected_set_lifecycle", c.String())

	// Nothing but fork, exec, the UID calls and exit may write the map.
	for _, write := range []string{"bpf_map_update_elem(&trace_protected_tgids", "bpf_map_delete_elem(&trace_protected_tgids"} {
		inHelpers := 0
		for _, name := range []string{"protect_forked_child", "protect_on_exec", "protect_on_setuid", "protect_on_exit"} {
			inHelpers += strings.Count(bpfSourceHelper(t, "wafio_trace.c", name), write)
		}
		if total := strings.Count(string(source), write); total != inHelpers {
			t.Errorf("%s: %d writes in wafio_trace.c, %d in the fork, exec, setuid and exit helpers", write, total, inHelpers)
		}
	}
}

// protectedLifecycleC is the main of the native harness, after the mocks and
// the helpers of wafio_trace.c.
const protectedLifecycleC = `
static int failures;
#define EXPECT(cond, msg) do { if (!(cond)) { fprintf(stderr, "%s\n", msg); failures++; } } while (0)
static int has(__u32 tgid) { return bpf_map_lookup_elem(&trace_protected_tgids, &tgid) != NULL; }
static void protect(__u32 tgid, __u64 start_ns) { __u64 ticks = start_ns / TRACE_NSEC_PER_USER_HZ_TICK; bpf_map_update_elem(&trace_protected_tgids, &tgid, &ticks, BPF_ANY); }
static void image(__u64 ino, __u32 dev, __u32 gen, __u64 flags, const char *unit) {
  struct protected_image_key k = { ino, dev, gen }; struct protected_image v = { flags };
  if (unit) strncpy(v.unit, unit, sizeof v.unit - 1);
  bpf_map_update_elem(&trace_protected_images, &k, &v, BPF_ANY);
}
static struct signal_struct alive = { { 1 } }, dead = { { 0 } };
static struct task_struct mk_task(__u32 pid, __u32 tgid, __u64 start) { struct task_struct t = { pid, tgid, NULL, start, &alive }; return t; }
static __s64 budget_slot(__u32 slot) { __s64 *v = bpf_map_lookup_elem(&trace_protected_budget, &slot); return v ? *v : -999; }
static void set_slot(__u32 slot, __s64 n) { bpf_map_update_elem(&trace_protected_budget, &slot, &n, BPF_ANY); }
/* What the refresh writes: the budget and the most it may hold. */
static void set_budget(__s64 n) { set_slot(TRACE_PROTECTED_LIMIT_SLOT, n); set_slot(TRACE_PROTECTED_BUDGET_SLOT, n); }
static __s64 budget(void) { return budget_slot(TRACE_PROTECTED_BUDGET_SLOT); }
/* The task that execs: its mm->exe_file is the file with this identity and its
 * cgroup of the default hierarchy is /<slice>/<unit> at the given level (the
 * slice is the parent). The comm is what the process calls itself; the kernel
 * code must not read it. */
static struct super_block exec_sb; static struct inode exec_inode; static struct file exec_file; static struct mm_struct exec_mm; static struct task_struct exec_task;
static struct kernfs_node kn_unit, kn_slice; static struct cgroup cg_unit, cg_slice; static struct css_set cset;
static void in_cgroup(const char *unit, int level, const char *slice) {
  kn_unit.name = unit; kn_slice.name = slice;
  cg_unit.kn = &kn_unit; cg_unit.level = level; cg_unit.self.parent = &cg_slice.self;
  cg_slice.self.cgroup = &cg_slice; cg_slice.kn = &kn_slice; cg_slice.level = 1;
  cset.dfl_cgrp = &cg_unit; exec_task.cgroups = &cset;
}
static void run_exec(__u32 tgid, __u64 ino, __u32 dev, __u32 gen, const char *comm, __u32 uid) {
  exec_sb.s_dev = dev; exec_inode.i_ino = ino; exec_inode.i_sb = &exec_sb; exec_inode.i_generation = gen;
  exec_file.f_inode = &exec_inode; exec_mm.exe_file = &exec_file; exec_task.mm = &exec_mm; cur_task = &exec_task;
  cur_pid_tgid = ((__u64)tgid << 32) | tgid; strncpy(cur_comm, comm, 15); cur_uid_gid = uid; protect_on_exec();
}
/* The task at the exit of a UID call: it runs the image with this identity, its
 * parent is the process with parent_tgid, and its real UID is now uid. */
static struct task_struct setuid_parent;
static void run_setuid(__u32 tgid, __u32 parent_tgid, __u64 ino, __u32 dev, __u32 gen, __u32 uid) {
  exec_sb.s_dev = dev; exec_inode.i_ino = ino; exec_inode.i_sb = &exec_sb; exec_inode.i_generation = gen;
  exec_file.f_inode = &exec_inode; exec_mm.exe_file = &exec_file; exec_task.mm = &exec_mm; cur_task = &exec_task;
  setuid_parent.tgid = parent_tgid; exec_task.real_parent = &setuid_parent;
  cur_pid_tgid = ((__u64)tgid << 32) | tgid; cur_uid_gid = uid; protect_on_setuid();
}
/* n times "u", in a buffer of its own. */
static const char *u_run(int n) { static char buf[128]; memset(buf, 0, sizeof buf); memset(buf, 'u', (size_t)n); return buf; }
/* An exec of the image as uid by a protected tgid: whether the entry survives. */
static int survives(__u64 ino, __u32 dev, __u32 gen, __u32 uid) {
  protect(990, 1000000000ULL);
  run_exec(990, ino, dev, gen, "x", uid);
  int kept = has(990);
  bpf_map_delete_elem(&trace_protected_tgids, &(__u32){ 990 });
  return kept;
}

int main(void) {
  /* Device 259:2 (0x10300002), one inode generation per file. */
  const __u32 DEV = 0x10300002, OTHER_DEV = 0x10300003;
  const __u64 SSHD_SESSION = 1001, AGENT = 1002, NETWORKD = 1003, EXECUTOR = 1004, WAF = 1005, BOTH = 1006, NOTHING = 1007, UNKNOWN_BIT = 1008, NO_UNIT = 1009, LONG_UNIT = 1010;
  const char *long_unit = u_run(46); /* the most userspace stores */
  image(SSHD_SESSION, DEV, 7, TRACE_PROTECTED_IMAGE_ROOT, NULL); image(AGENT, DEV, 8, TRACE_PROTECTED_IMAGE_ANY, NULL);
  image(NETWORKD, DEV, 9, TRACE_PROTECTED_IMAGE_UNIT, "systemd-networkd.service"); image(EXECUTOR, DEV, 10, TRACE_PROTECTED_IMAGE_ROOT, NULL);
  image(WAF, DEV, 11, TRACE_PROTECTED_IMAGE_UNIT, "wafio-waf-agent.service");
  image(BOTH, DEV, 12, TRACE_PROTECTED_IMAGE_ROOT | TRACE_PROTECTED_IMAGE_UNIT, "wafio-waf-agent.service");
  image(NOTHING, DEV, 13, 0, "wafio-waf-agent.service"); image(UNKNOWN_BIT, DEV, 14, 8, NULL);
  image(NO_UNIT, DEV, 15, TRACE_PROTECTED_IMAGE_UNIT, NULL); image(LONG_UNIT, DEV, 16, TRACE_PROTECTED_IMAGE_UNIT, long_unit);
  set_slot(TRACE_PROTECTED_REFUSED_SLOT, 0);

  /* No budget (before the first refresh, or an agent that never writes it):
   * nothing is inherited, and the refusal is counted. */
  set_budget(0);
  {
    struct task_struct p = mk_task(1, 1, 1); p.group_leader = &p;
    struct task_struct c = mk_task(150, 150, 5500000000ULL); c.group_leader = &c;
    protect_forked_child(&p, &c);
    EXPECT(!has(150), "inherited without budget");
    EXPECT(budget_slot(TRACE_PROTECTED_REFUSED_SLOT) == 1, "refused insert not counted");
    EXPECT(budget() == 0, "empty budget went negative");
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
  in_cgroup("systemd-networkd.service", 2, "system.slice");
  run_exec(700, 4242, DEV, 3, "systemd-network", 998);
  EXPECT(!has(700), "a fake systemd-network as a service account kept the entry");
  protect(701, 9200000000ULL);
  run_exec(701, EXECUTOR, DEV, 10, "17", 0);
  run_exec(701, NETWORKD, DEV, 9, "systemd-network", 998);
  EXPECT(has(701), "the real systemd-networkd image as its service account in its unit dropped the entry");
  /* A unit that runs a file with a numeric name as root is not the executor. */
  protect(702, 9300000000ULL);
  run_exec(702, 4243, DEV, 3, "1", 0);
  EXPECT(!has(702), "a root exec of an unlisted file with a numeric comm kept the entry");
  protect(702, 9300000000ULL);
  run_exec(702, EXECUTOR, DEV, 10, "2a", 998);
  EXPECT(!has(702), "the executor image as a non-root user kept the entry");

  /* A unit-bound image keeps the entry only inside its unit: the cgroup of the
   * default hierarchy is at level 2, named like the unit, under system.slice.
   * The user does not matter, so root outside the unit loses it and a service
   * account inside keeps it. */
  in_cgroup("wafio-waf-agent.service", 2, "system.slice");
  EXPECT(survives(WAF, DEV, 11, 998), "the WAF agent image in its unit as a service account dropped the entry");
  EXPECT(survives(WAF, DEV, 11, 0), "the WAF agent image in its unit as root dropped the entry");
  in_cgroup("sshd.service", 2, "system.slice");
  EXPECT(!survives(WAF, DEV, 11, 998), "the WAF agent image in another unit kept the entry");
  EXPECT(!survives(WAF, DEV, 11, 0), "the WAF agent image run by root in another unit kept the entry");
  in_cgroup("wafio-waf-agent.service", 3, "system.slice");
  EXPECT(!survives(WAF, DEV, 11, 998), "the WAF agent image in a sub-cgroup of its unit kept the entry");
  in_cgroup("wafio-waf-agent.service", 1, "system.slice");
  EXPECT(!survives(WAF, DEV, 11, 998), "a level 1 cgroup with the unit name kept the entry");
  in_cgroup("wafio-waf-agent.service", 0, "system.slice");
  EXPECT(!survives(WAF, DEV, 11, 998), "a root cgroup with the unit name kept the entry (cgroup v1 only host)");
  const char *slices[] = { "user.slice", "system.slic", "system.slice2", "System.slice", "system.slice\n", "", "init.scope", "user@1000.service" };
  for (unsigned i = 0; i < sizeof slices / sizeof slices[0]; i++) {
    in_cgroup("wafio-waf-agent.service", 2, slices[i]);
    EXPECT(!survives(WAF, DEV, 11, 998), "the WAF agent image under another parent cgroup kept the entry");
  }
  const char *units[] = { "wafio-waf-agent.servic", "wafio-waf-agent.service2", "wafio-waf-agent.service.", "xafio-waf-agent.service", "Wafio-waf-agent.service", "", "wafio-waf-agent.service/sub" };
  for (unsigned i = 0; i < sizeof units / sizeof units[0]; i++) {
    in_cgroup(units[i], 2, "system.slice");
    EXPECT(!survives(WAF, DEV, 11, 998), "a cgroup with another name kept the entry");
  }
  /* A name longer than the buffer is cut, and the cut copy never equals what
   * userspace stored (at most 46 characters). */
  in_cgroup(long_unit, 2, "system.slice");
  EXPECT(survives(LONG_UNIT, DEV, 16, 998), "a unit name of the stored length did not match itself");
  in_cgroup(u_run(47), 2, "system.slice");
  EXPECT(!survives(LONG_UNIT, DEV, 16, 998), "a 47 character name matched a 46 character unit");
  in_cgroup(u_run(80), 2, "system.slice");
  EXPECT(!survives(LONG_UNIT, DEV, 16, 998), "a name cut by the buffer matched a 46 character unit");
  /* An image with an empty unit, or with no flag, or with a flag this program
   * does not know, keeps nothing, root included. */
  in_cgroup("", 2, "system.slice");
  EXPECT(!survives(NO_UNIT, DEV, 15, 0), "a unit image with an empty unit kept the entry");
  in_cgroup("wafio-waf-agent.service", 2, "system.slice");
  EXPECT(!survives(NOTHING, DEV, 13, 0), "an image with no flag kept the entry for root in its unit");
  EXPECT(!survives(UNKNOWN_BIT, DEV, 14, 0), "an image with an unknown flag kept the entry");
  /* The flags are alternatives. */
  EXPECT(survives(BOTH, DEV, 12, 0), "a root or unit image dropped the entry for root outside any unit check");
  EXPECT(survives(BOTH, DEV, 12, 998), "a root or unit image dropped the entry inside its unit");
  in_cgroup("sshd.service", 2, "system.slice");
  EXPECT(survives(BOTH, DEV, 12, 0), "a root or unit image dropped the entry for root in another unit");
  EXPECT(!survives(BOTH, DEV, 12, 998), "a root or unit image kept the entry for a service account in another unit");
  EXPECT(survives(AGENT, DEV, 8, 998), "an image for any task dropped the entry outside a unit");
  /* Every read is checked: a task with no cgroup set, a cgroup with no node, a
   * node with no name, a failed string read and a kernel that lacks a field
   * read as no match. */
  in_cgroup("wafio-waf-agent.service", 2, "system.slice");
  exec_task.cgroups = NULL;
  EXPECT(!survives(WAF, DEV, 11, 998), "a task without a css_set kept the entry");
  in_cgroup("wafio-waf-agent.service", 2, "system.slice"); cset.dfl_cgrp = NULL;
  EXPECT(!survives(WAF, DEV, 11, 998), "a css_set without a default cgroup kept the entry");
  in_cgroup("wafio-waf-agent.service", 2, "system.slice"); cg_unit.kn = NULL;
  EXPECT(!survives(WAF, DEV, 11, 998), "a cgroup without a kernfs node kept the entry");
  in_cgroup("wafio-waf-agent.service", 2, "system.slice"); kn_unit.name = NULL;
  EXPECT(!survives(WAF, DEV, 11, 998), "a kernfs node without a name kept the entry");
  in_cgroup("wafio-waf-agent.service", 2, "system.slice"); cg_unit.self.parent = NULL;
  EXPECT(!survives(WAF, DEV, 11, 998), "a cgroup without a parent kept the entry");
  in_cgroup("wafio-waf-agent.service", 2, "system.slice"); cg_slice.kn = NULL;
  EXPECT(!survives(WAF, DEV, 11, 998), "a parent without a kernfs node kept the entry");
  in_cgroup("wafio-waf-agent.service", 2, "system.slice"); cg_slice.self.cgroup = NULL;
  EXPECT(!survives(WAF, DEV, 11, 998), "a parent css without its cgroup kept the entry");
  in_cgroup("wafio-waf-agent.service", 2, "system.slice"); fail_str_read = 1;
  EXPECT(!survives(WAF, DEV, 11, 998), "a failed name read kept the entry");
  fail_str_read = 0;
  in_cgroup("wafio-waf-agent.service", 2, "system.slice"); missing_field = 1;
  EXPECT(!survives(WAF, DEV, 11, 998), "a kernel without the cgroup fields kept the entry");
  EXPECT(survives(AGENT, DEV, 8, 998), "a kernel without the cgroup fields dropped an image that needs no cgroup");
  EXPECT(survives(SSHD_SESSION, DEV, 7, 0), "a kernel without the cgroup fields dropped a root image");
  missing_field = 0;
  EXPECT(survives(WAF, DEV, 11, 998), "the unit match no longer holds after the failure cases");

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
  image(SSHD_SESSION, DEV, 7, TRACE_PROTECTED_IMAGE_ROOT, NULL);

  /* A forked child that gives up root without exec (an nginx worker, the child
   * of sshd that switches to the user) keeps its entry only when its image
   * keeps it for a task without root. The budget unit comes back. */
  image(AGENT, DEV, 8, TRACE_PROTECTED_IMAGE_ANY, NULL); image(WAF, DEV, 11, TRACE_PROTECTED_IMAGE_UNIT, "wafio-waf-agent.service");
  struct task_struct priv = mk_task(800, 800, 9600000000ULL); priv.group_leader = &priv;
  protect(800, 9600000000ULL);
  struct task_struct dropped = mk_task(801, 801, 9700000000ULL); dropped.group_leader = &dropped;
  set_budget(2);
  protect_forked_child(&priv, &dropped);
  EXPECT(has(801), "child of a protected process not inherited");
  EXPECT(budget() == 1, "the inherited child did not take a budget unit");
  run_setuid(801, 800, SSHD_SESSION, DEV, 7, 1000);
  EXPECT(!has(801) && budget() == 2, "a child of a protected process that dropped root in a root-only image kept the entry or the budget unit");
  /* a child of PID 1 is left to its exec: systemd switches to User= right
   * before it execs the service binary, */
  protect(802, 9800000000ULL); set_slot(TRACE_PROTECTED_BUDGET_SLOT, 1);
  run_setuid(802, 1, SSHD_SESSION, DEV, 7, 998);
  EXPECT(has(802) && budget() == 1, "a child of PID 1 lost the entry at its UID change");
  /* and its exec decides: a root-only image as a service account loses it, the
   * image of the WAF agent in its unit keeps it. */
  run_exec(802, SSHD_SESSION, DEV, 7, "sshd-session", 998);
  EXPECT(!has(802) && budget() == 2, "the exec after a UID change did not decide");
  /* An image that keeps the entry for any task, or inside the unit the task is
   * in, keeps it through the UID change, whoever the parent is. */
  protect(803, 9900000000ULL);
  run_setuid(803, 800, AGENT, DEV, 8, 998);
  EXPECT(has(803), "an image for any task lost the entry at a UID change");
  in_cgroup("wafio-waf-agent.service", 2, "system.slice");
  protect(804, 9910000000ULL);
  run_setuid(804, 800, WAF, DEV, 11, 999);
  EXPECT(has(804), "a unit-bound image in its unit lost the entry at a UID change");
  in_cgroup("sshd.service", 2, "system.slice");
  run_setuid(804, 800, WAF, DEV, 11, 999);
  EXPECT(!has(804), "a unit-bound image outside its unit kept the entry at a UID change");
  /* A real UID that is still 0 changes nothing, whatever the image. */
  protect(805, 9920000000ULL);
  run_setuid(805, 800, SSHD_SESSION, DEV, 7, 0);
  run_setuid(805, 800, 4242, DEV, 3, 0);
  EXPECT(has(805), "a task that is still root lost the entry");
  /* An image the table does not list, a read that fails and a delete that
   * fails: the first two drop the entry, the last gives nothing back. */
  run_setuid(805, 800, 4242, DEV, 3, 998);
  EXPECT(!has(805), "an unlisted image kept the entry at a UID change");
  protect(806, 9930000000ULL);
  { struct task_struct t = mk_task(806, 806, 9930000000ULL); cur_task = &t; cur_pid_tgid = ((__u64)806 << 32) | 806; cur_uid_gid = 998; protect_on_setuid(); }
  EXPECT(!has(806), "a UID change whose image could not be read kept the entry");
  protect(807, 9940000000ULL); set_slot(TRACE_PROTECTED_BUDGET_SLOT, 1);
  fail_delete = 1;
  run_setuid(807, 800, 4242, DEV, 3, 998);
  fail_delete = 0;
  EXPECT(has(807) && budget() == 1, "a delete that removed nothing gave a unit back at a UID change");
  bpf_map_delete_elem(&trace_protected_tgids, &(__u32){ 807 });
  /* A task with no entry has nothing to drop and gives nothing back. */
  run_setuid(808, 800, SSHD_SESSION, DEV, 7, 998);
  EXPECT(!has(808) && budget() == 1, "a UID change of a process without an entry changed the map or the budget");
  /* A parent that cannot be read is not PID 1. */
  protect(809, 9950000000ULL);
  exec_sb.s_dev = DEV; exec_inode.i_ino = SSHD_SESSION; exec_inode.i_sb = &exec_sb; exec_inode.i_generation = 7;
  exec_file.f_inode = &exec_inode; exec_mm.exe_file = &exec_file; exec_task.mm = &exec_mm; exec_task.real_parent = NULL; cur_task = &exec_task;
  cur_pid_tgid = ((__u64)809 << 32) | 809; cur_uid_gid = 998; protect_on_setuid();
  EXPECT(!has(809), "a parent that could not be read kept a root-only entry like PID 1's child");

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

  /* The budget counts entries in the map, not forks since the refresh. A client
   * that opens and closes connections as fast as sshd forks used to spend the
   * budget in a few seconds, and the logins after it started without an entry. */
  set_budget(2);
  set_slot(TRACE_PROTECTED_REFUSED_SLOT, 0);
  struct task_struct daemon = mk_task(900, 900, 20000000000ULL); daemon.group_leader = &daemon;
  protect(900, daemon.start_boottime);
  for (int i = 0; i < 1000; i++) {
    struct task_struct conn = mk_task(5000 + i, 5000 + i, 21000000000ULL + (__u64)i * 10000000ULL); conn.group_leader = &conn;
    protect_forked_child(&daemon, &conn);
    if (!has(5000 + i)) { EXPECT(0, "a connection after many closed ones was not inherited"); break; }
    conn.signal = &dead; cur_task = &conn; cur_pid_tgid = ((__u64)(5000 + i) << 32) | (5000 + i); protect_on_exit();
    EXPECT(!has(5000 + i), "a closed connection left its entry");
  }
  EXPECT(budget() == 2, "the budget after closed connections is not back at the refresh value");
  EXPECT(budget_slot(TRACE_PROTECTED_REFUSED_SLOT) == 0, "a fork of a connection that fits was refused");
  /* Connections that stay open hold their units, and the next one is refused. */
  struct task_struct open1 = mk_task(6001, 6001, 22000000000ULL), open2 = mk_task(6002, 6002, 22100000000ULL), open3 = mk_task(6003, 6003, 22200000000ULL);
  open1.group_leader = &open1; open2.group_leader = &open2; open3.group_leader = &open3;
  protect_forked_child(&daemon, &open1); protect_forked_child(&daemon, &open2); protect_forked_child(&daemon, &open3);
  EXPECT(has(6001) && has(6002) && !has(6003), "open connections do not hold the budget");
  EXPECT(budget() == 0, "two open connections left a different budget");
  /* An exec that drops the entry gives the unit back too: sshd-session's child
   * that execs the user's shell. */
  run_exec(6001, 9999, DEV, 1, "bash", 998);
  EXPECT(!has(6001) && budget() == 1, "an exec drop did not give the unit back");
  run_exec(6002, SSHD_SESSION, DEV, 7, "sshd-session", 0);
  EXPECT(has(6002) && budget() == 1, "an exec that keeps the entry changed the budget");
  /* An insert the map refuses gives its unit back. */
  fail_update = 1;
  protect_forked_child(&daemon, &open3);
  fail_update = 0;
  EXPECT(!has(6003) && budget() == 1, "a failed insert kept the budget unit");
  EXPECT(budget_slot(TRACE_PROTECTED_REFUSED_SLOT) == 2, "a failed insert was not counted as refused");
  /* The limit is what userspace wrote: units the kernel did not take do not
   * raise the budget above it, and a budget of 0 stays 0. */
  set_budget(2);
  protect(7001, 23000000000ULL); protect(7002, 23100000000ULL); protect(7003, 23200000000ULL);
  for (unsigned tgid = 7001; tgid <= 7003; tgid++) {
    struct task_struct gone = mk_task(tgid, tgid, 23000000000ULL + (tgid - 7001) * 100000000ULL); gone.group_leader = &gone; gone.signal = &dead;
    cur_task = &gone; cur_pid_tgid = ((__u64)tgid << 32) | tgid; protect_on_exit();
  }
  EXPECT(budget() == 2, "entries written by userspace raised the budget above its limit");
  set_budget(0);
  protect(7004, 23300000000ULL);
  run_exec(7004, 9999, DEV, 1, "bash", 998);
  EXPECT(!has(7004) && budget() == 0, "a drop with the exec keep off raised the budget");
  protect(7005, 23400000000ULL);
  { struct task_struct gone = mk_task(7005, 7005, 23400000000ULL); gone.group_leader = &gone; gone.signal = &dead; cur_task = &gone; cur_pid_tgid = ((__u64)7005 << 32) | 7005; protect_on_exit(); }
  EXPECT(!has(7005) && budget() == 0, "an exit with the exec keep off raised the budget");
  /* Nothing to give back when this delete did not remove the entry: userspace
   * (or another CPU) got there first, and its removal is counted by the refresh. */
  set_budget(2); set_slot(TRACE_PROTECTED_BUDGET_SLOT, 1);
  protect(7010, 23600000000ULL);
  fail_delete = 1;
  run_exec(7010, 9999, DEV, 1, "bash", 998);
  { struct task_struct gone = mk_task(7010, 7010, 23600000000ULL); gone.group_leader = &gone; gone.signal = &dead; cur_task = &gone; cur_pid_tgid = ((__u64)7010 << 32) | 7010; protect_on_exit(); }
  fail_delete = 0;
  EXPECT(budget() == 1, "a delete that removed nothing gave a unit back");
  /* Nothing to give back when nothing was deleted: an exec or an exit of a
   * process without an entry. */
  set_budget(2); set_slot(TRACE_PROTECTED_BUDGET_SLOT, 1);
  run_exec(7006, 9999, DEV, 1, "bash", 998);
  { struct task_struct plain = mk_task(7007, 7007, 23500000000ULL); plain.group_leader = &plain; plain.signal = &dead; cur_task = &plain; cur_pid_tgid = ((__u64)7007 << 32) | 7007; protect_on_exit(); }
  EXPECT(budget() == 1, "an exec or exit without an entry gave a unit back");
  return failures != 0;
}
`
