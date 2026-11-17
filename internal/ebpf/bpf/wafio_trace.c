// SPDX-License-Identifier: GPL-2.0
// wafio_trace.c — Enterprise runtime security tracing via eBPF tracepoints.
//
//  Hooks 20+ syscalls across four domains:
//    • Process   — execve, execveat, clone/fork, exit, kill, prctl
//    • File      — openat, unlinkat, renameat2, fchmodat, fchownat
//    • Network   — connect, accept4, bind, socket, listen
//    • Security  — setuid, setgid, ptrace, finit_module, init_module,
//                   mount, mprotect, memfd_create, dup3, pipe2
//
//  Events are emitted into a shared BPF_MAP_TYPE_RINGBUF and consumed by the
//  Go TraceManager via cilium/ebpf/ringbuf; kill candidates use a small
//  second ring (trace_priority_events).
//
//  Compile:
//    clang -O2 -g -target bpf \
//      -D__TARGET_ARCH_arm64 \
//      -I/usr/include/aarch64-linux-gnu \
//      -c internal/ebpf/bpf/wafio_trace.c \
//      -o internal/ebpf/bpf/wafio_trace.o

#include "wafio_trace.h"

char LICENSE[] SEC("license") = "GPL";

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAPS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Ring buffer for trace events to userspace (16 MB) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} trace_events SEC(".maps");

/* Event preparation must not depend on userspace export capacity. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct wafio_event);
    __uint(max_entries, 1);
} trace_scratch SEC(".maps");

/* Trace configuration (single-entry array, key=0) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, struct trace_config);
    __uint(max_entries, 1);
} trace_config_map SEC(".maps");

/* Enforcement rules map — keyed by event_type for O(1) lookup */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);          /* event_type (TRACE_EVENT_*) */
    __type(value, struct trace_enforce_rule);
    __uint(max_entries, MAX_ENFORCE_RULES);
} trace_enforce_map SEC(".maps");

/* Process-bound deferred requests. Private, unpinned, destroyed on agent stop.
 * state 0 pending, 1 claimed, 2 completed. No numeric-PID signal syscall.
 * tgid repeats the key: a preallocated hash element is reused at once after
 * the agent deletes it, so a program still holding the pointer checks the
 * owner before writing (BPF_F_NO_PREALLOC is not an option: tracing programs
 * are refused non-preallocated hash maps on PREEMPT_RT, and trigger a kernel
 * WARN elsewhere before 6.1). */
struct deferred_signal {
    __u64 process_start_ns;
    __u64 expires_ns;
    __u64 state;
    __s32 result;
    __u32 policy_id;
    __u32 tgid;
    __u32 _pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct deferred_signal);
    __uint(max_entries, 4096);
} trace_deferred_signals SEC(".maps");

/* Protected processes: TGIDs that no kill path may signal, beyond the
 * built-in pid<=1 / agent guard. Populated and refreshed by the Go
 * TraceManager from its protected-process set (sshd, systemd, containerd, …).
 * Optional ABI: userspace tolerates objects without it. max_entries must
 * match maxProtectedTGIDs in trace_protect.go.
 * The value is the process start time in USER_HZ ticks as /proc/<pid>/stat
 * reports it (start_boottime / 10ms, nsec_to_clock_t): an entry protects only
 * the process it was written for, never an unrelated process that reuses the
 * PID before the next 5 s refresh. Userspace writes a 1-byte flag instead to
 * objects built before this ABI (value size 1).
 *
 * The kernel maintains the map between refreshes too. A process forked
 * by a protected process (or by PID 1) is inserted at sched_process_fork,
 * before it first runs; exec keeps an entry only for a protected image
 * (trace_protected_comms); the leader's exit removes it. The refresh
 * reconciles against the map's content and drops what it cannot verify. */
#define TRACE_MAX_PROTECTED 1024
#define TRACE_NSEC_PER_USER_HZ_TICK 10000000ULL
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   /* tgid */
    __type(value, __u64); /* start time, USER_HZ ticks */
    __uint(max_entries, TRACE_MAX_PROTECTED);
} trace_protected_tgids SEC(".maps");

/* Protected comm names, written once by the TraceManager from its
 * protected set: the executable basenames truncated to TASK_COMM_LEN-1.
 * Bit TRACE_PROTECTED_COMM_ROOT: the name protects only a root process (the
 * built-in and configured names; configured exe paths do not require root).
 * max_entries must match maxProtectedComms in trace_protect.go. */
#define TRACE_MAX_PROTECTED_COMMS 1024
#define TRACE_PROTECTED_COMM_ROOT 1
struct protected_comm_key {
    char comm[TRACE_COMM_LEN];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct protected_comm_key);
    __type(value, __u8);
    __uint(max_entries, TRACE_MAX_PROTECTED_COMMS);
} trace_protected_comms SEC(".maps");

/* Budget for kernel fork inserts. Slot 0: inserts left, written
 * by userspace at every refresh so inherited entries never take the map above
 * 3/4 of TRACE_MAX_PROTECTED and the refresh's own inserts still fit (0 until
 * the first refresh, and with an agent that predates it: no inheritance).
 * Slot 1: inserts refused (budget spent or map full), read by userspace.
 * Must match protectedBudgetSlot / protectedRefusedSlot in trace_protect.go. */
#define TRACE_PROTECTED_BUDGET_SLOT 0
#define TRACE_PROTECTED_REFUSED_SLOT 1
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __s64);
    __uint(max_entries, 2);
} trace_protected_budget SEC(".maps");

static __always_inline int is_protected_tgid(__u32 tgid, __u64 start_ns)
{
    __u64 *ticks = bpf_map_lookup_elem(&trace_protected_tgids, &tgid);
    if (!ticks)
        return 0;
    return start_ns / TRACE_NSEC_PER_USER_HZ_TICK == *ticks;
}

static __always_inline void
protected_inherit_refused(void)
{
    __u32 slot = TRACE_PROTECTED_REFUSED_SLOT;
    __s64 *refused = bpf_map_lookup_elem(&trace_protected_budget, &slot);
    if (refused)
        __sync_fetch_and_add(refused, 1);
}

/* Takes one insert from the budget; 0 when it is spent. Read, then an atomic
 * add whose result is unused (BPF_XADD, CPU v1, kernel >= 5.8): CPUs racing on
 * the last unit can overshoot by at most one insert each, which the 1/4
 * headroom absorbs; userspace rewrites the slot at every refresh. */
static __always_inline int
protected_inherit_take(void)
{
    __u32 slot = TRACE_PROTECTED_BUDGET_SLOT;
    __s64 *budget = bpf_map_lookup_elem(&trace_protected_budget, &slot);
    if (!budget || *budget <= 0)
        return 0;
    __sync_fetch_and_add(budget, -1);
    return 1;
}

/* A child forked by a protected process runs that process's verified
 * image until it execs, so it is protected from its first instruction instead
 * of after the next 5 s refresh (sshd's per-connection child, sshd-session's
 * pre-auth child). PID 1 is guarded by number, so its children count too.
 * A new thread shares the parent's TGID and needs no entry. Inserts are
 * bounded by trace_protected_budget; a refused insert only delays the child's
 * kernel protection to the next refresh. Called at sched_process_fork, before
 * the child is woken. */
static __always_inline void
protect_forked_child(struct task_struct *parent, struct task_struct *child)
{
    __u32 child_pid = BPF_CORE_READ(child, pid);
    __u32 child_tgid = BPF_CORE_READ(child, tgid);
    if (child_pid != child_tgid)
        return;
    __u32 parent_tgid = BPF_CORE_READ(parent, tgid);
    if (parent_tgid != 1) {
        struct task_struct *parent_leader = BPF_CORE_READ(parent, group_leader);
        if (!is_protected_tgid(parent_tgid, BPF_CORE_READ(parent_leader, start_boottime)))
            return;
    }
    if (!protected_inherit_take()) {
        protected_inherit_refused();
        return;
    }
    __u64 ticks = BPF_CORE_READ(child, start_boottime) / TRACE_NSEC_PER_USER_HZ_TICK;
    if (bpf_map_update_elem(&trace_protected_tgids, &child_tgid, &ticks, BPF_ANY))
        protected_inherit_refused();
}

/* exec replaces the image the protection was granted for. The entry is
 * kept only when the new comm is a protected name (as root, when the name
 * requires it); the next refresh verifies the binary by inode. Anything else
 * (the user's shell after sshd-session, a service binary after PID 1) loses
 * the protection it inherited at fork. Called at sched_process_exec, after
 * the kernel set the new comm. */
static __always_inline void
protect_on_exec(void)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&trace_protected_tgids, &tgid))
        return;
    struct protected_comm_key key = {};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    __u8 *flags = bpf_map_lookup_elem(&trace_protected_comms, &key);
    if (flags && (!(*flags & TRACE_PROTECTED_COMM_ROOT) ||
                  (__u32)bpf_get_current_uid_gid() == 0))
        return;
    bpf_map_delete_elem(&trace_protected_tgids, &tgid);
}

/* The process is gone; drop its entry so a burst of short-lived
 * protected children (one per SSH connection) cannot fill the map between
 * refreshes. Only the exit of the whole thread group ends the entry — not the
 * leader's own exit (pthread_exit from main, or the old leader reaped by a
 * non-leader thread's exec) — and only an entry written for this very
 * process (leader start time). do_exit decrements signal->live before
 * trace_sched_process_exit, so 0 here means no thread of the group is left.
 * Called at sched_process_exit. */
static __always_inline void
protect_on_exit(void)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    struct signal_struct *signal = BPF_CORE_READ(task, signal);
    if (BPF_CORE_READ(signal, live.counter) != 0)
        return;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (is_protected_tgid(tgid, BPF_CORE_READ(leader, start_boottime)))
        bpf_map_delete_elem(&trace_protected_tgids, &tgid);
}

/* PID filter: ignore events from specific PIDs (used to filter agent itself) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);
    __type(value, __u8);
    __uint(max_entries, 256);
} trace_pid_filter SEC(".maps");

/* Per-event-type counters for statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, 32); /* indexes 0..TRACE_EVENT_MAX */
} trace_stats SEC(".maps");

/* Kill candidates get their own small ring (1 MB, ~700 events), so a
 * flood that fills trace_events cannot drop the event a userspace Kill policy
 * waits for. Optional ABI: agents without it read trace_events only, and an
 * agent tolerates objects without these three maps. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} trace_priority_events SEC(".maps");

/* Per event type: see struct trace_priority_rule (wafio_trace.h). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, struct trace_priority_rule);
    __uint(max_entries, 32); /* indexes 0..TRACE_EVENT_MAX */
} trace_priority_rules SEC(".maps");

/* TRACE_PRIO_* counters (wafio_trace.h). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, TRACE_PRIO_STATS);
} trace_priority_stats SEC(".maps");

/* struct trace_priority_ctl (wafio_trace.h): reader attached, name count. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, struct trace_priority_ctl);
    __uint(max_entries, 1);
} trace_priority_ctl SEC(".maps");

/* Per event type: events shed for shared-ring headroom (trace_shed_count). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, 32); /* indexes 0..TRACE_EVENT_MAX */
} trace_shed_stats SEC(".maps");

/* Final path components of the filename terms of Kill policies on openat
 * (hashed, see trace_final_name_hash); value unused. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64);
    __type(value, __u8);
    __uint(max_entries, 256);
} trace_priority_names SEC(".maps");

/* Path components that keep an openat from being shed (trace_open_keep):
 * key hashed like trace_priority_names, value TRACE_KEEP_* bits. Written by
 * the agent; its presence also tells the agent the object never sheds what
 * the map names. Optional: an agent tolerates objects without it. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64);
    __type(value, __u8);
    __uint(max_entries, 1024);
} trace_keep_names SEC(".maps");

/* Open events wait here for the result of their syscall: key = pid_tgid of the
 * thread inside the open (one open at a time), value = the finished event, with
 * the open's kind (TRACE_OPEN_KIND_*) in aux. The exit probes export it with
 * ret_val set. A full map is not an error: the open then leaves at entry
 * without a result (trace_open_submit). Sized for the threads inside an open at
 * once, a few per CPU plus the blocked ones. Any user can hold entries by
 * blocking in the open of a FIFO: that costs the other opens their result
 * (TRACE_OPEN_NO_FULL) and nothing else. */
#define TRACE_OPEN_PENDING_MAX 2048
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64);
    __type(value, struct wafio_event);
    __uint(max_entries, TRACE_OPEN_PENDING_MAX);
} trace_open_pending SEC(".maps");

/* struct trace_open_ctl (wafio_trace.h). Optional: an agent tolerates objects
 * without it. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, struct trace_open_ctl);
    __uint(max_entries, 1);
} trace_open_ctl SEC(".maps");

/* TRACE_OPEN_* counters (wafio_trace.h). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, TRACE_OPEN_STATS);
} trace_open_stats SEC(".maps");

/* Plain loads and stores only. __sync_val_compare_and_swap and
 * __sync_lock_test_and_set compile to BPF cmpxchg/xchg at every -mcpu, which
 * the verifier accepts only from Linux 5.12; inlined into every program, they
 * made 5.8-5.11 reject the whole trace collection. Without a compare-and-swap
 * two threads of the target can pass the state check at the same instant:
 * both run the same identity and expiry checks and signal the same verified
 * process, and SIGKILL twice is SIGKILL once. The result is stored before
 * state 2; the agent pre-fills result with TRACE_DEFERRED_PENDING and waits
 * while it is still there, since a weakly ordered CPU (arm64) may expose the
 * state store first. */
#define TRACE_DEFERRED_PENDING 1 /* never a helper result (0 or -errno) */
#define TRACE_WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))

static __always_inline void check_deferred_signal(struct trace_config *cfg) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid <= 1 || pid == cfg->agent_pid) return;
    struct deferred_signal *request = bpf_map_lookup_elem(&trace_deferred_signals, &pid);
    if (!request || request->state || request->tgid != pid) return;
    __u64 want_start = request->process_start_ns;
    __u64 want_exp = request->expires_ns;
    TRACE_WRITE_ONCE(request->state, 1); /* claim, best effort (see above) */
    struct task_struct *task = (void *)bpf_get_current_task();
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    __u64 start = BPF_CORE_READ(leader, start_boottime);
    __s32 result;
    if (is_protected_tgid(pid, start))
        result = -1; /* protected process: never signalled */
    else if (!start || start != want_start)
        result = -3; /* identity mismatch / process exited */
    else if (bpf_ktime_get_ns() >= want_exp)
        result = -110; /* expired */
    else
        result = bpf_send_signal(9);
    /* Completed and deleted by another thread, then reused for another
     * request meanwhile: not ours to complete. */
    if (request->tgid != pid || request->expires_ns != want_exp) return;
    TRACE_WRITE_ONCE(request->result, result);
    TRACE_WRITE_ONCE(request->state, 2);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Check if tracing is enabled and this event type is allowed. */
static __always_inline int should_trace(__u32 event_type, __u32 severity)
{
    __u32 key = 0;
    struct trace_config *cfg = bpf_map_lookup_elem(&trace_config_map, &key);
    if (!cfg)
        return 0;
    check_deferred_signal(cfg);
    struct trace_enforce_rule *rule = bpf_map_lookup_elem(&trace_enforce_map, &event_type);
    int enforcing = rule && rule->enabled;
    if (!enforcing && (!cfg->enabled ||
        (event_type <= 32 && !(cfg->event_mask_lo & (1u << (event_type - 1))))))
        return 0;
    /* Severity can rise while decoding arguments; filter only after decoding. */

    /* Check PID filter (suppress agent's own events) */
    if (cfg->filter_own_pid) {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 tgid = pid_tgid >> 32;
        if (tgid == cfg->agent_pid)
            return 0;
        /* Also check the hash map for additional filtered PIDs */
        if (bpf_map_lookup_elem(&trace_pid_filter, &tgid))
            return 0;
    }

    return 1;
}

/* Reserve a trace_event from the ringbuf, zero it, and fill process context. */
static __always_inline struct wafio_event *
new_event(__u32 event_type, __u32 severity)
{
    struct wafio_event *evt;

    __u32 key = 0;
    evt = bpf_map_lookup_elem(&trace_scratch, &key);
    if (!evt)
        return 0;

    /* Zero ONLY the fields not unconditionally written below. A whole-struct
     * memset (1432B) inside this __always_inline helper makes clang emit an
     * unsupported memset() library call in high-register-pressure callers;
     * small field-scoped clears inline as plain stores everywhere. String
     * fields need no clearing: comm/parent/grandparent use NUL-padding
     * helpers, args are written by bpf_probe_read_user_str (and the unused
     * argv slots are covered by the args clear below). filename gets its
     * leading NUL: only file, exec, clone, mount and memfd events write it,
     * and trace_scratch is a per-CPU buffer reused by every event, so a
     * network or credential event would otherwise carry the path the
     * previous event on that CPU opened (a sendto "reading" /etc/shadow
     * matched path rules and escalated). Readers stop at the
     * first NUL. */
    evt->filename[0] = 0;
    __builtin_memset(evt->args, 0, sizeof(evt->args));
    __builtin_memset(evt->addr, 0, sizeof(evt->addr));
    evt->flags = 0;
    evt->ret_val = 0;
    evt->detail = 0;
    evt->port = 0;
    evt->addr_family = 0;
    evt->action = 0;
    evt->policy_id = 0;
    evt->signal_result = 0;
    evt->signal_attempted = 0;
    evt->process_start_ns = 0;

    evt->event_type  = event_type;
    evt->severity    = severity;
    evt->timestamp_ns = bpf_ktime_get_ns();

    /* Process identity */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = (__u32)uid_gid;
    evt->gid = uid_gid >> 32;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->cgroup_id = bpf_get_current_cgroup_id();

    /* Get parent PID via task_struct CO-RE access */
    struct task_struct *task = (void *)bpf_get_current_task();
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    evt->process_start_ns = BPF_CORE_READ(leader, start_boottime);

    /* Identity decided in-kernel at event time, so neither a renamed
     * comm nor an exec before userspace reads the event can forge it. */
    evt->proc_flags = (evt->pid == 1 || is_protected_tgid(evt->pid, evt->process_start_ns))
                          ? TRACE_PROC_PROTECTED : 0;
    evt->aux = 0;

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    evt->ppid = BPF_CORE_READ(parent, tgid);

    /* Capture process lineage (parent + grandparent comm) for context-aware detection */
    BPF_CORE_READ_STR_INTO(&evt->parent_comm, parent, comm);
    struct task_struct *gp = BPF_CORE_READ(parent, real_parent);
    BPF_CORE_READ_STR_INTO(&evt->grandparent_comm, gp, comm);

    return evt;
}

/* Increment per-event-type counter. */
static __always_inline void bump_stat(__u32 event_type)
{
    __u64 *cnt = bpf_map_lookup_elem(&trace_stats, &event_type);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

/* Swap bytes for a 16-bit value (network-to-host). */
static __always_inline __u16 trace_ntohs(__u16 v)
{
    return (v >> 8) | (v << 8);
}

/* ── Enforcement: check policy and optionally kill the process ────────────
 *  Called AFTER event is fully populated but BEFORE bpf_ringbuf_submit().
 *  Looks up the enforcement rule for this event_type, checks severity
 *  threshold, and applies the configured action (ALERT / KILL).
 *  On KILL: sends SIGKILL via bpf_send_signal() — signal acceptance is not observed process exit.
 *  pid<=1, the agent and trace_protected_tgids entries are refused (-1).
 * ──────────────────────────────────────────────────────────────────────── */
static __always_inline void enforce_check(struct wafio_event *evt)
{
    struct trace_enforce_rule *rule;
    __u32 key = evt->event_type;

    rule = bpf_map_lookup_elem(&trace_enforce_map, &key);
    if (!rule || !rule->enabled)
        return;

    /* Check severity threshold */
    if (evt->severity < rule->min_severity)
        return;

    /* Record the enforcement action in the event */
    evt->action    = rule->action;
    evt->policy_id = rule->policy_id;

    /* Execute the action */
    if (rule->action == TRACE_ACTION_KILL) {
        __u32 zero = 0;
        struct trace_config *cfg = bpf_map_lookup_elem(&trace_config_map, &zero);
        evt->signal_attempted = 1;
        if (evt->pid <= 1 || (cfg && evt->pid == cfg->agent_pid) ||
            is_protected_tgid(evt->pid, evt->process_start_ns))
            evt->signal_result = -1; /* refused: protected target */
        else
            evt->signal_result = bpf_send_signal(9); /* acceptance is not observed exit */
    }
}

/* Bump a TRACE_PRIO_* counter. */
static __always_inline void trace_prio_stat(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&trace_priority_stats, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

/* The agent's priority-ring control word, or NULL. */
static __always_inline struct trace_priority_ctl *trace_prio_ctl(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&trace_priority_ctl, &zero);
}

/* An event is a kill candidate when the kernel already killed for it
 * (keep that record), or when an enabled userspace Kill policy could select
 * its type at its severity (trace_priority_rules, written by the agent).
 * Never while no agent reads the priority ring (ctl.attached unset). */
static __always_inline int trace_is_kill_candidate(const struct wafio_event *evt)
{
    struct trace_priority_ctl *ctl = trace_prio_ctl();
    if (!ctl || !ctl->attached)
        return 0;
    if (evt->action == TRACE_ACTION_KILL)
        return 1;
    __u32 type = evt->event_type;
    struct trace_priority_rule *rule = bpf_map_lookup_elem(&trace_priority_rules, &type);
    return rule && rule->enabled && evt->severity >= rule->min_severity;
}

/* One FNV-1a 64 step over a path byte, ASCII lowercased (MatchFilename
 * compares case-insensitively); the agent hashes names the same way. */
static __always_inline __u64 trace_name_hash_byte(__u64 h, __u8 c)
{
    if (c >= 'A' && c <= 'Z')
        c |= 0x20;
    return (h ^ c) * TRACE_FNV64_PRIME;
}

/* The kernel raises openat severity on an exact path only; the agent
 * cleans and resolves the path first (/etc/./shadow, "shadow" from /etc,
 * /etc/./sudoers.d/x) and may raise it to the level a Kill policy waits for.
 * trace_priority_names lists the last component of each filename term of such
 * a policy. An openat is a candidate at any kernel severity when its final
 * component is listed, or - opened for writing (O_WRONLY, O_RDWR, O_TRUNC) -
 * when any component is: a directory term (/etc/sudoers.d/, /proc/, /sys/)
 * gets a raised severity only for a write, and a read under /proc must not
 * crowd the ring. Only listed names route: a flood has to use them. The
 * nonempty flag (not a length) keeps the verifier's states per iteration
 * bounded. */
static __always_inline int trace_open_name_candidate(const struct wafio_event *evt)
{
    struct trace_priority_ctl *ctl = trace_prio_ctl();
    if (!ctl || !ctl->attached || !ctl->open_names)
        return 0;
    int modifies = (evt->flags & 3) || (evt->flags & 01000);
    __u64 h = TRACE_FNV64_OFFSET;
    int nonempty = 0;
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < TRACE_FILENAME_LEN; i++) {
        __u8 c = evt->filename[i];
        if (!c)
            break;
        if (c != '/') {
            h = trace_name_hash_byte(h, c);
            nonempty = 1;
            continue;
        }
        if (modifies && nonempty && bpf_map_lookup_elem(&trace_priority_names, &h))
            return 1;
        h = TRACE_FNV64_OFFSET;
        nonempty = 0;
    }
    return nonempty && bpf_map_lookup_elem(&trace_priority_names, &h) != 0;
}

/* Shed exemption of an openat, asked only when the event would be shed (so a
 * ring the reader keeps up with pays nothing for it): 1 = export it anyway,
 * because the agent or ingest may raise it after the ring.
 *  - a relative path opened for writing (O_WRONLY, O_RDWR, O_TRUNC): the
 *    agent resolves it against the CWD or dirfd (/etc/sudoers.d, /proc);
 *  - an absolute path that filepath.Clean changes ("//", "/./", "/../", a
 *    trailing "/", "/." or "/.."): the agent cleans it and re-derives the
 *    severity (/etc//shadow, /tmp/../etc/sudoers.d/x);
 *  - a component in trace_keep_names (agent-written: credential, auth and
 *    persistence names, the filename terms of Kill/Alert/Simulate policies):
 *    any entry keeps a write that has it as any component, TRACE_KEEP_NAME
 *    a read whose final component it is, TRACE_KEEP_DIR any read below it.
 * Verifier cost: the loop carries only the running hash. Each component end
 * re-reads the bytes before it and the open flags instead of keeping flags or
 * a state machine in registers, so every iteration has about one state (a
 * flag carried across iterations multiplied the open programs' processed
 * instructions twentyfold). */
static __always_inline int trace_open_keep(const struct wafio_event *evt)
{
    if (evt->filename[0] != '/' && ((evt->flags & 3) || (evt->flags & 01000)))
        return 1;
    __u64 h = TRACE_FNV64_OFFSET;
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < TRACE_FILENAME_LEN; i++) {
        __u8 c = evt->filename[i];
        if (c && c != '/') {
            h = trace_name_hash_byte(h, c);
            continue;
        }
        /* A component ends at i (a '/' or the NUL). */
        if (i > 0) {
            __u8 p1 = evt->filename[i - 1];
            /* empty: "//", or a trailing '/' (not the root alone) */
            int odd = p1 == '/' && (c || i > 1);
            /* "." or ".." */
            if (p1 == '.' && (i == 1 || evt->filename[i - 2] == '/' ||
                              (evt->filename[i - 2] == '.' &&
                               (i == 2 || evt->filename[i - 3] == '/'))))
                odd = 1;
            if (odd && evt->filename[0] == '/')
                return 1;
            if (p1 != '/') {
                __u8 *v = bpf_map_lookup_elem(&trace_keep_names, &h);
                if (v && ((evt->flags & 3) || (evt->flags & 01000) ||
                          (*v & TRACE_KEEP_DIR) || (!c && (*v & TRACE_KEEP_NAME))))
                    return 1;
            }
        }
        if (!c)
            return 0;
        h = TRACE_FNV64_OFFSET;
    }
    return 0;
}

/* Shared-ring headroom (wafio_trace.h, TRACE_SHED_*): 1 = this event may be
 * shed at the ring's current fill. Only a monitor event below MEDIUM that is
 * not a credential change (the caller also rules out kill candidates and,
 * for openat, what trace_open_keep keeps); below 6/8 fill nothing is shed,
 * so an idle or keeping-up reader sees every event. */
static __always_inline int trace_shed_wanted(const struct wafio_event *evt)
{
    if (evt->severity >= SEV_MEDIUM || evt->action != TRACE_ACTION_MONITOR)
        return 0;
    __u32 type = evt->event_type;
    if (type < 32 && (TRACE_SHED_KEEP_TYPES & (1u << type)))
        return 0;
    __u64 size = bpf_ringbuf_query(&trace_events, BPF_RB_RING_SIZE);
    __u64 used = bpf_ringbuf_query(&trace_events, BPF_RB_AVAIL_DATA);
    if (!size || used * 8 < size * TRACE_SHED_NOISE_EIGHTHS)
        return 0;
    if (used * 8 < size * TRACE_SHED_ALL_EIGHTHS &&
        !(type < 32 && (TRACE_NOISE_TYPES & (1u << type))))
        return 0;
    return 1;
}

/* Count a shed event in trace_shed_stats (per event type). */
static __always_inline void trace_shed_count(__u32 type)
{
    __u64 *cnt = bpf_map_lookup_elem(&trace_shed_stats, &type);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

#define TRACE_ROUTE_DROP     0
#define TRACE_ROUTE_SHARED   1
#define TRACE_ROUTE_PRIORITY 2

/* Where an event goes after enforcement: not exported (the config does not
 * want it, or the shared ring is nearly full: counted in trace_shed_stats), the
 * shared ring, or the kill-candidate ring. A kill candidate goes to
 * trace_priority_events first and falls back to the shared ring when that is
 * full (trace_export); any other event may be shed when the shared ring is
 * nearly full (trace_shed_wanted), unless trace_open_keep keeps it. open_name:
 * the event is an openat (only trace_open_path passes 1): check the
 * final-component route and the openat shed exemptions. */
static __always_inline int trace_route(struct wafio_event *evt, int open_name)
{
    __u32 zero = 0;
    struct trace_config *cfg = bpf_map_lookup_elem(&trace_config_map, &zero);
    if (evt->action == TRACE_ACTION_MONITOR &&
        (!cfg || !cfg->enabled || evt->severity < cfg->min_severity ||
         !(cfg->event_mask_lo & (1u << (evt->event_type - 1)))))
        return TRACE_ROUTE_DROP;
    if (trace_is_kill_candidate(evt) ||
        (open_name && trace_open_name_candidate(evt)))
        return TRACE_ROUTE_PRIORITY;
    if (trace_shed_wanted(evt) && !(open_name && trace_open_keep(evt))) {
        trace_shed_count(evt->event_type);
        return TRACE_ROUTE_DROP;
    }
    return TRACE_ROUTE_SHARED;
}

/* Export on the ring trace_route chose; trace_stats[0] counts shared-ring
 * output failures. */
static __always_inline void trace_export(struct wafio_event *evt, int priority)
{
    __u32 zero = 0;
    if (priority) {
        if (!bpf_ringbuf_output(&trace_priority_events, evt, sizeof(*evt), 0)) {
            trace_prio_stat(TRACE_PRIO_ROUTED);
            return;
        }
        trace_prio_stat(TRACE_PRIO_FULL);
    }
    if (bpf_ringbuf_output(&trace_events, evt, sizeof(*evt), 0)) {
        __u64 *lost = bpf_map_lookup_elem(&trace_stats, &zero);
        if (lost)
            __sync_fetch_and_add(lost, 1);
        if (priority)
            trace_prio_stat(TRACE_PRIO_LOST);
    }
}

/* Export after enforcement. */
static __always_inline void submit_event_routed(struct wafio_event *evt, int open_name)
{
    int route = trace_route(evt, open_name);
    if (route != TRACE_ROUTE_DROP)
        trace_export(evt, route == TRACE_ROUTE_PRIORITY);
}

static __always_inline void submit_event(struct wafio_event *evt)
{
    submit_event_routed(evt, 0);
}

/* ── Open results ───────────────────────────────────────────────────────────
 * An open is traced at entry (path, severity, enforcement, routing), where its
 * result is not known. The finished event waits in trace_open_pending and the
 * sys_exit probe of its syscall exports it with ret_val and
 * TRACE_EVT_OPEN_RESULT. It leaves at entry, or without a result, when
 *  - the agent did not arm it (trace_open_ctl.defer);
 *  - something may act on it before the open returns: a kill candidate (a
 *    userspace Kill must reach a slow open) or a kernel Kill (the process dies
 *    as the syscall ends);
 *  - its exit probe will not run (kind 0: an x32 task through a kprobe twin);
 *  - the map is full: TRACE_OPEN_NO_FULL;
 *  - the kernel restarts the open, which then enters again: TRACE_OPEN_NO_RESTART;
 *  - the thread went on before the exit probe ran: TRACE_OPEN_NO_NEXT;
 *  - the thread exited inside the open: TRACE_OPEN_NO_EXIT. */
static __always_inline void trace_open_count(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&trace_open_stats, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

/* Export a waiting open as it stands. */
static __always_inline void trace_open_leave(struct wafio_event *pend, __u32 counter)
{
    pend->aux = 0;
    trace_open_count(counter);
    trace_export(pend, 0);
}

/* The waiting open of this thread leaves without a result and its slot is
 * released. */
static __always_inline void trace_open_release(__u32 counter)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct wafio_event *pend = bpf_map_lookup_elem(&trace_open_pending, &key);
    if (!pend)
        return;
    trace_open_leave(pend, counter);
    bpf_map_delete_elem(&trace_open_pending, &key);
}

/* First step of trace_open_path, before anything can drop the new open: a
 * thread entering an open has finished the last one, so an event still waiting
 * lost its exit probe and must not collect the result of a later open. */
static __always_inline void trace_open_release_stale(void)
{
    trace_open_release(TRACE_OPEN_NO_NEXT);
}

/* The last step of trace_open_path. kind: TRACE_OPEN_KIND_* of the syscall, 0
 * when its exit probe will not run. */
static __always_inline void trace_open_submit(struct wafio_event *evt, __u32 kind)
{
    int route = trace_route(evt, 1);
    if (route == TRACE_ROUTE_DROP)
        return;
    if (kind && route == TRACE_ROUTE_SHARED && evt->action != TRACE_ACTION_KILL) {
        __u32 zero = 0;
        struct trace_open_ctl *ctl = bpf_map_lookup_elem(&trace_open_ctl, &zero);
        if (ctl && ctl->defer) {
            __u64 key = bpf_get_current_pid_tgid();
            evt->aux = kind;
            if (!bpf_map_update_elem(&trace_open_pending, &key, evt, BPF_ANY))
                return;
            evt->aux = 0;
            trace_open_count(TRACE_OPEN_NO_FULL);
        }
    }
    trace_export(evt, route == TRACE_ROUTE_PRIORITY);
}

/* sys_exit of an open syscall of the given kind: the waiting open of this
 * thread leaves with the result. */
static __always_inline int trace_open_exit(__u32 kind, __s64 ret)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct wafio_event *pend = bpf_map_lookup_elem(&trace_open_pending, &key);
    if (!pend)
        return 0;
    if (pend->aux != kind) {
        /* Not the open this exit belongs to: the older one lost its exit. */
        trace_open_release(TRACE_OPEN_NO_NEXT);
        return 0;
    }
    if (ret <= -TRACE_ERESTART_FIRST && ret >= -TRACE_ERESTART_LAST) {
        /* Not a result: the kernel runs the open again, as a new entry. */
        trace_open_release(TRACE_OPEN_NO_RESTART);
        return 0;
    }
    pend->ret_val = ret;
    pend->proc_flags |= TRACE_EVT_OPEN_RESULT;
    trace_open_leave(pend, TRACE_OPEN_RESULT);
    bpf_map_delete_elem(&trace_open_pending, &key);
    return 0;
}

/* sched_process_exit of a thread that died inside an open. */
static __always_inline void trace_open_flush(void)
{
    trace_open_release(TRACE_OPEN_NO_EXIT);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SYSCALL ENTRY: tracepoint or kprobe (trace_ksys_*)
 *
 *  Each hook on a syscall with a user-string argument (path, name, module
 *  parameters) is a body over the six syscall arguments, attached one of two
 *  ways. Linux 6.19+/7.0 syscall tracepoints copy those strings from user
 *  memory in perf_syscall_enter (sys_fault_user -> trace_user_fault_read)
 *  before any BPF program runs: work the hooks never use, done with
 *  preemption toggled and retried while the CPU's context-switch count moves.
 *  The retry loop compares a 32-bit copy of that 64-bit count, so once a CPU
 *  has done 2^32 switches every copy fails 100 times and
 *  WARN_ONCE("Too many tries to read user space") fires (seen on 7.0 after
 *  21 days on one vCPU). On such a kernel (the tracepoint format carries a
 *  __<arg>_val field) the agent attaches trace_ksys_<name>, a kprobe on the
 *  syscall's arch wrapper (__x64_sys_<name>), which reads the arguments from
 *  the user pt_regs and reaches the same body; every other kernel, or a
 *  failed kprobe attach, keeps the tracepoint. Both run after seccomp and see
 *  the same arguments; neither sees 32-bit compat syscalls.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* The tracepoint record's arguments, copied out of the context: a ctx pointer
 * plus an offset must not reach the bodies (the verifier refuses modified
 * ctx pointers). */
#define TRACE_TP_ARGS(a, ctx)                                                  \
    __u64 a[6] = { (ctx)->args[0], (ctx)->args[1], (ctx)->args[2],            \
                   (ctx)->args[3], (ctx)->args[4], (ctx)->args[5] }

#if defined(__TARGET_ARCH_x86_64) || defined(__TARGET_ARCH_x86)
#define TRACE_KSYSCALL 1
/* __x64_sys_<name>(const struct pt_regs *regs): the syscall arguments are in
 * the user registers at entry (x86_64 syscall ABI: di si dx r10 r8 r9). */
static __always_inline int trace_ksyscall_args(struct pt_regs *ctx, __u64 *a)
{
    struct pt_regs *regs = (struct pt_regs *)ctx->di;
    if (!regs)
        return -1;
    a[0] = BPF_CORE_READ(regs, di);
    a[1] = BPF_CORE_READ(regs, si);
    a[2] = BPF_CORE_READ(regs, dx);
    a[3] = BPF_CORE_READ(regs, r10);
    a[4] = BPF_CORE_READ(regs, r8);
    a[5] = BPF_CORE_READ(regs, r9);
    return 0;
}
#define TRACE_KSYSCALL_ARGS(a, ctx)                                            \
    __u64 a[6] = {};                                                           \
    if (trace_ksyscall_args((ctx), a))                                         \
        return 0

/* An x32 task enters the same __x64_sys_<name> wrapper, but the syscall
 * tracepoints skip x32: an open entered here never gets its exit probe, so it
 * must not wait for one (kind 0). */
#define TRACE_X32_SYSCALL_BIT 0x40000000
static __always_inline __u32 trace_ksyscall_open_kind(struct pt_regs *ctx, __u32 kind)
{
    struct pt_regs *regs = (struct pt_regs *)ctx->di;
    if (regs && (BPF_CORE_READ(regs, orig_ax) & TRACE_X32_SYSCALL_BIT))
        return 0;
    return kind;
}
#else
#define TRACE_KSYSCALL 0
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  PROCESS HOOKS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* read_argv_into copies argv[1..] into evt->args as NUL-separated strings
 * (long arguments must survive: the old scheme truncated every
 * argument at 31 bytes).
 *
 * Verifier safety: fixed compile-time slot offsets via X-macro expansion —
 * every probe_write touches evt->args + <literal>, which the verifier bounds
 * statically. 8 slots × 128 bytes (127 usable per argument). Zero padding
 * between slots is invisible to the userspace NUL-split join. */
#define READ_ARG_SLOT(N)                                                       \
	do {                                                                   \
		arg = NULL;                                                    \
		bpf_probe_read_user(&arg, sizeof(arg), &argv[N]);              \
		if (arg)                                                       \
			bpf_probe_read_user_str(                               \
				evt->args + ((N) - 1) * TRACE_ARG_CHUNK,       \
				TRACE_ARG_CHUNK, arg);                         \
	} while (0)

static __always_inline void
read_argv_into(struct wafio_event *evt, const char * const *argv)
{
	const char *arg;
	READ_ARG_SLOT(1); READ_ARG_SLOT(2); READ_ARG_SLOT(3); READ_ARG_SLOT(4);
	READ_ARG_SLOT(5); READ_ARG_SLOT(6); READ_ARG_SLOT(7); READ_ARG_SLOT(8);
}

/* ── execve() — command execution ────────────────────────────────────────── */
static __always_inline int sys_enter_execve_args(const __u64 *a)
{
    if (!should_trace(TRACE_EVENT_EXECVE, SEV_INFO))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_EXECVE, SEV_INFO);
    if (!evt) return 0;

    /* args[0] = const char *filename */
    const char *fn = (const char *)a[0];
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), fn);

    /* Read argv[1..TRACE_MAX_ARGS-1] into evt->args as NUL-separated strings
     * (see read_argv_into for the extraction and verifier-safety notes). */
    const char * const *argv = (const char * const *)a[1];
    if (argv)
        read_argv_into(evt, argv);

    /* Bump severity for suspicious executables */
    if (evt->uid == 0)
        evt->severity = SEV_LOW; /* root exec is noteworthy */

    bump_stat(TRACE_EVENT_EXECVE);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_execve_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_execve")
int trace_ksys_execve(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_execve_args(a);
}
#endif

/* ── execveat() — command execution (alternate) ──────────────────────────── */
static __always_inline int sys_enter_execveat_args(const __u64 *a)
{
    if (!should_trace(TRACE_EVENT_EXECVEAT, SEV_INFO))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_EXECVEAT, SEV_LOW);
    if (!evt) return 0;

    /* args[0] = dirfd, args[1] = filename, args[2] = argv, args[3] = envp, args[4] = flags */
    evt->flags  = (__u32)a[4]; /* AT_ flags */
    evt->detail = (__u32)a[0]; /* dirfd */
    const char *fn = (const char *)a[1];
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), fn);

    /* Capture argv[1..] the same way as execve (see read_argv_into). */
    const char * const *argv = (const char * const *)a[2];
    if (argv)
        read_argv_into(evt, argv);

    bump_stat(TRACE_EVENT_EXECVEAT);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_sys_enter_execveat(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_execveat_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_execveat")
int trace_ksys_execveat(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_execveat_args(a);
}
#endif

/* ── sched_process_fork — process creation (covers clone/fork/vfork) ─────── */
/* The formatted tracepoint changed its comm fields to __data_loc in Linux 6.16.
 * Raw TP arguments remain parent/child task_struct pointers across kernels. */
SEC("raw_tracepoint/sched_process_fork")
int trace_sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *parent = (void *)ctx->args[0];
    struct task_struct *child = (void *)ctx->args[1];
    /* Protection is maintained whether or not clone events are traced. */
    protect_forked_child(parent, child);

    if (!should_trace(TRACE_EVENT_CLONE, SEV_INFO))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_CLONE, SEV_INFO);
    if (!evt) return 0;

    evt->detail = BPF_CORE_READ(child, pid);
    BPF_CORE_READ_STR_INTO(&evt->filename, child, comm);

    bump_stat(TRACE_EVENT_CLONE);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── sched_process_exit — process exit ───────────────────────────────────── */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct sched_process_exit_ctx *ctx)
{
    /* Before the exit event: the open it waited for happened first. */
    trace_open_flush();
    if (should_trace(TRACE_EVENT_EXIT, SEV_INFO)) {
        struct wafio_event *evt = new_event(TRACE_EVENT_EXIT, SEV_INFO);
        if (evt) {
            /* Use prio from context (exit_code not read to avoid kernel-version
             * specific task_struct offsets that break the BPF verifier). */
            evt->ret_val = 0;
            evt->detail  = (__u32)ctx->prio;

            bump_stat(TRACE_EVENT_EXIT);
            enforce_check(evt);
            submit_event(evt);
        }
    }
    /* After the event, so it still carries the process's identity flag. */
    protect_on_exit();
    return 0;
}

/* ── sched_process_exec — protected-set maintenance only ────────────────── */
/* No event: execve/execveat entry and exec_exit already report the exec. */
SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(void *ctx)
{
    protect_on_exec();
    return 0;
}

/* ── kill() — send signal ────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_kill")
int trace_sys_enter_kill(struct syscall_enter_ctx *ctx)
{
    __u32 target_pid = (__u32)ctx->args[0];
    __u32 sig        = (__u32)ctx->args[1];

    /* Elevate severity for SIGKILL / SIGTERM / SIGSTOP */
    __u32 sev = SEV_INFO;
    if (sig == 9 || sig == 15 || sig == 19)
        sev = SEV_MEDIUM;

    if (!should_trace(TRACE_EVENT_KILL, sev))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_KILL, sev);
    if (!evt) return 0;

    evt->detail = sig;
    evt->flags  = target_pid;

    bump_stat(TRACE_EVENT_KILL);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── prctl() — process control ───────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_sys_enter_prctl(struct syscall_enter_ctx *ctx)
{
    __u32 option = (__u32)ctx->args[0];

    /* Only trace security-relevant options */
    /* PR_SET_DUMPABLE=4, PR_SET_NO_NEW_PRIVS=38, PR_SET_SECCOMP=22,
       PR_SET_NAME=15, PR_CAPBSET_DROP=24, PR_CAP_AMBIENT=47 */
    __u32 sev = SEV_INFO;
    switch (option) {
    case 22: /* PR_SET_SECCOMP */
    case 24: /* PR_CAPBSET_DROP */
    case 47: /* PR_CAP_AMBIENT */
        sev = SEV_MEDIUM;
        break;
    case 4:  /* PR_SET_DUMPABLE */
    case 15: /* PR_SET_NAME */
    case 38: /* PR_SET_NO_NEW_PRIVS */
        sev = SEV_LOW;
        break;
    default:
        return 0; /* skip uninteresting prctl options */
    }

    if (!should_trace(TRACE_EVENT_PRCTL, sev))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_PRCTL, sev);
    if (!evt) return 0;

    evt->detail = option;
    evt->flags  = (__u32)ctx->args[1]; /* arg2 */

    bump_stat(TRACE_EVENT_PRCTL);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  FILE SYSTEM HOOKS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* AT_FDCWD as the u32 detail field, for the syscalls without a dirfd
 * (open, creat, unlink, chmod): their relative paths are CWD-relative. */
#define TRACE_AT_FDCWD ((__u32)-100)
/* creat(path, mode) == open(path, O_CREAT | O_WRONLY | O_TRUNC, mode). */
#define TRACE_CREAT_FLAGS 01101
/* O_RDWR: what an openat2 with an unreadable open_how is taken to request. */
#define TRACE_O_RDWR 02

/* ── open event — openat() and open/creat/openat2 ───────────────────────── */
/* One event shape for every open syscall, so policies, detection rules and
 * kill-candidate routing see them alike: detail = dirfd, flags = open
 * flags; mark = TRACE_EVT_* bits for proc_flags; kind = TRACE_OPEN_KIND_* of
 * the syscall, 0 when its exit probe will not run (trace_open_submit). */
static __always_inline int
trace_open_path(__u32 dirfd, const char *fn, __u32 flags, __u32 mark, __u32 kind)
{
    trace_open_release_stale();
    if (!should_trace(TRACE_EVENT_OPEN, SEV_INFO))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_OPEN, SEV_INFO);
    if (!evt) return 0;

    evt->proc_flags |= mark;
    evt->detail = dirfd;
    evt->flags  = flags; /* open flags (O_RDWR, O_CREAT, etc.) */

    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), fn);

    /* Elevate severity only for exact sensitive path matches.
     * Use 6-char disambiguation to avoid false positives on paths like
     * /etc/pam.d/_ (p-a-m diverges at index 7 from /etc/passwd p-a-s).
     * /etc/shells  (s-h-e diverges at index 7 from /etc/shadow s-h-a).
     * All other /etc/_ paths are re-evaluated Go-side with process context. */
    if (evt->filename[0] == '/' && evt->filename[1] == 'e' &&
        evt->filename[2] == 't' && evt->filename[3] == 'c' &&
        evt->filename[4] == '/') {
        /* /etc/shadow:  s(5)h(6)a(7)d(8)o(9)w(10)\0 */
        int is_shadow =
            evt->filename[5]=='s' && evt->filename[6]=='h' &&
            evt->filename[7]=='a' && evt->filename[8]=='d' &&
            evt->filename[9]=='o' && evt->filename[10]=='w' &&
            evt->filename[11]=='\0';
        /* /etc/passwd:  p(5)a(6)s(7)s(8)w(9)d(10)\0 */
        int is_passwd =
            evt->filename[5]=='p' && evt->filename[6]=='a' &&
            evt->filename[7]=='s' && evt->filename[8]=='s' &&
            evt->filename[9]=='w' && evt->filename[10]=='d' &&
            evt->filename[11]=='\0';
        /* /etc/sudoers: s(5)u(6)d(7)o(8)e(9)r(10)s(11)\0 */
        int is_sudoers =
            evt->filename[5]=='s' && evt->filename[6]=='u' &&
            evt->filename[7]=='d' && evt->filename[8]=='o' &&
            evt->filename[9]=='e' && evt->filename[10]=='r' &&
            evt->filename[11]=='s' &&
            (evt->filename[12]=='\0' ||
             (evt->filename[12]=='.' && evt->filename[13]=='d' && evt->filename[14]=='/'));
        if (is_shadow || ((is_passwd || is_sudoers) &&
                          ((evt->flags & 3) != 0 || (evt->flags & 01000))))
            evt->severity = SEV_HIGH;
    }

    /* O_WRONLY or O_RDWR on /proc or /sys → suspicious */
    __u32 acc_mode = evt->flags & 3; /* O_RDONLY=0, O_WRONLY=1, O_RDWR=2 */
    if (acc_mode > 0 && evt->filename[0] == '/' &&
        ((evt->filename[1] == 'p' && evt->filename[2] == 'r' &&
          evt->filename[3] == 'o' && evt->filename[4] == 'c' && evt->filename[5] == '/') ||
         (evt->filename[1] == 's' && evt->filename[2] == 'y' &&
          evt->filename[3] == 's' && evt->filename[4] == '/')))
        evt->severity = (evt->severity > SEV_MEDIUM) ? evt->severity : SEV_MEDIUM;

    bump_stat(TRACE_EVENT_OPEN);
    enforce_check(evt);
    trace_open_submit(evt, kind); /* routed here, exported with the result */
    return 0;
}

static __always_inline int sys_enter_openat_args(const __u64 *a, __u32 kind)
{
    /* args[0]=dfd, args[1]=filename, args[2]=flags, args[3]=mode */
    return trace_open_path((__u32)a[0], (const char *)a[1], (__u32)a[2], 0, kind);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_openat_args(a, TRACE_OPEN_KIND_OPENAT);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_openat")
int trace_ksys_openat(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_openat_args(a, trace_ksyscall_open_kind(ctx, TRACE_OPEN_KIND_OPENAT));
}
#endif

/* openat2(dfd, filename, struct open_how *how, size): how->flags is the
 * first __u64; the kernel refuses bits above 31 (EINVAL), so the low word
 * is the whole of it. The tracepoint cannot fault a page in, so a read that
 * fails may still leave the syscall a readable how: fail closed — O_RDWR,
 * marked TRACE_EVT_ARGS_UNREADABLE. */
static __always_inline int sys_enter_openat2_args(const __u64 *a, __u32 kind)
{
    __u64 how_flags = 0;
    __u32 mark = 0;
    if (bpf_probe_read_user(&how_flags, sizeof(how_flags), (const void *)a[2]) != 0) {
        how_flags = TRACE_O_RDWR;
        mark = TRACE_EVT_ARGS_UNREADABLE;
    }
    return trace_open_path((__u32)a[0], (const char *)a[1], (__u32)how_flags, mark, kind);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_sys_enter_openat2(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_openat2_args(a, TRACE_OPEN_KIND_OPENAT2);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_openat2")
int trace_ksys_openat2(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_openat2_args(a, trace_ksyscall_open_kind(ctx, TRACE_OPEN_KIND_OPENAT2));
}
#endif

/* Legacy syscalls without a dirfd (x86_64; arm64 and riscv lack them — the
 * agent skips a missing tracepoint). */
static __always_inline int sys_enter_open_args(const __u64 *a, __u32 kind)
{
    /* args[0]=filename, args[1]=flags, args[2]=mode */
    return trace_open_path(TRACE_AT_FDCWD, (const char *)a[0], (__u32)a[1], 0, kind);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_sys_enter_open(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_open_args(a, TRACE_OPEN_KIND_OPEN);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_open")
int trace_ksys_open(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_open_args(a, trace_ksyscall_open_kind(ctx, TRACE_OPEN_KIND_OPEN));
}
#endif

static __always_inline int sys_enter_creat_args(const __u64 *a, __u32 kind)
{
    /* args[0]=pathname, args[1]=mode */
    return trace_open_path(TRACE_AT_FDCWD, (const char *)a[0], TRACE_CREAT_FLAGS, 0, kind);
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_sys_enter_creat(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_creat_args(a, TRACE_OPEN_KIND_CREAT);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_creat")
int trace_ksys_creat(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_creat_args(a, trace_ksyscall_open_kind(ctx, TRACE_OPEN_KIND_CREAT));
}
#endif

/* The exit side of the four open syscalls: the result of the open the thread
 * entered (trace_open_exit). The kprobe twins above replace only the entry
 * hooks, so these stay tracepoints on every kernel. */
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_sys_exit_openat(struct syscall_exit_ctx *ctx)
{
    return trace_open_exit(TRACE_OPEN_KIND_OPENAT, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_sys_exit_openat2(struct syscall_exit_ctx *ctx)
{
    return trace_open_exit(TRACE_OPEN_KIND_OPENAT2, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_sys_exit_open(struct syscall_exit_ctx *ctx)
{
    return trace_open_exit(TRACE_OPEN_KIND_OPEN, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_creat")
int trace_sys_exit_creat(struct syscall_exit_ctx *ctx)
{
    return trace_open_exit(TRACE_OPEN_KIND_CREAT, ctx->ret);
}

/* ── unlink event — unlinkat() and unlink() ──────────────────────────────── */
static __always_inline int
trace_unlink_path(__u32 dirfd, const char *fn, __u32 flags)
{
    if (!should_trace(TRACE_EVENT_UNLINK, SEV_LOW))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_UNLINK, SEV_LOW);
    if (!evt) return 0;

    evt->detail = dirfd;
    evt->flags  = flags;

    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), fn);

    bump_stat(TRACE_EVENT_UNLINK);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

static __always_inline int sys_enter_unlinkat_args(const __u64 *a)
{
    /* args[0]=dfd, args[1]=pathname, args[2]=flags */
    return trace_unlink_path((__u32)a[0], (const char *)a[1], (__u32)a[2]);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_sys_enter_unlinkat(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_unlinkat_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_unlinkat")
int trace_ksys_unlinkat(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_unlinkat_args(a);
}
#endif

static __always_inline int sys_enter_unlink_args(const __u64 *a)
{
    /* args[0]=pathname */
    return trace_unlink_path(TRACE_AT_FDCWD, (const char *)a[0], 0);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_sys_enter_unlink(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_unlink_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_unlink")
int trace_ksys_unlink(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_unlink_args(a);
}
#endif

/* ── rename event — renameat2() and rename()/renameat() ──────────────────── */
/* Both directory fds are recorded: detail = old dirfd, aux =
 * new dirfd, marked TRACE_EVT_DIRFDS; the agent resolves each relative path
 * against its own dirfd like the other *at calls. */
static __always_inline int
trace_rename_paths(__u32 old_dirfd, const char *old_name, __u32 new_dirfd,
                   const char *new_name, __u32 flags)
{
    if (!should_trace(TRACE_EVENT_RENAME, SEV_LOW))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_RENAME, SEV_LOW);
    if (!evt) return 0;

    evt->flags = flags;
    evt->detail = old_dirfd;
    evt->aux = new_dirfd;
    evt->proc_flags |= TRACE_EVT_DIRFDS;

    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), old_name);
    bpf_probe_read_user_str(evt->args, sizeof(evt->args), new_name);

    bump_stat(TRACE_EVENT_RENAME);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

static __always_inline int sys_enter_renameat2_args(const __u64 *a)
{
    /* args[0]=olddfd, args[1]=oldname, args[2]=newdfd, args[3]=newname, args[4]=flags */
    return trace_rename_paths((__u32)a[0], (const char *)a[1],
                              (__u32)a[2], (const char *)a[3], (__u32)a[4]);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_sys_enter_renameat2(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_renameat2_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_renameat2")
int trace_ksys_renameat2(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_renameat2_args(a);
}
#endif

static __always_inline int sys_enter_renameat_args(const __u64 *a)
{
    /* args[0]=olddfd, args[1]=oldname, args[2]=newdfd, args[3]=newname */
    return trace_rename_paths((__u32)a[0], (const char *)a[1],
                              (__u32)a[2], (const char *)a[3], 0);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_sys_enter_renameat(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_renameat_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_renameat")
int trace_ksys_renameat(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_renameat_args(a);
}
#endif

static __always_inline int sys_enter_rename_args(const __u64 *a)
{
    /* args[0]=oldname, args[1]=newname */
    return trace_rename_paths(TRACE_AT_FDCWD, (const char *)a[0],
                              TRACE_AT_FDCWD, (const char *)a[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_sys_enter_rename(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_rename_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_rename")
int trace_ksys_rename(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_rename_args(a);
}
#endif

/* ── chmod event — fchmodat() and chmod()/fchmodat2() ──────────────────── */
static __always_inline int
trace_chmod_path(__u32 dirfd, const char *fn, __u32 mode)
{
    if (!should_trace(TRACE_EVENT_CHMOD, SEV_LOW))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_CHMOD, SEV_LOW);
    if (!evt) return 0;

    evt->detail = dirfd;
    evt->flags  = mode; /* mode bits */

    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), fn);

    /* SUID/SGID bit → high severity */
    if (evt->flags & 06000)
        evt->severity = SEV_HIGH;

    bump_stat(TRACE_EVENT_CHMOD);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

static __always_inline int sys_enter_fchmodat_args(const __u64 *a)
{
    /* args[0]=dfd, args[1]=filename, args[2]=mode */
    return trace_chmod_path((__u32)a[0], (const char *)a[1], (__u32)a[2]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_sys_enter_fchmodat(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_fchmodat_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_fchmodat")
int trace_ksys_fchmodat(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_fchmodat_args(a);
}
#endif

/* fchmodat2 (Linux 6.6+): glibc routes fchmodat(..., AT_SYMLINK_NOFOLLOW)
 * through it. args[0]=dfd, args[1]=filename, args[2]=mode, args[3]=flags */
static __always_inline int sys_enter_fchmodat2_args(const __u64 *a)
{
    return trace_chmod_path((__u32)a[0], (const char *)a[1], (__u32)a[2]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int trace_sys_enter_fchmodat2(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_fchmodat2_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_fchmodat2")
int trace_ksys_fchmodat2(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_fchmodat2_args(a);
}
#endif

static __always_inline int sys_enter_chmod_args(const __u64 *a)
{
    /* args[0]=filename, args[1]=mode */
    return trace_chmod_path(TRACE_AT_FDCWD, (const char *)a[0], (__u32)a[1]);
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_sys_enter_chmod(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_chmod_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_chmod")
int trace_ksys_chmod(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_chmod_args(a);
}
#endif

/* ── fchownat() — ownership change ──────────────────────────────────────── */
static __always_inline int sys_enter_fchownat_args(const __u64 *a)
{
    if (!should_trace(TRACE_EVENT_CHOWN, SEV_LOW))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_CHOWN, SEV_LOW);
    if (!evt) return 0;

    /* args[0]=dfd, args[1]=filename, args[2]=uid, args[3]=gid, args[4]=flags */
    evt->detail = (__u32)a[2]; /* target uid */
    evt->flags  = (__u32)a[3]; /* target gid */

    const char *fn = (const char *)a[1];
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), fn);

    /* Changing ownership to root → high */
    if (evt->detail == 0)
        evt->severity = SEV_HIGH;

    bump_stat(TRACE_EVENT_CHOWN);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int trace_sys_enter_fchownat(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_fchownat_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_fchownat")
int trace_ksys_fchownat(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_fchownat_args(a);
}
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  NETWORK HOOKS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── connect() — outbound connection ─────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct syscall_enter_ctx *ctx)
{
    if (!should_trace(TRACE_EVENT_CONNECT, SEV_INFO))
        return 0;

    /* args[0]=fd, args[1]=sockaddr*, args[2]=addrlen */
    void *sa_ptr = (void *)ctx->args[1];
    __u32 addrlen = (__u32)ctx->args[2];
    if (!sa_ptr || addrlen < 2)
        return 0;

    /* Read address family first */
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), sa_ptr);

    struct wafio_event *evt = new_event(TRACE_EVENT_CONNECT, SEV_INFO);
    if (!evt) return 0;

    evt->detail      = (__u32)ctx->args[0]; /* fd */
    evt->addr_family = family;

    if (family == 2 /* AF_INET */) {
        struct trace_sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), sa_ptr);
        evt->port = trace_ntohs(sa.sin_port);
        __builtin_memcpy(evt->addr, &sa.sin_addr, 4);

        /* DNS query → medium severity */
        if (evt->port == 53)
            evt->severity = SEV_MEDIUM;
    } else if (family == 10 /* AF_INET6 */) {
        struct trace_sockaddr_in6 sa6 = {};
        bpf_probe_read_user(&sa6, sizeof(sa6), sa_ptr);
        evt->port = trace_ntohs(sa6.sin6_port);
        __builtin_memcpy(evt->addr, sa6.sin6_addr, 16);

        if (evt->port == 53)
            evt->severity = SEV_MEDIUM;
    }

    bump_stat(TRACE_EVENT_CONNECT);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── accept4() — inbound connection ──────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_sys_enter_accept4(struct syscall_enter_ctx *ctx)
{
    if (!should_trace(TRACE_EVENT_ACCEPT, SEV_INFO))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_ACCEPT, SEV_INFO);
    if (!evt) return 0;

    /* args[0]=fd, args[1]=addr, args[2]=addrlen, args[3]=flags */
    evt->detail = (__u32)ctx->args[0]; /* listening fd */
    evt->flags  = (__u32)ctx->args[3];

    bump_stat(TRACE_EVENT_ACCEPT);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── bind() — port binding ───────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_sys_enter_bind(struct syscall_enter_ctx *ctx)
{
    if (!should_trace(TRACE_EVENT_BIND, SEV_LOW))
        return 0;

    void *sa_ptr = (void *)ctx->args[1];
    __u32 addrlen = (__u32)ctx->args[2];
    if (!sa_ptr || addrlen < 2)
        return 0;

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), sa_ptr);

    struct wafio_event *evt = new_event(TRACE_EVENT_BIND, SEV_LOW);
    if (!evt) return 0;

    evt->detail      = (__u32)ctx->args[0]; /* fd */
    evt->addr_family = family;

    if (family == 2) {
        struct trace_sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), sa_ptr);
        evt->port = trace_ntohs(sa.sin_port);
        __builtin_memcpy(evt->addr, &sa.sin_addr, 4);
    } else if (family == 10) {
        struct trace_sockaddr_in6 sa6 = {};
        bpf_probe_read_user(&sa6, sizeof(sa6), sa_ptr);
        evt->port = trace_ntohs(sa6.sin6_port);
        __builtin_memcpy(evt->addr, sa6.sin6_addr, 16);
    }

    /* Binding to privileged port → medium */
    if (evt->port > 0 && evt->port < 1024)
        evt->severity = SEV_MEDIUM;

    bump_stat(TRACE_EVENT_BIND);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── socket() — socket creation ──────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_sys_enter_socket(struct syscall_enter_ctx *ctx)
{
    if (!should_trace(TRACE_EVENT_SOCKET, SEV_INFO))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_SOCKET, SEV_INFO);
    if (!evt) return 0;

    /* args[0]=domain, args[1]=type, args[2]=protocol */
    evt->addr_family = (__u16)ctx->args[0]; /* AF_INET, AF_INET6, AF_UNIX, etc. */
    evt->detail      = (__u32)ctx->args[1]; /* SOCK_STREAM, SOCK_DGRAM, SOCK_RAW */
    evt->flags       = (__u32)ctx->args[2]; /* protocol number */

    /* NETLINK uses SOCK_RAW for ordinary kernel/service communication. */
    if ((evt->detail & 0xff) == SOCK_RAW && evt->addr_family != 16 /* AF_NETLINK */)
        evt->severity = SEV_HIGH;

    /* RxRPC supports AFS and raw ESP supports IPsec. Socket creation alone
     * cannot distinguish those workloads from an exploit attempt. */
    if (evt->addr_family == AF_RXRPC ||
        ((evt->detail & 0xff) == SOCK_RAW && evt->flags == IPPROTO_ESP))
        evt->severity = SEV_MEDIUM;

    bump_stat(TRACE_EVENT_SOCKET);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── listen() — start listening ──────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_listen")
int trace_sys_enter_listen(struct syscall_enter_ctx *ctx)
{
    if (!should_trace(TRACE_EVENT_LISTEN, SEV_LOW))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_LISTEN, SEV_LOW);
    if (!evt) return 0;

    /* args[0]=fd, args[1]=backlog */
    evt->detail = (__u32)ctx->args[0];
    evt->flags  = (__u32)ctx->args[1]; /* backlog */

    bump_stat(TRACE_EVENT_LISTEN);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── sendto() — unconnected UDP egress ─────────────────────────────────────
 *  connect()-based coverage is blind to UDP sends that never call connect:
 *  hardcoded-IP C2 beacons and DNS exfiltration both ship via sendto.
 *  args[0]=fd, args[1]=buf, args[2]=len, args[4]=dest sockaddr, args[5]=addrlen
 */
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct syscall_enter_ctx *ctx)
{
    if (!should_trace(TRACE_EVENT_SENDTO, SEV_INFO))
        return 0;

    void *sa_ptr = (void *)ctx->args[4];
    __u32 addrlen = (__u32)ctx->args[5];
    if (!sa_ptr || addrlen < 2)
        return 0;

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), sa_ptr);

    struct wafio_event *evt = new_event(TRACE_EVENT_SENDTO, SEV_INFO);
    if (!evt) return 0;

    evt->detail      = (__u32)ctx->args[0]; /* fd */
    evt->flags       = (__u32)ctx->args[2]; /* datagram length (capped) */
    evt->addr_family = family;

    if (family == 2 /* AF_INET */) {
        struct trace_sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), sa_ptr);
        evt->port = trace_ntohs(sa.sin_port);
        __builtin_memcpy(evt->addr, &sa.sin_addr, 4);
    } else if (family == 10 /* AF_INET6 */) {
        struct trace_sockaddr_in6 sa6 = {};
        bpf_probe_read_user(&sa6, sizeof(sa6), sa_ptr);
        evt->port = trace_ntohs(sa6.sin6_port);
        __builtin_memcpy(evt->addr, sa6.sin6_addr, 16);
    }

    bump_stat(TRACE_EVENT_SENDTO);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── bpf() — BPF program/map manipulation ──────────────────────────────────
 *  A runtime-security product must see attackers loading their own BPF
 *  (rootkits, hidden keyloggers). The agent's own bpf() traffic is dropped by
 *  the agent-pid filter in should_trace(). args[0]=cmd (BPF_MAP_CREATE=0,
 *  BPF_PROG_LOAD=5, ...).
 */
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_sys_enter_bpf(struct syscall_enter_ctx *ctx)
{
    /* Reads and inventory are routine monitoring. Map mutation is noteworthy;
     * program/link changes retain high severity regardless of process name. */
    __u32 sev = SEV_HIGH;
    switch ((__u32)ctx->args[0]) {
    case BPF_MAP_LOOKUP_ELEM: case BPF_MAP_GET_NEXT_KEY:
    case BPF_OBJ_GET: case BPF_PROG_GET_NEXT_ID: case BPF_MAP_GET_NEXT_ID:
    case BPF_PROG_GET_FD_BY_ID: case BPF_MAP_GET_FD_BY_ID:
    case BPF_OBJ_GET_INFO_BY_FD: case BPF_PROG_QUERY:
    case BPF_BTF_GET_FD_BY_ID: case BPF_TASK_FD_QUERY:
    case BPF_BTF_GET_NEXT_ID: case BPF_MAP_LOOKUP_BATCH:
    case BPF_LINK_GET_FD_BY_ID: case BPF_LINK_GET_NEXT_ID:
        sev = SEV_INFO;
        break;
    case BPF_MAP_CREATE: case BPF_MAP_UPDATE_ELEM: case BPF_MAP_DELETE_ELEM:
    case BPF_MAP_LOOKUP_AND_DELETE_ELEM: case BPF_MAP_FREEZE:
    case BPF_MAP_LOOKUP_AND_DELETE_BATCH: case BPF_MAP_UPDATE_BATCH:
    case BPF_MAP_DELETE_BATCH: case BPF_OBJ_PIN: case BPF_BTF_LOAD:
    case BPF_ENABLE_STATS: case BPF_ITER_CREATE:
        sev = SEV_MEDIUM;
        break;
    }
    if (!should_trace(TRACE_EVENT_BPF_SYSCALL, sev))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_BPF_SYSCALL, sev);
    if (!evt) return 0;

    evt->detail = (__u32)ctx->args[0]; /* bpf() cmd */

    bump_stat(TRACE_EVENT_BPF_SYSCALL);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── sys_exit execve — did the exec actually succeed? ──────────────────────
 *  Enter-side events cannot distinguish a successful exec from an exploit
 *  spray of failing ones. ret_val<0 = failed exec (ENOENT/EACCES/...) — the
 *  canonical signature of exploit brute-forcing.
 */
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_sys_exit_execve(struct syscall_exit_ctx *ctx)
{
    __u32 sev = (ctx->ret < 0) ? SEV_LOW : SEV_INFO;
    if (!should_trace(TRACE_EVENT_EXEC_EXIT, sev))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_EXEC_EXIT, sev);
    if (!evt) return 0;

    evt->ret_val = ctx->ret;

    bump_stat(TRACE_EVENT_EXEC_EXIT);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── sys_exit connect — successful vs failed connection ────────────────────
 *  Enables userspace rules like "successful connection to internal range"
 *  (ret_val >= 0) without the noise of refused/dropped attempts.
 */
SEC("tracepoint/syscalls/sys_exit_connect")
int trace_sys_exit_connect(struct syscall_exit_ctx *ctx)
{
    if (!should_trace(TRACE_EVENT_CONNECT_EXIT, SEV_INFO))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_CONNECT_EXIT, SEV_INFO);
    if (!evt) return 0;

    evt->ret_val = ctx->ret;

    bump_stat(TRACE_EVENT_CONNECT_EXIT);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECURITY HOOKS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── setuid() — privilege change ─────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_sys_enter_setuid(struct syscall_enter_ctx *ctx)
{
    __u32 target_uid = (__u32)ctx->args[0];

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 current_uid = BPF_CORE_READ(task, cred, euid.val);
    /* Entry evidence: a request, not proof the credential change succeeded. */
    __u32 sev = target_uid == current_uid ? SEV_INFO :
                target_uid == 0 ? SEV_CRITICAL : SEV_LOW;

    if (!should_trace(TRACE_EVENT_SETUID, sev))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_SETUID, sev);
    if (!evt) return 0;

    evt->detail = target_uid;

    bump_stat(TRACE_EVENT_SETUID);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── setgid() — privilege change ─────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_sys_enter_setgid(struct syscall_enter_ctx *ctx)
{
    __u32 target_gid = (__u32)ctx->args[0];

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 current_gid = BPF_CORE_READ(task, cred, egid.val);
    __u32 sev = target_gid == current_gid ? SEV_INFO :
                target_gid == 0 ? SEV_HIGH : SEV_LOW;

    if (!should_trace(TRACE_EVENT_SETGID, sev))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_SETGID, sev);
    if (!evt) return 0;

    evt->detail = target_gid;

    bump_stat(TRACE_EVENT_SETGID);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── ptrace() — process debug/injection ──────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_sys_enter_ptrace(struct syscall_enter_ctx *ctx)
{
    __u32 request    = (__u32)ctx->args[0];
    __u32 target_pid = (__u32)ctx->args[1];

    /* Preserve alerts for attach, writes and unknown requests. Ordinary
     * debugger reads/control and self-tracing carry no injection evidence. */
    __u32 sev = SEV_HIGH;
    switch (request) {
    case 0: /* TRACEME */
    case 1: case 2: case 3: /* PEEK{TEXT,DATA,USER} */
    case 7: case 9: case 17: /* CONT, SINGLESTEP, DETACH */
    case 12: case 14: case 18: /* GETREGS, GETFPREGS, GETFPXREGS */
    case 0x4201: case 0x4202: case 0x4204: /* GETEVENTMSG, GETSIGINFO, GETREGSET */
    case 0x4207: case 0x4208: case 0x4209: /* INTERRUPT, LISTEN, PEEKSIGINFO */
    case 0x420a: case 0x420e: /* GETSIGMASK, GET_SYSCALL_INFO */
        sev = SEV_LOW;
        break;
    }

    if (!should_trace(TRACE_EVENT_PTRACE, sev))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_PTRACE, sev);
    if (!evt) return 0;

    evt->detail = request;
    evt->flags  = target_pid;

    bump_stat(TRACE_EVENT_PTRACE);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── finit_module() / init_module() — kernel module loading ──────────────── */
static __always_inline int sys_enter_finit_module_args(const __u64 *a)
{
    /* Kernel module loading is always critical */
    if (!should_trace(TRACE_EVENT_MODULE_LOAD, SEV_CRITICAL))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_MODULE_LOAD, SEV_CRITICAL);
    if (!evt) return 0;

    /* args[0]=fd, args[1]=param_values, args[2]=flags */
    evt->detail = (__u32)a[0]; /* fd */
    evt->flags  = (__u32)a[2]; /* MODULE_INIT_* flags */

    const char *params = (const char *)a[1];
    if (params)
        bpf_probe_read_user_str(evt->args, sizeof(evt->args), params);

    bump_stat(TRACE_EVENT_MODULE_LOAD);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_sys_enter_finit_module(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_finit_module_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_finit_module")
int trace_ksys_finit_module(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_finit_module_args(a);
}
#endif

static __always_inline int sys_enter_init_module_args(const __u64 *a)
{
    if (!should_trace(TRACE_EVENT_INIT_MODULE, SEV_CRITICAL))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_INIT_MODULE, SEV_CRITICAL);
    if (!evt) return 0;

    /* args[0]=module_image, args[1]=len, args[2]=param_values */
    evt->detail = (__u32)a[1]; /* module image length */

    const char *params = (const char *)a[2];
    if (params)
        bpf_probe_read_user_str(evt->args, sizeof(evt->args), params);

    bump_stat(TRACE_EVENT_INIT_MODULE);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_sys_enter_init_module(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_init_module_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_init_module")
int trace_ksys_init_module(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_init_module_args(a);
}
#endif

/* ── mount() — filesystem mount ──────────────────────────────────────────── */
static __always_inline int sys_enter_mount_args(const __u64 *a)
{
    if (!should_trace(TRACE_EVENT_MOUNT, SEV_HIGH))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_MOUNT, SEV_HIGH);
    if (!evt) return 0;

    /* args[0]=dev_name, args[1]=dir_name, args[2]=type, args[3]=flags, args[4]=data */
    evt->flags = (__u32)a[3]; /* mount flags */

    const char *dev = (const char *)a[0];
    if (dev)
        bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), dev);

    const char *dir = (const char *)a[1];
    if (dir)
        bpf_probe_read_user_str(evt->args, sizeof(evt->args), dir);

    bump_stat(TRACE_EVENT_MOUNT);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_sys_enter_mount(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_mount_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_mount")
int trace_ksys_mount(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_mount_args(a);
}
#endif

/* ── umount2() — filesystem unmount ──────────────────────────────────────── */
static __always_inline int sys_enter_umount_args(const __u64 *a)
{
    if (!should_trace(TRACE_EVENT_UMOUNT, SEV_MEDIUM))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_UMOUNT, SEV_MEDIUM);
    if (!evt) return 0;

    /* args[0]=name, args[1]=flags */
    evt->flags = (__u32)a[1];

    const char *name = (const char *)a[0];
    if (name)
        bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), name);

    bump_stat(TRACE_EVENT_UMOUNT);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount")
int trace_sys_enter_umount(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_umount_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_umount")
int trace_ksys_umount(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_umount_args(a);
}
#endif

/* ── mprotect() — memory protection change ───────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_sys_enter_mprotect(struct syscall_enter_ctx *ctx)
{
    /* args[0]=addr, args[1]=len, args[2]=prot */
    __u32 prot = (__u32)ctx->args[2];

    /* Only care about making memory executable (PROT_EXEC=4) */
    if (!(prot & 4))
        return 0;

    /* PROT_WRITE + PROT_EXEC = W^X violation → critical */
    __u32 sev = SEV_MEDIUM;
    if (prot & 2) /* PROT_WRITE */
        sev = SEV_CRITICAL;

    if (!should_trace(TRACE_EVENT_MPROTECT, sev))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_MPROTECT, sev);
    if (!evt) return 0;

    evt->flags = prot;
    evt->detail = (__u32)(ctx->args[0] & 0xFFFFFFFF); /* low 32 bits of address */

    /* Store full address and length in args as hex string */
    /* (can't do snprintf in BPF, so store raw values) */
    __u64 addr = ctx->args[0];
    __u64 len  = ctx->args[1];
    __builtin_memcpy(evt->args, &addr, 8);
    __builtin_memcpy(evt->args + 8, &len, 8);

    bump_stat(TRACE_EVENT_MPROTECT);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── memfd_create() — anonymous memory-backed file creation ──────────────── */
static __always_inline int sys_enter_memfd_create_args(const __u64 *a)
{
    /* Creation is also used for ordinary shared memory; execution is separate. */
    if (!should_trace(TRACE_EVENT_MEMFD, SEV_MEDIUM))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_MEMFD, SEV_MEDIUM);
    if (!evt) return 0;

    /* args[0]=name, args[1]=flags */
    evt->flags = (__u32)a[1];

    const char *name = (const char *)a[0];
    if (name)
        bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), name);

    bump_stat(TRACE_EVENT_MEMFD);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_sys_enter_memfd_create(struct syscall_enter_ctx *ctx)
{
    TRACE_TP_ARGS(a, ctx);
    return sys_enter_memfd_create_args(a);
}

#if TRACE_KSYSCALL
SEC("kprobe/sys_memfd_create")
int trace_ksys_memfd_create(struct pt_regs *ctx)
{
    TRACE_KSYSCALL_ARGS(a, ctx);
    return sys_enter_memfd_create_args(a);
}
#endif

/* ── dup3() — file descriptor duplication ────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_sys_enter_dup3(struct syscall_enter_ctx *ctx)
{
    /* dup2/dup3 to stdin/stdout/stderr can be used for shell redirects */
    __u32 newfd = (__u32)ctx->args[1];
    if (newfd > 2) return 0; /* only care about 0/1/2 */

    if (!should_trace(TRACE_EVENT_DUP, SEV_MEDIUM))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_DUP, SEV_MEDIUM);
    if (!evt) return 0;

    /* args[0]=oldfd, args[1]=newfd, args[2]=flags */
    evt->detail = (__u32)ctx->args[0]; /* oldfd */
    evt->flags  = newfd;               /* newfd (0/1/2) */

    bump_stat(TRACE_EVENT_DUP);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}

/* ── pipe2() — pipe creation ─────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_pipe2")
int trace_sys_enter_pipe2(struct syscall_enter_ctx *ctx)
{
    if (!should_trace(TRACE_EVENT_PIPE, SEV_INFO))
        return 0;

    struct wafio_event *evt = new_event(TRACE_EVENT_PIPE, SEV_INFO);
    if (!evt) return 0;

    /* args[0]=pipefd, args[1]=flags */
    evt->flags = (__u32)ctx->args[1];

    bump_stat(TRACE_EVENT_PIPE);
    enforce_check(evt);
    submit_event(evt);
    return 0;
}
