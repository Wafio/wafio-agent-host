// SPDX-License-Identifier: GPL-2.0
// wafio_trace.h — Shared definitions for Wafio enterprise runtime security tracing.
//
// Provides struct & constant definitions shared between the BPF tracepoint
// programs (wafio_trace.c) and the Go userspace manager.
//
// CO-RE: uses vmlinux.h so task_struct offsets are resolved at load time by libbpf.

#ifndef __WAFIO_TRACE_H__
#define __WAFIO_TRACE_H__

#include "vmlinux.h"           /* all kernel types — CO-RE portable */
#include "wafio_compat.h"      /* UAPI constants not in BTF         */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  TRACE EVENT TYPES — one per syscall / hook
 * ═══════════════════════════════════════════════════════════════════════════ */

#define TRACE_EVENT_EXECVE         1   /* execve() — command execution          */
#define TRACE_EVENT_EXECVEAT       2   /* execveat() — command execution (alt)  */
#define TRACE_EVENT_OPEN           3   /* openat() — file open / create         */
#define TRACE_EVENT_CONNECT        4   /* connect() — outbound connection       */
#define TRACE_EVENT_ACCEPT         5   /* accept4() — inbound connection        */
#define TRACE_EVENT_CLONE          6   /* clone() / fork() — process spawn      */
#define TRACE_EVENT_EXIT           7   /* sched_process_exit — process exit     */
#define TRACE_EVENT_KILL           8   /* kill() — send signal                  */
#define TRACE_EVENT_UNLINK         9   /* unlinkat() — file deletion            */
#define TRACE_EVENT_RENAME        10   /* renameat2() — file rename             */
#define TRACE_EVENT_CHMOD         11   /* fchmodat() — permission change        */
#define TRACE_EVENT_CHOWN         12   /* fchownat() — ownership change         */
#define TRACE_EVENT_SETUID        13   /* setuid() — privilege escalation       */
#define TRACE_EVENT_SETGID        14   /* setgid() — privilege escalation       */
#define TRACE_EVENT_PTRACE        15   /* ptrace() — process debug / injection  */
#define TRACE_EVENT_MOUNT         16   /* mount() — filesystem mount            */
#define TRACE_EVENT_UMOUNT        17   /* umount2() — filesystem unmount        */
#define TRACE_EVENT_MODULE_LOAD   18   /* finit_module() — kernel module load   */
#define TRACE_EVENT_MPROTECT      19   /* mprotect() — memory protection change */
#define TRACE_EVENT_BIND          20   /* bind() — port binding                 */
#define TRACE_EVENT_SOCKET        21   /* socket() — socket creation            */
#define TRACE_EVENT_LISTEN        22   /* listen() — start listening            */
#define TRACE_EVENT_DUP           23   /* dup3() — file descriptor duplication  */
#define TRACE_EVENT_PIPE          24   /* pipe2() — pipe creation               */
#define TRACE_EVENT_PRCTL         25   /* prctl() — process control             */
#define TRACE_EVENT_MEMFD         26  /* memfd_create() — memory file creation */
#define TRACE_EVENT_INIT_MODULE   27  /* init_module() — kernel module (raw)   */
#define TRACE_EVENT_SENDTO        28  /* sendto() — unconnected UDP egress     */
#define TRACE_EVENT_BPF_SYSCALL   29  /* bpf() — BPF program/map manipulation  */
#define TRACE_EVENT_EXEC_EXIT     30  /* sys_exit execve — execve() result     */
#define TRACE_EVENT_CONNECT_EXIT  31  /* sys_exit connect — connect() result   */

#define TRACE_EVENT_MAX           31

/* ═══════════════════════════════════════════════════════════════════════════
 *  ENFORCEMENT ACTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

#define TRACE_ACTION_MONITOR      0   /* observe only (default)                */
#define TRACE_ACTION_ALERT        1   /* observe + flag as alert               */
#define TRACE_ACTION_KILL         2   /* send SIGKILL via bpf_send_signal()    */
#define TRACE_ACTION_SIMULATE     3   /* simulate / dry run                    */
#define TRACE_ACTION_BLOCK        4   /* block execution via BPF-LSM (-EPERM)  */

#define MAX_ENFORCE_RULES         64

/* ═══════════════════════════════════════════════════════════════════════════
 *  SEVERITY LEVELS
 * ═══════════════════════════════════════════════════════════════════════════ */

#define SEV_INFO      0   /* informational — normal operation        */
#define SEV_LOW       1   /* low — slightly unusual                  */
#define SEV_MEDIUM    2   /* medium — suspicious activity            */
#define SEV_HIGH      3   /* high — likely attack                    */
#define SEV_CRITICAL  4   /* critical — confirmed compromise pattern */

/* ═══════════════════════════════════════════════════════════════════════════
 *  CATEGORIES (bitflags)
 * ═══════════════════════════════════════════════════════════════════════════ */

#define CAT_PROCESS    (1 << 0)   /* process lifecycle events               */
#define CAT_FILE       (1 << 1)   /* file system operations                */
#define CAT_NETWORK    (1 << 2)   /* network activity                      */
#define CAT_SECURITY   (1 << 3)   /* privilege / security sensitive         */
#define CAT_CONTAINER  (1 << 4)   /* container-relevant operations         */

/* ═══════════════════════════════════════════════════════════════════════════
 *  FIELD SIZES
 * ═══════════════════════════════════════════════════════════════════════════ */

#define TRACE_COMM_LEN      16
#define TRACE_FILENAME_LEN  256
#define TRACE_ARGS_LEN      1024
#define TRACE_MAX_ARGS      9    /* argv[1..8] slots captured per exec */
#define TRACE_ARG_CHUNK     128  /* max bytes copied per argument (8×128 = buffer) */

/* ═══════════════════════════════════════════════════════════════════════════
 *  TRACE CONFIG — per-event-type enable/disable (key=0, single entry)
 * ═══════════════════════════════════════════════════════════════════════════ */

struct trace_config {
    __u32 enabled;               /* master switch: 0=off, 1=on            */
    __u32 event_mask_lo;         /* bitmask for events 1-32               */
    __u32 min_severity;          /* only emit events >= this severity     */
    __u32 filter_own_pid;        /* 1 = suppress events from agent PID   */
    __u32 agent_pid;             /* PID to suppress (auto-filled)         */
    __u32 _pad[3];
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  ENFORCEMENT RULE (per-event-type enforcement pushed from userspace)
 *  Stored in BPF_MAP_TYPE_HASH keyed by event_type.
 * ═══════════════════════════════════════════════════════════════════════════ */

struct trace_enforce_rule {
    __u32 enabled;               /* 0=off, 1=on                           */
    __u32 action;                /* TRACE_ACTION_*                        */
    __u32 min_severity;          /* only enforce if severity >= this      */
    __u32 policy_id;             /* userspace policy ID reference         */
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  KILL-CANDIDATE ROUTING
 *  trace_priority_rules (ARRAY, index = event_type): an event at or above
 *  min_severity may be selected by an enabled userspace Kill policy, so it is
 *  exported on the small trace_priority_events ring, where a flood of other
 *  events cannot crowd it out. Written by the agent from its policy set;
 *  all-zero = not a candidate.
 * ═══════════════════════════════════════════════════════════════════════════ */

struct trace_priority_rule {
    __u32 enabled;               /* 0=off, 1=on                           */
    __u32 min_severity;          /* candidate if severity >= this         */
};

/* trace_priority_ctl[0], written by the agent. Nothing is routed to the
 * priority ring until attached is set: an agent that does not read the ring
 * (older, or its reader failed to open) keeps every event on the shared one.
 * open_names: entries in trace_priority_names; 0 skips the openat name scan. */
struct trace_priority_ctl {
    __u32 attached;
    __u32 open_names;
};

/* trace_priority_names keys: FNV-1a 64 of a final path component, ASCII
 * lowercased (the agent hashes the same way). */
#define TRACE_FNV64_OFFSET  0xcbf29ce484222325ULL
#define TRACE_FNV64_PRIME   0x100000001b3ULL

/* trace_open_ctl[0], written by the agent once every open exit probe is
 * attached: opens then wait for their result (trace_open_pending). Zero keeps
 * the open event leaving at entry, without a result. */
struct trace_open_ctl {
    __u32 defer;
    __u32 _pad;
};

/* trace_open_stats indexes (per-CPU counters read by the agent): how open
 * events left the kernel. */
#define TRACE_OPEN_RESULT     0   /* with the result of the open                */
#define TRACE_OPEN_NO_FULL    1   /* at entry, without result: map refused it   */
#define TRACE_OPEN_NO_NEXT    2   /* without result: the thread went on         */
#define TRACE_OPEN_NO_EXIT    3   /* without result: the thread exited          */
#define TRACE_OPEN_NO_RESTART 4   /* without result: the kernel restarts it     */
#define TRACE_OPEN_STATS      5

/* The open syscall an event belongs to, kept in aux while it waits for its
 * result so the exit probe only completes an open of its own kind. 0 is no
 * kind: the open does not wait. */
#define TRACE_OPEN_KIND_OPENAT  1
#define TRACE_OPEN_KIND_OPENAT2 2
#define TRACE_OPEN_KIND_OPEN    3
#define TRACE_OPEN_KIND_CREAT   4

/* Return values the sys_exit probe sees when a signal ended the syscall and the
 * kernel runs it again (ERESTARTSYS .. ERESTART_RESTARTBLOCK): not a result. */
#define TRACE_ERESTART_FIRST 512
#define TRACE_ERESTART_LAST  516

/* trace_priority_stats indexes (per-CPU counters read by the agent) */
#define TRACE_PRIO_ROUTED   0   /* exported on the priority ring              */
#define TRACE_PRIO_FULL     1   /* priority ring full: tried the shared ring   */
#define TRACE_PRIO_LOST     2   /* both rings full: kill candidate lost        */
#define TRACE_PRIO_STATS    4

/* ═══════════════════════════════════════════════════════════════════════════
 *  SHARED-RING HEADROOM (submit_event_routed, trace_shed_wanted)
 *
 *  When the agent's reader falls behind (a burst on a small host), the shared
 *  ring used to fill with INFO openat and drop whatever came next, MEDIUM+
 *  events included. Past a fill level, low-value events are shed instead of
 *  exported and counted per event type in trace_shed_stats:
 *    ≥ 6/8 full: events of TRACE_NOISE_TYPES below MEDIUM — the file and
 *                network types the control plane's noise filter does not
 *                store below MEDIUM anyway;
 *    ≥ 7/8 full: every event below MEDIUM.
 *  Never shed: MEDIUM and above, enforced events (action != MONITOR), kill
 *  candidates (they go to trace_priority_events first), credential
 *  changes (TRACE_SHED_KEEP_TYPES), and an openat the agent or ingest may
 *  raise (trace_open_keep): an absolute path not in canonical form (//, /./,
 *  /../, trailing / or /. or /..: the agent cleans it and re-derives the
 *  severity), a relative path opened for writing (resolved by the agent
 *  against the CWD or dirfd), and a path whose final component - or, for a
 *  write, any component; for a TRACE_KEEP_DIR entry any component - is in
 *  trace_keep_names (agent-written: credential, auth and persistence file
 *  names, the filename terms of Alert and Simulate policies). The agent
 *  turns a rise in trace_shed_stats into a trace_events_shed security event.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define TRACE_SHED_NOISE_EIGHTHS 6
#define TRACE_SHED_ALL_EIGHTHS   7
/* openat, connect, accept, unlink, rename, bind, socket, listen, sendto,
 * connect_exit: categories file/network only (TestTraceNoiseTypesMatchIngest). */
#define TRACE_NOISE_TYPES ((1u << 3) | (1u << 4) | (1u << 5) | (1u << 9) | (1u << 10) | (1u << 20) | (1u << 21) | (1u << 22) | (1u << 28) | (1u << 31))
/* setuid, setgid: credential changes are never shed (LOW = a change to a
 * non-root id; ingest rules and correlation stages build on them). */
#define TRACE_SHED_KEEP_TYPES ((1u << 13) | (1u << 14))
/* trace_keep_names values (bits, agent-written). Any entry keeps a write
 * that has it as any component; the bits say which reads it keeps. */
#define TRACE_KEEP_NAME  1  /* also a read whose final component it is      */
#define TRACE_KEEP_DIR   2  /* also a read with it as any component         */
#define TRACE_KEEP_WRITE 4  /* writes only (network config, systemd units)  */

/* ═══════════════════════════════════════════════════════════════════════════
 *  TRACE EVENT (sent via BPF ringbuf to userspace)
 * ═══════════════════════════════════════════════════════════════════════════ */

struct wafio_event {
    /* ── identity (32 bytes) ──────────────────────────────────────────── */
    __u64 timestamp_ns;          /* bpf_ktime_get_ns() — monotonic        */
    __u64 cgroup_id;             /* bpf_get_current_cgroup_id()           */
    __u32 pid;                   /* userspace PID (kernel tgid)           */
    __u32 tid;                   /* kernel thread ID (kernel pid)         */
    __u32 ppid;                  /* parent PID                            */
    __u32 uid;                   /* real user ID                          */

    /* ── classification (16 bytes) ────────────────────────────────────── */
    __u32 gid;                   /* real group ID                         */
    __u32 event_type;            /* TRACE_EVENT_* constant                */
    __u32 severity;              /* SEV_* constant                        */
    __u32 flags;                 /* syscall-specific flags (O_RDWR, etc.) */

    /* ── details (16 bytes) ───────────────────────────────────────────── */
    __s64 ret_val;               /* return value (exit probes, opens)     */
    __u32 detail;                /* signal num, target PID, prot, etc.    */
    __u16 port;                  /* port (host byte order) for net events */
    __u16 addr_family;           /* AF_INET / AF_INET6                    */

    /* ── network address (16 bytes) ───────────────────────────────────── */
    __u8  addr[16];              /* IPv4 in [0..3], IPv6 in [0..15]       */

    /* ── strings (1296 bytes) ─────────────────────────────────────────── */
    char  comm[TRACE_COMM_LEN];
    char  filename[TRACE_FILENAME_LEN];
    char  args[TRACE_ARGS_LEN];  /* NUL-separated argv slots */

    /* ── process lineage (32 bytes) ───────────────────────────────────── */
    char  parent_comm[TRACE_COMM_LEN];       /* real_parent->comm              */
    char  grandparent_comm[TRACE_COMM_LEN];  /* real_parent->real_parent->comm */

    /* ── enforcement (8 bytes) ────────────────────────────────────────── */
    __u32 action;                /* TRACE_ACTION_* — action taken         */
    __u32 policy_id;             /* which policy triggered (0 = none)     */
    __s32 signal_result;
    __u32 signal_attempted;
    __u64 process_start_ns; /* exact group-leader start_boottime */

    /* ── identity flags (8 bytes) ─────────────────────────────────────── */
    __u32 proc_flags;       /* TRACE_PROC_* | TRACE_EVT_* */
    __u32 aux;              /* event-specific; rename: new dirfd (TRACE_EVT_DIRFDS) */
};
/* 1440 bytes total: 1408-byte core, 8-byte signal result, 8-byte exact process
 * identity, 8-byte identity flags. Userspace accepts 1432-byte events from
 * older objects (no flags). */

/* proc_flags: the process was PID 1 or in trace_protected_tgids when the event
 * was produced — the agent-verified protected set, or a child forked by it
 * that has not exec'd since. Detection rules key on it instead of the
 * attacker-settable comm. */
#define TRACE_PROC_PROTECTED 1
/* proc_flags bits 8+ describe the event, not the process;
 * objects before them always leave these bits and aux zero. */
/* openat2: open_how was unreadable at the tracepoint (a not-resident page
 * may still be readable to the syscall), so flags carry O_RDWR: fail closed. */
#define TRACE_EVT_ARGS_UNREADABLE (1u << 8)
/* rename events: detail = old dirfd, aux = new dirfd (AT_FDCWD for rename). */
#define TRACE_EVT_DIRFDS          (1u << 9)
/* open events: ret_val is the result of the open, a descriptor or a negative
 * errno. Without the bit the result was not recorded and ret_val is 0. */
#define TRACE_EVT_OPEN_RESULT     (1u << 10)

/* ═══════════════════════════════════════════════════════════════════════════
 *  GENERIC SYSCALL ENTER CONTEXT
 *  Works for all SEC("tracepoint/syscalls/sys_enter_*") programs.
 *  Layout: [8-byte common header] [4-byte syscall_nr + 4-byte pad] [6×8 args]
 * ═══════════════════════════════════════════════════════════════════════════ */

struct syscall_enter_ctx {
    __u64 _common;              /* 8 bytes: common trace header          */
    __u32 syscall_nr;           /* offset 8                              */
    __u32 _pad;                 /* offset 12                             */
    __u64 args[6];              /* offset 16: syscall arguments          */
};

/* sys_exit tracepoint context:
 *  Layout: [8-byte common header] [8-byte syscall number] [8-byte return value]
 */
struct syscall_exit_ctx {
    __u64 _common;              /* 8 bytes: common trace header          */
    __s64 syscall_nr;
    __s64 ret;                  /* syscall return value                  */
};

/* Context for sched_process_exit tracepoint */
struct sched_process_exit_ctx {
    __u64 _common;
    char  comm[16];
    __s32 pid;
    __s32 prio;
};

/* Userspace sockaddr structures for reading connect/bind args */
struct trace_sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;          /* big-endian */
    __u32 sin_addr;          /* big-endian */
    __u8  _pad[8];
};

struct trace_sockaddr_in6 {
    __u16 sin6_family;
    __u16 sin6_port;         /* big-endian */
    __u32 sin6_flowinfo;
    __u8  sin6_addr[16];
    __u32 sin6_scope_id;
};

#endif /* __WAFIO_TRACE_H__ */
