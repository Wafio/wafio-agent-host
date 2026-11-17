package ebpf

// ────────────────────────────────────────────────────────────────────────────
//  Tracepoint definitions — program section → tracepoint path
// ────────────────────────────────────────────────────────────────────────────

// traceProbe maps a program of wafio_trace.o to its tracepoint. Portable (no
// build tag) so TestTraceProbesMatchObjectSource can check it against the C
// source on any host.
type traceProbe struct {
	funcName string // C function name = key in Collection.Programs
	group    string // tracepoint group (e.g. "syscalls" or "sched")
	name     string // tracepoint name (e.g. "sys_enter_execve")
	raw      bool   // use stable raw tracepoint args instead of formatted event record
	// optional: added after the objects were last verifier-checked on a real
	// kernel (legacy file syscalls). A kernel that rejects it drops only this
	// program (createDroppingOptional), not the whole trace object.
	optional bool
	// mayBeAbsent: the syscall is missing on some architectures or kernels
	// (open/creat/unlink/rename/chmod on arm64, renameat on riscv,
	// fchmodat2 before 6.6); a missing tracepoint is not a probe failure.
	mayBeAbsent bool
	// kprobeTwin: a syscall with a user-string argument (path, name, module
	// parameters). The object also has trace_ksys_<syscall>, the same hook
	// as a kprobe on the syscall's arch wrapper, used where the kernel's
	// syscall tracepoint copies those strings from user memory before the
	// program runs (Linux 6.19+/7.0: perf_syscall_enter -> sys_fault_user,
	// whose retry loop WARNs once a CPU passed 2^32 context switches).
	kprobeTwin bool
}

var traceProbes = []traceProbe{
	// Process
	{funcName: "trace_sys_exit_execve", group: "syscalls", name: "sys_exit_execve"},
	{funcName: "trace_sys_exit_connect", group: "syscalls", name: "sys_exit_connect"},
	{funcName: "trace_sys_enter_sendto", group: "syscalls", name: "sys_enter_sendto"},
	{funcName: "trace_sys_enter_bpf", group: "syscalls", name: "sys_enter_bpf"},
	{funcName: "trace_sys_enter_execve", group: "syscalls", name: "sys_enter_execve", kprobeTwin: true},
	{funcName: "trace_sys_enter_execveat", group: "syscalls", name: "sys_enter_execveat", kprobeTwin: true},
	// Protected-set maintenance: exec (emits no event) and exit attach
	// before fork, so once fork starts inserting children of protected
	// processes, an exec into an unprotected image already drops the entry
	// and an exit already removes it (the protected set and
	// the fork budget are filled before any probe attaches).
	{funcName: "trace_sched_process_exec", group: "sched", name: "sched_process_exec"},
	{funcName: "trace_sched_process_exit", group: "sched", name: "sched_process_exit"},
	{funcName: "trace_sched_process_fork", group: "sched", name: "sched_process_fork", raw: true},
	{funcName: "trace_sys_enter_kill", group: "syscalls", name: "sys_enter_kill"},
	{funcName: "trace_sys_enter_prctl", group: "syscalls", name: "sys_enter_prctl"},

	// File
	{funcName: "trace_sys_enter_openat", group: "syscalls", name: "sys_enter_openat", kprobeTwin: true},
	{funcName: "trace_sys_enter_unlinkat", group: "syscalls", name: "sys_enter_unlinkat", kprobeTwin: true},
	{funcName: "trace_sys_enter_renameat2", group: "syscalls", name: "sys_enter_renameat2", kprobeTwin: true},
	{funcName: "trace_sys_enter_fchmodat", group: "syscalls", name: "sys_enter_fchmodat", kprobeTwin: true},
	{funcName: "trace_sys_enter_fchownat", group: "syscalls", name: "sys_enter_fchownat", kprobeTwin: true},
	// The same events from the syscalls that bypassed the *at hooks.
	{funcName: "trace_sys_enter_openat2", group: "syscalls", name: "sys_enter_openat2", kprobeTwin: true, optional: true},
	{funcName: "trace_sys_enter_open", group: "syscalls", name: "sys_enter_open", kprobeTwin: true, optional: true, mayBeAbsent: true},
	{funcName: "trace_sys_enter_creat", group: "syscalls", name: "sys_enter_creat", kprobeTwin: true, optional: true, mayBeAbsent: true},
	{funcName: "trace_sys_enter_unlink", group: "syscalls", name: "sys_enter_unlink", kprobeTwin: true, optional: true, mayBeAbsent: true},
	{funcName: "trace_sys_enter_rename", group: "syscalls", name: "sys_enter_rename", kprobeTwin: true, optional: true, mayBeAbsent: true},
	{funcName: "trace_sys_enter_renameat", group: "syscalls", name: "sys_enter_renameat", kprobeTwin: true, optional: true, mayBeAbsent: true},
	{funcName: "trace_sys_enter_chmod", group: "syscalls", name: "sys_enter_chmod", kprobeTwin: true, optional: true, mayBeAbsent: true},
	{funcName: "trace_sys_enter_fchmodat2", group: "syscalls", name: "sys_enter_fchmodat2", kprobeTwin: true, optional: true, mayBeAbsent: true},

	// The result of an open: the exit side of the four open syscalls. Each adds
	// ret_val to the open event the entry probe recorded; the kernel holds the
	// events for it only once all of them are attached (armOpenResult). All
	// four are optional: a kernel that rejects one keeps the trace object, and
	// open events then carry no result.
	{funcName: "trace_sys_exit_openat", group: "syscalls", name: "sys_exit_openat", optional: true},
	{funcName: "trace_sys_exit_openat2", group: "syscalls", name: "sys_exit_openat2", optional: true},
	{funcName: "trace_sys_exit_open", group: "syscalls", name: "sys_exit_open", optional: true, mayBeAbsent: true},
	{funcName: "trace_sys_exit_creat", group: "syscalls", name: "sys_exit_creat", optional: true, mayBeAbsent: true},

	// Network
	{funcName: "trace_sys_enter_connect", group: "syscalls", name: "sys_enter_connect"},
	{funcName: "trace_sys_enter_accept4", group: "syscalls", name: "sys_enter_accept4"},
	{funcName: "trace_sys_enter_bind", group: "syscalls", name: "sys_enter_bind"},
	{funcName: "trace_sys_enter_socket", group: "syscalls", name: "sys_enter_socket"},
	{funcName: "trace_sys_enter_listen", group: "syscalls", name: "sys_enter_listen"},

	// Security
	{funcName: "trace_sys_enter_setuid", group: "syscalls", name: "sys_enter_setuid"},
	{funcName: "trace_sys_enter_setgid", group: "syscalls", name: "sys_enter_setgid"},
	{funcName: "trace_sys_enter_ptrace", group: "syscalls", name: "sys_enter_ptrace"},
	{funcName: "trace_sys_enter_finit_module", group: "syscalls", name: "sys_enter_finit_module", kprobeTwin: true},
	{funcName: "trace_sys_enter_init_module", group: "syscalls", name: "sys_enter_init_module", kprobeTwin: true},
	{funcName: "trace_sys_enter_mount", group: "syscalls", name: "sys_enter_mount", kprobeTwin: true},
	{funcName: "trace_sys_enter_umount", group: "syscalls", name: "sys_enter_umount", kprobeTwin: true},
	{funcName: "trace_sys_enter_mprotect", group: "syscalls", name: "sys_enter_mprotect"},
	{funcName: "trace_sys_enter_memfd_create", group: "syscalls", name: "sys_enter_memfd_create", kprobeTwin: true},
	{funcName: "trace_sys_enter_dup3", group: "syscalls", name: "sys_enter_dup3"},
	{funcName: "trace_sys_enter_pipe2", group: "syscalls", name: "sys_enter_pipe2"},
}

// optionalTracePrograms lists the trace programs whose verifier rejection
// must not cost the rest of the object.
func optionalTracePrograms() []string {
	var names []string
	for _, p := range traceProbes {
		if p.optional {
			names = append(names, p.funcName)
		}
	}
	return names
}
