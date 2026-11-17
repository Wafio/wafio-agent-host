package ebpf

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Compile the actual entry hooks with only kernel I/O replaced; severity and
// enforcement ordering remain production code, including access-mode parsing.
func TestTraceSyscallSeverity(t *testing.T) {
	source, err := os.ReadFile("bpf/wafio_trace.c")
	if err != nil {
		t.Fatal(err)
	}
	header, err := os.ReadFile("bpf/wafio_trace.h")
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := os.ReadFile("bpf/vmlinux.h")
	if err != nil {
		t.Fatal(err)
	}
	var c strings.Builder
	c.WriteString(`typedef uint32_t __u32; typedef uint64_t __u64; typedef uint16_t __u16;
#define SOCK_RAW 3
#define AF_RXRPC 33
#define IPPROTO_ESP 50
struct syscall_enter_ctx { unsigned long args[6]; };
struct wafio_event { __u32 detail, flags, severity, uid, gid; __u16 addr_family; char filename[256]; char args[256]; __u32 proc_flags, aux; };
static struct wafio_event event;
static __u64 identity;
struct cred { struct { __u32 val; } euid, egid; };
struct task_struct { struct cred *cred; };
static struct cred credentials;
static struct task_struct task = { &credentials };
#define BPF_CORE_READ(t, c, f) ((t)->c->f)
static void *bpf_get_current_task(void) { return &task; }
static __u64 bpf_get_current_uid_gid(void) { return identity; }
static int should_trace(__u32 type, __u32 sev) { return 1; }
static struct wafio_event *new_event(__u32 type, __u32 sev) { memset(&event,0,sizeof(event)); event.severity=sev; event.uid=identity; event.gid=identity>>32; return &event; }
static void bump_stat(__u32 type) {}
static void enforce_check(struct wafio_event *e) {}
static void submit_event(struct wafio_event *e) {}
static void submit_event_routed(struct wafio_event *e, int open_name) {}
static void trace_open_release_stale(void) {}
static void trace_open_submit(struct wafio_event *e, __u32 kind) {}
static void bpf_probe_read_user_str(char *dst, unsigned long n, const char *src) { snprintf(dst,n,"%s",src); }
static long bpf_probe_read_user(void *dst, unsigned long n, const void *src) { if (!src) { memset(dst,0,n); return -14; } memcpy(dst,src,n); return 0; }
`)
	for _, line := range strings.Split(string(header), "\n") {
		if strings.HasPrefix(line, "#define SEV_") || strings.HasPrefix(line, "#define TRACE_EVENT_") || strings.HasPrefix(line, "#define TRACE_EVT_") || strings.HasPrefix(line, "#define TRACE_OPEN_KIND_") {
			c.WriteString(line + "\n")
		}
	}
	c.WriteString(regexp.MustCompile(`(?s)enum bpf_cmd \{.*?\};`).FindString(string(kernel)) + "\n")
	for _, line := range strings.Split(string(source), "\n") {
		if strings.HasPrefix(line, "#define TRACE_AT_FDCWD") || strings.HasPrefix(line, "#define TRACE_CREAT_FLAGS") || strings.HasPrefix(line, "#define TRACE_O_RDWR") {
			c.WriteString(line + "\n")
		}
	}
	// The file hooks share one helper per event type.
	for _, name := range []string{"trace_open_path", "trace_unlink_path", "trace_rename_paths", "trace_chmod_path"} {
		body := regexp.MustCompile(`(?s)static __always_inline int\n` + name + `\(.*?\n\}`).FindString(string(source))
		if body == "" {
			t.Fatalf("missing helper %s", name)
		}
		c.WriteString(body + "\n")
	}
	// Tracepoint entries copy the record's arguments (TRACE_TP_ARGS) into the
	// body they share with their kprobe twin (sys_enter_<name>_args).
	tpArgs := regexp.MustCompile(`(?m)^#define TRACE_TP_ARGS\(a, ctx\)(?:.*\\\n)+.*\n`).FindString(string(source))
	if tpArgs == "" {
		t.Fatal("missing TRACE_TP_ARGS")
	}
	c.WriteString(tpArgs)
	for _, name := range []string{"bpf", "setuid", "setgid", "ptrace", "openat", "openat2", "open", "creat",
		"unlinkat", "unlink", "renameat2", "renameat", "rename", "fchmodat", "fchmodat2", "chmod", "socket", "memfd_create"} {
		if shared := regexp.MustCompile(`(?s)static __always_inline int sys_enter_` + name + `_args\(.*?\n\}`).FindString(string(source)); shared != "" {
			c.WriteString(shared + "\n")
		}
		body := regexp.MustCompile(`(?s)int trace_sys_enter_` + name + `\(.*?\n\}`).FindString(string(source))
		if body == "" {
			t.Fatalf("missing hook %s", name)
		}
		c.WriteString(body + "\n")
	}
	c.WriteString(`static int failures;
#define FIELDS(hook,a,b,d,e,f,dir,fl,file,newfile) do { struct syscall_enter_ctx ctx = {{a,b,d,e,f}}; identity=0; credentials.euid.val=0; credentials.egid.val=0; trace_sys_enter_##hook(&ctx); if(event.detail != (__u32)(dir) || event.flags != (__u32)(fl) || strcmp(event.filename,file) || strcmp(event.args,newfile)) { fprintf(stderr,#hook " detail %x flags %o file %s new %s\n",event.detail,event.flags,event.filename,event.args); failures++; } } while(0)
#define CHECK(hook,a,b,d,uid,gid,want) do { struct syscall_enter_ctx ctx = {{a,b,d}}; identity=((__u64)(gid)<<32)|(uid); credentials.euid.val=uid; credentials.egid.val=gid; trace_sys_enter_##hook(&ctx); if(event.severity != want) { fprintf(stderr,#hook "(%lu) severity %u want %u\n",(unsigned long)(a),event.severity,want); failures++; } } while(0)
int main(void) {
 CHECK(bpf,1,0,0,0,0,SEV_INFO);
 CHECK(bpf,4,0,0,0,0,SEV_INFO);
 CHECK(bpf,15,0,0,0,0,SEV_INFO);
 CHECK(bpf,24,0,0,0,0,SEV_INFO);
 CHECK(bpf,2,0,0,0,0,SEV_MEDIUM);
 CHECK(bpf,5,0,0,0,0,SEV_HIGH);
 CHECK(bpf,8,0,0,0,0,SEV_HIGH);
 CHECK(bpf,28,0,0,0,0,SEV_HIGH);
 CHECK(bpf,29,0,0,0,0,SEV_HIGH);
 CHECK(bpf,999,0,0,0,0,SEV_HIGH);
 CHECK(setuid,0,0,0,0,0,SEV_INFO);
 CHECK(setuid,1000,0,0,0,0,SEV_LOW);
 CHECK(setuid,0,0,0,1000,1000,SEV_CRITICAL);
 CHECK(setgid,0,0,0,0,0,SEV_INFO);
 CHECK(setgid,1000,0,0,0,0,SEV_LOW);
 CHECK(setgid,0,0,0,1000,1000,SEV_HIGH);
 CHECK(ptrace,0,0,0,1000,1000,SEV_LOW);
 CHECK(ptrace,1,0,0,1000,1000,SEV_LOW);
 CHECK(ptrace,4,0,0,1000,1000,SEV_HIGH);
 CHECK(ptrace,16,0,0,1000,1000,SEV_HIGH);
 CHECK(ptrace,0x4206,0,0,1000,1000,SEV_HIGH);
 CHECK(ptrace,13,0,0,1000,1000,SEV_HIGH);
 CHECK(ptrace,999,0,0,1000,1000,SEV_HIGH);
 CHECK(openat,0,(unsigned long)"/etc/passwd",0,1000,1000,SEV_INFO);
 CHECK(openat,0,(unsigned long)"/etc/passwd",1,1000,1000,SEV_HIGH);
 CHECK(openat,0,(unsigned long)"/etc/shadow",0,1000,1000,SEV_HIGH);
 CHECK(openat,0,(unsigned long)"/etc/passwd",01000,0,0,SEV_HIGH);
 CHECK(openat,0,(unsigned long)"/etc/sudoers",1,0,0,SEV_HIGH);
 CHECK(openat,0,(unsigned long)"/etc/sudoers.d/admin",1,0,0,SEV_HIGH);
 CHECK(openat,0,(unsigned long)"/etc/sudoers.bak",1,0,0,SEV_INFO);
 CHECK(openat,0,(unsigned long)"/srv/app/log",1,0,0,SEV_INFO);
 CHECK(openat,0,(unsigned long)"/proc/sys/kernel/core_pattern",1,0,0,SEV_MEDIUM);
 CHECK(socket,16,3,0,0,0,SEV_INFO);
 CHECK(socket,2,3,1,0,0,SEV_HIGH);
 CHECK(socket,2,3,50,0,0,SEV_MEDIUM);
 CHECK(socket,33,2,0,0,0,SEV_MEDIUM);
 CHECK(memfd_create,(unsigned long)"shared-memory",0,0,1000,1000,SEV_MEDIUM);
 /* open/creat/openat2 are the same open event, classified alike. */
 struct { __u64 flags, mode, resolve; } how_rd = {0,0,0}, how_rdwr = {2,0,0};
 CHECK(open,(unsigned long)"/etc/shadow",0,0,1000,1000,SEV_HIGH);
 CHECK(open,(unsigned long)"/etc/passwd",0,0,1000,1000,SEV_INFO);
 CHECK(open,(unsigned long)"/etc/passwd",1,0,1000,1000,SEV_HIGH);
 CHECK(creat,(unsigned long)"/etc/passwd",0644,0,0,0,SEV_HIGH);
 CHECK(creat,(unsigned long)"/proc/sys/kernel/core_pattern",0644,0,0,0,SEV_MEDIUM);
 CHECK(openat2,5,(unsigned long)"/etc/shadow",(unsigned long)&how_rd,0,0,SEV_HIGH);
 CHECK(openat2,5,(unsigned long)"/etc/sudoers",(unsigned long)&how_rdwr,0,0,SEV_HIGH);
 CHECK(openat2,5,(unsigned long)"/etc/sudoers",(unsigned long)&how_rd,0,0,SEV_INFO);
 CHECK(openat2,5,(unsigned long)"/etc/passwd",0,0,0,SEV_HIGH);
 if (event.flags != TRACE_O_RDWR || !(event.proc_flags & TRACE_EVT_ARGS_UNREADABLE)) { fprintf(stderr,"unreadable open_how: flags %o marks %x\n",event.flags,event.proc_flags); failures++; }
 CHECK(openat2,5,(unsigned long)"/etc/passwd",(unsigned long)&how_rd,0,0,SEV_INFO);
 if (event.proc_flags & TRACE_EVT_ARGS_UNREADABLE) { fprintf(stderr,"readable open_how marked\n"); failures++; }
 CHECK(chmod,(unsigned long)"/usr/local/bin/x",04755,0,0,0,SEV_HIGH);
 CHECK(chmod,(unsigned long)"/tmp/x",0644,0,0,0,SEV_LOW);
 CHECK(fchmodat2,3,(unsigned long)"x",02755,0,0,SEV_HIGH);
 CHECK(unlink,(unsigned long)"/tmp/x",0,0,0,0,SEV_LOW);
 CHECK(rename,(unsigned long)"/a",(unsigned long)"/b",0,0,0,SEV_LOW);
 /* Same event shape: dirfd in detail (AT_FDCWD without one), flags, paths. */
 FIELDS(openat,7,(unsigned long)"rel",2,0,0,7,2,"rel","");
 FIELDS(open,(unsigned long)"rel",2,0,0,0,TRACE_AT_FDCWD,2,"rel","");
 FIELDS(creat,(unsigned long)"rel",0600,0,0,0,TRACE_AT_FDCWD,TRACE_CREAT_FLAGS,"rel","");
 FIELDS(openat2,9,(unsigned long)"rel",(unsigned long)&how_rdwr,24,0,9,2,"rel","");
 FIELDS(unlinkat,3,(unsigned long)"rel",0x200,0,0,3,0x200,"rel","");
 FIELDS(unlink,(unsigned long)"rel",0,0,0,0,TRACE_AT_FDCWD,0,"rel","");
 /* rename: detail = old dirfd, aux = new dirfd, marked TRACE_EVT_DIRFDS. */
 FIELDS(renameat2,5,(unsigned long)"old",6,(unsigned long)"new",1,5,1,"old","new");
 if (event.aux != 6 || !(event.proc_flags & TRACE_EVT_DIRFDS)) { fprintf(stderr,"renameat2 dirfds: aux %u marks %x\n",event.aux,event.proc_flags); failures++; }
 FIELDS(renameat,5,(unsigned long)"old",6,(unsigned long)"new",0,5,0,"old","new");
 if (event.aux != 6 || !(event.proc_flags & TRACE_EVT_DIRFDS)) { fprintf(stderr,"renameat dirfds: aux %u\n",event.aux); failures++; }
 FIELDS(rename,(unsigned long)"old",(unsigned long)"new",0,0,0,TRACE_AT_FDCWD,0,"old","new");
 if (event.aux != TRACE_AT_FDCWD || !(event.proc_flags & TRACE_EVT_DIRFDS)) { fprintf(stderr,"rename dirfds: aux %x\n",event.aux); failures++; }
 FIELDS(fchmodat,4,(unsigned long)"rel",0640,0,0,4,0640,"rel","");
 FIELDS(fchmodat2,4,(unsigned long)"rel",0640,0x100,0,4,0640,"rel","");
 FIELDS(chmod,(unsigned long)"rel",0640,0,0,0,TRACE_AT_FDCWD,0640,"rel","");
 /* Real uid/gid can remain zero after only effective credentials are dropped. */
 struct syscall_enter_ctx root = {{0}};
 identity=0; credentials.euid.val=1000; credentials.egid.val=1000;
 trace_sys_enter_setuid(&root);
 if(event.severity != SEV_CRITICAL) { fprintf(stderr,"effective UID escalation missed\n"); failures++; }
 trace_sys_enter_setgid(&root);
 if(event.severity != SEV_HIGH) { fprintf(stderr,"effective GID escalation missed\n"); failures++; }
 return failures != 0;
}
`)
	runNativeC(t, "severity_classification", c.String())
}

func TestTraceSetuidDescriptionIsAnAttempt(t *testing.T) {
	event := (&RawTraceEvent{EventType: TraceSetuid, Detail: 0, UID: 0}).ToTraceEvent(0)
	if strings.Contains(event.Description, "ESCALATION") || !strings.Contains(event.Description, "requested") {
		t.Fatalf("entry hook claims completed escalation: %s", event.Description)
	}
}

func TestTraceObjectCreationDoesNotClaimExploit(t *testing.T) {
	for _, raw := range []RawTraceEvent{
		{EventType: TraceSocket, AddrFamily: 33, Detail: 2},
		{EventType: TraceSocket, AddrFamily: 2, Detail: 3, Flags: 50},
		{EventType: TraceMemfd},
	} {
		event := raw.ToTraceEvent(0)
		if strings.Contains(strings.ToLower(event.Description), "exploit") || strings.Contains(event.Description, "fileless execution") {
			t.Errorf("creation claims exploit evidence: %s", event.Description)
		}
	}
}
