# Linux integration fixtures

`TestTraceObserveAndSimulate` is opt-in and uses a fresh unpinned BPF collection. It attaches tracing probes temporarily, observes its own inert file/TCP operations, verifies simulate (not kill), the syscall-exit ABI, and deletion of the last policy. Cleanup closes only its own links/maps. Other host activity is discarded by the test and never printed.

Build on macOS without Docker, then execute on an authorized Linux lab:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o build/ebpf-integration-linux.test ./internal/ebpf/integration
# Transfer the test and a freshly compiled matching wafio_trace.o to the lab.
WAFIO_EBPF_INTEGRATION=1 WAFIO_TRACE_OBJECT=/absolute/lab/wafio_trace.o ./ebpf-integration-linux.test -test.v -test.timeout=30s
```

Run as root with BTF and all expected tracepoints. Missing probes fail this acceptance test; they are not silently accepted. Ordinary `go test` skips the privileged run. This verifies only the actual kernel/architecture tested. It does not establish compatibility across the support matrix, packet/firewall correctness, enforcement safety under PID reuse, kernel kill, or load/overflow behavior.

### Private network path

`TestFirewallOnPrivateVeth` requires `WAFIO_EBPF_INTEGRATION=1` and
`WAFIO_TEST_BPF_DIR` containing the rebuilt XDP/TC objects. It creates fresh
PID-named veth interfaces, one namespace, and a private bpffs directory. No
namespace default route is added. It attaches generic XDP and both TCX hooks,
then verifies real ICMP allow, source-IP block, monitor pass, and remove-block
pass. Cleanup detaches its own links and removes only those new resources.
This verifies a veth/generic-XDP path, not driver offload or customer interfaces.

Recorded lab result: Linux6.8.0-111 amd64, 2026-09-11: PASS (4.10s), all three
hooks attached; private interface wlh2388223 and namespace/pins removed.

### Open results

`TestTraceOpenResult`, `TestTraceOpenResultBlockedAndKilled`,
`TestTraceOpenResultRestart`, `TestTraceOpenResultPendingFull` and, on x86_64,
`TestTraceOpenResultLegacySyscalls` run the same way as the first fixture
(`-test.run TestTraceOpenResult`): a fresh unpinned trace collection, probes
attached for the length of the test, no network hook. They open a fixture file
in a private temporary directory: once as root (a descriptor), once as an
unprivileged child (EACCES, through the 0700 directory), once for a missing
file (ENOENT), through openat, open, creat and openat2, and check each is one
event carrying its result.

The blocked cases open a fifo with no writer in a child and wait until
`/proc/<pid>/syscall` shows it asleep in openat before they act, so a slow
start cannot make them pass without testing anything. The kill case checks no
event leaves while the open waits, kills the child and checks the event leaves
as an attempt without a result (the kernel's restart code is not a result). The
restart case stops and continues the child: the interrupted open is an
attempt, the open it restarts carries the descriptor. The full-map case blocks
2112 threads in the fifo open (2048 is the size of `trace_open_pending`; it
needs about 2200 free task slots in the cgroup and skips with a message when
the cgroup allows fewer), checks the refused opens are attempts and counted,
then opens the fifo for writing and checks the held ones leave with their
result and that no open is missing (a signal the Go runtime sends to a blocked
thread restarts its open, which adds an attempt event, so the count may exceed
the number of opens).

`BenchmarkTraceOpenCost` times an open and close of an existing file without
tracing and with the trace manager, at about 200k opens a second. Run it with
the object of this build and with one from before open results to see what
waiting for the result costs. Kill candidates and events with a kernel Kill are
not held for a result, so a Kill policy needs no lab test here: the pending
logic is in the native C harness (`TestTraceOpenResultPending`).

### Deferred process termination fixture

`TestTraceDeferredFixtureTermination` uses a separate trace collection and a
unique private filename. Only its own child reads that file repeatedly. The
complex filename predicate uses deferred exact-process identity enforcement;
parent observation is excluded. It verifies the child actually exits through
SIGKILL before its timeout and the outcome log reports helper acceptance.
No running host-agent policy is changed. Linux6.8 amd64 result2026-09-11:
PASS1.26s after fixing outcome loss when the initial log had already drained.
A separate negative identity test rejects mismatched process start identity.

### VM scenarios (CI)

`vm_scenarios_linux_test.go` holds the lockout and Kill scenarios that used to
need a console VM. They run only inside the disposable QEMU VM of the
`ebpf-verifier-vm` job (kernels 5.10, 5.15, 6.1 and 6.12), started by
`build/vm-test.sh` after the verifier and kernel tests, over the SSH session the
job itself uses. If a scenario cuts that session the job fails; the runner's
`ssh` gives up within about 30 s (`ServerAliveInterval 5`, `ServerAliveCountMax 6`).
Every test skips unless `WAFIO_EBPF_VM_SCENARIOS=1`, so an ordinary `go test`
only compiles them (and runs the pure parser tests).

Environment (inside the VM, as root):

| Variable | Meaning |
|---|---|
| `WAFIO_EBPF_VM_SCENARIOS=1` | enable the scenarios |
| `WAFIO_TEST_BPF_DIR` | directory with `wafio_xdp.o`, `wafio_tc.o`, `wafio_trace.o` |
| `SSH_CONNECTION` | required (set by sshd); names the session that must survive |
| `WAFIO_VM_PEER` | optional peer address; default is the default-route gateway (QEMU host alias, usually 10.0.2.2) |
| `WAFIO_VM_PEER_SERVE=1` | runner side only: makes `TestVMPeerServer` serve |

The peer is `TestVMPeerServer` of the same test binary, started on the runner
before the VM: TCP 7000 and 7001 (`PING n` -> `PONG n`; 7000 also answers
`PROBE 7002`), UDP 127.0.0.1:53 echo. The VM reaches it through the QEMU
gateway. Port 7002 is the reverse direction: the VM listens on it and the peer
dials it through the `port-forward: '7002:7002'` of the lvh action.

Scenarios (all through the real `Manager` on the primary interface, generic
XDP, private pin directory `/sys/fs/bpf/wafio-vmtest-<pid>`, state applied in
the agent's order: guard, config, rules replaced, deny switch last):

- `TestVMScenarioIngressDenyRestart`: ingress Deny All + TCP allow for the SSH
  port; second policy pushed; manager stopped and restarted. The SSH session
  and a VM-driven long-lived connection to the peer survive every step; the
  probe of 7002 fails before its allow rule (negative control) and works after.
- `TestVMScenarioEgressDenyControlPlane`: egress Deny All with the control-plane
  exemption at the peer's 7000. The pinned connection survives, an ordinary
  outbound flow to 7001 is cut (egress policy applies in full to flows the host
  opened), the DNS reply path follows the 53/udp rule.
- `TestVMScenarioKillNarrowAndBroad`: a narrowed Kill (comm + marker file) in
  Simulate, then Kill, hits only its uniquely named fixture process; sshd and
  its sessions are untouched; a broad Kill without `kill_acknowledged` is
  refused as saved and applied as alert.

Manual run in a throwaway VM only (they change the firewall of the machine):
build the test binary and the objects, start the peer on the host with
`sudo env WAFIO_VM_PEER_SERVE=1 ./ebpf-vm-scenarios.test -test.run '^TestVMPeerServer$' -test.timeout=0`,
then run `build/vm-test.sh`'s scenario line inside the VM.
