# Linux lab for the host agent

The unit tests cover the Go logic. The BPF programs, the kernel verifier, packet
handling, the firewall lockout guards and process kill need a real Linux kernel,
so they are tested in a lab. This page says what the lab needs and which test
runs where.

## What the lab needs

- Linux x86_64, kernel 5.10 or later with BTF (`ls /sys/kernel/btf/vmlinux`).
- Root, for loading BPF programs and attaching XDP and TC hooks.
- `clang`, `llvm` and `libbpf-dev` to build the objects natively, or Docker
  (`scripts/build-ebpf.sh` falls back to an `ubuntu:24.04` container).
- A disposable machine or VM for the firewall scenarios: they change the
  firewall of the machine they run on.

Build the objects from the BPF sources of the same commit as the Go code: the
map layouts change between versions, so tests use fresh private maps, and
reusing old pinned maps is not supported.

## Test ladder

| Level | Command | Needs |
|---|---|---|
| Go tests | `go test ./...` | Linux, nothing privileged; kernel tests skip |
| Stack headroom | part of `go test ./internal/ebpf/` | clang, llvm-objdump, libbpf headers (`WAFIO_BPF_INCLUDE` names an extra include directory) |
| Verifier and budgets | `WAFIO_TEST_BPF_DIR=build/ebpf go test -count=1 -run 'TestBPFObjectsPassVerifier\|TestBPFFirewallVerifierBudget\|TestBPFTraceVerifierBudget' ./internal/ebpf/` | root, objects from `scripts/build-ebpf.sh` |
| Integration fixtures | see `internal/ebpf/integration/README.md` | root, `WAFIO_EBPF_INTEGRATION=1`, an authorized lab |
| Lockout and Kill scenarios | `.github/workflows/ebpf-vm.yml` (dispatch) | a VM per kernel: 5.10, 5.15, 6.1 and 6.12 |
| Full maps | `WAFIO_TEST_BPF_DIR=build/ebpf go test -count=1 -run 'TestBPFObjectMapSizes\|TestTraceProtectedImagesMapMatchesAgent\|TestKernelMapFull' ./internal/ebpf/` | root, objects |
| Protected set in the kernel | `WAFIO_TEST_BPF_DIR=build/ebpf go test -count=1 -run 'TestKernelProtected\|TestKernelBTFHasUnitCheckFields' ./internal/ebpf/` | root, objects, cgroup v2 with `/sys/fs/cgroup/system.slice` (a systemd host), a root-owned `sleep` and `setpriv` (util-linux) and room to copy the test binary, on ext4, XFS or btrfs; attaches the fork, exec, exit and the exit programs of `setuid`, `setreuid` and `setresuid` for a few seconds and makes cgroups named `wafio-itest-*`, which it removes |
| Restart, kill and load at the smallest sizes | `WAFIO_EBPF_VM_SCENARIOS=1 WAFIO_EBPF_FLOOR_LOAD=1 go test ./internal/ebpf/integration -run 'TestVMScenarioMapScale\|TestVMScenarioKilledAgent\|TestVMScenarioLastGood\|TestMapFloorLoad'` | root, objects, veth, a disposable VM |

`scripts/ci-local.sh` runs the first three rows (the third only as root). The
VM workflow is run by hand before a release and after a change under
`internal/ebpf`.

A passing compile or trace run does not prove firewall behaviour, kernel kill,
other kernels or architectures, production capacity or the absence of false
positives. Each result holds for the kernel and architecture it ran on.

## Running the agent in a lab

Start a control plane (see the wafio-cp-backend README), create a host in its
dashboard to get a host key, and issue mTLS credentials. Then run the agent as
root with the objects from `build/ebpf`:

```sh
sudo env WAFIO_HOST_KEY=wafh_... WAFIO_AGENT_NAME=lab-host \
  WAFIO_GRPC_SERVER=<control plane>:9090 \
  WAFIO_GRPC_CLIENT_CERT=client.crt WAFIO_GRPC_CLIENT_KEY=client.key WAFIO_GRPC_CA_CERT=ca.crt \
  ./build/wafio-host-agent --interface <nic> \
    --xdp-obj build/ebpf/wafio_xdp.o --tc-obj build/ebpf/wafio_tc.o \
    --trace --trace-obj build/ebpf/wafio_trace.o
```

Use a named lab unit if you run it under systemd, and stop only that unit
afterwards. Never stop sshd, the interface or other services on the machine to
clean up. The private-network tests create their own veth pair, namespace and
pin directory and remove only those.

To see which processes the kernel protects, read the `protected-process
self-check` line in the agent's log first (see "Protected processes" in the
README). It names the map as `trace_protected_tgids`, but `bpftool` cuts map names
to 15 characters, so that name finds nothing: all three protected-set maps show as
`trace_protected` and `bpftool map dump name trace_protected_tgids` fails with
"can't parse name". List them and dump by id:

```sh
sudo bpftool map list | grep -A1 'name trace_protected'
sudo bpftool map dump id <id>
```

The process map is the `hash` with `key 4B value 8B`: keys are process IDs, values
start times in clock ticks.

## Upgrade order

Upgrade the control plane before the host agent: telemetry v2 needs the
control plane's process receipts. A receipt means the batch was accepted for
processing, not that it is stored. Retention and duplicate suppression are
bounded and live in the process, so a restart resets the counters; do not read
a counter reset by an upgrade as zero historical loss.

## Map sizing tests

The agent sizes its preallocated maps by host memory (README, "Memory use and map
sizes"). These tests show what happens at the smallest sizes and when a map is
full.

`TestBPFObjectMapSizes` reads the objects: each sized map declares the ceiling of
the Go sizing table, the egress blocklist is allocated on insert in both objects,
and the jail is a hash map. It needs no privileges.

`TestKernelMapFull*` (`internal/ebpf/map_full_linux_test.go`, BPF_PROG_TEST_RUN)
load the objects at the floor sizes (scale 0.001) and fill each bounded map past
its capacity with distinct sources:

- SYN flood, rate limit and port scan: a source tracked before the fill is still
  dropped; a new source passes with no event, and `state_table_full` and the
  `wafio_state_full` slot both grow; after the entries age and the prune ran, a
  new abuser is tracked and dropped; under SYN pressure the untracked SYNs drop
  and an established flow passes; replies to host-opened flows never reach the
  full rate map.
- Conntrack: twice the floor in spoofed ACK and UDP flows to an allowed port under
  ingress Deny All; then the reply of a real host-opened connection (IPv4 and
  IPv6) passes by socket proof and its entry comes back, an ACK to a denied
  listening port stays dropped, an ACK with no socket stays dropped.
- Socket proof (`TestKernelMapFullReplyProofAtDrops`): in a network namespace of
  the test thread, with a public address on its loopback, a reply that lost its
  entry passes at each drop that replies skip (family-wide block, geo allow mode,
  ingress default deny, rate limit) and gets its entry back; a forged ACK stays
  dropped; a reply that passes anyway runs no socket lookup and writes no entry.
- Jail: filled to the floor, the next add fails with `ErrJailFull`; entries past
  their TTL make room; jailed sources stay dropped.
- Geoip and bandwidth (LRU): an evicted geoip address escapes the reactive geo
  block until it is enriched again; the accounting map accepts any number of
  sources and no verdict depends on it. The sampler reports both at capacity and
  never as full. A conntrack table filled with ended flows is not full either; a
  flood of fresh flows is.
- The entry counter (batch lookup in chunks and the key walk) and the load of XDP
  and TC at the floor and the ceiling sizes through `loadXDP` and `loadTC`, with
  identical shared maps.

The sampler and the coverage warning run on the same maps in these tests.

`TestMapFloorLoad` (`internal/ebpf/integration/map_floor_load_linux_test.go`,
`WAFIO_EBPF_FLOOR_LOAD=1`) runs on a private veth pair, the peer in a network
namespace of a child process of the test binary. At scale 0.001 it tracks an
abuser, sends 150000 packets from distinct spoofed sources (SYN, ACK or a probe of
a port of their own) and loops requests of a legitimate client for 40 s. It passes
when at least 99.9 % of the requests succeed, the abuser is still dropped, the
refused inserts equal `state_table_full`, and entries plus refusals account for the
sources sent. A run takes about 40 s for each of the three checks.

The scenarios in `vm_scenarios_linux_test.go` for map sizing use the same pair, not
the primary interface:

- `TestVMScenarioMapScaleRestartKeepsServerPush`: a connection the host opened to
  a server that only pushes data survives a restart with another scale under ingress
  Deny All, the host sending nothing. It logs the fail-open window, the time without
  an XDP program on the interface.
- `TestVMScenarioKilledAgentRestartAttachesTC` (kernels before 6.6): an agent is
  killed with SIGKILL, the next start removes its stale legacy filters and attaches
  TC.
- `TestVMScenarioLastGoodEgressListAtFloorScale`: 100000 egress entries apply at the
  smallest scale.

### Running them in QEMU

The distribution kernels build veth, `sch_ingress` and `cls_bpf` as modules, and the
guest is a busybox initramfs with no module tree. Extract those three modules from the
kernel package (`linux-modules-*` on Ubuntu, `linux-image-*` on Debian), decompress
them, put them in the initramfs in dependency order and `insmod` them in `init`, with
`ip link set lo up` for the loopback sockets of the socket proof tests and
`ulimit -l unlimited` (kernels before 5.11 charge maps to the memlock limit, as the
unit's `LimitMEMLOCK=infinity` allows). Run the static test binaries
(`CGO_ENABLED=0 go test -c`) as root:

```sh
WAFIO_TEST_BPF_DIR=/objs/ebpf ebpf-kernel.test -test.run 'TestBPF|TestKernel'
WAFIO_TEST_BPF_DIR=/objs/ebpf WAFIO_EBPF_VM_SCENARIOS=1 WAFIO_EBPF_FLOOR_LOAD=1 \
  WAFIO_EBPF_INTEGRATION=1 WAFIO_TRACE_OBJECT=/objs/ebpf/wafio_trace.o ebpf-integration.test \
  -test.run 'TestVMScenarioMapScale|TestVMScenarioKilledAgent|TestVMScenarioLastGood|TestMapFloorLoad|TestTraceOpenResultPendingFull'
```

### Results

Run on QEMU with KVM (2 vCPUs, 1.5 GB), objects built with clang 18, root. The runs
predate the removal of BPF-LSM: the guests booted with `lsm=capability,bpf` and the
counts include its tests. "Kernel tests" is `TestBPF*` and `TestKernel*` of
`internal/ebpf` (the object, verifier, budget, packet and map full tests);
"scenarios" is the three scenarios above, `TestMapFloorLoad` and the two
`TestTraceOpenResultPendingFull*` tests.

| Kernel | Kernel tests | Scenarios and load test | Fail-open window |
|---|---|---|---|
| 5.10.0-43 (Debian 11) | 84 pass, 2 skip | 6 pass | 1.1 s |
| 5.15.0-160 (Ubuntu 22.04) | 84 pass, 2 skip | 6 pass | 1.3 s |
| 6.1.0-47 (Debian 12) | 85 pass, 1 skip | 6 pass | 1.1 s |
| 6.8.0-110 (Ubuntu 24.04) | 85 pass, 1 skip | 5 pass, 1 skip (TCX: nothing to clean up) | 1.2 s |

The skips are tests that need a newer kernel feature, and the kill scenario on 6.8.
The XDP verifier accepts `bpf_sk_lookup_tcp` and the TC verifier accepts the
allocate-on-insert egress map on all four kernels. The verifier log counts these
processed instructions (limit 1,000,000):

| Kernel | `wafio_xdp_v4` | `wafio_xdp_v6` | `wafio_tc_egress` |
|---|---|---|---|
| 5.10, 6.1 | 314757 | 336770 | 484335 |
| 5.15 | 434834 | 356124 | 584082 |
| 6.8 | 192923 | 217738 | 382594 |

The same tests also pass on kernel 6.17 (the build host, as root).

The load test, on every kernel: 2000 of 2000 legitimate requests in each of the
three runs, the tracked abuser dropped, and for each map 133618 or 133619 refused
inserts plus 16384 entries for 150000 spoofed sources plus the real ones.

The fail-open window is the longest time without an XDP program on the interface
during a restart (stop, then start). The old programs detach first, so the window is
the time to create the maps, load and verify the new objects and attach them. It
does not depend on the map size at these sizes.

Memory the kernel reports for the maps of the firewall objects after the load (the
sized ones, then all of them), against the estimate of the sized ones:

| Kernel | Smallest scale | Full scale | Estimate |
|---|---|---|---|
| 6.8, 6.17 | 20 MiB of 23 MiB | 158 MiB of 161 MiB | 20 and 152 MiB |
| 5.10 | 20 MiB of 79 MiB | 159 MiB of 218 MiB | 20 and 152 MiB |

Kernels 5.15 and 6.1 report 11 and 83 MiB for the sized maps: the per-map figure of
those kernels is an approximation that leaves out part of the preallocated
elements. On 5.10 the allocate-on-insert maps are charged at their full capacity,
which is why its total is larger. The trace maps add 4.8 MiB at the smallest scale
and 19 MiB at full scale (the ring and `trace_open_pending`). The README table
lists the totals by host memory.
