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

## Upgrade order

Upgrade the control plane before the host agent: telemetry v2 needs the
control plane's process receipts. A receipt means the batch was accepted for
processing, not that it is stored. Retention and duplicate suppression are
bounded and live in the process, so a restart resets the counters; do not read
a counter reset by an upgrade as zero historical loss.
