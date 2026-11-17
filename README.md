# wafio-agent-host

The Wafio host agent. It runs as root on one Linux host and does two things:
an eBPF firewall (XDP and TC programs for L3 and L4 filtering, block and allow
lists, geo rules, rate limits) and runtime security tracing (syscall events,
process attestation, kill policies). It reports to a Wafio control plane over
gRPC with mutual TLS. It does no HTTP inspection: that is the WAF agent.

## Place in the platform

| Repo | Contents |
|---|---|
| wafio-cp-backend | Go control plane, migrations, `shared/` module |
| wafio-cp-frontend | SvelteKit dashboard |
| wafio-agent-waf | Rust WAF agent |
| **wafio-agent-host (this repo)** | Go host agent, BPF C |
| wafio-portal | wafio.cloud site and blog (SvelteKit), portal API (Go) (private) |
| uddin-lang-rs | Rust uddin interpreter |
| wafio-release | installers, release bundle layout, release and publish scripts (private) |
| wafio-docs | skills, role agents, specs, findings, plans, ops notes (private) |

The agent protocol (`shared/proto/agent/v1` and the generated `shared/agentpb`),
the firewall and trace policy model and a few helpers come from
`github.com/wafio/wafio-cp-backend/shared`. A protocol change starts there.

## Requirements

- Go toolchain from `go.mod` (`go 1.26.0`, `toolchain go1.26.11`).
- To run: Linux x86_64, kernel 5.10 or later with BTF (`/sys/kernel/btf/vmlinux`),
  root or the capabilities listed under "Capabilities".
- To build the BPF objects: `clang`, `llvm` and `libbpf-dev` on Linux, or Docker.
- For the gates: `golangci-lint`, and `gitleaks` or Docker.
- `go.mod` requires `github.com/wafio/wafio-cp-backend/shared v0.1.0`, which `go`
  fetches from the public wafio-cp-backend repository. To change `shared` and this
  agent together, check out wafio-cp-backend next to this repo and use an untracked
  workspace that replaces the module (`go.work` is in `.gitignore`):
  `go work init . && go work edit -replace github.com/wafio/wafio-cp-backend/shared=../wafio-cp-backend/shared`.
  A `use` line is not enough: Go still looks up the version `go.mod` names.

## Build

The agent only builds and runs on Linux (the loader and the tracer carry
`//go:build linux`). Build and test on a Linux machine.

```sh
scripts/build-ebpf.sh                    # build/ebpf/wafio_{xdp,tc,trace,lsm}.o
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o build/wafio-host-agent ./cmd/wafio-host-agent
```

`scripts/build-ebpf.sh` uses `clang` when it is installed and falls back to an
`ubuntu:24.04` container. It pins `-mcpu=v1`: newer clang versions default to
CPU v3, whose atomics kernels before 5.12 reject. The objects are CO-RE, so one
set loads on any kernel from 5.10 with BTF.

## Test

```sh
scripts/ci-local.sh
```

`scripts/ci-local.sh` runs on Linux and covers: secret scan (gitleaks), a check
that no agent files, tracker IDs or planning-doc references are tracked,
`golangci-lint`, `go build`, `go vet`, `go test`, `go test -race`, `govulncheck`,
the BPF object build, and as root the kernel verifier tests. The kernel
scenarios that change a machine's firewall run only in VMs: see `docs/lab.md`
and `.github/workflows/ebpf-vm.yml` (manual dispatch).

## Run

The agent needs a control plane (agent gRPC on `:9090`), a host key from the
dashboard (Hosts, Add host) and mTLS credentials (Credentials). Example from a
checkout, as root:

```sh
sudo env WAFIO_HOST_KEY=wafh_... WAFIO_AGENT_NAME=my-host \
  WAFIO_GRPC_SERVER=<control plane>:9090 \
  WAFIO_GRPC_CLIENT_CERT=/etc/wafio/certs/host/client.crt \
  WAFIO_GRPC_CLIENT_KEY=/etc/wafio/certs/host/client.key \
  WAFIO_GRPC_CA_CERT=/etc/wafio/certs/host/ca.crt \
  ./build/wafio-host-agent --interface eth0 \
    --xdp-obj build/ebpf/wafio_xdp.o --tc-obj build/ebpf/wafio_tc.o \
    --trace --trace-obj build/ebpf/wafio_trace.o \
    --geoip-db /etc/wafio/security-data/geoip/country.mmdb
```

- Local API: `127.0.0.1:18089` (`--listen`). Every route except `/healthz` needs
  the per-start token written to `/run/wafio/host-agent.token` (`0600`).
- Metrics: set `WAFIO_METRICS_ADDR=127.0.0.1:9100` to serve `/metrics` (a loopback
  address only; anything else stops the start).
- GeoIP database: `wafio-host-agent fetch-data --dir /etc/wafio/security-data`
  downloads the country database (DB-IP by default, MaxMind with a key).
- Lab setup and what each test level proves: `docs/lab.md`.

In production the installer from wafio-release installs the bundle, the
systemd unit and the env file. A manual install is the same steps: create the
`wafio` group (`useradd --system --no-create-home --shell /usr/sbin/nologin wafio`),
put the binary in `/usr/local/bin`, the objects in `/etc/wafio/ebpf/`, the
credentials in `/etc/wafio/certs/host/`, copy `deploy/systemd/host-agent.env.example`
to `/etc/wafio/host-agent.env`, copy `deploy/systemd/wafio-host-agent.service` to
`/etc/systemd/system/`, then `systemctl enable --now wafio-host-agent`.

## Configuration

`wafio-host-agent --help` lists the flags. Most have an environment variable
(`WAFIO_*`), so the systemd unit keeps the host key off the command line, where
every local user could read it in `/proc/<pid>/cmdline`. The unit reads
`/etc/wafio/host-agent.env`; `deploy/systemd/host-agent.env.example` documents
every key.

The agent refuses to start on a non-Linux system, with both `--ebpf` and
`--trace` off, or with an invalid protected-process entry.

### Capabilities

The unit runs as root with `CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_PERFMON
CAP_KILL CAP_SYS_RESOURCE CAP_SYS_PTRACE` and `LimitMEMLOCK=infinity` (kernels
before 5.11 charge BPF maps to the memlock limit). `CAP_KILL` is for enforcement
across users. `CAP_SYS_PTRACE` lets the agent read `/proc/<pid>/exe` of root
daemons to protect them; without it only PID 1 and the agent are protected.

### Protected processes

Kill policies never terminate a protected process. The built-in set is `sshd`
(including `sshd-session` and `sshd-auth`), `systemd`, `systemd-journald`,
`containerd`, `dockerd` and `kubelet`, each counted only when it runs the host
binary. Add daemons with `WAFIO_PROTECTED_PROCESSES` (basenames) and
`WAFIO_PROTECTED_EXE_PATHS` (absolute paths); `WAFIO_PROTECTED_REPLACE_DEFAULTS=true`
replaces the built-in names instead of extending them. A shell or interpreter in
the list is accepted with a warning, because every root process running it
would become unkillable.

Check a running agent:

```sh
journalctl -u wafio-host-agent -b | grep 'protected-process self-check'
```

`kernel_set=present` means the kernel side protects them too. `proc_access=denied`
means the unit lacks `CAP_SYS_PTRACE`.

### eBPF objects ship with the binary

The release bundle carries the compiled objects next to the binary
(`ebpf/wafio_{xdp,tc,trace,lsm}.o`). Install them together: a binary and objects
from different builds can disagree on map layouts. Nothing pushes an object to a
host at run time. The first start after an upgrade needs the new objects in
`/etc/wafio/ebpf/`.

## Release

```sh
scripts/build-dist.sh v1.11.0
```

It builds the objects, builds the binary with `go build -trimpath` and writes
`dist/host-agent/`: the binary, `ebpf/` with the objects, their C source in `ebpf/src/`
and the GPL-2.0 text as `ebpf/COPYING`, `systemd/` with the unit, `NOTICES.txt`, `VERSION`
and `SHA256SUMS`. It signs and uploads nothing. The binary is not obfuscated.

`scripts/release.sh` of wafio-release takes the directory with `--host-agent`, adds
`install.sh`, packs `wafio-host-agent-<version>-linux-amd64.tar.gz`, signs it, writes an
SBOM and uploads it. The bundle layout is `deploy/BUNDLE.md` there. The version reaches
the control plane in the agent's Hello message through
`-X github.com/wafio/wafio-agent-host/internal/agent.AgentVersion`.

`NOTICES.txt` is generated: `scripts/gen-notices.sh`.

## Layout

```
cmd/wafio-host-agent/     entry point and the fetch-data command
internal/agent/           connection to the control plane, telemetry, bundle apply, firewall and trace sync
internal/ebpf/            loader, firewall manager, trace manager, policy engine
internal/ebpf/bpf/        BPF C sources and vmlinux.h (GPL-2.0; shipped as ebpf/src/ in the bundle)
licenses/                 GPL-2.0 text, shipped as ebpf/COPYING in the bundle
internal/ebpf/integration/  Linux integration fixtures and VM scenarios
deploy/systemd/           unit and env example, shipped inside the bundle
docs/lab.md               Linux lab and test levels
scripts/                  ci-local.sh, build-ebpf.sh, build-dist.sh, gen-notices.sh
.github/workflows/        ci.yml (pull requests), ebpf-vm.yml (manual)
```

## License

Copyright (C) 2026 Wafio. This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3 only, as published by the Free Software Foundation. It comes without any warranty. The full text is in `LICENSE` (SPDX: `GPL-3.0-only`).

The BPF programs under `internal/ebpf/bpf/` are the exception: they carry the SPDX identifier GPL-2.0 in their file headers. The Linux kernel lets a BPF program call GPL-only helpers only when the program declares a licence the kernel accepts, so those files stay under GPL-2.0. The text of GPL-2.0 is `licenses/GPL-2.0.txt`; every bundle ships it as `ebpf/COPYING`, with the C source of the objects in `ebpf/src/`. Third-party notices are in `NOTICES.txt`.
