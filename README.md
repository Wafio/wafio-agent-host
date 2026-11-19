# wafio-agent-host

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16870/badge)](https://www.bestpractices.dev/projects/16870) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Wafio/wafio-agent-host/badge)](https://scorecard.dev/viewer/?uri=github.com/Wafio/wafio-agent-host)

This repository is one part of [WAFio](https://github.com/Wafio/wafio). Start there to install WAFio, to see the releases, or to report a problem when you do not know which part it is in.

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
| wafio-docs | internal notes (private) |

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
scripts/build-ebpf.sh                    # build/ebpf/wafio_{xdp,tc,trace}.o
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
(including `sshd-session` and `sshd-auth`), `systemd`, `systemd-executor`,
`systemd-journald`, `containerd`, `dockerd`, `kubelet` and `nginx`, each counted
only when it runs the host binary as root, the WAF agent and systemd-networkd.
For `nginx` that is the master process: its workers run as the configured user
and do not count. The WAF agent is matched by
the exact path `/usr/local/bin/wafio-waf-agent` (the unit installer) or
`/opt/wafio/wafio-waf-agent` (the installer in the WAF agent bundle) and counts
only inside its own unit, the cgroup `/system.slice/wafio-waf-agent.service`: it
runs as a service account and reads key and library paths from its own
configuration, so the path alone would let any local user run the binary and be
trusted. systemd-networkd is matched the same way, by
`/usr/lib/systemd/systemd-networkd` or `/lib/systemd/systemd-networkd`, and
counts only in the cgroup `/system.slice/systemd-networkd.service`; it runs as
its own user (`systemd-network`). A copy elsewhere, a session scope, a user unit of the same name and a
process with no readable cgroup do not count. The unit check follows the path,
also when `WAFIO_PROTECTED_EXE_PATHS` lists it again. A binary replaced on disk
(a package upgrade) counts until the next restart, but only while the running
file is one that only root can write and sits on the filesystem of the directory
its path names; for a path that is not bound to a unit the process must also be
in the host mount namespace. `systemd-executor` is the helper
systemd 255 and later run between PID 1 and each service.

A protected process also gets `exe_verified` on its own trace events, so the
control plane can tell the WAF agent reading its TLS key, or the nginx master
loading its own, from another process reading it. The mark says only that the
kernel saw the process in the protected set. A child forked by a protected process keeps it until the child execs or the
next refresh (5 s) drops it, also when the child changes its user in between, and a thread can rename itself with
`prctl(PR_SET_NAME)`. A rule that trusts the mark should therefore also match
the process name and the user. The same set makes the WAF agent immune to Kill
policies, so a policy cannot take down the sites it fronts.

Across `exec` the kernel keeps the mark only when the new program is a file the
agent trusts. It tells files apart by device, inode number and inode generation,
never by name. The trusted files are the protected names (built-in and from
`WAFIO_PROTECTED_PROCESSES`) found in the system directories (`/usr/sbin`,
`/usr/bin`, `/usr/lib/openssh`, `/usr/lib/systemd` and the like), which keep the
mark only for root; the paths in `WAFIO_PROTECTED_EXE_PATHS`, which keep it for
any user; the WAF agent and systemd-networkd paths above, which keep it only
inside their unit; the programs of processes the agent has already verified;
and the `systemd-executor` file that PID 1 holds open. The agent rewrites the
list every 5 s and at once when a file with one of those names changes in one
of those directories, so a restart right after a package upgrade is still
verified from its first event. A program that only carries a protected name (a
copy, a renamed file, a binary in another directory) loses the mark at `exec`,
before its first instruction.

A file is trusted only if root owns it and neither its group nor others can
write it, and the same holds for its directory. An account that owns the file or
the directory could rename a copy of its own over a trusted path, and the agent
would then take the copy for the daemon. The agent reads the paths inside the
root of PID 1, not its own: a symlink in a configured path is followed inside
that root, while the system directories a protected name is searched in must
not be symlinks and the file itself is never a symlink (on a host where `/bin`
points to `usr/bin` the file is found as `/usr/bin/<name>`). Without `openat2`
(before Linux 5.6, or a seccomp filter that refuses it) no path with a symlink
is trusted. A directory
that is group-writable, as `/usr/local/bin` is on some Debian hosts
(`root:staff`, mode 2775), makes the files in it untrusted until it is set to
`755`. A directory that does not exist when the agent starts is watched as soon
as it appears (at the next 5 s refresh), and one that is moved or replaced is
watched again the same way. A WAF agent whose binary or directory an account
other than root owns (an installer that hands `/opt/wafio` to the service
account) is not protected and has no mark: leave both to root. The agent says so
once in its log for each such path ("can be written by an account other than
root"), at start with a warning too, and again if the path becomes writable
again.

The kernel checks the unit of the WAF agent and systemd-networkd at `exec` too.
It keeps the mark only when the new process runs in a cgroup of the default
hierarchy that is at level 2, is named like the unit and sits under
`system.slice`. The genuine binary run by root or by a user outside its unit
loses the mark at `exec`. A host with only cgroup v1 has no such cgroup, so its
processes lose the mark at `exec` too and get it back at the next refresh; a
hybrid host is untested. Only root can create a directory in `system.slice`.
The check reads the cgroup names with CO-RE and fails closed: a kernel without
the fields, a failed read or a name longer than 46 characters drops the mark.
The fields exist on Linux 5.10, 5.15, 6.1, 6.8 and 6.17, and the check ran on a
real kernel on 6.17 only. On 6.17 `kernfs_node.parent` is named `__parent`; the
program reads the parent through `cgroup.self.parent`, which every kernel has.
Newer kernels read `kernfs_node.name` under RCU; the field keeps its name, so
the same read applies.

Where the agent cannot identify a file, the mark is dropped at `exec` and comes
back at the next refresh once the process is verified. That covers a kernel
before 5.8 (no mount ID from `statx`), and a protected name in a nested
directory: list its path in `WAFIO_PROTECTED_EXE_PATHS`. A filesystem that
reports no inode generation (overlayfs, squashfs, erofs, and tmpfs on some kernels) is
trusted only when its superblock is mounted read-only (`ro` among the super
options in the mountinfo line, not the options of the mount), with generation 0,
which is what the kernel reads for a filesystem that never sets one. A
filesystem that sets one without exposing it has another value in the kernel, the
key does not match and the mark is dropped: the agent prefers not to trust. A
trace object without the image list, or a kernel where the `exec` hook did not
attach, also turns off the inheritance of the mark by children of protected
processes.

A protected process that forks gives its child a mark at once, from a budget the
agent refills at every refresh (room for 768 entries less those in the map). The
kernel takes one unit for each child and gives it back when it removes an entry,
at `exec` or at exit, up to the value of the refresh. A client that opens and
closes SSH connections as fast as `sshd` forks therefore does not use the budget
up and the logins that follow still get their mark. When the budget does run out,
the children are marked at the next refresh and the agent logs how many were
refused.

Add daemons with `WAFIO_PROTECTED_PROCESSES` (basenames) and
`WAFIO_PROTECTED_EXE_PATHS` (absolute paths); `WAFIO_PROTECTED_REPLACE_DEFAULTS=true`
replaces the built-in names and the built-in unit-bound paths (WAF agent, systemd-networkd) instead of extending them. A
shell or interpreter in the list is accepted with a warning, because every root
process running it would become unkillable.

Check a running agent:

```sh
journalctl -u wafio-host-agent -b | grep 'protected-process self-check'
```

`kernel_set=present` means the kernel side protects them too. `proc_access=denied`
means the unit lacks `CAP_SYS_PTRACE`. `untrusted_owner=<paths>` lists files or
directories that an account other than root can write under a protected process:
that process is not protected until root owns the path and neither its group nor
others can write it.

### Memory use and map sizes

The firewall keeps its state in BPF maps that the kernel preallocates when the
agent loads them, whatever the traffic. Every host used to pay about 190 MB of
kernel memory for them. The agent now sizes the maps from the memory of the host
when it loads them, so a small server does not pay for the capacity of a large one.

**Formula.** The memory basis R is `MemTotal` from `/proc/meminfo`, lowered to
the smallest numeric `memory.max` on the agent's cgroup v2 path up to the root
(kernels from 5.11 charge map memory to the cgroup; cgroup v1 is ignored). If
`MemTotal` cannot be read the agent uses the full sizes and logs a WARN. The
scale is `s = min(1, R / 8 GiB)`. Each hash or LRU map gets
`clamp(trunc(ceiling * s), floor, ceiling)`: the ceiling is the size the object
declares, the floor is what a small server still needs. An LRU map keeps at least
1024 entries for each possible CPU (at most its ceiling), because every CPU holds
free nodes back and eviction starts before the map is full. `trace_events` is the
largest power of two at most 16 MiB * s, between 4 and 16 MiB. No size is ever
above its ceiling, and the same formula applies to every map.

| Map | Type | Ceiling | Floor |
|---|---|---|---|
| `wafio_conntrack` | LRU | 500000 | 65536 |
| `wafio_syn_state` | hash | 200000 | 16384 |
| `wafio_rate_state` | hash | 100000 | 16384 |
| `wafio_portscan` | hash | 100000 | 16384 |
| `wafio_bandwidth` | LRU | 100000 | 8192 |
| `wafio_geoip` | LRU | 100000 | 16384 |
| `wafio_jail` | hash | 65536 | 16384 |
| `trace_open_pending` | hash | 2048 | 512 |
| `trace_events` | ring buffer | 16 MiB | 4 MiB |

`wafio_egress_blocklist` is not scaled: it is allocated on insert, so its memory
follows its content, and its capacity stays 100000. The maps of 1 MB or less keep
their fixed sizes. The memory the sized maps preallocate (key, value and about 64
bytes an entry, estimated):

| Host memory | 1 GB | 2 GB | 4 GB | 8 GB and more |
|---|---|---|---|---|
| Sized maps | 28 MB | 45 MB | 90 MB | 180 MB |

At the smallest scale the sized maps take about 26 MB, at full scale about 180 MB.
The LPM tries (allow, block, geo CIDR, egress subnets) are allocated on insert and
grow with their content.

**Setting.** `--ebpf-map-scale` takes `auto` (the default) or a number above 0 and
at most 1, which replaces `s`: `1` gives every host the full sizes, `0.001` every
map its floor. `WAFIO_EBPF_MAP_SCALE` is read when the flag is not set, so the
unit's `ExecStart` stays as it is. Any other value stops the start with
`invalid --ebpf-map-scale "1.5" (or WAFIO_EBPF_MAP_SCALE): want auto or a number above 0 and at most 1`.
Every start logs the sizes in use, for example:

```
eBPF map sizing: scale=0.240 source=auto memory=1962MiB (meminfo) wafio_conntrack=119750 wafio_syn_state=47900 wafio_rate_state=23950 wafio_portscan=23950 wafio_bandwidth=23950 wafio_geoip=23950 wafio_jail=16384 trace_open_pending=512 trace_events=4MiB est=41MiB
```

**When a map is full.** A full map never makes legitimate traffic drop, and no
protection goes off without a signal.

| Map | When full |
|---|---|
| `wafio_conntrack` (LRU) | Evicts the flows used least recently. A host-opened TCP flow that lost its entry passes again by socket proof: an ACK (no SYN, no RST) that a check replies skip would drop (the family-wide block, geo allow mode, the ingress default deny, the rate limit) passes as a reply when the kernel holds an established connection for exactly its 4-tuple and no listener owns the local port. A forged ACK finds no such socket. The proof runs only at such a drop, so a packet that passes anyway costs no socket lookup. |
| `wafio_syn_state`, `wafio_rate_state`, `wafio_portscan` (hash) | The insert is refused. The packet passes and the per-source check is skipped, with no event. A source already tracked stays tracked, so a known abuser stays limited. The refusals count in `state_table_full` and in `wafio_state_full`. |
| `wafio_bandwidth` (LRU) | Evicts. The accounting is incomplete; no verdict depends on it. |
| `wafio_geoip` (LRU) | Evicts. An evicted address escapes the reactive geo block until the enricher resolves it again. The enricher clears its own cache when it reaches the size of the map. The geo CIDR tries are not affected. |
| `wafio_jail` (hash) | Refuses a new address. The agent first deletes the entries past their TTL and tries once more (at most one such sweep a second, since a sweep reads every entry); if the jail is still full the local API answers `409 IP_LIST_FULL` and the refusal is counted. A jailed address is never evicted, and the WAF agent still blocks at L7. |
| `trace_open_pending` (hash) | The open result is unknown. The event leaves without a result and counts in `open_result_unknown`. |
| `trace_events` (ring) | Low-severity events are shed at 6/8 full and the losses are counted. |

**What the operator sees.** The status carries `map_sizing` (`ebpf_status` for the
firewall maps, `trace_status` for the trace maps): the scale and where it came
from, the memory it came from, and for each sized map `max_entries`, the size the
object declares, the live `entries` (sampled every 30 s), `full_count` (inserts
refused since start; absent for the LRU maps) and `last_full_at`. The conntrack
table keeps the entries of ended flows until it needs their room, so on a busy
host it always sits at capacity: its `entries` counts only the flows still fresh
(30 s for UDP, 300 s for TCP since their last packet), and `last_full_at` is the
last sample that found those within one eviction margin of full, when the table
evicts live flows. `wafio_bandwidth` and `wafio_geoip` are caches that fill up and
evict by design; they report `entries` and never count as full. While a
firewall map was full in the last 10 minutes the status adds one coverage warning,
`eBPF maps full in the last 10 minutes: <names>. Map scale <s> (<source>): raise WAFIO_EBPF_MAP_SCALE (at most 1) or look for a flood.`,
which marks the host degraded in the fleet view. The agent logs a WARN when a map
becomes full, at most once every 10 minutes for each map. A full map during a flood
is the table doing its job: raise the scale only when it is full without one.

**Restart and upgrade.** Nothing is pinned: every start creates its maps at the
size it computes, so a change of size or of the agent version cannot meet an old
map. Every restart loses the conntrack table, the detection counters, the jail,
the bandwidth accounting and the geoip cache, whatever the size; the policy comes
back from the last good state. Inbound flows to allowed ports pass and TC adopts
them again. Host-opened TCP passes by socket proof. Host-opened UDP recovers on
the host's next outbound packet. Jail entries return when the WAF agent jails the
address again. Geo allow mode starts its grace again. The last good restore cannot
fail on size, because the egress capacity does not depend on the scale. TC takes
size and flags of every shared map from the XDP map, so a size difference between
two objects cannot switch the firewall off. On a kernel that attaches TC through a
legacy clsact filter (before 6.6), a start removes the `wafio_` filters that a
killed agent left behind. Between the old programs detaching and the new ones
attaching the host runs unfiltered; `docs/lab.md` has the measured time.

**Known limits.** Under egress Deny All, a DNAT or container flow whose entry was
evicted or lost is cut until the client reconnects: the socket proof sees only
sockets of the host namespace, and a fix needs the netfilter conntrack kfuncs
(kernel 6.0 and later). Host-opened UDP has no proof and recovers only on the
host's next outbound packet. An agent with old objects ignores the setting, and a
new agent with old objects sizes the maps by name but keeps an LRU jail (no full
signal) and has no socket proof; the bundle ships the objects with the binary, so
this happens only on a mixed manual install.

### eBPF objects ship with the binary

The release bundle carries the compiled objects next to the binary
(`ebpf/wafio_{xdp,tc,trace}.o`). Install them together: a binary and objects
from different builds can disagree on map layouts. Nothing pushes an object to a
host at run time. The first start after an upgrade needs the new objects in
`/etc/wafio/ebpf/`.

## Release

```sh
scripts/build-dist.sh v2.0.0
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
.github/workflows/        ci.yml (pushes to main and pull requests), ebpf-vm.yml (manual)
```

## License

Copyright (C) 2026 Wafio. This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3 only, as published by the Free Software Foundation. It comes without any warranty. The full text is in `LICENSE` (SPDX: `GPL-3.0-only`).

The BPF programs under `internal/ebpf/bpf/` are the exception: they carry the SPDX identifier GPL-2.0 in their file headers. The Linux kernel lets a BPF program call GPL-only helpers only when the program declares a licence the kernel accepts, so those files stay under GPL-2.0. The text of GPL-2.0 is `licenses/GPL-2.0.txt`; every bundle ships it as `ebpf/COPYING`, with the C source of the objects in `ebpf/src/`. Third-party notices are in `NOTICES.txt`.
