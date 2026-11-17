# Contributing to wafio-agent-host

Thank you for looking at the code. This file says what a change needs before it can be merged.

## Before you start

- For anything larger than a small fix, open an issue first and say what you want to change. It saves you work if the change does not fit.
- A security problem does not go into an issue: see `SECURITY.md`.

## Build and test

The requirements are in the README. The agent builds and runs on Linux only. The full gate:

```sh
scripts/ci-local.sh
```

The kernel verifier tests need root and are skipped without it; `docs/lab.md` describes the lab for them.

## Rules of this repository

- The BPF programs under `internal/ebpf/bpf/` are GPL-2.0 and must stay so: the kernel requires a GPL-compatible licence for the helpers they call. A contribution to those files is under GPL-2.0.
- The BPF objects load on kernels from 5.10 with BTF. `scripts/build-ebpf.sh` builds them with `-mcpu=v1`; keep it.
- A change to a BPF program comes with a verifier test, and you say on which kernels you loaded it.
- The agent protocol and the shared packages come from the `shared` module of wafio-cp-backend. Change them there.
- A new dependency must be maintained and have a licence that GPL-3.0 allows; run `scripts/gen-notices.sh` after adding one.

## Pull requests

- One topic per pull request, with tests for what it changes.
- Say what the change does and how you checked it.
- Commit messages and comments are plain English.
- Do not commit secrets, local configuration, certificates or keys.
- Do not add instruction files for coding assistants, or planning notes, to the repository. The gate refuses them.

## Licence of your contribution

The project is under the GNU General Public License, version 3 only (`LICENSE`). Before a contribution can be merged you must agree to the Wafio Contributor Licence Agreement in `CLA.md`. You keep your copyright; the agreement gives Wafio the right to publish your contribution in this project and in the products built from it. Section 5 of `CLA.md` says how to agree.

If part of a change comes from another project, say so in the pull request: the project, the copyright holder and the licence. Such code needs an entry in the third-party notices.
