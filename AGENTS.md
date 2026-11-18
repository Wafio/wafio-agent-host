# AGENTS.md

Instructions for coding assistants that work on wafio-agent-host. The rules for every contribution are in
`CONTRIBUTING.md`; this file is the short form.

## What this is

The Wafio host agent, in Go with BPF programs in C: a firewall in XDP and TC, and runtime security tracing.
It builds and runs on Linux only (kernel 5.10 or later with BTF). The agent protocol comes from the `shared`
module of wafio-cp-backend.

## Commands

    scripts/build-ebpf.sh   # the BPF objects, into build/ebpf/
    CGO_ENABLED=0 GOOS=linux go build -trimpath -o build/wafio-host-agent ./cmd/wafio-host-agent
    go test ./...           # the tests that need no root
    scripts/ci-local.sh     # the gate: must pass before a pull request

The gate runs the secret scan, `golangci-lint`, build, vet, the tests with the race detector, `govulncheck`,
the BPF build and, as root, the kernel verifier tests. Fix what it reports; do not disable a check.

## Rules

- The BPF programs under `internal/ebpf/bpf/` are GPL-2.0 and stay so.
- The BPF objects must load on kernels from 5.10. Keep `-mcpu=v1` in `scripts/build-ebpf.sh`.
- A change to a BPF program comes with a verifier test, and the pull request says on which kernels it was
  loaded. Never test a firewall change on a machine you reach over the network it filters: `docs/lab.md`
  describes the lab.
- A struct shared between C and Go changes on both sides together, with its size test.
- A change comes with a test.
- A new dependency must be maintained and have a licence GPL-3.0 allows; run `scripts/gen-notices.sh`.

## Do not edit

- The agent protocol and the shared packages: change them in wafio-cp-backend, module `shared`.
- `internal/ebpf/bpf/vmlinux.h`: Linux kernel type definitions, not code of this project.
- `LICENSE`, `CLA.md`.

## Writing

Comments, commit messages and documents are plain English. One topic per pull request.

## Security

Do not put a vulnerability in an issue, a pull request or a commit message. `SECURITY.md` says how to report it.

## The person, not the assistant

The person who opens the pull request has read the change, understands it and answers for it, and agrees to
`CLA.md`. A security
report must be reproduced before it is sent. `CONTRIBUTING.md`, "Work done with a coding assistant", says the same.
