#!/usr/bin/env bash
# Build what a release takes from this repository: the host agent, its eBPF objects and what ships with them.
#
#   scripts/build-dist.sh v2.0.0
#
# Output, in dist/host-agent/:
#   wafio-host-agent                    the agent, linux/amd64, static
#   ebpf/wafio_{xdp,tc,trace,lsm}.o     the CO-RE objects
#   ebpf/COPYING, ebpf/src/             the GPL-2.0 text and the C source the objects were built from
#   systemd/wafio-host-agent.service    the unit
#   NOTICES.txt
#   VERSION                             the version
#   SHA256SUMS                          the SHA-256 of every file above
# scripts/release.sh of wafio-release takes the directory (--host-agent), adds the installer, packs the bundle and
# signs it. Nothing here is signed or uploaded. Bundle layout: deploy/BUNDLE.md of wafio-release.
#
# Needs: the Go toolchain named in go.mod, and clang or Docker (BPF objects).
set -euo pipefail

version=${1:?usage: scripts/build-dist.sh vX.Y.Z}
[ $# -eq 1 ] || { echo "usage: scripts/build-dist.sh vX.Y.Z" >&2; exit 2; }
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] || { echo "version must look like v2.0.0" >&2; exit 2; }

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=$root/dist/host-agent

echo "[1/3] eBPF objects"
# A release always builds the default objects into build/ebpf at -mcpu=v1. BPF_OUT_DIR or BPF_EXTRA_CFLAGS left in the
# environment would otherwise write them elsewhere, or build objects that older kernels reject, while this script copies
# from the fixed build/ebpf.
env -u BPF_OUT_DIR -u BPF_EXTRA_CFLAGS "$root/scripts/build-ebpf.sh"

echo "[2/3] wafio-host-agent $version (linux/amd64)"
rm -rf "$out"
mkdir -p "$out/ebpf/src" "$out/systemd"
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags="-s -w -X github.com/wafio/wafio-agent-host/internal/agent.AgentVersion=$version" \
  -o "$out/wafio-host-agent" ./cmd/wafio-host-agent)

echo "[3/3] $out"
for o in wafio_xdp.o wafio_tc.o wafio_trace.o wafio_lsm.o; do
  install -m 0644 "$root/build/ebpf/$o" "$out/ebpf/$o"
done
# The objects are GPL-2.0: they ship with the source they were built from and the licence text.
install -m 0644 "$root/licenses/GPL-2.0.txt" "$out/ebpf/COPYING"
for f in "$root"/internal/ebpf/bpf/*.c "$root"/internal/ebpf/bpf/*.h; do
  install -m 0644 "$f" "$out/ebpf/src/"
done
install -m 0644 "$root/deploy/systemd/wafio-host-agent.service" "$out/systemd/"
install -m 0644 "$root/NOTICES.txt" "$out/NOTICES.txt"
printf '%s\n' "$version" > "$out/VERSION"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$out" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do sha256 "$f"; done > SHA256SUMS)
sed 's/^/      /' "$out/SHA256SUMS"
