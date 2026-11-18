#!/usr/bin/env bash
# Build the three CO-RE eBPF objects (wafio_xdp.o, wafio_tc.o, wafio_trace.o)
# into build/ebpf. One set loads on every kernel from 5.10 with BTF.
#
#   scripts/build-ebpf.sh
#   BPF_OUT_DIR=build/ebpf-x scripts/build-ebpf.sh      other output directory
#   BPF_EXTRA_CFLAGS=-mcpu=v2 scripts/build-ebpf.sh     extra clang flags
#   BPF_DOCKER=1 scripts/build-ebpf.sh                  force the Docker build
#
# Uses clang on the PATH when this is Linux with clang and the libbpf headers
# installed (apt install clang llvm libbpf-dev); otherwise builds in an
# ubuntu:24.04 container. -mcpu=v1 is pinned: clang 20 and later default to v3,
# which turns even a plain __sync_fetch_and_add into an atomic that kernels
# before 5.12 reject. A later -mcpu in BPF_EXTRA_CFLAGS wins.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
src=$root/internal/ebpf/bpf
out=${BPF_OUT_DIR:-build/ebpf}
extra=${BPF_EXTRA_CFLAGS:-}

# The flags end up in a shell command string: allow flag syntax only.
if [[ ! $extra =~ ^[A-Za-z0-9=_.,\ -]*$ ]]; then
  echo "BPF_EXTRA_CFLAGS: letters, digits and = _ . , - only" >&2
  exit 1
fi
case $out in
  /* | *..*) echo "BPF_OUT_DIR must be a relative path inside the repository" >&2; exit 1 ;;
esac
mkdir -p "$root/$out"

compile='for o in xdp tc trace; do clang $CFLAGS -c "$SRC/wafio_$o.c" -o "$OUT/wafio_$o.o"; done'
flags="-O2 -g -target bpf -mcpu=v1 -D__TARGET_ARCH_x86_64"

if [ "$(uname -s)" = Linux ] && [ -z "${BPF_DOCKER:-}" ] && command -v clang >/dev/null && [ -f /usr/include/bpf/bpf_helpers.h ]; then
  echo "[build-ebpf] native clang: $(clang --version | head -1)"
  SRC=$src OUT=$root/$out CFLAGS="$flags -I$src -I/usr/include${extra:+ $extra}" bash -c "set -e; $compile"
else
  command -v docker >/dev/null || { echo "need Linux with clang and libbpf-dev, or Docker" >&2; exit 1; }
  echo "[build-ebpf] docker: ubuntu:24.04"
  docker run --rm --platform linux/amd64 \
    -v "$src":/src:ro -v "$root/$out":/out \
    -e SRC=/src -e OUT=/out -e CFLAGS="$flags -I/src -I/usr/include${extra:+ $extra}" \
    -e OWNER="$(id -u):$(id -g)" \
    ubuntu:24.04 bash -c "set -e
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -q >/dev/null && apt-get install -y -q clang llvm libbpf-dev >/dev/null
      $compile
      chown -R \$OWNER /out"
fi

ls -l "$root/$out"/*.o
