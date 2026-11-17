#!/usr/bin/env bash
# Regenerate NOTICES.txt, the third-party attribution shipped in the bundle.
#
#   A. data the agent downloads at run time (GeoIP databases) and BPF build
#      inputs: written by hand in this script
#   B. the Go standard library and the Go modules compiled into
#      cmd/wafio-host-agent, each with its LICENSE text, the NOTICE file of the
#      module when it has one, and the licence files inside linked packages
#
# Needs the Go module cache.
set -euo pipefail
cd "$(dirname "$0")/.."
out=NOTICES.txt
tmp=$(mktemp)
trap 'rm -f "$tmp" "$tmp.mods" "$tmp.pkgs"' EXIT
sep="───────────────────────────────────────────────────────────────────────────────"
bar="═══════════════════════════════════════════════════════════════════════════════"

cat > "$tmp" <<TXT
WAFio host agent: third-party notices
=====================================

This product includes software and data developed by third parties. The
notices below are required by their licenses. scripts/gen-notices.sh writes
this file: do not edit it by hand, edit the script.

$bar
SECTION A: RUN-TIME DATA AND BPF BUILD INPUTS
$bar

$sep
DB-IP GEOLOCATION DATA (default GeoIP provider)
https://db-ip.com
IP geolocation data provided by DB-IP.com under the Creative Commons
Attribution 4.0 International License (CC BY 4.0).
https://creativecommons.org/licenses/by/4.0/
This product includes IP geolocation data created by DB-IP (https://db-ip.com).

$sep
MAXMIND GEOLITE2 (optional, only when the operator supplies a MaxMind key)
https://www.maxmind.com
When configured with a MaxMind license key, this product uses GeoLite2 data
created by MaxMind, available from https://www.maxmind.com, under the MaxMind
GeoLite2 End User License Agreement. https://www.maxmind.com/en/geolite2/eula
This product includes GeoLite2 data created by MaxMind.

$sep
LIBBPF HEADERS (bpf_helpers.h, bpf_core_read.h, bpf_endian.h, bpf_tracing.h)
https://github.com/libbpf/libbpf
Included by the BPF programs in internal/ebpf/bpf at build time.
Licensed under LGPL-2.1 OR BSD-2-Clause.

$sep
LINUX KERNEL TYPE DEFINITIONS (internal/ebpf/bpf/vmlinux.h)
Generated from kernel BTF. Derived from the Linux kernel, licensed under
GPL-2.0. The BPF programs themselves carry the SPDX identifier GPL-2.0.

$sep
THE eBPF OBJECTS (ebpf/wafio_xdp.o, wafio_tc.o, wafio_trace.o, wafio_lsm.o)
The four objects are licensed under GPL-2.0. Their C source, including the
headers and vmlinux.h, is in ebpf/src/ of this bundle, and the licence text is
ebpf/COPYING. The Go program that loads them is a separate program and is not
covered by that licence.

$bar
SECTION B: GO STANDARD LIBRARY AND GO MODULES COMPILED INTO wafio-host-agent
$bar

TXT

goroot=$(go env GOROOT)
[ -f "$goroot/LICENSE" ] || { echo "gen-notices: no LICENSE in GOROOT $goroot" >&2; exit 1; }
{
  echo "$sep"
  echo "The Go standard library  $(go env GOVERSION)"
  echo "https://go.dev"
  cat "$goroot/LICENSE"
  echo
} >> "$tmp"

go list -deps -f '{{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}' ./cmd/wafio-host-agent | sort -u > "$tmp.mods"

# first_file DIR NAME...: the first existing file of DIR that matches one of the names
first_file() {
  local dir=$1 name f
  shift
  for name in "$@"; do
    for f in "$dir"/$name; do
      [ -f "$f" ] && { printf '%s\n' "$f"; return 0; }
    done
  done
  return 1
}

while IFS='|' read -r path ver dir; do
  [ -n "$path" ] && [ -n "$dir" ] || continue
  case $path in github.com/wafio/*) continue ;; esac # own code
  lic=$(first_file "$dir" 'LICENSE*' 'LICENCE*' 'COPYING*' 'License*' 'UNLICENSE*' || true)
  notice=$(first_file "$dir" 'NOTICE' 'NOTICE.txt' 'NOTICE.md' || true)
  {
    echo "$sep"
    echo "$path  $ver"
    if [ -n "$lic" ]; then cat "$lic"; else echo "(no LICENSE file in the module; see $path upstream)"; fi
    if [ -n "$notice" ]; then
      echo
      echo "-- NOTICE --"
      cat "$notice"
    fi
    echo
  } >> "$tmp"
done < "$tmp.mods"

# Licence files inside linked packages, below the module root (for example the xxhash and
# snapref code inside klauspost/compress). Text identical to the module's own licence is skipped.
go list -deps -f '{{if .Module}}{{.Module.Path}}|{{.Module.Dir}}|{{.ImportPath}}|{{.Dir}}{{end}}' ./cmd/wafio-host-agent | sort -u > "$tmp.pkgs"
while IFS='|' read -r mpath mdir ipath pdir; do
  [ -n "$mpath" ] && [ -n "$mdir" ] && [ "$pdir" != "$mdir" ] || continue
  case $mpath in github.com/wafio/*) continue ;; esac
  nested=$(first_file "$pdir" 'LICENSE*' 'LICENCE*' 'COPYING*' 'License*' 'UNLICENSE*' || true)
  [ -n "$nested" ] || continue
  root=$(first_file "$mdir" 'LICENSE*' 'LICENCE*' 'COPYING*' 'License*' 'UNLICENSE*' || true)
  if [ -n "$root" ] && cmp -s "$nested" "$root"; then continue; fi
  {
    echo "$sep"
    echo "$ipath  (licence file inside the package, module $mpath)"
    cat "$nested"
    echo
  } >> "$tmp"
done < "$tmp.pkgs"

mv "$tmp" "$out"
echo "Wrote $out ($(wc -l < "$out") lines)"
