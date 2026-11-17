#!/usr/bin/env bash
# Every gate of this repo in one run. It keeps going after a failure, prints a
# summary and exits nonzero when a gate failed. The host agent is Linux only
# and its BPF tests need Linux, so it runs on Linux only.
#
# It checks the working tree, uncommitted files included. The kernel verifier
# tests need root and are skipped otherwise.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ "$(uname -s)" != Linux ]; then
  echo "ci-local.sh runs on Linux" >&2
  exit 2
fi

failed=()
notrun=()
step() {
  local name=$1 start=$SECONDS
  shift
  printf '\n== %s\n' "$name"
  if "$@"; then
    printf -- '-- ok: %s (%ds)\n' "$name" $((SECONDS - start))
  else
    printf -- '-- FAILED: %s (%ds)\n' "$name" $((SECONDS - start))
    failed+=("$name")
  fi
}

secrets() {
  local g=gitleaks
  if ! command -v gitleaks >/dev/null; then
    command -v docker >/dev/null || { echo "need gitleaks (CI pins 8.30.1) or Docker"; return 1; }
    g="docker run --rm -u $(id -u):$(id -g) -v $PWD:/r -w /r zricethezav/gitleaks:v8.30.1"
  fi
  $g git --redact --verbose --exit-code 1 --config .gitleaks.toml .
}

# No agent files, no tracker IDs (finding, wave, work-package, decision, plan unit)
# and no planning-doc references in code or strings. Markdown is excluded so a doc
# may cite a spec section. Needs a git checkout (git ls-files, git grep).
# No \b or \s (macOS git grep -E matches nothing with them) and no grep -q after a
# pipe (SIGPIPE under pipefail). -I skips binary files, which can match by chance.
# The doc names are written with a bracket (PORTIN[G]) and the self-test samples
# are built with printf, so this file does not match its own patterns.
ai_material() {
  # Outside a checkout git grep fails and every check below would pass without looking.
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 && [ -e .git ] || { echo 'ai check: needs a git checkout' >&2; return 1; }
  local ai_files='(^|/)(AGENTS|CLAUDE|GEMINI)\.md$|(^|/)\.claude/|copilot-instructions|port-statu[s]|PORTIN[G]\.md'
  local ai_ids='(^|[^A-Za-z0-9_])(K-[0-9]{2,3}|[Ww]ave[- ]?[0-9]+|WP-[0-9]+|DEC-[0-9]+|FSD-[0-9]+|BR-[0-9]+|ADR-[0-9]+|CF-[0-9]+|SP-[0-9]+|TG-[0-9]+|OD-[0-9]+|CU-[0-9]+|RK-[0-9]+|POC-[A-Z]+|GAP-[A-Z]+-[0-9]+|F-[0-9]{2}|SEC-[0-9]+|REQ-[0-9]+|INV-[0-9]{1,2}|T-[0-9]+)([^0-9]|$)'
  local ai_docs='(^|[^A-Za-z0-9_])(PORTIN[G]|port-statu[s]|docs/(superpowers/)?plan[s]/|[Pp]lan §[0-9]|[Ss]pec §[0-9]|PRD §[0-9]|split-pre[p]|[Oo]wner decision|[Cc]ontroller ruling|[Ii]ntegrator decision|[Rr]eview (finding|round) [0-9]|[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-z])'
  local ai_refs='(AGENT[S]|CLAUDE|GEMINI)\.md'
  hits() { [ "$(printf '%s\n' "$2" | grep -cE "$1")" = "$3" ] || { echo 'ai check: pattern self-test failed' >&2; return 1; }; }
  hits "$ai_ids" "$(printf 'x K-%s y' 12)" 1 || return 1
  hits "$ai_ids" "$(printf 'x WP-%s y' 5.1)" 1 || return 1
  hits "$ai_ids" "$(printf 'x %s 3 y' wave)" 1 || return 1
  hits "$ai_ids" "$(printf 'x POC-%s y' FCGI)" 1 || return 1
  hits "$ai_ids" "$(printf 'x GAP-RT-%s y' 04)" 1 || return 1
  hits "$ai_ids" "$(printf 'x F-%s y' 05)" 1 || return 1
  hits "$ai_ids" "$(printf 'x T-%s y' 26)" 1 || return 1
  hits "$ai_ids" 'AES-256 SHA-256 UTF-8 X-Forwarded-For TEST-NET-3 U+0041 0x1F-1' 0 || return 1
  hits "$ai_docs" "$(printf 'see %s/plans/x' docs)" 1 || return 1
  hits "$ai_docs" "$(printf 'see %s/superpowers/plans/x' docs)" 1 || return 1
  hits "$ai_docs" "$(printf 'the %s decision' owner)" 1 || return 1
  hits "$ai_docs" "$(printf 'review %s 5' finding)" 1 || return 1
  hits "$ai_docs" "$(printf 'see 2026-10-10-%s-v2' firewall)" 1 || return 1
  hits "$ai_docs" 'a plan for the 2026-10-10T12:00:00Z lists' 0 || return 1
  hits "$ai_refs" "$(printf 'see %s.md' AGENTS)" 1 || return 1
  if git ls-files | grep -E "$ai_files"; then echo 'ai check: agent files tracked' >&2; return 1; fi
  if git grep -nIE "$ai_ids" -- ':!*.md'; then echo 'ai check: IDs in code or strings' >&2; return 1; fi
  if git grep -nIE "$ai_docs" -- ':!*.md'; then echo 'ai check: planning docs referenced in code or strings' >&2; return 1; fi
  if git grep -nIE "$ai_refs" -- ':!*.md'; then echo 'ai check: agent files referenced in code or strings' >&2; return 1; fi
}

ebpf_objects() {
  ./scripts/build-ebpf.sh || return 1
  local o
  for o in wafio_xdp.o wafio_tc.o wafio_trace.o wafio_lsm.o; do
    test -s "build/ebpf/$o" || { echo "missing build/ebpf/$o"; return 1; }
  done
}

# Loads the objects into the running kernel and checks the verifier budgets.
verifier() {
  WAFIO_TEST_BPF_DIR=$PWD/build/ebpf go test -count=1 \
    -run 'TestBPFObjectsPassVerifier|TestBPFFirewallVerifierBudget|TestBPFTraceVerifierBudget' ./internal/ebpf/
}

dirty=$(git status --porcelain)
[ -z "$dirty" ] || echo "note: uncommitted changes are checked too"

step "secret scan" secrets
step "agent material" ai_material
step "golangci-lint" golangci-lint run ./...
step "go build" go build ./...
step "go vet" go vet ./...
step "go test" go test ./...
step "go test -race" go test -race -timeout 15m ./...
step "govulncheck" go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
step "eBPF objects" ebpf_objects
if [ "$(id -u)" = 0 ]; then
  step "kernel verifier" verifier
else
  notrun+=("kernel verifier tests (need root)")
fi

printf '\n== summary\n'
for n in "${notrun[@]+"${notrun[@]}"}"; do echo "not run: $n"; done
[ -z "$dirty" ] || echo "note: the working tree had uncommitted changes"
if [ ${#failed[@]} -gt 0 ]; then
  for n in "${failed[@]}"; do echo "FAILED: $n"; done
  exit 1
fi
echo "all gates passed"
