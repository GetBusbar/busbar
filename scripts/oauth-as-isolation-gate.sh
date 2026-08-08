#!/usr/bin/env bash
# oauth-as isolation gate: CI guard that crates/oauth-as never grows a busbar dependency.
#
# WHY THIS EXISTS:
#   crates/oauth-as is a standalone OAuth 2.1 Authorization Server library that busbar EMBEDS. The
#   plan of record is to extract it, unchanged, to its own repository once its API stops moving.
#   That plan only survives if the crate's isolation is a property of the tree, not a discipline
#   someone remembers: the day it links a busbar crate (or quietly reaches one through a `path`
#   dependency) the extraction stops being trivial and the zero-RAM-when-unconfigured boundary
#   stops being structural. So the rule is enforced here, in CI, not by convention.
#
# WHAT THIS GATE ENFORCES:
#   1. NO-PATH-DEP rule: crates/oauth-as/Cargo.toml declares no `path = ...` dependency in any
#      dependencies section ([dependencies], [dev-dependencies], [build-dependencies],
#      [target.*.dependencies]). Every workspace-internal edge is a path edge, so banning path
#      edges bans them all, including a renamed one (`x = { package = "busbar-api", path = .. }`).
#      A `path` key OUTSIDE a dependencies section (e.g. `[lib] path = "src/lib.rs"`) is fine.
#   2. NO-BUSBAR-TEXT rule: the string `busbar` (case-insensitive) appears NOWHERE in any file
#      under crates/oauth-as, except copyright/license attribution lines. This is deliberately
#      blunter than a dependency check: the crate must be extractable to its own repo UNCHANGED,
#      so even a doc comment that narrates busbar internals is coupling. Registry dependencies
#      named busbar-* are caught by this rule too.
#
# Runs in CI (see .github/workflows/ci.yml, structure-lint job). No external deps; bash 3.2 +
# POSIX awk (macOS/Linux). `--selftest` proves both scanners still catch real violations before
# their verdict on the tree is trusted (same discipline as structure-lint.sh --selftest).
set -euo pipefail
cd "$(dirname "$0")/.."

note() { printf '  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

CRATE_DIR="crates/oauth-as"

# ── SCANNER 1 (one copy; the self-test drives THIS function, never a duplicate) ───────────────────
# Emits `file:lineno: <line>` for every `path = ...` inside a dependencies-flavored TOML section.
scan_path_deps() {
  awk '
    /^[[:space:]]*\[/ {
      # Entering a TOML section: dependencies-flavored iff the header is [dependencies],
      # [dev-dependencies], [build-dependencies], or [target.<...>.dependencies] (dotted-key
      # subtables like [dependencies.foo] count too).
      in_deps = ($0 ~ /^[[:space:]]*\[(dev-|build-)?dependencies([.\]])/) \
             || ($0 ~ /^[[:space:]]*\[target\..*dependencies([.\]])/)
      next
    }
    /^[[:space:]]*#/ { next }                       # whole-line comment
    {
      if (in_deps && $0 ~ /(^|[{,[:space:]])path[[:space:]]*=/) {
        disp = $0; sub(/^[[:space:]]+/, "", disp)
        printf "%s:%d: %s\n", FILENAME, FNR, disp
      }
    }
  ' "$@"
}

# ── SCANNER 2 ─────────────────────────────────────────────────────────────────────────────────────
# Emits `file:lineno: <line>` for every case-insensitive `busbar` occurrence, exempting
# copyright/license attribution lines (the one place the name legitimately appears).
scan_busbar_text() {
  awk '
    {
      line = tolower($0)
      if (index(line, "busbar") == 0) next
      if (line ~ /copyright/) next                  # attribution is not coupling
      disp = $0; sub(/^[[:space:]]+/, "", disp)
      printf "%s:%d: %s\n", FILENAME, FNR, disp
    }
  ' "$@"
}

# ── SELF-TEST, neither scanner can be lied to ────────────────────────────────────────────────────
run_selftest() {
  hdr "oauth-as-isolation-gate SELF-TEST (both scanners proven RED before the verdict is trusted)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 pass=0

  # RED fixtures: each is a real violation shape; the scanners MUST flag every one.
  cat >"${tmp}/red.toml" <<'RED'
[dependencies]
serde = { version = "1" }
helper = { path = "../api" }
busbar-secret-ref = { version = "1" }

[dev-dependencies.renamed]
package = "some-crate"
path = "../plugin-abi"

[target.'cfg(unix)'.dependencies]
sneaky = { version = "1", path = "../busbar" }
RED
  local hits n
  hits="$(scan_path_deps "${tmp}/red.toml" || true)"
  n="$(printf '%s' "$hits" | grep -c ':' || true)"
  if [ "$n" -eq 3 ]; then
    pass=$((pass+1)); note "RED path-dep: flagged all 3 path dependencies"
  else
    fail=1; note "RED path-dep FAILED: expected 3 flags, got ${n}:"; printf '%s\n' "$hits"
  fi

  cat >"${tmp}/red.rs" <<'RED'
use busbar_api::store::Store;
// glue that calls Busbar internals
fn f() { let _ = BUSBAR_MARKER; }
RED
  hits="$(scan_busbar_text "${tmp}/red.rs" "${tmp}/red.toml" || true)"
  n="$(printf '%s' "$hits" | grep -c ':' || true)"
  if [ "$n" -eq 5 ]; then
    pass=$((pass+1)); note "RED busbar-text: flagged all 5 busbar mentions (3 in .rs, 2 in .toml)"
  else
    fail=1; note "RED busbar-text FAILED: expected 5 flags, got ${n}:"; printf '%s\n' "$hits"
  fi

  # GREEN fixtures: legitimate shapes the scanners must NOT flag.
  cat >"${tmp}/green.toml" <<'GREEN'
[package]
name = "oauth-as"

[lib]
path = "src/lib.rs"

[dependencies]
serde = { version = "1", features = ["derive"] }
getrandom = "0.3"
# a comment mentioning path = "../x" is prose, not a dependency
GREEN
  cat >"${tmp}/green.rs" <<'GREEN'
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
/// The verification path a bus bar electrician would not recognize.
pub struct Route { pub path: Option<String> }
GREEN
  hits="$(scan_path_deps "${tmp}/green.toml" || true)"
  local hits2; hits2="$(scan_busbar_text "${tmp}/green.rs" "${tmp}/green.toml" || true)"
  if [ -z "$hits" ] && [ -z "$hits2" ]; then
    pass=$((pass+1)); note "GREEN: flagged neither [lib] path, nor comment prose, nor the copyright attribution"
  else
    fail=1; note "GREEN FAILED: expected 0 flags, got:"; printf '%s\n%s\n' "$hits" "$hits2"
  fi

  note "self-test: ${pass}/3 fixture groups passed"
  if [ "$fail" -ne 0 ]; then
    note "oauth-as-isolation-gate SELF-TEST FAILED, a busbar dependency could slip through"
    return 1
  fi
  note "ok"
  return 0
}

if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

fail=0

hdr "oauth-as isolation (the crate must stay extractable unchanged)"
if [ ! -d "$CRATE_DIR" ]; then
  note "FAILED: ${CRATE_DIR} does not exist, if the crate moved, move this gate with it"
  exit 1
fi

# Rule 1: no path dependencies.
hits="$(scan_path_deps "${CRATE_DIR}/Cargo.toml" || true)"
if [ -n "$hits" ]; then
  while IFS= read -r h; do note "NO-PATH-DEP: $h"; done <<<"$hits"
  note "→ a path dependency reaches back into this workspace; oauth-as must depend only on"
  note "  registry crates so it can be extracted to its own repository unchanged."
  fail=1
else
  note "ok (no path dependency in ${CRATE_DIR}/Cargo.toml)"
fi

# Rule 2: no busbar text anywhere in the crate (attribution lines exempt).
files=()
while IFS= read -r f; do files+=("$f"); done < <(find "$CRATE_DIR" -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.md' \) | sort)
hits="$(scan_busbar_text "${files[@]}" || true)"
if [ -n "$hits" ]; then
  while IFS= read -r h; do note "NO-BUSBAR-TEXT: $h"; done <<<"$hits"
  note "→ oauth-as may not name or reach busbar: the crate is extracted to a standalone repo"
  note "  unchanged, and host-specific references (even in docs) are coupling. Describe the"
  note "  behavior host-neutrally, or move the text into the busbar-side embedding code."
  fail=1
else
  note "ok (${#files[@]} file(s) scanned, no busbar reference outside attribution lines)"
fi

hdr "result"
if [ "$fail" -ne 0 ]; then note "oauth-as-isolation-gate FAILED"; exit 1; fi
note "oauth-as-isolation-gate passed"
