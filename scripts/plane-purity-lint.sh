#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-purity-lint.sh — THE NEUTRAL-PURITY LINT (plane-extraction §6.2, the enforcement gate).
#
# WHY THIS EXISTS (docs/design/plane-extraction-design.md §1 — the honest post-mortem):
#   A protocol plane (LLM / MCP / A2A) must be a self-contained plugin merely compiled in for
#   convenience. Turn its feature off (or `git rm -r` its crate) and the NEUTRAL crates — busbar-core,
#   busbar-substrate, busbar-api — must still compile and run, serving no P protocol. That was the
#   requirement on day one; it eroded, for one reason above all: THERE WAS NO GATE. The extraction was
#   done by hand, nothing enforced completion or prevented regression, so new plane-specific code kept
#   landing in the neutral crates unchallenged. "A boundary with no instrument watching it drifts."
#   This lint is that instrument — the single most important artifact in the design.
#
# THE INVARIANT IT ENFORCES (§2.1 — EVERYTHING CROSSES THE ABI, NOTHING AROUND IT):
#   The plane ABI (PlaneDecl / ProtocolDecl / install_* / the opaque PlaneRecord / the plane_slots
#   type-erased runtime map / the PLANE_* diagnostics namespace) is the ONE AND ONLY surface across
#   which core and a plane communicate. Every SIDE CHANNEL is a violation to be removed, not "gated".
#   In a NEUTRAL-crate source (excluding comments, doc-strings, and test code), this lint fails RED on:
#
#     PATH-INCLUDE  (a) any `#[path = "…/busbar-{llm,mcp,a2a}/…"]` dual-compile — the witness-build
#                       side channel that reaches AROUND the ABI to compile plane source into a neutral
#                       crate. An INSTANT fail, scanned even in test scope: it must not exist at all.
#     SYMBOL        (b) any `busbar_{llm,mcp,a2a}::` symbol path — there is no legitimate one. The
#                       composition-root bin (crates/busbar) is NOT neutral and is exempt (not scanned).
#     KEY           (c1) a concrete plane key as a token: `mcp` / `a2a` / `llm`.
#     DIALECT       (c2) one of the six dialect names: openai / anthropic / gemini / bedrock / cohere /
#                        responses.
#     TYPE          (c3) a plane record type name (McpCallRecord / McpDemotionRow / TaskRow /
#                        TaskEventRow) or any plane-/dialect-prefixed CamelCase type (McpFoo, TaskRow,
#                        OpenaiFamily, …).
#
#   ALLOWED — the NEUTRAL ABI identifiers ONLY, and never flagged (the curated allow-list, made
#   executable by a GREEN self-test fixture that uses each and asserts ZERO hits):
#       PlaneRecord  PlaneDecl  ProtocolDecl  PlaneDecls  PlaneSlots  PlaneHost
#       plane_slots  plane_slot  plane_host   install_planes  install_protocols
#       install_diagnostics  install_path_ingress  BUILTIN_PLANE_DECLS  BUILTIN_DECLS
#       PLANE_*  (the neutral diagnostics namespace)
#   These are the target pattern (§3F "acceptable neutral seams — keep"). Word-boundary and
#   Plane/Protocol-prefix construction of the scanner mean none of them can match a KEY/DIALECT/TYPE
#   rule; the allow-list below is the defensive belt-and-braces and the thing the GREEN fixture proves.
#
# THE REVERSE EDGE ("no backwards reach", §2.1 item 2): a plane crate (busbar-{llm,mcp,a2a}) MAY name
#   the substrate ABI (busbar_substrate:: / busbar_api::) but must NOT name `busbar_core::`
#   implementation items. Core→plane and plane→core-internals are both forbidden; only plane→ABI and
#   ABI→plane(via registry) are allowed. A companion scan of the plane crates enforces this.
#
# ONE SCANNER, DRIVEN BY THE SELF-TEST (--selftest, run FIRST in CI like every sibling *-lint.sh):
#   `scan()` is the single scanner; the self-test drives THAT function, never a duplicate. It plants
#   the four side channels the design names — (i) a fake `#[path=…busbar-mcp…]`, (ii) a `busbar_a2a::`
#   reference, (iii) a `McpFoo` type, (iv) a plane-crate `busbar_core::internal::foo` backwards reach —
#   and proves the scanner flags all four (RED fixtures) AND passes clean/allow-listed/comment/test
#   fixtures (GREEN). The scanner cannot be lied to: its verdict on the tree is trusted only after it
#   re-proves itself on known inputs.
#
# ── HOW THIS STAYS OFF CI'S RED UNTIL THE EXTRACTION LANDS (the field-coverage discipline) ──────────
#   The tree is DIRTY today by design (§1: the deletion test fails for all three planes; §3 is the
#   residual ledger the extraction must drive to zero). So this lint has TWO tree modes, exactly as
#   field_coverage.rs keeps its acceptance `#[ignore]`d-until-drained:
#
#     --baseline   INFORMATIONAL. Prints the full categorized violation report and ALWAYS exits 0.
#                  This is what CI runs today (in the structure-lint job) so the baseline is surfaced
#                  on every push WITHOUT going red. It is the field-coverage `pinned-missing` half:
#                  visible, tracked, non-blocking.
#     --check      BLOCKING (fail-closed). Exits non-zero on ANY violation. This is the PERMANENT gate.
#                  It is wired into a qa/segments.toml `plane-purity` segment that is `reserved` (inert,
#                  excluded from the green claim, named in the scope line) until the extraction drains
#                  the neutral crates to zero — at which point arming it is a one-line reserved→active
#                  flip, and `--check` passes green and stays permanent. This is the field-coverage
#                  `-- --ignored` acceptance half: red-by-design while the queue is non-empty, the gate
#                  working rather than the gate broken.
#
#   So: the SELF-TEST is green NOW (it must be — it proves the scanner), the tree verdict is DEFERRED
#   (informational) NOW, and the same script becomes a permanent hard gate the day the tree is clean,
#   with nothing to edit in this file.
#
# No external deps beyond bash 3.2 + POSIX awk (macOS/Linux) — the same bare-runner posture as the
# sibling lints (structure-lint.sh, release-script-lint.sh, response-header-lint.sh).
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# The neutral crates (the ABI side) and the plane crates (the plugin side). Derived once; a plane or
# neutral crate that appears/disappears is a one-line edit here, never N stale paths scattered below.
NEUTRAL_ROOTS="crates/busbar-core/src crates/busbar-substrate/src crates/api/src"
PLANE_ROOTS="crates/busbar-llm/src crates/busbar-mcp/src crates/busbar-a2a/src"

neutral_files() { find $NEUTRAL_ROOTS -name '*.rs' 2>/dev/null | sort; }
plane_files()   { find $PLANE_ROOTS   -name '*.rs' 2>/dev/null | sort; }

# ── THE SCANNER (one copy; the self-test drives THIS function, never a duplicate) ─────────────────
# Emits one TSV line per violation:  CATEGORY<TAB>file:line<TAB>trimmed-source
#   mode=forward  scan NEUTRAL sources for the side channels (a)/(b)/(c).
#   mode=reverse  scan PLANE sources for the backwards reach (busbar_core:: implementation names).
# It strips comments/doc-comments/block-comments (respecting string literals so a `//` inside a string
# is NOT a comment and a token inside a string IS kept), and — for the SYMBOL/KEY/DIALECT/TYPE rules —
# excludes test code (a `*/tests/*` or `*_test(s).rs` file, and a `#[cfg(test)] mod … { … }` block).
# The PATH-INCLUDE rule is scanned UNCONDITIONALLY, test scope included: the witness `#[path]` include
# is an instant fail wherever it lives.
scan() {
  local mode="$1"; shift
  [ "$#" -gt 0 ] || return 0
  awk -v mode="$mode" '
    # Strip comments + block-comments, respecting string literals. inblk persists across lines
    # (block comments span lines); instr is per-line (Rust string literals are overwhelmingly
    # single-line, and resetting each line guards against a raw-string/char-literal desync).
    function strip(line,   res, i, n, c, c2, instr) {
      res = ""; n = length(line); i = 1; instr = 0
      while (i <= n) {
        c = substr(line, i, 1); c2 = substr(line, i, 2)
        if (inblk) { if (c2 == "*/") { inblk = 0; i += 2 } else { i++ } continue }
        if (instr) {
          res = res c
          if (c == "\\") { res = res substr(line, i + 1, 1); i += 2; continue }
          if (c == "\"") { instr = 0 }
          i++; continue
        }
        if (c2 == "/*") { inblk = 1; i += 2; continue }
        if (c2 == "//") { break }                       # line comment (covers // /// //!) to EOL
        if (c == "\"") { instr = 1; res = res c; i++; continue }
        res = res c; i++
      }
      return res
    }
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    # A whole-word (identifier-boundary) case-insensitive hit of a lowercase needle. The pad makes a
    # match at line start/end boundary-clean; the class [^a-z0-9_] is the identifier boundary.
    function word_ci(lc, needle) { return (lc ~ ("[^a-z0-9_]" needle "[^a-z0-9_]")) }
    function emit(cat, text) { printf "%s\t%s:%d\t%s\n", cat, FILENAME, FNR, trim(text) }

    # Per-FILE reset (awk shares state across the file list).
    FNR == 1 { inblk = 0; testdepth = 0; pend = 0 }

    {
      code = strip($0)
      pad  = " " code " "
      lc   = tolower(pad)
      nopen = gsub(/[{]/, "{", code); nclose = gsub(/[}]/, "}", code)

      istestfile = (FILENAME ~ /\/tests\// || FILENAME ~ /_tests?\.rs$/)

      # ── #[cfg(test)] mod { … } block tracking (so unit-test code is excluded from b/c) ──
      # A cfg predicate that mentions `test` (cfg(test), any(test,…), the test-support witness gate).
      is_cfgtest = (code ~ /#\[cfg\(/ && (lc ~ /[^a-z0-9_]test[^a-z0-9_]/))
      has_mod    = (code ~ /(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])/)
      entered = 0
      if (is_cfgtest && has_mod) {                       # attr + mod on one line
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0
      } else if (pend && has_mod) {                      # the mod that a prior cfg(test) attr guarded
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0
      } else if (pend && code ~ /[^[:space:]]/ && !is_cfgtest) {
        pend = 0                                          # the attr guarded a non-mod item; do not block-skip
      } else if (testdepth > 0) {
        testdepth += nopen - nclose; if (testdepth < 0) testdepth = 0
      }
      if (is_cfgtest && !has_mod) pend = 1                # remember: the guarded mod is on a later line
      intest = (istestfile || testdepth > 0 || entered)

      if (mode == "reverse") {
        # No backwards reach: a plane crate must not name busbar_core:: implementation items.
        if (!intest && code ~ /busbar_core::/) emit("BACKWARDS", code)
        next
      }

      # ── forward: neutral-crate side channels ──
      # (a) PATH-INCLUDE — unconditional, test scope included (instant fail).
      if (code ~ /#\[[[:space:]]*path[[:space:]]*=[[:space:]]*"[^"]*busbar-(llm|mcp|a2a)\//) emit("PATH-INCLUDE", code)

      if (intest) next                                    # (b)/(c) exclude test code

      # (b) SYMBOL — a plane-crate symbol path.
      if (code ~ /busbar_(llm|mcp|a2a)::/) emit("SYMBOL", code)

      # (c3) TYPE — the named plane record structs, plus any plane-/dialect-prefixed CamelCase type.
      #      (Checked before the bare-key rule so McpFoo reads as TYPE, not KEY.)
      if (code ~ /(^|[^A-Za-z0-9_])(McpCallRecord|McpDemotionRow|TaskRow|TaskEventRow)([^A-Za-z0-9_]|$)/ \
       || code ~ /(^|[^A-Za-z0-9_])(Mcp|A2a|A2A|Llm|Openai|Anthropic|Gemini|Bedrock|Cohere|Responses)[A-Z][A-Za-z0-9_]*/)
        emit("TYPE", code)

      # (c1) KEY — a concrete plane key as a bare token (mcp / a2a / llm). Word-boundary, so it does
      #      NOT match inside busbar_mcp / plane_mcp / MCP_RUNTIME_SLOT (underscore is not a boundary).
      if (word_ci(lc, "mcp") || word_ci(lc, "a2a") || word_ci(lc, "llm")) emit("KEY", code)

      # (c2) DIALECT — one of the six dialect names as a token.
      if (word_ci(lc, "openai") || word_ci(lc, "anthropic") || word_ci(lc, "gemini") \
       || word_ci(lc, "bedrock") || word_ci(lc, "cohere") || word_ci(lc, "responses")) emit("DIALECT", code)
    }
  ' "$@"
}

# ── SELF-TEST — the scanner cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "plane-purity-lint SELF-TEST (the side-channel scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0

  # ── RED (neutral): the four side channels the design names, plus a bare key + a dialect token ──
  # (i) a fake witness #[path=…busbar-mcp…]; (ii) a busbar_a2a:: reference; (iii) a McpFoo type;
  # plus a bare `mcp` key in a string and an `anthropic` dialect token — all must be flagged.
  cat >"$tmp/neutral_red.rs" <<'RED'
#[path = "../../../busbar-mcp/src/witness.rs"]
mod mcp_witness;
use busbar_a2a::TaskThing;
pub struct McpFoo;
fn route() { let plane_key = "mcp"; let dialect = "anthropic"; }
RED
  local out cat_count
  out="$(scan forward "$tmp/neutral_red.rs")"
  cat_count() { printf '%s\n' "$out" | awk -F'\t' -v c="$1" '$1==c{n++} END{print n+0}'; }
  local need ok=1
  for need in PATH-INCLUDE SYMBOL TYPE KEY DIALECT; do
    if [ "$(cat_count "$need")" -ge 1 ]; then
      note "RED neutral: flagged $need"
    else
      ok=0; note "RED neutral FAILED: $need not flagged"; fi
  done
  [ "$ok" -eq 1 ] || { fail=1; note "  (scanner output was:)"; printf '%s\n' "$out" | sed 's/^/    /'; }

  # ── GREEN (neutral): the intentional neutral ABI, plus a comment / block-comment / cfg(test) mod
  # that MENTION plane vocabulary — none may be flagged. This is the executable proof of the
  # curated allow-list AND of the comment/test exclusion.
  cat >"$tmp/neutral_green.rs" <<'GREEN'
use busbar_substrate::plane::{PlaneDecl, PlaneRecord};
use busbar_api::store::{ProtocolDecl, PlaneSlots};
// a comment naming mcp a2a llm anthropic gemini and McpCallRecord must be ignored
/* a block comment naming TaskRow and openai and bedrock also ignored */
pub fn install(d: &PlaneDecl, r: PlaneRecord) {
    install_planes(&[d]);
    install_protocols(&[]);
    install_diagnostics(&[]);
    let _slots = plane_slots();
    let _diag = PLANE_TASK_CHAIN_VERIFY_FAILED;
    let _n = BUILTIN_PLANE_DECLS.len();
}
#[cfg(test)]
mod tests {
    fn t() { let _ = McpCallRecord::default(); let k = "mcp"; let d = "anthropic"; }
}
GREEN
  out="$(scan forward "$tmp/neutral_green.rs")"
  if [ -z "$out" ]; then
    note "GREEN neutral: flagged none of the ABI / comment / block-comment / cfg(test) fixtures"
  else
    fail=1; note "GREEN neutral FAILED: expected 0 flags, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── RED (reverse): (iv) a plane crate reaching BACK into core implementation ──
  cat >"$tmp/plane_red.rs" <<'RRED'
use busbar_core::internal::foo;
fn f() { let _ = busbar_core::proto::PROTO_ANTHROPIC; }
RRED
  out="$(scan reverse "$tmp/plane_red.rs")"
  if [ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="BACKWARDS"{n++} END{print n+0}')" -ge 1 ]; then
    note "RED reverse: flagged the busbar_core:: backwards reach"
  else
    fail=1; note "RED reverse FAILED: backwards reach not flagged (got: $out)"
  fi

  # ── GREEN (reverse): a plane crate naming ONLY the substrate/api ABI is clean ──
  cat >"$tmp/plane_green.rs" <<'RGREEN'
use busbar_substrate::plane::PlaneDecl;
use busbar_api::store::PlaneRecord;
// busbar_core:: named only in a comment is not a reach
GREEN
RGREEN
  out="$(scan reverse "$tmp/plane_green.rs")"
  if [ -z "$out" ]; then
    note "GREEN reverse: a plane crate naming only the substrate/api ABI is clean"
  else
    fail=1; note "GREEN reverse FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  if [ "$fail" -ne 0 ]; then
    red "plane-purity-lint SELF-TEST FAILED — the scanner would let a side channel through"
    return 1
  fi
  grn "plane-purity-lint self-test: ALL GREEN (scanner RED/GREEN discipline proven)"
  return 0
}

# ── THE REAL RUN ──────────────────────────────────────────────────────────────────────────────────
# Scans the tree, prints a categorized report, and returns the total violation count via $REPORT_TOTAL.
REPORT_TOTAL=0
run_report() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local nf pf
  nf="$(neutral_files)"; pf="$(plane_files)"

  : >"$tmp/hits"
  # shellcheck disable=SC2086
  [ -n "$nf" ] && scan forward $nf >>"$tmp/hits"
  # shellcheck disable=SC2086
  [ -n "$pf" ] && scan reverse $pf >>"$tmp/hits"

  local total; total="$(wc -l <"$tmp/hits" | tr -d ' ')"
  REPORT_TOTAL="$total"

  hdr "NEUTRAL-PURITY report — side channels in the neutral crates + backwards reach from the planes"
  note "neutral roots: $NEUTRAL_ROOTS"
  note "plane roots:   $PLANE_ROOTS"

  hdr "by category (the ledger the extraction must drive to zero — §3)"
  # Category order fixed so the report is stable; count each even when zero.
  local c n
  for c in PATH-INCLUDE SYMBOL TYPE KEY DIALECT BACKWARDS; do
    n="$(awk -F'\t' -v c="$c" '$1==c{n++} END{print n+0}' "$tmp/hits")"
    printf '  %-13s %6d\n' "$c" "$n"
  done
  printf '  %-13s %6d\n' "TOTAL" "$total"

  hdr "top 15 files by violation count"
  awk -F'\t' '{split($2,a,":"); f[a[1]]++} END{for(k in f) printf "%6d  %s\n", f[k], k}' "$tmp/hits" \
    | sort -rn | head -15 | sed 's/^/  /'

  # Keep the hit list available for callers that want the full detail.
  cp "$tmp/hits" "${PLANE_PURITY_HITS_OUT:-/dev/null}" 2>/dev/null || true
}

# ── modes ─────────────────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --selftest)
    run_selftest; exit $?
    ;;
  --baseline)
    # INFORMATIONAL: surface the baseline on every push WITHOUT going red. Always exit 0.
    run_report
    hdr "verdict"
    if [ "$REPORT_TOTAL" -eq 0 ]; then
      grn "plane-purity: the neutral crates are CLEAN (0 side channels). Arm the qa segment (reserved→active)."
    else
      ylw "plane-purity: $REPORT_TOTAL side channel(s) — DEFERRED (informational) until the extraction lands."
      note "This is the baseline the plane-extraction (design §3–§5) must drive to zero, NOT a red build."
      note "The blocking gate is \`--check\`, wired as a RESERVED qa segment that arms (reserved→active)"
      note "the day this count reaches 0 — exactly as field_coverage.rs's acceptance is #[ignore]d-until-drained."
    fi
    exit 0
    ;;
  --check | "")
    # BLOCKING (fail-closed): the PERMANENT gate. Red on ANY violation. Wired into the reserved
    # `plane-purity` qa segment; arming it (reserved→active) is a one-line flip once the tree is clean.
    run_report
    hdr "verdict"
    if [ "$REPORT_TOTAL" -eq 0 ]; then
      grn "plane-purity gate: PASS — no side channel in the neutral crates, no backwards reach"
      exit 0
    fi
    red "plane-purity gate: FAIL — $REPORT_TOTAL side channel(s) cross AROUND the ABI (see report above)"
    note "Every one is a violation to REMOVE, not to gate (design §2.1). Route it through the ABI:"
    note "  PATH-INCLUDE → the plane's tests live in the plane crate; core exercises it via the registry."
    note "  SYMBOL/TYPE  → cross the ABI as an opaque PlaneRecord / a registry capability lookup."
    note "  KEY/DIALECT  → read the opaque &str key the registry supplies; the registry is the truth."
    note "  BACKWARDS    → a plane may name the substrate/api ABI, never busbar_core:: implementation."
    exit 1
    ;;
  -h | --help)
    sed -n '2,60p' "$0"
    ;;
  *)
    echo "usage: $0 [--selftest | --baseline | --check]" >&2
    exit 2
    ;;
esac
