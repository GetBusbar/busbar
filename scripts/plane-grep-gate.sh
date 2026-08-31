#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-grep-gate.sh — THE SUBSTRING DIALECT-NAME NEUTRALITY GATE (the "Protocols as Plugins" debt meter).
#
# WHY THIS EXISTS (the gap plane-purity-lint.sh leaves):
#   scripts/plane-purity-lint.sh enforces the plane ABI with WORD-BOUNDARY rules: it bans the plane
#   KEYS (mcp / a2a / llm as whole tokens) and the six DIALECT names as whole words. That is exactly
#   right for the structural side-channel invariant it guards — but it is deliberately narrow. A token
#   like `gemini_api_version`, a path literal `"/v1/models"` that is really a Gemini/OpenAI wire fact,
#   or a field named `openai_compat` is NOT a whole-word `gemini`/`openai` hit, so plane-purity is
#   blind to it. The "Protocols as Plugins" work (owner acceptance scope F4) needs a STRICTER meter:
#   dialect names banned AS SUBSTRINGS in PRODUCTION .rs outside busbar-llm, so `gemini_api_version`,
#   `openai_style`, `cohere_rerank_v2` and friends all light up.
#
# THE ACCEPTANCE SCOPE (F4, owner-pinned):
#   Ban DIALECT NAMES in PRODUCTION Rust code outside `busbar-llm`, EXCLUDING comments/doc-strings,
#   tests, and the neutral `busbar-api` `Operation` enum (crates/api/src/operation.rs) — the generic
#   op vocabulary (chat / embedding / rerank / …) is NEUTRAL and stays. Concretely:
#
#     NEUTRAL crates (busbar-core, busbar-substrate, busbar-api): ZERO occurrences (as substrings) of
#       the six dialect names — openai gemini anthropic bedrock cohere responses — PLUS the plane keys
#       `mcp` / `a2a` (a neutral crate must name neither plane by key).
#     busbar-mcp : may name `mcp`, but NOT the six dialect names and NOT `a2a`.
#     busbar-a2a : may name `a2a`, but NOT the six dialect names and NOT `mcp`.
#     busbar-llm : OWNS the dialect names — not scanned.
#
#   Substring match (index, not word-boundary) is the whole point: it is a SUPERSET of plane-purity's
#   dialect rule, catching the `_api_version` / `_compat` / `/v1/…`-adjacent leakage plane-purity cannot.
#
# WHAT IS EXCLUDED (so the meter measures real debt, not comments or test scaffolding):
#   * comments + doc-comments + block comments — stripped before matching (respecting string literals,
#     so a token INSIDE a string literal is KEPT and a `//` inside a string is NOT a comment). This is
#     the same strip() the sibling plane-purity-lint.sh uses.
#   * test code — a `*/tests/*` or `*_test(s).rs` file, and a `#[cfg(test)] mod … { … }` block.
#   * the neutral `Operation` enum — crates/api/src/operation.rs is EXCLUDED wholesale: its variants
#     (Chat/Embeddings/Moderation/…) are the generic, protocol-neutral op vocabulary the ABI carries as
#     DATA, and are explicitly in-scope-neutral per F4.
#
# REPORTING MODE (this lands NON-BLOCKING to measure the debt R3/R4/R5 will drive to 0):
#   GREP_GATE_REPORT_ONLY=1 (DEFAULT) → PRINT the violation count + the offending file:line list, EXIT 0.
#   GREP_GATE_REPORT_ONLY=0           → BLOCKING: exit 1 if any violation remains (the future hard gate).
#   Either way the full report is printed; only the exit code differs. This is the same two-mode posture
#   plane-purity used while it drained (baseline-informational → armed-check), here folded onto one env
#   flag so arming the gate is a manifest edit, not a code edit.
#
# THE SELF-TEST (--selftest, run FIRST like every sibling *-lint.sh): the scanner cannot be lied to.
#   It plants a fake `gemini_api_version` and a `busbar_a2a::Foo` in a NEUTRAL fixture and proves BOTH
#   are caught (RED), proves a per-crate symmetric case (busbar-mcp naming `a2a`/`anthropic` is caught,
#   naming `mcp` is not), and proves a CLEAN neutral fixture — plus a comment / cfg(test) block that
#   MENTION dialect names — passes with zero hits (GREEN). The tree verdict is trusted only after the
#   scanner re-proves itself on known inputs.
#
# No external deps beyond bash 3.2 + POSIX awk (macOS/Linux) — same bare-runner posture as the sibling
# gates (plane-purity-lint.sh, config-stability-gate.sh).
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# ── THE NEEDLE SETS ──────────────────────────────────────────────────────────────────────────────
# The six dialect names — banned as SUBSTRINGS everywhere outside busbar-llm.
DIALECTS="openai gemini anthropic bedrock cohere responses"

# ── THE CRATE GROUPS AND THEIR BANNED NEEDLES ────────────────────────────────────────────────────
# Each group names a crate src root and the exact set of needles that must NOT appear there. A crate
# added/removed/re-scoped is a one-line edit here, never N stale paths below.
#   neutral  : the ABI side — bans every dialect + BOTH plane keys (names no plane at all).
#   mcp      : may name `mcp`; bans the dialects + the OTHER plane key `a2a`.
#   a2a      : may name `a2a`; bans the dialects + the OTHER plane key `mcp`.
#   (busbar-llm owns the dialect names and is not scanned.)
NEUTRAL_ROOTS="crates/busbar-core/src crates/busbar-substrate/src crates/api/src"
NEUTRAL_NEEDLES="$DIALECTS mcp a2a"
MCP_ROOT="crates/busbar-mcp/src"
MCP_NEEDLES="$DIALECTS a2a"
A2A_ROOT="crates/busbar-a2a/src"
A2A_NEEDLES="$DIALECTS mcp"

# The neutral Operation enum — generic op vocabulary, explicitly in-scope-neutral (F4). Excluded whole.
OPERATION_EXCLUDE="crates/api/src/operation.rs"

# Production .rs under a set of roots, minus test files and the excluded Operation enum.
prod_files() {
  find $* -name '*.rs' 2>/dev/null \
    | grep -v '/tests/' \
    | grep -Ev '_tests?\.rs$' \
    | grep -vxF "$OPERATION_EXCLUDE" \
    | sort
}

# ── THE SCANNER (one copy; the self-test drives THIS function, never a duplicate) ─────────────────
# Emits one TSV line per violation:  NEEDLE<TAB>file:line<TAB>trimmed-source
# It strips comments/doc-comments/block-comments (respecting string literals) and excludes
# `#[cfg(test)] mod { … }` blocks, then flags any case-insensitive SUBSTRING hit of a banned needle.
scan() {
  local needles="$1"; shift
  [ "$#" -gt 0 ] || return 0
  awk -v needles="$needles" '
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
        if (c2 == "//") { break }
        if (c == "\"") { instr = 1; res = res c; i++; continue }
        res = res c; i++
      }
      return res
    }
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    function emit(needle, text) { printf "%s\t%s:%d\t%s\n", needle, FILENAME, FNR, trim(text) }

    BEGIN { nN = split(needles, N, " ") }

    # Per-FILE reset (awk shares state across the file list).
    FNR == 1 { inblk = 0; testdepth = 0; pend = 0 }

    {
      code = strip($0)
      lc   = tolower(code)
      nopen = gsub(/[{]/, "{", code); nclose = gsub(/[}]/, "}", code)

      # ── #[cfg(test)] mod { … } block tracking (exclude unit-test code) ──
      is_cfgtest = (code ~ /#\[cfg\(/ && (tolower(" " code " ") ~ /[^a-z0-9_]test[^a-z0-9_]/))
      has_mod    = (code ~ /(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])/)
      entered = 0
      if (is_cfgtest && has_mod) {
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0
      } else if (pend && has_mod) {
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0
      } else if (pend && code ~ /[^[:space:]]/ && !is_cfgtest) {
        pend = 0
      } else if (testdepth > 0) {
        testdepth += nopen - nclose; if (testdepth < 0) testdepth = 0
      }
      if (is_cfgtest && !has_mod) pend = 1
      if (testdepth > 0 || entered) next

      # ── substring dialect / plane-key hits ──
      for (k = 1; k <= nN; k++) {
        if (index(lc, N[k]) > 0) emit(N[k], code)
      }
    }
  ' "$@"
}

# ── SELF-TEST — the scanner cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "plane-grep-gate SELF-TEST (the substring dialect scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 out

  # ── RED (neutral): a planted `gemini_api_version` + a `busbar_a2a::Foo` — the substring wins that
  # plane-purity's word-boundary rule would MISS on the first. Both must be flagged.
  cat >"$tmp/neutral_red.rs" <<'RED'
pub const GEMINI_KEY: &str = "gemini_api_version";
use busbar_a2a::Foo;
fn probe() { let url = "https://api.openai.com/v1/models"; }
RED
  out="$(scan "$NEUTRAL_NEEDLES" "$tmp/neutral_red.rs")"
  local hit_gemini hit_a2a hit_openai
  hit_gemini="$(printf '%s\n' "$out" | awk -F'\t' '$1=="gemini"{n++} END{print n+0}')"
  hit_a2a="$(printf '%s\n' "$out"    | awk -F'\t' '$1=="a2a"{n++}    END{print n+0}')"
  hit_openai="$(printf '%s\n' "$out" | awk -F'\t' '$1=="openai"{n++} END{print n+0}')"
  if [ "$hit_gemini" -ge 1 ]; then note "RED neutral: caught gemini SUBSTRING in \`gemini_api_version\`"; else fail=1; note "RED neutral FAILED: gemini_api_version not flagged"; fi
  if [ "$hit_a2a"    -ge 1 ]; then note "RED neutral: caught the busbar_a2a:: plane-key reach"; else fail=1; note "RED neutral FAILED: busbar_a2a:: not flagged"; fi
  if [ "$hit_openai" -ge 1 ]; then note "RED neutral: caught openai SUBSTRING in the /v1/models url host"; else fail=1; note "RED neutral FAILED: api.openai.com not flagged"; fi
  [ "$fail" -eq 0 ] || { note "  (scanner output was:)"; printf '%s\n' "$out" | sed 's/^/    /'; }

  # ── GREEN (neutral): the generic neutral vocabulary + a comment / cfg(test) block MENTIONING dialect
  # names — none may be flagged (executable proof of the comment/test exclusion).
  cat >"$tmp/neutral_green.rs" <<'GREEN'
pub enum Op { Chat, Embeddings, Rerank, Moderation }
// this comment names openai gemini anthropic bedrock cohere responses mcp a2a and must be ignored
/* block comment naming gemini_api_version and openai too — ignored */
pub fn install() { let _op = Op::Chat; let _e = Op::Embeddings; }
#[cfg(test)]
mod tests {
    fn t() { let _ = "openai gemini anthropic"; let _k = "mcp a2a"; }
}
GREEN
  out="$(scan "$NEUTRAL_NEEDLES" "$tmp/neutral_green.rs")"
  if [ -z "$out" ]; then
    note "GREEN neutral: generic Op vocabulary + comment + cfg(test) fixtures flagged NONE"
  else
    fail=1; note "GREEN neutral FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── SYMMETRIC (busbar-mcp): may name `mcp`, must NOT name `a2a` or a dialect. ──
  cat >"$tmp/mcp_case.rs" <<'MCP'
use busbar_mcp::server::McpEndpoint;
fn wire() { let _ = "a2a"; let _d = "anthropic_v1"; }
MCP
  out="$(scan "$MCP_NEEDLES" "$tmp/mcp_case.rs")"
  local mcp_hit_mcp mcp_hit_a2a mcp_hit_anthropic
  mcp_hit_mcp="$(printf '%s\n' "$out"       | awk -F'\t' '$1=="mcp"{n++}       END{print n+0}')"
  mcp_hit_a2a="$(printf '%s\n' "$out"       | awk -F'\t' '$1=="a2a"{n++}       END{print n+0}')"
  mcp_hit_anthropic="$(printf '%s\n' "$out" | awk -F'\t' '$1=="anthropic"{n++} END{print n+0}')"
  # `mcp` is NOT in MCP_NEEDLES, so it must never appear as a category, and `busbar_mcp` must not trip.
  if [ "$mcp_hit_mcp" -eq 0 ];      then note "SYMMETRIC mcp: did NOT flag its own \`mcp\` name"; else fail=1; note "SYMMETRIC mcp FAILED: flagged its own \`mcp\`"; fi
  if [ "$mcp_hit_a2a" -ge 1 ];      then note "SYMMETRIC mcp: flagged the foreign \`a2a\` plane key"; else fail=1; note "SYMMETRIC mcp FAILED: foreign a2a not flagged"; fi
  if [ "$mcp_hit_anthropic" -ge 1 ]; then note "SYMMETRIC mcp: flagged \`anthropic\` SUBSTRING in anthropic_v1"; else fail=1; note "SYMMETRIC mcp FAILED: anthropic_v1 not flagged"; fi

  if [ "$fail" -ne 0 ]; then
    red "plane-grep-gate SELF-TEST FAILED — the scanner would let a dialect substring through"
    return 1
  fi
  grn "plane-grep-gate self-test: ALL GREEN (substring RED/GREEN discipline proven)"
  return 0
}

# ── THE REAL RUN ──────────────────────────────────────────────────────────────────────────────────
# Scans every group, prints the categorized report, and returns the total via $REPORT_TOTAL.
REPORT_TOTAL=0
run_report() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  : >"$tmp/hits"

  local nf mf af
  nf="$(prod_files $NEUTRAL_ROOTS)"; mf="$(prod_files $MCP_ROOT)"; af="$(prod_files $A2A_ROOT)"
  # shellcheck disable=SC2086
  [ -n "$nf" ] && scan "$NEUTRAL_NEEDLES" $nf >>"$tmp/hits"
  # shellcheck disable=SC2086
  [ -n "$mf" ] && scan "$MCP_NEEDLES"     $mf >>"$tmp/hits"
  # shellcheck disable=SC2086
  [ -n "$af" ] && scan "$A2A_NEEDLES"     $af >>"$tmp/hits"

  local total; total="$(wc -l <"$tmp/hits" | tr -d ' ')"
  REPORT_TOTAL="$total"

  hdr "PLANE-GREP report — dialect-name SUBSTRINGS outside busbar-llm (production .rs, comments/tests/Operation excluded)"
  note "neutral roots: $NEUTRAL_ROOTS   (bans: $NEUTRAL_NEEDLES)"
  note "mcp root:      $MCP_ROOT   (bans: $MCP_NEEDLES)"
  note "a2a root:      $A2A_ROOT   (bans: $A2A_NEEDLES)"
  note "excluded:      $OPERATION_EXCLUDE (neutral Operation enum), */tests/*, *_test(s).rs, #[cfg(test)]"

  hdr "by needle (a clean tree reports zero)"
  local d n
  for d in $DIALECTS mcp a2a; do
    n="$(awk -F'\t' -v c="$d" '$1==c{n++} END{print n+0}' "$tmp/hits")"
    printf '  %-12s %6d\n' "$d" "$n"
  done
  printf '  %-12s %6d\n' "TOTAL" "$total"

  hdr "top 20 files by violation count"
  awk -F'\t' '{split($2,a,":"); f[a[1]]++} END{for(k in f) printf "%6d  %s\n", f[k], k}' "$tmp/hits" \
    | sort -rn | head -20 | sed 's/^/  /'

  hdr "first 40 offending file:line"
  awk -F'\t' '{printf "  %-10s %s\n", $1, $2}' "$tmp/hits" | head -40

  cp "$tmp/hits" "${PLANE_GREP_HITS_OUT:-/dev/null}" 2>/dev/null || true
}

# ── modes ─────────────────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --selftest)
    run_selftest; exit $?
    ;;
  --report | --check | "")
    run_report
    hdr "verdict"
    report_only="${GREP_GATE_REPORT_ONLY:-1}"
    if [ "$REPORT_TOTAL" -eq 0 ]; then
      grn "plane-grep gate: PASS — no dialect-name substring outside busbar-llm"
      exit 0
    fi
    if [ "$report_only" = "0" ]; then
      red "plane-grep gate: FAIL — $REPORT_TOTAL dialect-name substring(s) outside busbar-llm (see report above)"
      note "Route each through the plane ABI / a neutral op-vocabulary constant; the dialect names belong in busbar-llm."
      exit 1
    fi
    ylw "plane-grep gate: $REPORT_TOTAL dialect-name substring(s) — REPORT-ONLY (GREP_GATE_REPORT_ONLY=1, non-blocking)."
    note "This meter is informational for now; R3/R4/R5 drive it to 0. Set GREP_GATE_REPORT_ONLY=0 to arm the hard gate."
    exit 0
    ;;
  -h | --help)
    sed -n '2,60p' "$0"
    ;;
  *)
    echo "usage: $0 [--selftest | --report | --check]   (env GREP_GATE_REPORT_ONLY=1 default report-only; =0 blocking)" >&2
    exit 2
    ;;
esac
