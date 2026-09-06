#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-noun-gate.sh — THE LLM-NOUN DEBT METER for the NEUTRAL crates. REPORT-ONLY (today).
#
# WHY THIS EXISTS. The 1.6.0 audit found ONE bounded root cause behind the plane-extraction debt:
# LLM-SHAPED NOUNS — the vocabulary of one protocol's billing and prompting — frozen into the
# NEUTRAL crates (busbar-core, busbar-substrate, api, busbar-plugin) that every plane is supposed to
# share as a protocol-agnostic ABI. `tokens_input`, `max_tokens`, `rate_card`, `reasoning_effort`,
# `Billing::Tokens`: each is an LLM concept the MCP / A2A / voice planes do not own, and each one
# that lives in the neutral surface is a place the ABI leaks one protocol's shape into all of them.
#
# This is a METER, not a gate — YET. The neutral crates are RED today (the eviction is moves M1–M5,
# and the money-path relocation is its own tracked move); a blocking gate now would only paint CI red
# with work already queued. So this prints a DEBT COUNT and EXITS 0. It exists so the debt has a
# NUMBER that later moves drive down, and so the day it reaches zero, arming the hard gate is a
# one-flag flip — exactly the posture of scripts/plane-grep-gate.sh.
#
# MODES / ENV (mirrors plane-grep-gate.sh):
#   (no arg) | --report | --check   Scan, print the per-needle table + TOTAL debt, then:
#     GREP_GATE_REPORT_ONLY=1 (DEFAULT)  → report-only: EXIT 0 regardless of the count.
#     GREP_GATE_REPORT_ONLY=0            → future hard gate: exit 1 if TOTAL>0. NOT used in CI today.
#   PLANE_NOUN_HITS_OUT=<path>          Optional: copy the raw file:line hit list there.
#
# WHAT COUNTS (path-scoped, word-boundary, CURATED — a homonym is not a leak):
#   * Compound LLM nouns, matched with word boundaries so an unrelated identifier that merely
#     contains the stem is not swept in: tokens_input / tokens_output / tokens_cache* / max_tokens /
#     default_max_tokens / rate_card / reasoning_effort / ModelTokens / TierTokens / Billing::Tokens.
#   * The bare nouns `provider` and `model` ONLY on lines that ALSO carry metering/pricing context
#     (price|pricing|cost|billing|rate_card|meter|metering|budget|spend|charge|invoice|quota). A
#     bare `provider`/`model` elsewhere is a HOMONYM — a TLS/identity provider, a data model, a
#     route template, an auth-token line — and is deliberately NOT counted.
#
# WHAT IS ALLOWLISTED (genuine homonyms that would otherwise drown the signal):
#   * bare `token`     — auth/session/CSRF tokens (~1171 hits); only the LLM COMPOUNDS above count.
#   * bare `provider`  — TLS / identity / config providers (~579 hits); only pricing-context counts.
#   * bare `model`     — data models, MVC, DB models; only pricing-context counts.
#   * route templates and doc-comment prose — whole-line comments are stripped before matching.
#   * test code — `.../tests/...`, `*_tests.rs`, `*_test.rs`, `test_support` — a fixture exercising a
#     noun is not the shipped-ABI leak this meter is about.
#
# The count is a DEBT METER, NOT a verdict: a non-zero number here is expected and is the queue the
# eviction moves burn down. Which makes the LOW reading the dangerous one — 0 is the signal to arm the
# hard gate — so `--selftest` (run FIRST in CI, like every sibling lint) drives the whole pipeline over
# fixture roots and proves the meter counts a planted noun, ignores prose, and REFUSES to report a
# number at all when its roots are missing or its file list is empty. bash 3.2 + POSIX grep/awk, same
# bare-runner posture as its siblings.
set -uo pipefail
# Resolved BEFORE the cd, so --selftest can re-invoke this exact file as a child process (the root
# guard below exits the process, which a `$(…)` subshell would swallow).
SELF="$(cd "$(dirname "$0")" >/dev/null && pwd)/$(basename "$0")"
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# ── THE NEUTRAL SURFACE (the ABI side; the only place these nouns are a leak) ─────────────────────
# The four ABI-side roots are single-sourced from scripts/plane-keys.sh — the same list
# plane-purity-lint.sh and plane-transport-neutrality.sh scan, so the gates cannot disagree about
# what "neutral" means and a drained crate leaves the set by ONE named deletion there. THIS gate adds
# `crates/busbar-plugin/src`: the plugin ABI is the surface a third-party plugin compiles against, so
# an LLM noun frozen into it is the same leak as one in busbar-core, and it is measured here alone.
# shellcheck source=scripts/plane-keys.sh
. "$(dirname "$0")/plane-keys.sh"
# The env override exists for ONE caller: the --selftest fixtures below. Nothing in CI sets it.
NEUTRAL_ROOTS="${PLANE_NOUN_NEUTRAL_ROOTS:-$(neutral_src_roots) crates/busbar-plugin/src}"

# ── THE ROOT GUARD — a missing root is RED, never silence ──────────────────────────────────────────
# `find $ROOTS … 2>/dev/null` swallows the diagnostic for a root that has been renamed, split or
# drained, and the pipe loses find's status. The result is an EMPTY file list, an empty code stream,
# a DEBT_TOTAL of 0 and the "CLEAN — arm the hard gate" verdict printed over a tree this meter never
# opened. Every root is proven to be a directory first, and a missing one aborts. Exits the PROCESS,
# so it is called from run_report directly, never inside a `$(…)`.
require_roots() {
  local r missing=""
  for r in "$@"; do
    [ -d "$r" ] || missing="${missing:+$missing }$r"
  done
  [ -z "$missing" ] && return 0
  red "plane-noun gate: FAIL — neutral root(s) listed but not present on disk: $missing"
  note "A listed root that does not exist is scanned as ZERO files, and zero is this meter's CLEAN."
  note "If the crate is legitimately gone, DELETE its entry from scripts/plane-keys.sh in a reviewed"
  note "diff that says so (busbar-plugin is added by this script and is deleted here). Never leave a"
  note "stale root in the list: the meter must not be able to read 0 by accident."
  exit 1
}

count_files() { [ -n "$1" ] || { printf '0'; return 0; }; printf '%s\n' "$1" | wc -l | tr -d ' '; }
# shellcheck disable=SC2086  # the split is the measurement
count_roots() { local n; set -f; set -- $1; n=$#; set +f; printf '%d' "$n"; }

# The metering/pricing context that promotes a bare `provider`/`model` from homonym to leak.
CTX_RE='price|pricing|cost|billing|rate_card|meter|metering|budget|spend|charge|invoice|quota'

# The curated word-boundary compound needles. `tokens_cache` is a prefix (tokens_cache_read/write).
WB_NEEDLES="tokens_input tokens_output max_tokens default_max_tokens rate_card reasoning_effort ModelTokens TierTokens"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/plane-noun-gate.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
HITS="$TMP/hits"       # NEEDLE<TAB>file:line
CODE="$TMP/code"       # file:line:content  — comment-only lines dropped
: > "$HITS"

# Non-test .rs under the neutral roots. No `2>/dev/null` — require_roots has already proven every
# root exists, so any remaining find diagnostic is real and must be seen.
neutral_files() {
  # shellcheck disable=SC2086
  find $NEUTRAL_ROOTS -name '*.rs' \
    | grep -vE '/tests/|_tests?\.rs$|/test_support/' | sort
}

# Build the comment-stripped code stream ONCE: every non-comment line as "file:line:content", so a
# noun discussed in doc-comment prose (`//`, `///`, `//!`, block `*`/`/*`) is not counted as a
# frozen ABI noun. awk has no `\b`, so word-boundary matching is done by grep -w over THIS stream.
build_code_stream() {
  local f
  while IFS= read -r f; do
    awk '
      { s=$0; sub(/^[ \t]+/,"",s) }
      s ~ /^\/\// || s ~ /^\*/ || s ~ /^\/\*/ { next }
      { printf "%s:%d:%s\n", FILENAME, FNR, $0 }
    ' "$f"
  done < <(neutral_files) > "$CODE"
}

# Record a needle by grepping the code stream. $3 = "word" → grep -w (portable word boundaries);
# anything else → grep -E substring. Extracts file:line (path has no ':'; line is field 2).
record() {   # $1 = label ; $2 = pattern ; $3 = mode(word|sub)
  local label="$1" pat="$2" mode="${3:-sub}" flags='-E'
  [ "$mode" = word ] && flags='-wE'
  grep $flags -e "$pat" "$CODE" 2>/dev/null \
    | awk -F: -v L="$label" '{print L"\t"$1":"$2}' >> "$HITS"
}

run_report() {
  # shellcheck disable=SC2086  # a space-separated root list; splitting is the point
  require_roots $NEUTRAL_ROOTS
  local n_nf n_nr
  n_nf="$(count_files "$(neutral_files)")"; n_nr="$(count_roots "$NEUTRAL_ROOTS")"

  # ── THE ZERO-FILE GUARD — trusted before DEBT_TOTAL is ───────────────────────────────────────────
  # require_roots has ruled out a missing directory; this catches every OTHER way the list comes back
  # empty (a root that exists but holds no non-test .rs, a layout move that left the sources one level
  # down). A zero-file scan and a fully-evicted tree produce the IDENTICAL number — 0 leak lines — and
  # this meter's 0 is the signal to ARM the hard gate, so the two must never be confused. Unlike the
  # debt itself, this is an instrument failure, not a queue: it exits non-zero even in report-only mode.
  if [ "$n_nf" -eq 0 ]; then
    red "plane-noun gate: FAIL — scanned $n_nf file(s) across $n_nr neutral root(s); zero is RED"
    note "A scan of zero files reports zero leak lines, which reads as CLEAN — the arm-the-gate signal."
    note "neutral roots: $NEUTRAL_ROOTS"
    note "Fix the root list in scripts/plane-keys.sh rather than letting the meter read 0 on an empty list."
    exit 1
  fi

  hdr "LLM-noun debt in the neutral crates (report-only)"
  note "neutral roots: $NEUTRAL_ROOTS ($n_nf non-test .rs file(s) across $n_nr root(s))"
  build_code_stream

  # Curated compounds, word-bounded so an identifier that merely contains the stem is not swept in.
  local n
  for n in $WB_NEEDLES; do
    record "$n" "$n" word
  done
  record "tokens_cache*"   "tokens_cache" sub
  record "Billing::Tokens" "Billing::Tokens" sub

  # Bare provider/model ONLY in pricing/metering context (word-bounded noun + a context word).
  grep -wE -e 'provider' "$CODE" 2>/dev/null | grep -iE "$CTX_RE" \
    | awk -F: '{print "provider@pricing\t"$1":"$2}' >> "$HITS"
  grep -wE -e 'model' "$CODE" 2>/dev/null | grep -iE "$CTX_RE" \
    | awk -F: '{print "model@pricing\t"$1":"$2}' >> "$HITS"

  # Per-needle table (raw hit lines).
  hdr "per-needle hits"
  awk -F'\t' '{c[$1]++} END{for(k in c) printf "  %-18s %6d\n", k, c[k]}' "$HITS" | sort

  # The DEBT: distinct file:line locations (a line hit by two needles is one leak).
  DEBT_TOTAL=$(cut -f2 "$HITS" | sort -u | grep -c . || true)
  RAW_TOTAL=$(grep -c . "$HITS" || true)

  hdr "top 15 files by leak lines"
  cut -f2 "$HITS" | sort -u | awk -F: '{f[$1]++} END{for(k in f) printf "%6d  %s\n", f[k], k}' \
    | sort -rn | head -15 | sed 's/^/  /'

  cut -f2 "$HITS" | sort -u > "${PLANE_NOUN_HITS_OUT:-/dev/null}" 2>/dev/null || true
}

# ── SELF-TEST — the meter cannot be lied to ───────────────────────────────────────────────────────
# This gate is a DEBT METER, and its most dangerous reading is the LOW one: 0 leak lines is the signal
# to arm the hard gate. So the self-test drives the WHOLE pipeline (roots → file list → code stream →
# needles → DEBT_TOTAL) as a child process over fixture roots, and proves the three ways it can be
# wrong: a planted noun that must be COUNTED, a comment-only mention that must NOT be, and the two
# blind-scan cases where the meter would read 0 because it opened nothing.
run_selftest() {
  hdr "plane-noun-gate SELF-TEST (the debt meter cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 hits

  # ── RED: a planted compound needle and a pricing-context bare noun must both be counted. ──
  mkdir -p "$tmp/red"
  cat >"$tmp/red/leak.rs" <<'RED'
pub struct Budget { pub max_tokens: u32 }
pub fn cost_for(provider: &str) -> u64 { 0 }
RED
  hits="$tmp/red.hits"
  PLANE_NOUN_NEUTRAL_ROOTS="$tmp/red" PLANE_NOUN_HITS_OUT="$hits" \
    bash "$SELF" --report >"$tmp/red.log" 2>&1
  if [ "$(grep -c . "$hits" 2>/dev/null || true)" -ge 2 ]; then
    note "RED: a planted max_tokens and a pricing-context bare provider are both counted"
  else
    fail=1; note "RED FAILED: planted nouns not counted (hits: $(cat "$hits" 2>/dev/null | tr '\n' ' '))"
  fi

  # ── GREEN: the SAME nouns in comment prose are stripped before matching and count for nothing. ──
  mkdir -p "$tmp/green"
  cat >"$tmp/green/prose.rs" <<'GRN'
// max_tokens and rate_card discussed in prose, and a provider priced per token
/// doc-comment naming reasoning_effort and a cost model
pub fn neutral() {}
GRN
  hits="$tmp/green.hits"
  PLANE_NOUN_NEUTRAL_ROOTS="$tmp/green" PLANE_NOUN_HITS_OUT="$hits" \
    bash "$SELF" --report >"$tmp/green.log" 2>&1
  if [ "$(grep -c . "$hits" 2>/dev/null || true)" -eq 0 ]; then
    note "GREEN: the same nouns in comment / doc-comment prose count for nothing"
  else
    fail=1; note "GREEN FAILED: prose-only mentions were counted (hits: $(cat "$hits" 2>/dev/null | tr '\n' ' '))"
  fi

  # ── THE BLIND-SCAN CASES: the meter must not be able to read 0 by scanning NOTHING ──────────────
  # A 0 here is the "arm the hard gate" signal, so a 0 produced by an empty file list is the worst
  # reading this script can print. Both cases run as CHILD processes: the guards exit by design.
  if PLANE_NOUN_NEUTRAL_ROOTS="crates/busbar-core-does-not-exist/src" \
     bash "$SELF" --report >"$tmp/missing.log" 2>&1; then
    fail=1; note "BLIND-SCAN FAILED: a non-existent neutral root still exited 0 (the meter read 0 having opened nothing)"
  else
    note "BLIND-SCAN: a non-existent neutral root exits non-zero (a missing root is RED, not silence)"
  fi
  mkdir -p "$tmp/emptyroot"
  if PLANE_NOUN_NEUTRAL_ROOTS="$tmp/emptyroot" bash "$SELF" --report >"$tmp/empty.log" 2>&1; then
    fail=1; note "BLIND-SCAN FAILED: a zero-file neutral root still exited 0 (0 leak lines read as CLEAN)"
  else
    note "BLIND-SCAN: a real-but-empty neutral root exits non-zero (zero files scanned is RED)"
  fi

  if [ "$fail" -ne 0 ]; then
    red "plane-noun-gate SELF-TEST FAILED — the meter would misreport the neutral-crate debt"
    return 1
  fi
  grn "plane-noun-gate self-test: ALL GREEN (meter RED/GREEN discipline proven)"
  return 0
}

case "${1:-}" in
  --selftest)
    run_selftest; exit $?
    ;;
  --report | --check | "")
    run_report
    hdr "verdict"
    note "raw needle hits: $RAW_TOTAL"
    printf '  \033[1mLLM-NOUN DEBT (distinct neutral-crate leak lines): %s\033[0m\n' "$DEBT_TOTAL"
    report_only="${GREP_GATE_REPORT_ONLY:-1}"
    if [ "$DEBT_TOTAL" -eq 0 ]; then
      grn "plane-noun gate: CLEAN — no LLM-noun leak in the neutral crates. Arm the hard gate."
      exit 0
    fi
    if [ "$report_only" = "0" ]; then
      red "plane-noun gate: FAIL — $DEBT_TOTAL LLM-noun leak line(s) in the neutral crates."
      note "Evict each into its plane (M1–M5) or a neutral op-vocabulary; then this meter reaches 0."
      exit 1
    fi
    ylw "plane-noun gate: $DEBT_TOTAL LLM-noun leak line(s) — REPORT-ONLY (GREP_GATE_REPORT_ONLY=1, non-blocking)."
    note "Expected RED today; M1–M5 evict the nouns and drive this to 0. Set GREP_GATE_REPORT_ONLY=0 to arm."
    exit 0
    ;;
  *)
    echo "usage: $0 [--selftest|--report|--check]   (env: GREP_GATE_REPORT_ONLY=1 default, PLANE_NOUN_HITS_OUT=path)" >&2
    exit 2
    ;;
esac
