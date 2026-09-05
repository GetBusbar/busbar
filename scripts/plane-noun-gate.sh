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
# eviction moves burn down. bash 3.2 + POSIX grep/awk, same bare-runner posture as its siblings.
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# ── THE NEUTRAL SURFACE (the ABI side; the only place these nouns are a leak) ─────────────────────
NEUTRAL_ROOTS="crates/busbar-core/src crates/busbar-substrate/src crates/busbar-substrate-values/src crates/api/src crates/busbar-plugin/src"

# The metering/pricing context that promotes a bare `provider`/`model` from homonym to leak.
CTX_RE='price|pricing|cost|billing|rate_card|meter|metering|budget|spend|charge|invoice|quota'

# The curated word-boundary compound needles. `tokens_cache` is a prefix (tokens_cache_read/write).
WB_NEEDLES="tokens_input tokens_output max_tokens default_max_tokens rate_card reasoning_effort ModelTokens TierTokens"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/plane-noun-gate.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
HITS="$TMP/hits"       # NEEDLE<TAB>file:line
CODE="$TMP/code"       # file:line:content  — comment-only lines dropped
: > "$HITS"

# Non-test .rs under the neutral roots.
neutral_files() {
  # shellcheck disable=SC2086
  find $NEUTRAL_ROOTS -name '*.rs' 2>/dev/null \
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
  hdr "LLM-noun debt in the neutral crates (report-only)"
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

case "${1:-}" in
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
    echo "usage: $0 [--report|--check]   (env: GREP_GATE_REPORT_ONLY=1 default, PLANE_NOUN_HITS_OUT=path)" >&2
    exit 2
    ;;
esac
