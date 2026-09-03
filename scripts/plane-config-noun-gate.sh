#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-config-noun-gate.sh — THE FOUR-NOUN CONFIG-PARSE DEBT METER for busbar-core. REPORT-ONLY.
#
# WHY THIS EXISTS (docs/design/playbook/gate-isomorphism.md §2, Assertion N1):
#   Each of the four planes declares itself by the mere EXISTENCE of one top-level config.yaml section
#   — its `PlaneDecl.config_section`:  tools (mcp) · agents (a2a) · pools (llm) · streams (voice). The
#   isomorphism doctrine says core's config PARSER must name NONE of those section nouns as a CONCRETE
#   parse target: a plane's section reaches core ONLY through the seam (`PlaneDecl.config_section` /
#   `owned_config_sections`, folded by `config::config_sections_from`, parsed via `parse_section`). A
#   noun spelled as a literal match arm / serde binding / positional `.get("<noun>")` that steers
#   deserialization is a place core hard-codes one plane's grammar instead of reading it off the
#   registry.
#
# THIS IS A METER, NOT A HARD GATE — YET (exactly the posture of scripts/plane-noun-gate.sh). It is
# RED TODAY BY DESIGN: pre-Stage-A, every `owned_config_sections` is `&[]` and core still names all
# four sections concretely (named_map.rs `NamedMapSection::Tools => "tools"`, the DeployCfg named
# fields, …). Stage A evicts the sections onto the seam and drives this meter to ZERO; the day it
# reaches 0, arming the hard gate is a one-flag flip (GREP_GATE_REPORT_ONLY=0).
#
# WHAT COUNTS (a PARSE-STEERING occurrence, not every mention — the §2 curation discipline):
#   * a `NamedMapSection::Tools` / `::Agents` plane variant (the concrete named-map parse arm);
#   * a BARE quoted section literal `"tools"|"agents"|"pools"|"streams"` on a line that STEERS parsing
#     (a `=>` match arm, a `get(...)`/`get_mut(...)`/`.get("...")` positional section lookup, a
#     `serde(rename=...)`, or a DeployCfg named-field declaration).
#
# WHAT IS ALLOWLISTED (the legitimate seam + the homonyms that would drown the signal, §2 + Risk 1):
#   * THE SEAM — any line naming `config_section` / `owned_config_sections` / `config_sections_from` /
#     `plane_decl_for_config_section` / `CORE_OWNED_CONCRETE_SECTIONS`: the allowed path, never counted.
#   * THE FROZEN LEGACY MIGRATOR — crates/busbar-core/src/config/migrate*.rs operate on PAST on-disk
#     shapes (a frozen contract), not the live grammar.
#   * HOMONYM COMPOUNDS — `allowed_pools` (role grants), `tool_pools`/`agent_pools` (failover maps),
#     and any `<x>_pool(s)` / `pool_<x>` identifier: the noun is a substring, not a section target.
#   * comment/doc-comment prose (stripped before matching) and test code (`.../tests/...`, `*_tests.rs`).
#   * the config-schema.snapshot.json / openapi.json fixtures are `.json`, so structurally out of a `.rs` scan.
#
# The section nouns are NOT restated here: they are read from each plane crate's declared
# `PlaneDecl.config_section` (so a fifth plane's noun is scanned with no edit), and the plane set comes
# from scripts/plane-keys.sh — the single-source discipline every sibling gate follows.
#
# MODES / ENV (mirrors scripts/plane-noun-gate.sh):
#   (no arg) | --report | --check   Scan, print the per-noun table + DISTINCT-LINE debt, then:
#     GREP_GATE_REPORT_ONLY=1 (DEFAULT)  → report-only: EXIT 0 regardless of the count.
#     GREP_GATE_REPORT_ONLY=0            → hard gate: exit 1 if the debt > 0. Armed at Stage-A DoD.
#   --selftest                          Plant a fixture with a KNOWN parse target and a KNOWN
#                                       allowlisted homonym; prove the meter counts the first, not the second.
#   PLANE_NOUN_HITS_OUT=<path>          Optional: copy the raw distinct file:line hit list there.
#
# bash 3.2 + POSIX grep/awk, the same bare-runner posture as its siblings.
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# shellcheck source=scripts/plane-keys.sh
. "$(dirname "$0")/plane-keys.sh"

CORE_ROOT="crates/busbar-core/src"

# Resolve the four section nouns from each plane crate's DECLARED PlaneDecl.config_section — never a
# restated literal. `<key> -> crates/busbar-<key>/src`; read the `config_section: "<noun>",` line.
section_nouns() {
  local k dir declfile noun out=""
  for k in $PLANE_KEYS; do
    dir="crates/busbar-${k}/src"
    # The noun is read from the file that DECLARES the plane's `pub const PLANE_DECL`, never a test
    # fixture that restates a section_section for a different plane.
    declfile="$(grep -rlE 'pub const PLANE_DECL' "$dir" 2>/dev/null | grep -vE '/tests/|_tests?\.rs$' | head -1)"
    [ -n "$declfile" ] || continue
    noun="$(grep -hoE 'config_section:[[:space:]]*"[a-z_]+"' "$declfile" 2>/dev/null \
            | head -1 | sed -E 's/.*"([a-z_]+)".*/\1/')"
    [ -n "$noun" ] && out="${out:+$out }$noun"
  done
  printf '%s' "$out"
}

# Non-test .rs under core, EXCLUDING the frozen legacy migrator (past on-disk shapes, not live grammar).
core_files() {
  find "$CORE_ROOT" -name '*.rs' 2>/dev/null \
    | grep -vE '/tests/|_tests?\.rs$|/test_support/|/config/migrate' | sort
}

# THE COMMENT-STRIPPED CODE STREAM ("file:line:content"), so a noun in doc-comment prose is not a
# parse target. Same stripping shape as scripts/plane-noun-gate.sh's build_code_stream.
build_code_stream() {   # writes to $1
  local f
  while IFS= read -r f; do
    awk '
      { s=$0; sub(/^[ \t]+/,"",s) }
      s ~ /^\/\// || s ~ /^\*/ || s ~ /^\/\*/ { next }
      { printf "%s:%d:%s\n", FILENAME, FNR, $0 }
    ' "$f"
  done < <(core_files) > "$1"
}

# The SEAM + HOMONYM allowlist: a code line matching this is NEVER counted.
ALLOW_RE='config_section|owned_config_sections|config_sections_from|plane_decl_for_config_section|CORE_OWNED_CONCRETE_SECTIONS|allowed_pools|[a-z]_pools?|pool_[a-z]|[a-z]_pool'

# Scan one noun over a prepared code stream ($2), append distinct "file:line" hits to $3.
scan_noun() {   # $1 = noun ; $2 = code stream ; $3 = hits-out
  local noun="$1" code="$2" out="$3"
  # Cap-variant name for the two NamedMapSection plane sections (Tools/Agents). pools/streams have no
  # NamedMapSection variant, so their only parse targets are the bare literal / field forms.
  local cap
  cap="$(printf '%s' "$noun" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"

  # The code stream is already "file:line:content", so grep WITHOUT -n and take file:line as fields 1:2.
  # (1) NamedMapSection plane variant.
  grep -E "NamedMapSection::${cap}([^A-Za-z0-9_]|$)" "$code" 2>/dev/null \
    | grep -vE "$ALLOW_RE" | awk -F: '{print $1":"$2}' >> "$out"

  # (2) BARE quoted literal on a parse-steering line (match arm / get()/get_mut() / serde rename /
  #     DeployCfg named field). Word-bounded quote so `"tool_pools"` is not `"tools"`.
  grep -E "\"${noun}\"" "$code" 2>/dev/null \
    | grep -E '=>|get(_mut)?\(|rename|NamedMapSection|plane_section' \
    | grep -vE "$ALLOW_RE" | awk -F: '{print $1":"$2}' >> "$out"

  # (3) DeployCfg named-field declaration: `<vis> <noun>: <Type>` (a struct field bound to the noun).
  grep -E "(pub|pub\(crate\))?[[:space:]]*${noun}:[[:space:]]*[A-Z]" "$code" 2>/dev/null \
    | grep -vE "$ALLOW_RE" | awk -F: '{print $1":"$2}' >> "$out"
}

DEBT_TOTAL=0
run_report() {
  local nouns; nouns="$(section_nouns)"
  hdr "four-noun config-parse debt in busbar-core (report-only)"
  note "section nouns (from each PlaneDecl.config_section): $nouns"
  note "scanned root: $CORE_ROOT  (non-test, comment-stripped, frozen migrator excluded)"

  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  build_code_stream "$tmp/code"
  : >"$tmp/hits"

  hdr "per-noun parse-target lines"
  local n cnt
  for n in $nouns; do
    : >"$tmp/one"
    scan_noun "$n" "$tmp/code" "$tmp/one"
    sort -u "$tmp/one" >> "$tmp/hits"
    cnt="$(sort -u "$tmp/one" | grep -c . || true)"
    printf '  %-10s %6d\n' "$n" "$cnt"
  done

  DEBT_TOTAL="$(sort -u "$tmp/hits" | grep -c . || true)"

  hdr "files carrying a parse target"
  sort -u "$tmp/hits" | awk -F: '{f[$1]++} END{for(k in f) printf "%6d  %s\n", f[k], k}' \
    | sort -rn | sed 's/^/  /'

  sort -u "$tmp/hits" > "${PLANE_NOUN_HITS_OUT:-/dev/null}" 2>/dev/null || true
}

run_selftest() {
  hdr "plane-config-noun-gate SELF-TEST (the meter counts a parse target, not a homonym)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0

  # A fixture code stream: one KNOWN parse target per form, plus KNOWN allowlisted homonyms/seam.
  cat >"$tmp/code" <<'FIX'
fix.rs:1:            NamedMapSection::Tools => "tools",
fix.rs:2:    let Some(m) = root.get(Value::from("streams")) else { return };
fix.rs:3:    pub(crate) agents: NamedMap<AgentDef>,
fix.rs:4:    let grants = role.allowed_pools.clone();
fix.rs:5:    let fo = cfg.tool_pools.get(name);
fix.rs:6:    let sec = decl.config_section;
fix.rs:7:    // agents: this comment mentions agents but is prose
FIX
  : >"$tmp/hits"
  local n
  for n in tools agents pools streams; do scan_noun "$n" "$tmp/code" "$tmp/hits"; done
  sort -u "$tmp/hits" -o "$tmp/hits"

  # MUST count lines 1 (variant), 2 (get() literal), 3 (field decl).
  local ok=1 want
  for want in 1 2 3; do
    if grep -q ":${want}\$" "$tmp/hits"; then note "counted parse target on fixture line $want"; else ok=0; note "FAILED: parse target on line $want not counted"; fi
  done
  # MUST NOT count 4 (allowed_pools), 5 (tool_pools), 6 (config_section seam), 7 (comment — note the
  # fixture stream is pre-stripped so the caller drops comments; here line 7 is a code line that the
  # real build_code_stream would have dropped, but even present it names no parse-steering token).
  for want in 4 5 6; do
    if grep -q ":${want}\$" "$tmp/hits"; then ok=0; note "FAILED: allowlisted homonym/seam on line $want was counted"; else note "did NOT count allowlisted line $want"; fi
  done
  [ "$ok" -eq 1 ] || fail=1

  # The nouns must resolve from the real decls (not empty), or the gate would scan for nothing.
  local nouns; nouns="$(section_nouns)"
  local ncount; ncount="$(printf '%s' "$nouns" | wc -w | tr -d ' ')"
  if [ "$ncount" -ge 4 ]; then note "resolved $ncount section nouns from the plane decls: $nouns"; else fail=1; note "FAILED: only resolved $ncount section nouns ($nouns)"; fi

  if [ "$fail" -ne 0 ]; then red "plane-config-noun-gate SELF-TEST FAILED"; return 1; fi
  grn "plane-config-noun-gate self-test: ALL GREEN (counts parse targets, ignores homonyms/seam)"
  return 0
}

case "${1:-}" in
  --selftest) run_selftest; exit $? ;;
  --report | --check | "")
    run_report
    hdr "verdict"
    printf '  \033[1mFOUR-NOUN CONFIG-PARSE DEBT (distinct core parse-target lines): %s\033[0m\n' "$DEBT_TOTAL"
    report_only="${GREP_GATE_REPORT_ONLY:-1}"
    if [ "$DEBT_TOTAL" -eq 0 ]; then
      grn "plane-config-noun gate: CLEAN — core names no section noun as a parse target. Arm the hard gate."
      exit 0
    fi
    if [ "$report_only" = "0" ]; then
      red "plane-config-noun gate: FAIL — $DEBT_TOTAL section-noun parse target(s) in busbar-core."
      note "Evict each section onto the seam (owned_config_sections + config_sections_from); then this reaches 0."
      exit 1
    fi
    ylw "plane-config-noun gate: $DEBT_TOTAL parse target(s) — REPORT-ONLY (RED today, pre-Stage-A)."
    note "Stage A evicts the four sections onto the seam and drives this to 0. Set GREP_GATE_REPORT_ONLY=0 to arm."
    exit 0
    ;;
  -h | --help) sed -n '2,60p' "$0" ;;
  *) echo "usage: $0 [--report|--check|--selftest]   (env: GREP_GATE_REPORT_ONLY=1 default)" >&2; exit 2 ;;
esac
