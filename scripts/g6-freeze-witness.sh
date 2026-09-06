#!/usr/bin/env bash
# G6 freeze witness — the objective gate for "core names zero concrete LLM family type".
#
# The neutral-IR cutover is complete for a family only when
# busbar-core's PRODUCTION code references none of that family's concrete IR types — core reads the
# request only through the neutral projection (IrFacts / RouteView / TokenUsage) and drives translation
# through the plugin vtable. This script counts the remaining concrete-family references so the number
# can be driven to 0 and kept there.
#
# Round-2 review finding D6: the first-draft grep (IrRequest|IrResponse|IrBlock|IrStreamEvent|
# StreamDecodeState|EgressPrep) read GREEN while core still named IrUsage 11x. This is the broadened set.
#
# Usage: scripts/g6-freeze-witness.sh            # summary + per-type counts
#        scripts/g6-freeze-witness.sh -v         # also print every offending file:line
#
# Exit 0 iff the count is 0 (the freeze condition). Non-zero = work remaining.

set -euo pipefail
cd "$(dirname "$0")/.."

# The one input this witness has. Overridable so --selftest can drive the REAL scanner over fixture
# trees rather than a copy of it.
CORE="${G6_CORE:-crates/busbar-core/src}"

# Concrete LLM-family IR types that MUST leave core (move to busbar-llm at the cutover). Whole-word
# matched. Excludes the neutral surface that STAYS: IrFacts, ContentItem, Slot, Shape, Operation,
# IrError (= breaker::CanonicalSignal alias), and the genuinely-neutral cross-plane IRs InvokeReq/
# InvokeResp/SubscribeReq/SubscribeResp (used by mcp+a2a per the 2+-planes decision rule).
#
# EgressPrep excluded — provably neutral (an all-primitives resolved-param bag the engine hands a
# handle's `prepare_for_egress`; it names NO concrete IR), design-(b) retained in core (`ir::egress_prep`);
# it is not a concrete-IR family type (cf. the A0 exclusions of IrError/Slot/Shape). It was counted in
# the round-2 broadened set before the dissolve resolved which side of the seam it lands on; the A4b
# dissolve places it neutral-in-core, so counting it would conflate a neutral param bag with the LLM
# families and hold the freeze open on a type that correctly stays.
#
# The `IrReq`/`IrResp` hub enums are NOT listed: they do not relocate as a family — they DISSOLVE into
# a neutral core-owned opaque handle plus the core-owned invoke/subscribe leaves. Counting them here
# conflates "enum dissolved" with "concrete family named" and inflates the count while it still exists,
# masking per-leaf progress; their removal is asserted by a separate structural check.
TYPES=(
  IrRequest IrResponse IrMessage IrBlock IrBlockMeta IrRole IrTool IrToolChoice
  IrUsage IrUsageDetail IrDelta IrStreamEvent IrStopReason IrMediaKind IrCitation
  IrResponseFormat CacheControl CacheKind StreamDecodeState
  IrImageSource IrReasoningAsk IrReasoningEffort IrTokenLogprob IrTopLogprob
  StreamTranslate StreamFraming JsonArrayFramer
  EmbeddingsReq EmbeddingsResp ModerationReq ModerationResp ImageReq ImageResp
  TranscriptionReq TranscriptionResp SpeechReq SpeechResp RerankReq RerankResp
)

# Build a single alternation, whole-word.
PAT="\\b($(IFS='|'; echo "${TYPES[*]}"))\\b"

verbose="${1:-}"

# ── NOTHING TO SCAN IS NOT NOTHING FOUND ──────────────────────────────────────────────────────────
# This witness reports FREEZE MET when its count is 0, and every path to a zero count used to look
# alike. `rg … 2>/dev/null || true` and `grep -r … 2>/dev/null || true` both swallow the diagnostic
# AND the status, so a `$CORE` that was renamed, split or emptied produced no lines, a count of 0,
# and the headline "FREEZE MET — core names zero concrete LLM-family IR type" about a directory this
# script never opened. The freeze is the most consequential claim in the file; it may not be reached
# by accident. So the input is proven first, and separately from what was found in it.
prod_rs_count() {
  find "$CORE" -name '*.rs' 2>/dev/null \
    | grep -v '/tests/' | grep -v '/test_support/' | grep -Ev '_tests?\.rs$' \
    | grep -c . || true
}

require_subject() {
  if [ ! -d "$CORE" ]; then
    echo "── G6 freeze witness ──────────────────────────────────────────────"
    echo "RED — the scan root '$CORE' is not a directory."
    echo "  Nothing was read. A witness that read nothing has not witnessed a freeze; if core moved,"
    echo "  point CORE at its new home in a reviewed diff that says so."
    exit 2
  fi
  local n; n="$(prod_rs_count)"
  if [ "$n" -eq 0 ]; then
    echo "── G6 freeze witness ──────────────────────────────────────────────"
    echo "RED — '$CORE' holds no production .rs file."
    echo "  A scan of zero files names zero concrete types, which is indistinguishable from a met"
    echo "  freeze. Fix the root rather than declaring victory over an empty list."
    exit 2
  fi
}

# Production only: exclude test modules and test files. We drop lines under a tests/ path, lines that
# are `#[cfg(test)]`, and comment-only mentions (a leading // or /// or * doc line carries no compile
# edge). rg is preferred; fall back to grep.
# `|| true` is kept ONLY for the "no match" status (rg and grep both exit 1 on zero matches, which is
# a legitimate answer here). Exit 2 — a bad pattern, an unreadable tree — is a scanner that did not
# run, and is re-raised rather than folded into the empty result that means FREEZE MET.
scan() {
  local rc=0
  if command -v rg >/dev/null 2>&1; then
    rg -n --no-heading -e "$PAT" "$CORE" \
      -g '!**/tests/**' -g '!**/*_test.rs' -g '!**/test_support/**' || rc=$?
  else
    grep -rnE "$PAT" "$CORE" --include='*.rs' \
      | grep -v '/tests/' | grep -v '/test_support/' || rc=$?
  fi
  [ "$rc" -le 1 ] && return 0
  echo "g6-freeze-witness: the scanner exited $rc over '$CORE'; an aborted scan finds nothing, and" >&2
  echo "  finding nothing is this witness's FREEZE MET. RED." >&2
  return "$rc"
}

count_hits() {   # the hit lines for the current $CORE, comment-only mentions removed
  scan | awk -F: '{
  line = $0; sub(/^[^:]*:[^:]*:/, "", line);         # drop file:lineno:
  code = line; sub(/[[:space:]]*\/\/.*$/, "", code); # drop trailing line comment
  gsub(/^[[:space:]]+/, "", code);
  if (code ~ /^(\/\/|\/\*|\*)/) next;                # pure comment / doc line
  if (code == "") next;
  print $0;
}'
}

# ── SELF-TEST — a witness that can report FREEZE MET must prove it can also report the opposite ────
# Drives the REAL `scan`/`count_hits` over fixture trees by pointing $CORE at them, which is the only
# reason it proves anything about the run above.
run_selftest() {
  local fails=0 cases=0 out rc
  # NOT `local`: the EXIT trap fires after this function's frame is gone, and under `set -u` a trap
  # that cannot read the path it is meant to delete does not even run.
  G6_SELFTEST_TMP="$(mktemp -d)"; trap 'rm -rf "$G6_SELFTEST_TMP"' EXIT
  local tmp="$G6_SELFTEST_TMP"
  say() { printf '%s  %s\n' "$1" "$2"; cases=$((cases + 1)); [ "$1" = PASS ] || fails=$((fails + 1)); }
  echo "== G6 freeze witness SELF-TEST =="

  mkdir -p "$tmp/dirty" "$tmp/clean" "$tmp/commented" "$tmp/empty"
  printf 'pub fn f(u: &IrUsage) -> u64 { u.total }\n' >"$tmp/dirty/lib.rs"
  printf 'pub fn f(u: &IrFacts) -> u64 { u.total }\n' >"$tmp/clean/lib.rs"
  printf '// core must never name IrUsage again; see G6.\npub fn f() {}\n' >"$tmp/commented/lib.rs"

  out="$(CORE="$tmp/dirty" count_hits)" || true
  [ "$(printf '%s' "$out" | grep -c . || true)" -eq 1 ] \
    && say PASS "a concrete family type in production source is counted" \
    || say FAIL "dirty fixture counted [$out]"

  out="$(CORE="$tmp/clean" count_hits)" || true
  [ "$(printf '%s' "$out" | grep -c . || true)" -eq 0 ] \
    && say PASS "the neutral projection is not counted" \
    || say FAIL "clean fixture counted [$out]"

  out="$(CORE="$tmp/commented" count_hits)" || true
  [ "$(printf '%s' "$out" | grep -c . || true)" -eq 0 ] \
    && say PASS "a comment-only mention is not counted" \
    || say FAIL "commented fixture counted [$out]"

  # THE TWO WAYS THIS WITNESS USED TO DECLARE THE FREEZE MET HAVING READ NOTHING. Both are run
  # through the whole script, not through `require_subject` alone, because the bug was that the
  # headline was reached at all.
  rc=0; ( G6_CORE="$tmp/no-such-root" bash "$0" ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 2 ] && say PASS "a scan root that is not a directory is RED, not FREEZE MET" \
    || say FAIL "missing root exited $rc (wanted 2)"
  rc=0; ( G6_CORE="$tmp/empty" bash "$0" ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 2 ] && say PASS "a root holding no production .rs is RED, not FREEZE MET" \
    || say FAIL "empty root exited $rc (wanted 2)"
  # And the real root still clears both guards, so the two reds are not a witness that refuses
  # everything.
  rc=0; ( require_subject ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 0 ] && say PASS "this tree's own core root clears both guards" \
    || say FAIL "require_subject refused the real root (exit $rc)"

  echo
  [ "$fails" -eq 0 ] && { echo "g6-freeze-witness selftest: GREEN (${cases} cases)"; return 0; }
  echo "g6-freeze-witness selftest: RED (${fails}/${cases} cases failed)"; return 1
}

if [ "$verbose" = "--selftest" ]; then run_selftest; exit $?; fi

require_subject

# Strip comment-only lines (the code content before any // must contain the match) — one copy of
# that rule, in count_hits, so the self-test drives the same scanner this line does.
hits="$(count_hits)"

count="$(printf '%s' "$hits" | grep -c . || true)"
# Split: the ir/ module DEFINES the concrete types and moves to busbar-llm as a unit at the cutover;
# everything OUTSIDE ir/ is a consumer up-ref that must invert onto the neutral projection or relocate.
defs="$(printf '%s\n' "$hits" | grep -c "^$CORE/ir/" || true)"
uprefs=$((count - defs))

echo "── G6 freeze witness ──────────────────────────────────────────────"
echo "core production references to concrete LLM-family IR types: $count"
echo "  ├─ in ir/ (definitions — move to busbar-llm as a unit):    $defs"
echo "  └─ OUTSIDE ir/ (consumer up-refs — invert or relocate):    $uprefs"
echo
if [ "$count" -ne 0 ]; then
  echo "by type:"
  for t in "${TYPES[@]}"; do
    c="$(printf '%s\n' "$hits" | grep -cE "\\b$t\\b" || true)"
    [ "$c" -ne 0 ] && printf '  %-22s %s\n' "$t" "$c"
  done
  echo
  echo "by file (top 15):"
  printf '%s\n' "$hits" | awk -F: '{print $1}' | sort | uniq -c | sort -rn | head -15
  if [ "$verbose" = "-v" ]; then
    echo
    echo "all offending sites:"
    printf '%s\n' "$hits"
  fi
  echo
  echo "FREEZE NOT MET — $count concrete-family references remain in core."
  exit 1
fi
echo "FREEZE MET — core names zero concrete LLM-family IR type."
