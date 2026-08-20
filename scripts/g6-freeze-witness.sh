#!/usr/bin/env bash
# G6 freeze witness — the objective gate for "core names zero concrete LLM family type".
#
# The neutral-IR cutover (docs/design/1.6.0-neutral-ir.md) is complete for a family only when
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

CORE="crates/busbar-core/src"

# Concrete LLM-family IR types that MUST leave core (move to busbar-llm at the cutover). Whole-word
# matched. Excludes the neutral surface that STAYS: IrFacts, ContentItem, Slot, Shape, Operation,
# IrError (= breaker::CanonicalSignal alias), and the genuinely-neutral cross-plane IRs InvokeReq/
# InvokeResp/SubscribeReq/SubscribeResp (used by mcp+a2a per the 2+-planes decision rule).
TYPES=(
  IrRequest IrResponse IrMessage IrBlock IrBlockMeta IrRole IrTool IrToolChoice
  IrUsage IrUsageDetail IrDelta IrStreamEvent IrStopReason IrMediaKind IrCitation
  IrResponseFormat CacheControl CacheKind StreamDecodeState EgressPrep
  IrReq IrResp
  StreamTranslate StreamFraming JsonArrayFramer
  EmbeddingsReq EmbeddingsResp ModerationReq ModerationResp ImageReq ImageResp
  TranscriptionReq TranscriptionResp SpeechReq SpeechResp RerankReq RerankResp
)

# Build a single alternation, whole-word.
PAT="\\b($(IFS='|'; echo "${TYPES[*]}"))\\b"

verbose="${1:-}"

# Production only: exclude test modules and test files. We drop lines under a tests/ path, lines that
# are `#[cfg(test)]`, and comment-only mentions (a leading // or /// or * doc line carries no compile
# edge). rg is preferred; fall back to grep.
scan() {
  if command -v rg >/dev/null 2>&1; then
    rg -n --no-heading -e "$PAT" "$CORE" \
      -g '!**/tests/**' -g '!**/*_test.rs' -g '!**/test_support/**' 2>/dev/null || true
  else
    grep -rnE "$PAT" "$CORE" --include='*.rs' 2>/dev/null \
      | grep -v '/tests/' | grep -v '/test_support/' || true
  fi
}

# Strip comment-only lines (the code content before any // must contain the match).
hits="$(scan | awk -F: '{
  line = $0; sub(/^[^:]*:[^:]*:/, "", line);         # drop file:lineno:
  code = line; sub(/[[:space:]]*\/\/.*$/, "", code); # drop trailing line comment
  gsub(/^[[:space:]]+/, "", code);
  if (code ~ /^(\/\/|\/\*|\*)/) next;                # pure comment / doc line
  if (code == "") next;
  print $0;
}')"

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
