# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: cross-parity — the 4 ORDERED OpenAI<->Gemini pairs.
#
# The cross-dialect mapping (docs/design/voice-cross-dialect-mapping.*, authored by another agent)
# declares which behaviours MUST be equivalent across the two dialects. This leg drives all four
# ORDERED pairs and asserts the mapping holds in each direction:
#
#   oo  openai  -> openai   (self-parity: the mapping must be identity within a dialect)
#   og  openai  -> gemini   (a session captured on openai, re-derived under gemini, must map)
#   go  gemini  -> openai
#   gg  gemini  -> gemini
#
# Both diagonal pairs (oo, gg) are ordered slices in their own right, not skipped: a mapping that is
# not identity within a dialect is already broken, and only running the cross pairs would never see
# it. That is the cross-parity analogue of the sibling batteries' "a control that exercises a
# different path from the subject proves less than it appears to".
#
# STATUS: ready. Each ordered pair is driven as read(A) → shared IR → write(B) → IR against the
# machine-readable `docs/design/voice-cross-dialect-map.json`. For every SHARED concept the map
# declares, the load-bearing fields must survive the bridge (compared on a correlation-collapsed
# fingerprint, so a streamed⟷atomic tool-call reframing counts as agreement, and documented
# non-survivors — text modality, VAD specifics, truncate ms — are excluded per the map). And EVERY
# row of the asymmetry table is exercised as a documented drop+warn in its origin→other direction, so
# a one-dialect-only concept is accounted for, never silently lost. Concepts whose source-dialect
# fixture cannot decode (the one genuine codec gap, or a documented drop) are printed as PENDING
# sub-items, never faked green.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(oo og go gg)

leg_execute() {
  local pair="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $pair FAIL harness build failed"; return 0; }
  "$bin" cross "$pair" "$VC_FIXTURES/openai" "$VC_FIXTURES/gemini" "$VC_MAP"
}
