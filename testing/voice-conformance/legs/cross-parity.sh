# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
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
# STATUS: pending. DROP-IN: flip LEG_STATUS to `ready` and implement `leg_execute` to run the pair
# named by the slice and emit one RESULT line per mapped behaviour.

LEG_KIND=conformance
LEG_STATUS=pending
LEG_SLICES=(oo og go gg)

leg_execute() {
  local pair="$1"
  # DROP-IN: resolve $pair (oo/og/go/gg) to (from,to) dialects, drive the pair, and check each
  # behaviour the cross-dialect mapping marks equivalent:
  #   echo "RESULT $pair PASS <behaviour-id>"
  #   echo "RESULT $pair FAIL <behaviour-id> — <from> and <to> disagree"
  die "cross-parity[$pair]: not implemented — no cross-dialect mapping consumed / no runtime yet (scaffold)"
}
