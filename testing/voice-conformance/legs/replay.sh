# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: replay — captured-transcript replay.
#
# A recorded voice session (a captured transcript under
# testing/voice-conformance/fixtures/{openai,gemini}/) must re-derive IDENTICALLY when replayed
# through busbar's voice plane: same turn boundaries, same tool invocations, same barge-in points,
# same settlement. Replay is the leg that catches a change which passes the live spec but silently
# alters behaviour a real caller already depended on — the regression a spec-only battery cannot see.
#
# STATUS: ready. Each dialect's captured `transcript.jsonl` golden is driven through the real codec —
# threading ONE session `DecodeState`, honoring each line's `dir` (client → uplink, server →
# downlink) — and the decoded IR must re-derive the expected ordered concept skeleton
# (config → connect → audio → tool call → tool result → audio → barge-in → close/complete) with no
# load-bearing drop, and every decoded frame must re-encode to valid wire JSON. The Gemini uplink
# `realtimeInput.audio{}` frames the shipped codec does not read are recorded as a documented replay
# sub-item (the openai→gemini bridge still exercises that concept in cross-parity).

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(default)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" replay "$VC_FIXTURES"
}
