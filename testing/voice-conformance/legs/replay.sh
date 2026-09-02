# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# LEG: replay — captured-transcript replay.
#
# A recorded voice session (a captured transcript under
# testing/voice-conformance/fixtures/{openai,gemini}/) must re-derive IDENTICALLY when replayed
# through busbar's voice plane: same turn boundaries, same tool invocations, same barge-in points,
# same settlement. Replay is the leg that catches a change which passes the live spec but silently
# alters behaviour a real caller already depended on — the regression a spec-only battery cannot see.
#
# STATUS: pending. The runtime and the captured transcripts do not exist yet. DROP-IN: flip
# LEG_STATUS to `ready` and implement `leg_execute` to replay each captured transcript and emit one
# RESULT line per transcript (PASS when the re-derivation matches byte-for-byte, FAIL with the first
# divergence otherwise).

LEG_KIND=conformance
LEG_STATUS=pending
LEG_SLICES=(default)

leg_execute() {
  local slice="$1"
  # DROP-IN: for each captured transcript, replay it and diff the derivation:
  #   echo "RESULT $slice PASS <transcript-id>"
  #   echo "RESULT $slice FAIL <transcript-id> — diverged at <turn>"
  die "replay[$slice]: not implemented — no captured transcripts / no runtime yet (scaffold)"
}
