# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: governance — the 5 vision checkpoints, observed at the streaming plane's DOOR (linked AND
# dropped). NOT A CONFORMANCE RESULT: the runner keeps a governance FAIL out of the conformance verdict
# (proven by `--selftest`), exactly as testing/a2a-governance/ can never move the A2A verdict.
#
#   V1-barge-in-preemption      a far-end speech_started cancels the response and truncates the item at
#                               the ms the caller heard, upstream, and tells the caller.
#   V2-turn-budget-enforcement  a session past `streams.session_max_secs` is told why (session_expired)
#                               and ended once, on the kernel's tick clock.
#   V3-metering-lease-settled   a turn's usage settles exactly once (a short answer's re-call reports
#                               the same cumulative units; the end adds nothing settled).
#   V4-dialect-downscope        an OpenAI-only semantic_vad/g711 concept is down-scoped toward Gemini
#                               (codec), and the caller's session.update never reaches the far end:
#                               the locked session params do (door).
#   D2-hard-close-on-exhaustion once a session has ended no far-end audio reaches the caller and the cut
#                               renders in the dialect's error shape; reading the chain dry and cutting
#                               are the kernel's.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=governance
LEG_STATUS=ready
LEG_SLICES=(V1-barge-in-preemption V2-turn-budget-enforcement V3-metering-lease-settled V4-dialect-downscope D2-hard-close-on-exhaustion)

leg_execute() {
  local checkpoint="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $checkpoint FAIL harness build failed"; return 0; }
  "$bin" governance "$checkpoint"
}
