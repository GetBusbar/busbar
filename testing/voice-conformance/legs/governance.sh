# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: governance — the 5 vision checkpoints. NOT A CONFORMANCE RESULT.
#
# This leg observes busbar's voice PRODUCT POLICY, not the voice PROTOCOL. Exactly as
# testing/a2a-governance/ can never contribute to the A2A conformance verdict — a perfectly
# conformant agent that ignores every budget scores 100% on conformance — this leg's findings are
# OBSERVATIONS. The runner enforces the separation in code: a governance leg that FAILs cannot move
# the conformance verdict, and `--selftest` proves that separation bites.
#
# THE 5 VISION CHECKPOINTS (scaffolded; the real assertions and their fixtures are authored
# elsewhere — this file only fixes their names and order):
#
#   V1-barge-in-preemption      a caller barge-in must preempt the in-flight turn within budget.
#   V2-turn-budget-enforcement  a turn that overruns its token/time budget must be bounded.
#   V3-metering-lease-settled   every turn's metering lease (cost_reserve/cost_settle — the D2 host
#                               seam this battery's base commit wired) must settle; none may leak.
#   V4-dialect-downscope        crossing the OpenAI<->Gemini boundary must down-scope, never widen,
#                               what the far dialect is permitted to see.
#   D2-hard-close-on-exhaustion the D2 checkpoint: on budget/lease exhaustion the session must HARD
#                               CLOSE, not degrade open. A soft-degrade here is the exact failure D2
#                               exists to forbid.
#
# STATUS: ready. Each checkpoint is probed over the REAL T2 runtime (feature `runtime`) and recorded
# as an OBSERVATION — the runner records these but never lets a governance finding move the
# conformance verdict (proven by `--selftest`). The load-bearing one is D2-hard-close-on-exhaustion:
# it settles a real `LocalLease` past its cap and asserts the carrier HARD-closes (response.cancel
# upstream, no post-close audio reaches the client), reusing the runtime's actual exhaustion path.

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
