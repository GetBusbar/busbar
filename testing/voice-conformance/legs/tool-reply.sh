# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: tool-reply — a call the node does not serve is answered by the client, through the governed wait.
#
# The tool moat has two halves and only one of them was reachable from a served session. A call for a
# tool the node itself serves executes in-process and the client can neither see nor forge its result;
# that half is unchanged and is not what this leg judges. The other half is a call the node does NOT
# serve: the answer can only come from the client, so the call's leg is a WAIT the composition root
# enters when it plans the leg, and something on the socket has to be able to end it.
#
# Three facts, driven through a REAL session core on EVERY duplex dialect the plane serves (OpenAI
# Realtime and Gemini Live — one runtime, two codecs, which is the point of the neutral IR):
#
#   * the wake — the client's `function_call_output` (Gemini: `toolResponse.functionResponses`) goes to
#     the node's table FIRST and reaches the model only because the wait was woken;
#   * the refusal — a reply naming a call nobody is waiting on is refused by identifier and carried on
#     no wire at all, rather than paid out against whichever call happens to be standing;
#   * the sweep — the tick beside the pump ends a call nobody answered, so its unit exits under the
#     deadline its leg declared rather than settling as though the answer had arrived.
#
# WAS RED: the runtime executed every tool call in-process and carried a client-authored result
# upstream verbatim, so on the served path the wait was entered and then nothing ever woke it and
# nothing ever swept it. A client that never replied held the call's hold open forever, and a forged
# reply rode upstream under whatever call was open.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(tool-reply)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
