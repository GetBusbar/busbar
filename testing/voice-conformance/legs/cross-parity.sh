# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: cross-parity — the 4 ORDERED OpenAI<->Gemini pairs (oo, og, go, gg).
#
# For every shared concept of the machine-readable `qa/evidence/voice-cross-dialect-map.json`:
#   * DOOR: B's own fixtures of the concept are pushed through one live session on the door that
#     speaks B, on the linked AND the dropped door (ARCHITECT ruling R-18: the door half pushes
#     per-concept fixtures), and what the door relays must equal the session rules (a caller frame
#     reaches the far end as sent, a frame configuring the session or asking for a response held to
#     the lock at the JSON level; a far-end frame reaches the caller as sent, its usage also reported
#     as units; nothing goes to the far end on the caller's behalf). RED arms per concept: a door
#     reporting a token the far end never sent, re-encoding a frame, or dropping one fails.
# The bridge A → IR → B → IR and every asymmetry row are the plane's codec half, its own test
# (`every_shared_concept_survives_the_cross_dialect_bridge`): the harness reads the wire itself and
# never calls the plane's codec. A concept B carries no fixture of prints a SUBITEM PENDING line,
# never a pass.

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
