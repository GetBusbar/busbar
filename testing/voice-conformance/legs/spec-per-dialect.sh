# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: spec-per-dialect — the voice conformance spec, run once PER DIALECT (openai, gemini, twilio).
#
# Every captured fixture in `testing/voice-conformance/fixtures/$dialect/`:
#   * READ: the harness's own reader of the dialect's wire (ARCHITECT ruling R-18: a black-box rig
#     never calls the plane's codec) places it as a caller or a far-end frame; a fixture it reads as
#     neither passes only as a documented drop. The codec round trip (wire → IR → wire → IR) is the
#     plane's own test (`every_corpus_fixture_round_trips_to_an_ir_fixpoint`);
#   * DOOR: pushed through a live session on the dialect's door (the caller's frames as caller pieces,
#     the far end's as far-end pieces), linked AND dropped; the door must relay it by the session rules
#     (Law 5: byte for byte, a documented drop relayed to the caller unchanged like every far-end
#     frame; a frame configuring the session or asking for a response held to the lock at the JSON
#     level), every far frame on the dialect's socket need, the far end's tokens reported as units.
#     RED arms per fixture: a door reporting a token never sent, re-encoding a frame, or dropping one
#     fails.
#   * TWILIO (`fixtures/twilio/`, Twilio's published Media Streams messages, one file per message in
#     each direction, `from-twilio.*` and `to-twilio.*`): the read half is the harness's reading of
#     Twilio's published formats (`event`-tagged); the door half pushes Twilio's frames as caller pieces and the
#     far-end event that makes the door write a Twilio frame as far-end pieces, and holds the door to
#     Twilio's shapes (`start` locks the far end in µ-law, media to the far end as caller audio, the
#     far end's audio as `media`, a barge-in as `clear`; every far-bound frame is judged, and the end
#     of the far end's audio sends the far end nothing, what the caller is told for it being fixed by
#     no spec line); `transcript.jsonl` is one whole call. RED arm: a door handing the far end audio
#     nobody sent fails.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(openai gemini twilio)

leg_execute() {
  local dialect="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $dialect FAIL harness build failed"; return 0; }
  "$bin" spec "$dialect" "$VC_FIXTURES/$dialect"
}
