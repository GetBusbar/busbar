# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: gemini-live-route (the second-dialect route) — the Gemini Live dialect has a MOUNTED route, not just a codec.
#
# The spec-per-dialect and cross-parity legs already prove the Gemini Live codec is correct in
# isolation: wire<->IR round trips, and agreement with OpenAI Realtime where the cross-dialect map
# says the two must agree. Neither leg drives the MOUNT: `PLANE_DECL.wire_format_names` named
# `gemini_live` as a dialect the plane speaks, but `voice_claims` / `voice_ws_arrivals` named only the
# OpenAI base, so a caller had no ingress path to reach it at all — a real second dialect the plane
# could not actually serve.
#
# This leg judges the route, on the plane's own PUBLIC functions (the same ones the composition root
# and the core router call): the dispatch slot claims a Gemini-labelled base distinct from the OpenAI
# one, the plane still admits exactly one audience for both, a Gemini WS-accept arrival is declared
# and keyed to this plane's own slot, and — the wire handshake itself — a provider's `setupComplete`
# relays to the client verbatim through the EXACT `SessionCore<GeminiLiveCodec>` type the mounted
# route's `WsArrivalSpec` closure closes over.
#
# EVERY URL IS READ, NOT TYPED. The bases and mounts this leg compares against come off
# `busbar_plane_streams`'s declared `SURFACE` and off `busbar-voice`'s own `MOUNT_PATH`, never off a
# string in the harness — so the leg asserts that the legacy engine's mounted routes and the
# composition's declaration are THE SAME URLS, and goes red the moment either moves alone. A leg
# holding its own copy of a URL is a leg that keeps passing while the served surface changes, which
# is the one failure a conformance rig exists to make impossible.
#
# And ALL THREE declared mounts are checked, not just this leg's: the drift being judged does not
# announce which of the three legs it happened to, and a leg that checked only its own row would
# pass on a node whose carrier leg had quietly moved.
#
# WAS RED: no ingress route spoke Gemini Live at all.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(gemini-live-route)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
