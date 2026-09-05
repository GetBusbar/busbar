# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: provider-dial (K5) — a session actually DIALS the composed provider; the WS legs' upstream dial
# is no longer uncomposed.
#
# `topology::dial_provider` has existed since K1: breaker-admitted, net-guarded, counted on the shared
# upstream-attempt family. But nothing in the mounted routes called it — the telephony and Gemini WS
# accepts served the client socket only, discarding the uplink into a channel with no receiver, so no
# conformance leg (and no real deployment) ever drove a live provider socket end to end.
#
# This leg proves the wiring, not just the library function: it stands up a tiny loopback WS
# "provider" (no network, no vendor credential — a stand-in exactly as the shadow-oracle's mock
# upstream stands in for a real one), dials it through `dial_provider`'s own net-guarded path, feeds
# the frame it sends through the SAME `SessionCore` type the mounted routes open, and asserts the
# session's D2 metering lease actually settles the usage that arrived over that live socket — not a
# fixture, a socket.
#
# WAS RED: `topology::dial_provider` existed and passed its own unit tests in isolation, but no leg (and
# no mounted route) ever called it, so "the dial exists" and "a session dials it" were different, unproven
# claims.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(provider-dial)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
