# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: provider-dial — a session's far end is reached through the HOST CONNECTOR, never by the plane
# (Law 3; ARCHITECT Q128).
#
# THE DOOR'S HALF (judged, linked AND dropped door): a session's far frames name the dialect's socket
# under the member's base URL (`GET /v1/realtime`, the Gemini BidiGenerateContent path) on the declared
# need they ride (door::RIDES_REALTIME_SOCKET / RIDES_LIVE_SOCKET), and the usage the far end sends over
# that socket is reported as units. The plane opens no socket and holds no guard (its closure is
# contract + codecs: tests/purity.rs); the net guard, TLS and the upgrade are the connector's. RED arm:
# a socket frame that names the one-shot pass need fails.

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
