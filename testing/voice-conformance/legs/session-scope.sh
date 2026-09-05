# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: session-scope — the plane's one declared scope kind is a gate, not vocabulary.
#
# Holding a key that is valid for the voice door's AUDIENCE is not the same as being GRANTED a session
# on it: the audience check answers "is this token for this door", the grant answers "may this caller
# walk through it". The plane declares a `session` scope kind, which is what an operator's
# `allowed_scopes: [{ kind: session, value: … }]` entry validates against, and this leg judges that
# the door actually asks the question — the way MCP double-gates a tool and A2A gates an agent.
#
# The whole grant semantic is judged, not just the happy path: a key with no scope list at all is the
# store's wildcard and is granted every kind; a key with an explicit list must carry the session grant
# for this voice pool, so a model-plane key, a session grant aimed at another pool, and an empty list
# are all refused.
#
# WAS RED: any key valid for the plane's audience opened a session, and the declared scope kind was
# vocabulary nothing consulted.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(session-scope)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
