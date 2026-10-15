# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: provider-credential — the plane never holds the realtime provider's credential.
#
# THE DOOR'S HALF (judged, linked AND dropped door): every far request the door answers — the mint,
# the SDP offer, the sideband socket and the Gemini socket — names the declared OUTBOUND need it rides,
# under the auth style the kernel binds the provider credential to (`bearer` for OpenAI Realtime,
# `x-goog-api-key` for Gemini Live) and with the member's address, never a plane config path; no
# request carries a credential field, and the caller is named only by the kernel's opaque reference.
# RED arm: a mint that carries the caller's `Authorization` fails.
#
# THE COMPOSITION ROOT'S HALF (not the door's): resolving the catalog's secret reference through the
# deployment's resolver, set-once, an unresolvable reference composing nothing.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(provider-credential)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
