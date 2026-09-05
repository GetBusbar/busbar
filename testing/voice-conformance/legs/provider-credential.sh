# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: provider-credential — a MOUNTED voice door can actually reach a realtime provider.
#
# The plane's two one-shot HTTP passes (the browser `ek_` mint and the SDP broker) are governed and
# audience-checked whether or not a provider is composed — so "governed" is not the same claim as
# "serves". This leg judges the second: the composition root hands the plane the provider ORIGIN and
# the secret REFERENCE the deployment's own provider catalog declares for it, the plane resolves that
# reference through the deployment's ordinary secret resolver, and the mint / SDP passes serve under
# the resulting credential instead of reporting that there is nothing to dial.
#
# It also judges the two ways this must fail: a reference that does not resolve composes NOTHING (an
# unresolvable credential must never become an empty one), and the endpoint is set-once, so nothing
# later in the process can silently swap a deployment's realtime credential.
#
# WAS RED: nothing composed a provider on any deployment, so both passes answered "governed, but no
# provider credential composed" and the plane's real key had no way in.

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
