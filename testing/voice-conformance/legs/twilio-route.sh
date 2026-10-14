# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: twilio-route — Twilio is a dialect over the ws transport, claimed on a one-level `/twilio`
# prefix, authenticated by the webhook signature alone (BUSBAR-1.6.0.md l.418-419, l.847-852; Twilio's
# Media Streams messages: https://www.twilio.com/docs/voice/media-streams/websocket-messages).
#
# THE DOOR'S HALF (judged, linked AND dropped door): the plane's Twilio claim is on the `ws` transport
# at the one-level `/twilio` prefix (`/twilio/{id}` names the dialect; `/twilio`, `/twilio/a/b` and
# `/twiliofoo` name nothing) with `webhook-signature` as its ONLY scheme alternative; the snapshot
# claims `GET /twilio/{call_id}` as an upgrade line refused in Twilio's dialect, under the
# webhook-signature inbound need no other door shares; `arrive` on it asks for a principal on the
# session model's DIRECT route in the twilio-media-streams dialect; and the session opens on the
# `event`-tagged `start` frame: audio before it reaches the far end as nothing, audio after it reaches
# the far end, audio for another call's streamSid does not, and an OpenAI `type`-tagged frame is not
# taken for Twilio audio. RED arm: a claim that admits a bearer where the signature belongs fails.
#
# THE KERNEL'S HALF: the boot admitting the claim (overlap check, scheme registry), a missing
# `X-Twilio-Signature` being 401 end to end, and the HMAC-SHA1 verify itself
# (busbar-auth-webhook-signature, variant twilio; Twilio carries no replay rule).

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(twilio-route)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" twilio "$slice" "$VC_FIXTURES/twilio"
}
