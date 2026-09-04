#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# duplex-ws-default-edge.sh — THE MONEY-PATH WS-EDGE DEP-CLOSURE GATE.
#
# WHY THIS EXISTS:
#   The inbound WS-accept seam names `axum::extract::ws::WebSocketUpgrade` ONLY under the neutral
#   `duplex-ws` (busbar-core) / `runtime` (busbar-substrate) features, which pull `axum/ws` and hence
#   `tokio-tungstenite` + `sha1` + `base64`. The DEFAULT/shipped money-path build enables NONE of
#   those, so its compiled dependency closure must carry NO `tokio-tungstenite` — the invariant that
#   keeps the LLM money path byte-identical and voice strong-form deletable. A future edit that welds
#   `axum/ws` onto a default-on feature (or makes an always-compiled type name a WS type) silently
#   breaks it; this gate fails RED the moment it does.
#
# WHAT IT ASSERTS (feature-resolved, via `cargo tree`, not a lockfile presence scan):
#   THE MONEY PATH (busbar-core, the LLM completion codepath) carries NO WS edge, in any config:
#   1. busbar-core, DEFAULT features            → NO tokio-tungstenite
#   2. busbar-core, --no-default-features       → NO tokio-tungstenite
#   VOICE IS ARMED DEFAULT-ON + DELETABLE: the shipped binary ships the edge WITH the voice plane, and
#   removing the plane (`--no-default`) removes the whole edge (strong-form deletable):
#   3. busbar (shipped binary), DEFAULT features→ tokio-tungstenite IS present (voice armed default-on)
#   4. busbar (shipped binary), --no-default    → NO tokio-tungstenite (the edge disappears with voice)
#   POSITIVE CONTROL:
#   5. busbar --features plane-voice            → tokio-tungstenite IS present (the edge is the voice plane's)
#
# No deps beyond bash + cargo — the bare-runner posture of the sibling lints.
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

WS_CRATE="tokio-tungstenite"
fail=0

# Count matches of the WS edge in a crate's feature-resolved, dev-excluded dependency tree.
edge_count() { cargo tree -e no-dev "$@" -f "{p}" 2>/dev/null | grep -c "$WS_CRATE"; }

assert_absent() {
  local label="$1"; shift
  local n; n="$(edge_count "$@")"
  if [ "$n" -eq 0 ]; then
    grn "  ok — no $WS_CRATE in: $label"
  else
    red "  FAIL — $WS_CRATE present ($n) in the WS-free build: $label"
    fail=1
  fi
}

assert_present() {
  local label="$1"; shift
  local n; n="$(edge_count "$@")"
  if [ "$n" -ge 1 ]; then
    grn "  ok — $WS_CRATE present (positive control): $label"
  else
    red "  FAIL — $WS_CRATE MISSING where the WS edge must exist: $label"
    fail=1
  fi
}

printf '\n== duplex-ws default-edge gate: the money-path build carries no WS edge ==\n'
assert_absent "busbar-core (default, money path)"   -p busbar-core
assert_absent "busbar-core (--no-default)"           -p busbar-core --no-default-features
assert_present "busbar (default / shipped, voice armed default-on)" -p busbar
assert_absent "busbar (--no-default, voice removed)" -p busbar --no-default-features
assert_present "busbar (--features plane-voice)"     -p busbar --features plane-voice

printf '\n== verdict ==\n'
if [ "$fail" -eq 0 ]; then
  grn "duplex-ws default-edge gate: PASS — no tokio-tungstenite in the default money-path build; the WS edge is confined to plane-voice"
  exit 0
else
  red "duplex-ws default-edge gate: FAIL — the WS edge leaked into a build that must not carry it"
  exit 1
fi
