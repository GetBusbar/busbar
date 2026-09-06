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

# ── A TREE THAT WAS NEVER RESOLVED IS NOT A TREE WITHOUT THE EDGE ─────────────────────────────────
# `cargo tree … 2>/dev/null | grep -c` folded four different things into the number 0: the edge is
# absent (the answer this gate wants), cargo is not installed, the feature name in the argument list
# no longer exists, and the workspace does not build. The three failures all printed "ok — no
# tokio-tungstenite" — this gate's PASS — with the diagnostic already discarded. `-p busbar-voice`
# after a crate rename is not a hypothetical; it is the ordinary way this file rots.
#
# So the resolve is separated from the count. `edge_tree` writes the resolved tree to $1 and returns
# cargo's status; a non-zero status, or a tree with no lines in it, is UNRESOLVED and RED for both
# directions of assertion — the absence case as much as the presence case, because "absent" is the
# claim an unresolved tree fakes.
edge_tree() {   # $1 = out file ; rest = cargo tree args
  local out="$1"; shift
  local rc=0
  cargo tree -e no-dev "$@" -f "{p}" >"$out" 2>"$out.err" || rc=$?
  [ "$rc" -eq 0 ] || return "$rc"
  [ -s "$out" ] || return 90     # resolved "successfully" and named no package at all
  return 0
}

# Prints the failure reason cargo gave, so a rotted argument list is one line to read.
tree_why() { [ -s "$1.err" ] && sed 's/^/      /' "$1.err" | tail -3 || echo "      (no output)"; }

unresolved() {
  local label="$1" out="$2" rc="$3"
  red "  FAIL — could not resolve the dependency tree (cargo exited $rc): $label"
  note "an unresolved tree carries no packages, and no packages reads as 'no $WS_CRATE' — which is"
  note "this gate's PASS. It is RED instead."
  tree_why "$out"
  fail=1
}

assert_absent() {
  local label="$1"; shift
  local out; out="$(mktemp)"
  local rc=0; edge_tree "$out" "$@" || rc=$?
  if [ "$rc" -ne 0 ]; then unresolved "$label" "$out" "$rc"; rm -f "$out" "$out.err"; return; fi
  local n; n="$(grep -c "$WS_CRATE" "$out" || true)"
  if [ "$n" -eq 0 ]; then
    grn "  ok — no $WS_CRATE in: $label  ($(grep -c . "$out" || true) package(s) resolved)"
  else
    red "  FAIL — $WS_CRATE present ($n) in the WS-free build: $label"
    fail=1
  fi
  rm -f "$out" "$out.err"
}

assert_present() {
  local label="$1"; shift
  local out; out="$(mktemp)"
  local rc=0; edge_tree "$out" "$@" || rc=$?
  if [ "$rc" -ne 0 ]; then unresolved "$label" "$out" "$rc"; rm -f "$out" "$out.err"; return; fi
  local n; n="$(grep -c "$WS_CRATE" "$out" || true)"
  if [ "$n" -ge 1 ]; then
    grn "  ok — $WS_CRATE present (positive control): $label"
  else
    red "  FAIL — $WS_CRATE MISSING where the WS edge must exist: $label"
    fail=1
  fi
  rm -f "$out" "$out.err"
}

# ── SELF-TEST — the gate proves it can tell "no edge" from "no answer" ────────────────────────────
# Drives the REAL assert_absent/assert_present over cargo invocations whose outcome is known, and
# checks the `fail` flag each one leaves behind. Red-before-green: with the old `cargo tree … | grep
# -c` shape, cases 1 and 2 below both produced 0 and both reported "ok — no tokio-tungstenite".
run_selftest() {
  local cases=0 fails=0
  echo
  echo "== duplex-ws default-edge gate SELF-TEST =="
  say() { printf '%s  %s\n' "$1" "$2"; cases=$((cases + 1)); [ "$1" = PASS ] || fails=$((fails + 1)); }

  # 1. A package that does not exist: cargo cannot resolve, so there is no answer to read.
  fail=0
  assert_absent "a package that does not exist" -p busbar-no-such-crate >/dev/null 2>&1
  [ "$fail" -eq 1 ] && say PASS "an unresolvable tree is RED for an ABSENCE claim, not 'no WS edge'" \
    || say FAIL "an unresolvable tree passed an absence claim"

  # 2. The same for a presence claim, so case 1 is not just "this gate fails everything unknown".
  fail=0
  assert_present "a package that does not exist" -p busbar-no-such-crate >/dev/null 2>&1
  [ "$fail" -eq 1 ] && say PASS "an unresolvable tree is RED for a PRESENCE claim too" \
    || say FAIL "an unresolvable tree passed a presence claim"

  # 3. A feature that does not exist on a real package — the ordinary way this file's argument list
  #    rots — must be RED rather than a quiet "the edge is gone".
  fail=0
  assert_absent "a feature that does not exist" -p busbar --features no-such-feature >/dev/null 2>&1
  [ "$fail" -eq 1 ] && say PASS "a feature name that no longer exists is RED, not a vanished edge" \
    || say FAIL "a nonexistent feature passed as an absence"

  # 4. And the real, resolvable claims still behave — an absence that is really absent passes, and a
  #    presence that is really present passes. Without these, 1–3 prove only that the gate refuses.
  fail=0
  assert_absent "busbar-core (default, money path)" -p busbar-core >/dev/null 2>&1
  [ "$fail" -eq 0 ] && say PASS "a resolvable tree with no $WS_CRATE still passes" \
    || say FAIL "the real money-path absence claim did not pass"
  fail=0
  assert_present "busbar (default / shipped)" -p busbar >/dev/null 2>&1
  [ "$fail" -eq 0 ] && say PASS "a resolvable tree that carries $WS_CRATE still passes the control" \
    || say FAIL "the real positive control did not pass"

  fail=0
  echo
  [ "$fails" -eq 0 ] && { grn "duplex-ws default-edge selftest: GREEN (${cases} cases)"; return 0; }
  red "duplex-ws default-edge selftest: RED (${fails}/${cases} cases failed)"; return 1
}

if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

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
