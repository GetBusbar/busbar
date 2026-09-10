#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-keys.sh — THE ONE LIST OF PLANE KEYS.
#
# WHY THIS FILE EXISTS. The set of protocol PLANES the tree carries — {llm, mcp, a2a, voice} — was
# spelled as a constant in a dozen gate scripts (plane-delete-test's `PLANES`, plane-grep-gate's
# per-crate needle sets, plane-purity-lint's `PLANE_ROOTS`, plane-abi-neutrality's ban list). Each
# copy is one more place that silently NO-OPs on the day a plane is added and someone forgets a row:
# a gate that scans zero files of a plane it never heard of still prints `ok`. `voice` (Plane 4)
# arriving as a skeleton crate is exactly that day. There is one list of plane keys and it lives
# here; every gate that enumerates the planes SOURCES this file instead of restating the set.
#
# This is the shell twin of scripts/plane-roots.sh (which answers WHERE a plane lives); this answers
# WHICH planes exist. Between them, no gate hard-codes the plane set or its locations.
#
# CONTRACT. Sourcing this file exports `PLANE_KEYS` (all plane keys, canonical order) and
# `PLANE_KEYS_PROTOCOL` (every key EXCEPT `llm` — busbar-llm owns the LLM dialect names and is never
# scanned as a plane key by the grep gate, which bans the dialects there instead). It also defines
# three pure helpers used by the callers to reconstruct their existing views byte-for-byte:
#   plane_src_roots            → "crates/busbar-<k>/src …" for every key, in canonical order.
#   neutral_src_roots          → the NEUTRAL (ABI-side) src roots, in canonical order.
#   plane_keys_other <self>    → the PROTOCOL keys except <self>, in canonical order.
# It NEVER exits and NEVER prints — the caller owns its own reporting.

# The canonical order is the doctrine order: the three original protocols, then voice (Plane 4).
PLANE_KEYS="llm mcp a2a voice"

# The protocol subset: every plane key except `llm`. Derived from PLANE_KEYS so adding a plane in
# one place flows here automatically.
PLANE_KEYS_PROTOCOL=""
for _pk in $PLANE_KEYS; do
  [ "$_pk" = llm ] && continue
  PLANE_KEYS_PROTOCOL="${PLANE_KEYS_PROTOCOL:+$PLANE_KEYS_PROTOCOL }$_pk"
done
unset _pk

plane_src_roots() {   # echo "crates/busbar-<k>/src crates/busbar-<k>-codec/src …", canonical order.
  local k out=""
  # BOTH HALVES, AND BOTH DERIVED FROM THE KEY. Every plane is TWO crates since the codec split:
  # `busbar-<k>` kept its I/O half (the axum routes, the stdio serve loop, the tokio transports, the
  # telephony dial, the WS accept) and shed its pure half — the codecs, the record vocabularies, the
  # duplex IR, the dialect grammars — into `busbar-<k>-codec`, which a PURE kind may name. The gate
  # scans sources, not manifests, so both halves must be named or the bulk of a plane stops being
  # scanned.
  #
  # The codec halves used to be a hand-written list of four crate paths appended below this loop. That
  # is the one thing this file exists to abolish: the loop grew a fifth plane's `src` root by itself
  # and the literal list did NOT grow its `-codec` root, so a new plane would arrive half-scanned —
  # its pure half, the bulk of it, read by nothing while the gate reported clean over the half it
  # could see. A hard-coded list beside a derived one is a rot clock. Both come off the key now.
  for k in $PLANE_KEYS; do out="${out:+$out }crates/busbar-${k}/src crates/busbar-${k}-codec/src"; done
  printf '%s' "$out"
}

# ── THE NEUTRAL (ABI-side) SRC ROOTS ────────────────────────────────────────────────────────────────
# The other half of the same question. `plane_src_roots` answers "where do the PLUGINS live"; this
# answers "where does the NEUTRAL side live" — the crates a plane must never leak into and that must
# still compile with every plane crate `git rm -r`'d. It lives here, beside the plane list, for the
# reason the header gives: one list, sourced, never restated per gate.
#
# `busbar-substrate-values` is the PURE HALF of the substrate — the value families the codecs and the
# planes name, split out so a plane's closure resolves no hyper/reqwest/tokio edge. It is every bit as
# NEUTRAL as the crate it came out of, and the bulk of the surface a plane talks to (proto, ir,
# breaker, handlers) now lives there. Omitting it would leave those files scanned by nothing.
#
# REMOVING A ROOT IS A NAMED CHANGE, NEVER A SILENT ONE. The tree is heading somewhere real: busbar-core
# is being drained, and one day `crates/busbar-core/src` will legitimately cease to exist. On that day
# the entry below is DELETED HERE, in a reviewed diff, with the crate's disappearance as its stated
# reason. What must NOT happen is the directory vanishing while the entry stays: a root that is listed
# but absent means the gate scans zero files of it and reports the passing answer to every ban. The
# consumer (scripts/plane-purity-lint.sh) therefore treats a listed-but-missing root as RED and refuses
# a zero-file scan outright — so the only way a root leaves the set is through this line.
# `busbar-core-config` is the config layer, split off busbar-core into a home of its own so the engine
# can retire out from under the product's config grammar. It carries the config DOCUMENT ROOT — the
# grammar every plane's section hangs off — so it is precisely the kind of source a plane name must
# never appear in, and it is listed here in the same diff as the split.
NEUTRAL_ROOTS_LIST="crates/busbar-core/src crates/busbar-core-config/src crates/busbar-substrate/src crates/busbar-substrate-values/src crates/api/src"

neutral_src_roots() { printf '%s' "$NEUTRAL_ROOTS_LIST"; }

plane_keys_other() {  # $1 = self key. Echo the PROTOCOL keys except <self>, canonical order.
  local k out=""
  for k in $PLANE_KEYS_PROTOCOL; do
    [ "$k" = "$1" ] && continue
    out="${out:+$out }$k"
  done
  printf '%s' "$out"
}
