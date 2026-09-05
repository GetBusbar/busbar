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
# two pure helpers used by the callers to reconstruct their existing views byte-for-byte:
#   plane_src_roots            → "crates/busbar-<k>/src …" for every key, in canonical order.
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

plane_src_roots() {   # echo "crates/busbar-<k>/src …" for every plane key, canonical order.
  local k out=""
  for k in $PLANE_KEYS; do out="${out:+$out }crates/busbar-${k}/src"; done
  # The LLM protocol is TWO crates now: the engine kept the `busbar-llm` name and the six dialect
  # codecs moved to `busbar-llm-codec`. The gate scans sources, not manifests, so the moved files
  # have to be named here or the bulk of the LLM plane would stop being scanned — which is the
  # failure mode a split invites and the reason this line exists.
  out="${out} crates/busbar-llm-codec/src"
  # The SAME split, repeated for the other three planes: `busbar-mcp`, `busbar-a2a` and
  # `busbar-voice` each kept their I/O half (the axum routes, the stdio serve loop, the tokio
  # transports, the telephony dial and the WS accept) and shed their pure half — the codecs, the
  # record vocabularies, the duplex IR and the dialect grammars — into a `-codec` crate a PURE kind
  # may name. Same reason as the line above: the gate scans sources, not manifests.
  out="${out} crates/busbar-mcp-codec/src crates/busbar-a2a-codec/src crates/busbar-voice-codec/src"
  printf '%s' "$out"
}

plane_keys_other() {  # $1 = self key. Echo the PROTOCOL keys except <self>, canonical order.
  local k out=""
  for k in $PLANE_KEYS_PROTOCOL; do
    [ "$k" = "$1" ] && continue
    out="${out:+$out }$k"
  done
  printf '%s' "$out"
}
