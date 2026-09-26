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
# This answers WHICH planes exist. WHERE a plane lives is answered by `xtask/src/planes.rs`
# (`PlaneRoots`), whose tests in `xtask/tests/infra.rs` carry the zero/ambiguous/missing refusals;
# its old shell twin scripts/plane-roots.sh was sourced by nothing and is deleted (item 549).
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
#
# THIS IS THE ON-DISK ROSTER, NOT THE DOCTRINE ROSTER, AND THE GAP BETWEEN THEM IS NAMED BELOW
# (`PLANE_KEYS_LOCKED`), NOT PAPERED OVER HERE. DECISIONS #18 renamed Plane 4 voice -> streaming
# ("No `voice` as a plane/kind/crate/feature name") and DECISIONS #48 added a fifth plane, decisions
# (jev) — so the LOCKED roster is five: llm, mcp, a2a, streaming, decisions. `PLANE_KEYS` here still
# says `voice`, and still omits `decisions`, on purpose: every existing consumer of this exact
# variable treats each entry as a literal `crates/busbar-<key>` directory suffix
# (`plane_src_roots`/`neutral_src_roots` below) OR — scripts/plane-grep-gate.sh — as a literal GREP
# NEEDLE banned from the other planes' and the neutral crates' source. Spelling this `streaming`
# before `crates/busbar-voice` is actually renamed would make every one of those consumers open a
# directory that is not there, exactly the silent-zero-files failure mode this file exists to
# prevent (see the header). Adding `decisions` here today is worse than a no-op: this repo's own
# comment convention cites its own governance items as "DECISIONS #<n>" constantly, so the bare word
# `decisions` used as scripts/plane-grep-gate.sh's needle would flood that gate — a sibling gate this
# change does not own — with false positives on its own commit-message vocabulary. Both changes wait
# for their crate/wiring counterpart to land; until then, PLANE_KEYS states what is TRUE ON DISK, and
# PLANE_KEYS_LOCKED (below) states what is true IN DOCTRINE, so no caller can mistake one for the
# other by reading only this line.
PLANE_KEYS="llm mcp a2a voice"

# The protocol subset: every plane key except `llm`. Derived from PLANE_KEYS so adding a plane in
# one place flows here automatically.
PLANE_KEYS_PROTOCOL=""
for _pk in $PLANE_KEYS; do
  [ "$_pk" = llm ] && continue
  PLANE_KEYS_PROTOCOL="${PLANE_KEYS_PROTOCOL:+$PLANE_KEYS_PROTOCOL }$_pk"
done
unset _pk

# ── THE LOCKED (DOCTRINE) ROSTER, AND THE ALIAS BETWEEN IT AND WHAT IS TESTABLE TODAY ──────────────
# `PLANE_KEYS_LOCKED` is the five-plane roster the product is LOCKED to (llm, mcp, a2a, streaming,
# decisions — DECISIONS #18/#48), independent of what has physically landed on disk. It is ADDITIVE:
# nothing existing sources it today, so declaring it here changes no consumer's behavior. It exists
# for a caller that needs to tell the truth about COVERAGE rather than about source layout — today
# that is scripts/plane-delete-test.sh, whose `--all`/`--baseline` used to iterate `$PLANE_KEYS` (the
# on-disk four) and print a verdict that read as "the whole roster", proving nothing about the two
# planes that differ from it.
PLANE_KEYS_LOCKED="llm mcp a2a streaming decisions"

# plane_ondisk_key <locked-key> → the PLANE_KEYS entry that plane is REACHABLE under today, or empty
# if none exists yet. `streaming` is reachable — under its pre-rename name `voice`, the crate DECISIONS
# #18 has not yet renamed — so a caller asking "is streaming covered" gets a truthful "yes, as voice",
# not a false gap. A locked key with no entry here (`decisions`) returns empty: there is no on-disk
# stand-in, so a caller must report that plane as a NAMED GAP, never as a silent pass over zero files.
plane_ondisk_key() {
  case "$1" in
    streaming) printf 'voice' ;;
    llm | mcp | a2a) printf '%s' "$1" ;;
    *) printf '' ;;
  esac
}

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
  #
  # AND THE `-codec` HALF IS TRANSIENT. #39 deletes it: each codec folds into its plane crate, and
  # `busbar-mcp-codec` already has. So the codec root is named only while it EXISTS. This is not the
  # rot the paragraph above is about — that was a hand-written list failing to GROW; this is a
  # derived one that stops naming a crate the tree deleted, which `require_roots` would otherwise
  # kill the gate over. The folded dialect is scanned by the plane-kind regime, not by this list.
  for k in $PLANE_KEYS; do
    out="${out:+$out }crates/busbar-${k}/src"
    [ -d "crates/busbar-${k}-codec/src" ] && out="$out crates/busbar-${k}-codec/src"
  done
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
# REMOVING A ROOT IS A NAMED CHANGE, NEVER A SILENT ONE. That day has come for two of them, and this
# IS the reviewed diff that says so. `busbar-core` was absorbed into `busbar-kernel` (W4.a, 673ecdaaa)
# and `busbar-substrate`'s engine followed it (W4.b P2, 5fa320208), so `crates/busbar-core/src` and
# `crates/busbar-substrate/src` are gone from disk and `crates/busbar-kernel/src` is where the neutral
# side lives now. What must NOT happen is the directory vanishing while the entry stays: a root that is
# listed but absent means the gate scans zero files of it and reports the passing answer to every ban.
# The consumers (scripts/plane-noun-gate.sh, scripts/plane-grep-gate.sh) therefore treat a
# listed-but-missing root as RED and refuse a zero-file scan outright — which is exactly how these two
# stale entries were caught — so the only way a root leaves the set is through this line.
#
# THE RUST TWIN IS `xtask/src/planes.rs::neutral_src_roots`, and `xtask/tests/infra.rs`'s
# `the_plane_key_contract_matches_plane_keys_sh` pins the two lists equal. Move one, move both.
#
# THIS LINE WAS THREE ROOTS WHILE THE TWIN WAS TWENTY-ONE, and that test was red on it: the Rust
# side enrolled the kernel's decomposed crates, the money path (busbar-kernel-ledger), the ABI and
# contract surfaces (busbar-contract, busbar-plugin), the loader/SDK and the compiled-in cleanliness
# crates, and this line did not follow. Both shell meters that source it (plane-grep-gate.sh,
# plane-noun-gate.sh) therefore scanned 220 of 427 neutral files and printed 0 for needles that are
# not 0 -- the ZERO those meters document as the signal to arm their hard gates. The list below is
# the twin's, same order, one line (the pinning test parses this exact line).
NEUTRAL_ROOTS_LIST="crates/busbar-kernel/src crates/busbar-kernel-audit/src crates/busbar-kernel-breaker/src crates/busbar-kernel-budget/src crates/busbar-kernel-egress/src crates/busbar-kernel-identity/src crates/busbar-kernel-ledger/src crates/busbar-kernel-scope/src crates/busbar-kernel-wal/src crates/busbar-contract/src crates/busbar-plugin/src crates/busbar-substrate-values/src crates/plugin-loader/src crates/plugin-sdk/src crates/busbar-core-admin/src crates/busbar-core-connsec/src crates/busbar-oauth2/src crates/busbar-unit-transport-key/src"

neutral_src_roots() { printf '%s' "$NEUTRAL_ROOTS_LIST"; }

plane_keys_other() {  # $1 = self key. Echo the PROTOCOL keys except <self>, canonical order.
  local k out=""
  for k in $PLANE_KEYS_PROTOCOL; do
    [ "$k" = "$1" ] && continue
    out="${out:+$out }$k"
  done
  printf '%s' "$out"
}
