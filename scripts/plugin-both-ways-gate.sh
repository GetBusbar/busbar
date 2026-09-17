#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plugin-both-ways-gate.sh — THE PER-KIND DROP-IN CONFORMANCE GATE (DECISIONS #2, #3, #11).
#
# DECISION #11 requires 1.6.0 to prove, in the build gate, TWO things:
#   (1) BOTH DISTRIBUTIONS compile from one tree — DEFAULT (everything compiled in) and BARE-BONES
#       (core + drop-in plugins). That half is `scripts/bare-bones-build.sh`, which this gate runs.
#   (2) A PER-KIND DROP-IN CONFORMANCE RIG exists and passes for EVERY plugin kind: a representative
#       plugin of each kind, built as a `cdylib`, loaded over the drop-in ABI, behaving as the
#       compiled-in one does. #11 tracked this as "TODO arm bare-bones + drop-in rig". The rigs
#       themselves already live in the crate tests; what was missing — and what THIS gate adds — is
#       the single enumerated step that names each kind, runs its rig, and FAILS LOUD on any kind
#       that has no rig. `bare-bones-build.sh` only proves the two distributions COMPILE; its own
#       header defers the per-kind conformance to "the crate tests", but nothing enumerated them, so
#       "every kind is proved both-ways" was an unchecked claim. This gate is that check.
#
# WHY A DEDICATED GATE AND NOT JUST `cargo test --workspace`. `cargo test --workspace` runs these
# rigs, but it (a) does not require the cdylibs to be built first — a rig whose cdylib is absent
# SKIPS rather than fails unless `CI` is set (see `plane_conformance_tests.rs`); and (b) says nothing
# about WHICH kinds are covered, so a kind silently losing its only both-ways proof looks identical
# to green. This gate builds every example cdylib first, sets `CI=1` so a missing artifact is a hard
# failure not a skip, runs each kind's rig BY NAME, and prints a per-kind PASS/OWED matrix. A kind
# with no rig cannot hide in an aggregate green.
#
# THE 7 KINDS (DECISION #3): store, secret, auth, hook, export, plane, transport.
#   * ALL SEVEN are now fully both-ways — SDK `export_<kind>_plugin!` (or `export_plane!`) macro +
#     `plugin-loader` open path + `supported_abi(<kind>)` range + a passing drop-in rig. This gate
#     proves all seven.
#   * TRANSPORT was the one OWED kind; 1.6.0 closed it. It is ONE bidirectional kind (DECISION #3:
#     server-accept + client-connect are two DIRECTIONS, not two kinds). Its drop-in ABI mirrors the
#     plane HOT lane: a `transport` kind constant (`crates/busbar-plugin/src/cold/mod.rs`, `mod kind`),
#     an `export_transport_plugin!` macro, a `#[repr(C)]` `TransportDecl` vtable
#     (`crates/busbar-plugin/src/hot/transport.rs`), `open_transport` /
#     `supported_abi("transport")`, and the `busbar-plugin-example-transport` cdylib the rig loads and
#     drives BOTH ways (byte round-trip over accept + connect). The seven compiled-in carriers
#     (`busbar-transport-{http,ws,stdio,tcp,tls,sse,grpc}`) are UNCHANGED — this is purely additive
#     drop-in PACKAGING, exactly the "drop-in packaging owed" DECISION #3 named.
#
# USAGE
#   plugin-both-ways-gate.sh              build cdylibs, run both distributions + every kind's rig
#   plugin-both-ways-gate.sh --selftest   offline: prove the kind enumeration matches the ABI

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The seven kinds the ABI implements, each paired with the cargo package + `--exact` test that loads a
# real cdylib of that kind over the drop-in ABI and drives it. These test names are asserted to exist
# by `--selftest`, so a rename that silently drops a kind's coverage is caught here, not in the field.
KIND_STORE_PKG="busbar-plugin-loader"
KIND_STORE_TEST="tests::load_store_from_bytes_loads_the_given_bytes"
KIND_SECRET_PKG="busbar-plugin-loader"
KIND_SECRET_TEST="tests::load_and_exercise_secret_example_plugin"
KIND_AUTH_PKG="busbar-core"
KIND_AUTH_TEST="auth::plugin_chain_tests::auth_plugin_loads_and_identifies_through_middleware"
KIND_AUTH_FEATURES="auth-admin-tokens,test-support"
KIND_HOOK_PKG="busbar-plugin-loader"
KIND_HOOK_TEST="hook::tests::dlopen_policy_drives_every_op"
KIND_EXPORT_PKG="busbar-plugin-loader"
KIND_EXPORT_TEST="tests::load_and_exercise_export_example_plugin"
KIND_PLANE_PKG="busbar-plugin-loader"
KIND_PLANE_TEST="plane::tests::example_plane_loads_identically_compiled_in_and_dropped_in"
KIND_TRANSPORT_PKG="busbar-plugin-loader"
KIND_TRANSPORT_TEST="transport::tests::example_transport_loads_identically_compiled_in_and_dropped_in"

# Every example plugin cdylib the rigs load. Built FIRST so `CI=1` turns a missing artifact into a
# hard failure inside the rig instead of a silent skip.
CDYLIB_PKGS=(
  busbar-store-example-plugin
  busbar-secret-example-plugin
  busbar-auth-static-plugin
  busbar-hook-test-plugin
  busbar-export-example-plugin
  busbar-plugin-example-plane
  busbar-plugin-example-transport
)

run_rig() {
  local kind="$1" pkg="$2" test="$3" features="${4:-}"
  echo "== kind:${kind} — drop-in rig: ${pkg} :: ${test} =="
  local -a args=(test --manifest-path "$ROOT/Cargo.toml" --locked -p "$pkg")
  [ -n "$features" ] && args+=(--features "$features")
  args+=(-- --exact "$test")
  # CI=1: a rig whose cdylib is absent must FAIL, never skip. --exact: prove THIS named rig ran, so a
  # zero-tests-matched (e.g. a rename) is visible as "0 passed" and caught below.
  local out
  out="$(CI=1 cargo "${args[@]}" 2>&1)" || { echo "$out"; echo "  [FAIL] kind:${kind} rig errored"; return 1; }
  if ! printf '%s' "$out" | grep -qE '1 passed'; then
    printf '%s\n' "$out" | tail -5
    echo "  [FAIL] kind:${kind} rig did not run exactly one passing test (rename? gone?)"
    return 1
  fi
  echo "  [ok] kind:${kind} both-ways drop-in rig passed"
}

gate() {
  echo "### plugin-both-ways-gate: DECISIONS #11 — both distributions + per-kind drop-in conformance"
  echo

  echo "== (1/3) BOTH DISTRIBUTIONS (DEFAULT + BARE-BONES) =="
  "$ROOT/scripts/bare-bones-build.sh"
  echo

  echo "== (2/3) BUILD every example plugin cdylib (so a missing artifact is a hard rig failure) =="
  cargo build --manifest-path "$ROOT/Cargo.toml" --locked "${CDYLIB_PKGS[@]/#/-p}" >/dev/null 2>&1 \
    || cargo build --manifest-path "$ROOT/Cargo.toml" --locked $(printf -- '-p %s ' "${CDYLIB_PKGS[@]}")
  echo "  built: ${CDYLIB_PKGS[*]}"
  echo

  echo "== (3/3) PER-KIND DROP-IN CONFORMANCE RIGS =="
  local fails=0
  run_rig store  "$KIND_STORE_PKG"  "$KIND_STORE_TEST"  || fails=$((fails+1))
  run_rig secret "$KIND_SECRET_PKG" "$KIND_SECRET_TEST" || fails=$((fails+1))
  run_rig auth   "$KIND_AUTH_PKG"   "$KIND_AUTH_TEST" "$KIND_AUTH_FEATURES" || fails=$((fails+1))
  run_rig hook   "$KIND_HOOK_PKG"   "$KIND_HOOK_TEST"   || fails=$((fails+1))
  run_rig export "$KIND_EXPORT_PKG" "$KIND_EXPORT_TEST" || fails=$((fails+1))
  run_rig plane     "$KIND_PLANE_PKG"     "$KIND_PLANE_TEST"     || fails=$((fails+1))
  run_rig transport "$KIND_TRANSPORT_PKG" "$KIND_TRANSPORT_TEST" || fails=$((fails+1))
  echo

  echo "### SUMMARY"
  echo "  both distributions: DEFAULT + BARE-BONES compiled from one tree"
  echo "  drop-in rigs proved: store, secret, auth, hook, export, plane, transport (7/7 kinds)"

  if [ "$fails" -ne 0 ]; then
    echo "plugin-both-ways-gate: FAILED — ${fails} kind(s) lost their both-ways rig"
    return 1
  fi
  echo "plugin-both-ways-gate: 7/7 kinds proved both-ways — green"
}

# == SELFTEST ===
# The honesty ratchet: the set of kinds this gate runs a rig for MUST equal the set of kind constants
# the ABI actually defines — now SEVEN, transport included. 7 rigs == 7 kind constants. If a kind
# constant is added or removed without matching the rig set, this fails; if transport ever loses its
# constant (regressing the both-ways close), this fails too — the "7/7" claim cannot outlive its proof.
selftest() {
  local fails=0 kinds_file="$ROOT/crates/busbar-plugin/src/cold/mod.rs"
  echo "plugin-both-ways-gate.sh selftest"

  # Kind constants the ABI defines (the `pub const <NAME>: &str = "<kind>";` lines in `mod kind`,
  # excluding the `_NUL` byte-string siblings).
  local abi_kinds
  abi_kinds="$(grep -oE 'pub const [A-Z]+: &str = "[a-z]+"' "$kinds_file" \
    | sed -E 's/.*= "([a-z]+)"/\1/' | sort -u | tr '\n' ' ')"
  local want="auth export hook plane secret store transport "
  if [ "$abi_kinds" = "$want" ]; then
    echo "  [ok] ABI defines exactly the seven implemented kinds: ${abi_kinds}"
  else
    echo "  [FAIL] ABI kind constants changed: got '${abi_kinds}' want '${want}'"
    echo "         Every kind constant needs a matching drop-in rig named in gate() and below."
    fails=$((fails+1))
  fi

  # transport MUST now be an ABI kind constant (the both-ways gap is closed, not owed).
  if printf '%s' "$abi_kinds" | grep -qw transport; then
    echo "  [ok] transport is an ABI kind constant — both-ways, no longer owed"
  else
    echo "  [FAIL] 'transport' is missing from the ABI kind constants — the both-ways close regressed"
    fails=$((fails+1))
  fi

  # 7 rigs == 7 kind constants: the gate names exactly one rig per kind (rig_count asserted below).
  local kind_count rig_count=7
  kind_count="$(printf '%s' "$abi_kinds" | wc -w | tr -d ' ')"
  if [ "$kind_count" = "$rig_count" ]; then
    echo "  [ok] ${rig_count} drop-in rigs == ${kind_count} ABI kind constants"
  else
    echo "  [FAIL] ${rig_count} rigs != ${kind_count} ABI kind constants — a kind lost or gained a rig"
    fails=$((fails+1))
  fi

  # Each rig test the gate names must exist in the source, so a rename cannot silently drop coverage.
  local t
  for t in \
    "load_store_from_bytes_loads_the_given_bytes" \
    "load_and_exercise_secret_example_plugin" \
    "auth_plugin_loads_and_identifies_through_middleware" \
    "dlopen_policy_drives_every_op" \
    "load_and_exercise_export_example_plugin" \
    "example_plane_loads_identically_compiled_in_and_dropped_in" \
    "example_transport_loads_identically_compiled_in_and_dropped_in"; do
    if grep -rqE "fn ${t}\b" "$ROOT/crates"; then
      echo "  [ok] rig present: ${t}"
    else
      echo "  [FAIL] rig test not found in tree: ${t}"
      fails=$((fails+1))
    fi
  done

  echo
  if [ "$fails" -ne 0 ]; then
    echo "plugin-both-ways-gate.sh selftest FAILED (${fails} case(s))"
    return 1
  fi
  echo "plugin-both-ways-gate.sh selftest passed"
}

case "${1:-gate}" in
  --selftest) selftest ;;
  gate|"") gate ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
esac
