#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# bare-bones-build.sh — THE TWO-DISTRIBUTIONS-ONE-CONTRACT BUILD GATE (DECISIONS #11, #26 S4).
#
# 1.6.0 ships TWO distributions of `busbar`, one plugin contract:
#
#   * DEFAULT      — everything compiled in (the `default` feature set: proto-llm, plane-mcp,
#                    plane-a2a, plane-streaming, root-*). `cargo build -p busbar`.
#   * BARE-BONES   — core + the DROP-IN plugin path, no compiled-in protocol planes. The composition
#                    root's `register_planes()`/`register_protocols()` push nothing (every row is
#                    feature-gated), so the substrate plane registry is EMPTY and the node serves
#                    planes ONLY as dropped-in cdylibs. `cargo build -p busbar --no-default-features`.
#
# The drop-in half is the SAME in both builds: `busbar_plugin_loader::load_plane` / `open_plane`
# (the HOT-tier `PlaneDecl` loader), `busbar_plugin_loader::registry::supported_abi("plane")`, and
# the `busbar_plugin_sdk::export_plane!` SDK are unconditional — a bare-bones node loads a plane the
# same way a default node loads a dropped-in one, which is the whole point of "a plugin is a plugin"
# (DECISIONS #2). This gate proves BOTH distributions COMPILE from one tree; the per-kind drop-in
# CONFORMANCE (a representative plugin of each kind, plane included, loading identically compiled-in
# vs dropped-in) is proved by the crate tests — `busbar-plugin-loader`'s `plane::tests` for kind:plane
# and its `plane_sidecar_tests` + the store/secret example round trips for the five cold kinds.
#
# This is the runnable-locally twin of xtask full-gate's `cargo build --no-default-features --locked`
# step; it names both arms explicitly so the two-distributions contract has a gate of its own.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== DEFAULT distribution (everything compiled in) =="
cargo build --manifest-path "$ROOT/Cargo.toml" -p busbar --locked

echo "== BARE-BONES distribution (core + drop-in plugins, no compiled-in planes) =="
cargo build --manifest-path "$ROOT/Cargo.toml" -p busbar --no-default-features --locked

echo "bare-bones-build: BOTH distributions compiled from one tree, one contract — green"
