// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLUGIN'S TEST-KIT — the composition-root-shaped install seam a `test-support` consumer
//! (busbar-core's own integration target, and any downstream test binary) uses to bring the LLM
//! protocol and plane into the process registries.
//!
//! It replaces the deleted `#[path]` witness re-includes of the six dialect sources into
//! `busbar-core`: `ProtocolDecl` and `PlaneDecl` now live in `busbar-substrate`, so a test registers
//! the REAL, externally-linked declarations through the neutral substrate seams — exactly as
//! production's composition root (`crates/busbar/src/main.rs`) hands [`crate::DECLS`] and
//! [`crate::PLANE_DECL`] to `install_protocols`/`install_planes`. `busbar-core`'s `test-support`
//! `registry()` folds the registered set ahead of its (empty) built-ins on every read, so a test that
//! installs these before it builds an `App` sees the same protocol set a shipped "busbar with the LLM
//! plane" binary has.

/// INSTALL THE LLM PROTOCOL + PLANE the composition root installs in production. Idempotent (both
/// underlying substrate registrations dedupe by name/key), so a test may call it freely — including
/// from several tests in one binary.
///
/// NOTE the asymmetry with production: the `PATH_INGRESS` arrivals (gemini/bedrock URL-model) are NOT
/// installed here. `busbar_core::ingress::path_ingress::install_path_ingress` is a SET-ONCE seam (it
/// panics if called twice), so it cannot be driven from a per-test finalizer that many tests hit;
/// core's own test binary resolves those arrivals through its `BUILTIN_PATH_INGRESS` fixtures instead,
/// and a body-model `App` (the integration fixtures) needs no arrival at all.
pub fn install_test_seams() {
    busbar_substrate::proto::register_test_protocols(crate::DECLS);
    busbar_substrate::plane::registry::register_test_plane(&crate::PLANE_DECL);
}
