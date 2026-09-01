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
/// The `PATH_INGRESS` arrivals (gemini/bedrock URL-model) are seeded through the neutral
/// `set_test_path_ingress` HOOK (idempotent, first-writer-wins), NOT the set-once production
/// `install_path_ingress` — so a `test-support` consumer that builds a path-model `App` resolves the
/// gemini/bedrock arrivals, while a body-model `App` (which never resolves one) is unaffected.
pub fn install_test_seams() {
    busbar_substrate::proto::register_test_protocols(crate::DECLS);
    busbar_substrate::plane::registry::register_test_plane(&crate::PLANE_DECL);
    busbar_substrate::ingress::arrival::set_test_path_ingress(|| crate::PATH_INGRESS);
    busbar_substrate::ingress::arrival::set_test_body_ingress(|| crate::BODY_INGRESS);
    // The cross-protocol STREAMING translator factory. `busbar_core::proto::new_stream_translator`
    // routes through this installed pointer in a `test-support`/plugin test binary (where core's
    // `cfg(test)` is FALSE), so without it every cross-protocol streaming forward falls back to raw
    // passthrough — the exact composition-root write `main.rs::run` makes in production. Set-once.
    busbar_core::proto::install_stream_translator_factory(crate::proto_stream::new_stream_translator);
}
