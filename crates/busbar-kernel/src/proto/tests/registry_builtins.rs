// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORE'S OWN TEST-BINARY BUILT-IN PROTOCOL LIST — the extracted dialect plugin's own ordered
//! declaration table and the codec-less protocol's declaration, read off the two plugin crates core's
//! test binary links as dev-dependencies. Each plugin states its OWN list; this file names no dialect,
//! only the two tables.
//!
//! This is the exact analogue of `plane::tests::registry_tests::TEST_BUILTIN_PLANE_DECLS`. It replaces
//! the deleted `#[path]` witness re-includes of the dialect sources: those existed only because a
//! `ProtocolDecl` was once a `busbar-core` type, so an externally-linked crate's `&DECL` was a
//! DIFFERENT crate's type the registry could not hold. `ProtocolDecl` now lives in `busbar-substrate`,
//! so the plugins' declarations are the SAME `ProtocolDecl` type — core's own test binary reads them
//! directly, reproducing the shipped protocol set and its operator-visible ORDER WITHOUT re-compiling
//! the dialect sources into core.
//!
//! THE ORDER IS THE DIALECT PLUGIN'S `DECLS` ORDER, then the codec-less protocol — the same sequence
//! the composition root installs in production (`crates/busbar/src/main.rs::register_protocols`
//! extends its list with the same `DECLS` slice), so `known_protocols()`'s order (the metric-family
//! index and the config-error `must be one of:` order) is byte-identical to the shipped binary's, and
//! it is identical BY CONSTRUCTION: there is no second hand-kept copy of the dialect order to drift.

use std::sync::LazyLock;

use busbar_kernel::proto::registry::ProtocolDecl;

/// The shipped protocol set for core's test binary, built once. Deref is allocation-free after the
/// first read, so the registry's memoized fast path (which reads the built-in tail's LENGTH on every
/// resolution) stays allocation-free.
static TEST_BUILTIN_DECLS: LazyLock<Vec<&'static ProtocolDecl>> = LazyLock::new(|| {
    let mut decls: Vec<&'static ProtocolDecl> = busbar_llm::DECLS.to_vec();
    decls.push(&busbar_mcp::PROTO_DECL);
    decls
});

/// The shipped protocol set — see [`TEST_BUILTIN_DECLS`].
pub fn test_builtin_decls() -> &'static [&'static ProtocolDecl] {
    &TEST_BUILTIN_DECLS
}
