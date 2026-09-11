// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE'S ONE STORE HANDLE, bound once by the composition root.
//!
//! ## Why this file exists
//!
//! A plane may not hold a store and a unit may not know a schema, so the only kind entitled to bind
//! the two together is the composition. Until this file there was no production binding at all: the
//! adapter that carries the three unit-side store seams was constructed by tests and by nothing
//! else, so every plane's record legs had nothing to be bound TO and the one mounted leg was handed
//! a refusing stand-in instead. That is the gap this closes, and it closes it ONCE for every
//! plane rather than once per plane — a second binding would be a second answer to "which store did
//! this node write that record onto", and the two would agree right up until one of them did not.
//!
//! ## One handle, and how that is made a fact rather than a convention
//!
//! The node has exactly one store: whatever the configured `store.module` resolved to, which is the
//! in-tree RAM backend when a configuration names none and a loaded module when it names one. Both
//! arrive here as the same `busbar_api::Store`, and everything downstream — the plane record legs,
//! the mutation log's durable path, the per-call record's — is handed the handle THIS
//! function returns rather than taking its own read of the governance state. That is what makes
//! "the same handle" a property of the code and not of the reader's memory of it.
//!
//! ## What the RAM default and a durable module have in common, stated
//!
//! Nothing here branches on which backend is behind the face, and that is deliberate: the published
//! store protocol is the whole of what a record leg uses, the RAM backend implements it, and a
//! durable module implements it. A binding that asked which one it had would be a binding that
//! could answer differently for the two, and then "it works on memory" would stop meaning anything
//! about the deployment an operator actually runs.

use std::sync::Arc;

use busbar_plugin_loader::store_adapter::StoreAdapter;

/// Bind the node's one store handle behind the published ABI.
///
/// **This is the composition root's only construction of a store adapter, and the only one in the
/// tree outside tests.** What it returns is cheap to clone and every clone is the same store, so a
/// caller that needs the handle in two places takes two clones rather than binding twice.
///
/// The payload schema is the CURRENT one. That is exact for the RAM default and for a module
/// published against this release, and it is the only reading available where the handle exists:
/// the signed manifest that would say otherwise is read by the plugin registry during preflight and
/// is not carried on the `Store` face. What the schema gates is the verbs unit's node-local shim
/// (`StoreAdapter::speaks_new_ops`) and nothing on the record path, which passes every operation
/// through to the store untouched — so a module at an older schema still writes and reads its
/// plane records exactly as it did. A deployment that needs the shim gated on a manifest value
/// binds through `StoreAdapter::new` with that value; this function does not guess one.
#[must_use]
pub fn node_adapter(store: Arc<dyn busbar_api::Store>) -> StoreAdapter {
    StoreAdapter::native(store)
}

#[cfg(test)]
#[path = "tests/store.rs"]
mod tests;
