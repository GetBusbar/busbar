// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim + the `App`-facing half of the JSON-RPC ingress. The transport-neutral SEQUENCE
//! (`serve`), the core-refusal vocabulary ([`CoreRefusal`], [`Words`]), the request FACTS
//! ([`Request`]), the `Origin` admission and the RFC 9728 metadata RENDER ([`Metadata`],
//! [`metadata`]) moved DOWN into `busbar-substrate` in Phase-B B1; this glob keeps every
//! `crate::ingress::protocol::…` name resolving. What stays here is the one piece that reads a core
//! type: [`ResourceMetadata`] (which extends the moved [`Words`] trait cross-crate) and the
//! [`metadata_handler`] axum handler over [`crate::state::CurrentApp`].

// This JSON-RPC discovery/metadata ingress is served only by a JSON-RPC-fronted plane; with none such
// compiled in the re-export and the two `App`-facing stayers (`ResourceMetadata`, `metadata_handler`)
// read dead, exactly as the pre-split module did. Gated on the neutral `jsonrpc-ingress` CAPABILITY
// marker (naming a capability, not a plane, per the plane-purity lint) — enabled transitively by
// `plane-mcp`/`plane-a2a`, so `not(feature = "jsonrpc-ingress")` is byte-identical to the original
// `not(any(feature = "plane-mcp", feature = "plane-a2a"))` gate this replaced.
#![cfg_attr(not(feature = "jsonrpc-ingress"), allow(dead_code, unused_imports))]

use axum::response::Response;

// Glob, so the re-export is never an unused import when a plane consumer is compiled out.
pub use busbar_substrate::ingress::protocol::*;

/// THE THREE FACTS a protocol supplies so that ONE handler can serve its RFC 9728 document.
///
/// This is the whole of what a protocol writes for step 2 of the discovery loop. It is a trait and
/// not a function pointer because [`metadata_handler`] is mounted as `metadata_handler::<W>` — a
/// concrete fn item, which is what axum needs, and which is what makes the SAME handler serve two
/// planes without either of them owning a `metadata` function.
pub trait ResourceMetadata: Words + Default {
    /// This deployment's document facts, or `None` when this deployment does not carry the plane —
    /// which is [`CoreRefusal::MetadataUnavailable`], answered in this protocol's own words.
    fn document(app: &crate::state::App) -> Option<Metadata<'_>>;
}

/// `GET /.well-known/oauth-protected-resource<mount-path>`, for every protocol, once.
///
/// The path is registered CONCRETELY at mount time from the operator's canonical URI, never matched
/// as a prefix: a prefix exemption under `/.well-known/` would hand a free pass to every path
/// beneath it, and the RFC's path-insertion rule makes the exact string knowable at boot anyway.
pub async fn metadata_handler<W: ResourceMetadata>(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
) -> Response {
    match W::document(&app) {
        Some(doc) => metadata(&doc),
        None => W::default().refuse(CoreRefusal::MetadataUnavailable),
    }
}

#[cfg(test)]
#[path = "tests/protocol_tests.rs"]
mod protocol_tests;
