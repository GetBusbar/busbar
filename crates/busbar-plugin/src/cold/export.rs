// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **export** payload schema (kind = [`crate::cold::kind::EXPORT`]) that rides the kind-neutral `call`.
//!
//! ## One transport, every export op
//!
//! A `kind: export` plugin is a telemetry SINK behind the frozen six-symbol C ABI — the seam that
//! carries the engine's observability streams OUT to an external backend (the frozen vocabulary is
//! [`ExportStream`]). Like every other kind it exports the SAME six neutral symbols ([`crate::cold::symbol`]) at
//! `busbar_abi() == TRANSPORT_VERSION`; only its manifest `kind` and its own tiny request enum
//! ([`ExportRequest`]) distinguish it. Every op rides the ONE `busbar_call` as an op-discriminated
//! JSON envelope — the variant IS the op-code, so the C symbol set never grows.
//!
//! ## Two ops
//!
//! - `streams` — asked ONCE at load: which observability streams does THIS instance carry? The
//!   engine retains the answer and only routes deliveries for streams the plugin declared.
//! - `deliver` — hand one already-serialized batch for a declared stream to the sink. The payload is
//!   carried as an opaque [`serde_json::Value`] the engine built; the export ABI adds the envelope,
//!   never a second copy of the batch semantics.

use busbar_contract::http_endpoint::{HttpEndpointRequest, HttpEndpointResponse, Route};
use serde::{Deserialize, Serialize};

/// The export-plugin PAYLOAD schema version (the signed manifest's `abi_version` for `kind: export`).
/// v1: the initial `streams`/`deliver` wire. v2 (1.5.3): the PROJECTION GRAMMAR — the [`ExportStream`]
/// vocabulary was expanded and the `audit` stream REMOVED (an auditor is a projection made of other
/// streams, not a data type), so a v1 sink that declared `audit` no longer has a stream to declare.
/// A REMOVED wire token is a breaking payload change, so the floor moves rather than accepting a
/// token the engine can no longer route. This is the per-kind PAYLOAD axis, NOT the transport axis
/// — an export plugin exports the SAME six neutral symbols ([`crate::cold::symbol`]) as every other kind, at
/// `busbar_abi() == TRANSPORT_VERSION`. Named the same way [`crate::cold::SECRET_ABI_VERSION`] and
/// [`crate::cold::hook::HOOK_ABI_VERSION`] are, so the loader floor and the SDK's declared version share one
/// const and cannot silently drift apart.
pub const EXPORT_ABI_VERSION: u32 = 2;

/// The export sink's frozen observability vocabulary, and the sync contract a `kind: export` plugin
/// author implements against it — MOVED BY IDENTITY to `busbar_contract::export`, the one crate a
/// plugin manifest may name (`docs/design/1.6.0-one-face-per-kind.md` section 2). Re-exported at the
/// path they have always been published under: `ExportStream`, `ExportField` and their impls carry
/// no envelope semantics of their own, so `ExportRequest`/`ExportResponse` below name them through
/// this re-export rather than duplicating the definition.
pub use busbar_contract::export::{ExportField, ExportStream};
/// An export operation, serialized as the `call` request payload. One self-describing enum keeps the
/// C ABI to a single `call` symbol; the `op` tag is the op-code. Serialized with the op as a JSON tag
/// so a plugin matches on it directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ExportRequest {
    /// `streams` — which [`ExportStream`]s does this instance carry? Asked once at load; the reply is
    /// [`ExportResponse::Streams`].
    Streams,
    /// `deliver` — hand one batch for `stream` to the sink. `payload` is the engine-built batch as an
    /// opaque JSON value. Reply: [`ExportResponse::Delivered`].
    Deliver {
        /// The declared stream this batch belongs to.
        stream: ExportStream,
        /// The already-serialized batch (opaque to the ABI; built by the engine).
        payload: serde_json::Value,
    },
    /// `routes` — asked ONCE at load: which HTTP [`Route`]s does this instance serve? The engine
    /// collision-checks + namespace-confines the answer, then mounts them (see the `http_endpoint`
    /// module doc). Reply: [`ExportResponse::Routes`]. ADDITIVE: an older sink that cannot decode this
    /// op declares no routes (the loader treats the undecodable-variant signal as "no HTTP surface").
    Routes,
    /// `http_endpoint` — dispatch one inbound HTTP request matched to a registered route of THIS
    /// plugin. Fires only for a matched plugin route, off the data-plane hot path; the engine already
    /// enforced the route's declared auth. Reply: [`ExportResponse::Http`].
    HttpEndpoint {
        /// The host-built inbound request (bounded headers, no raw `Authorization`).
        request: HttpEndpointRequest,
    },
}

/// The success payload for an export `call`, matched to the request variant. A module-level FAILURE (a
/// sink that genuinely errored) rides `STATUS_ERR` with a UTF-8 message, NOT here.
///
/// UNLIKE [`ExportRequest`] (`op`-tagged, snake_case), this type carries NO `#[serde(...)]` attribute,
/// so it serializes with serde's default externally-tagged representation — the SAME asymmetry
/// [`crate::cold::hook::HookReply`] carries and for the same reason: this is JSON over the frozen C-ABI
/// transport, so a tagging change is a wire-breaking change, not a cosmetic one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportResponse {
    /// `streams` — the streams this instance carries.
    Streams(Vec<ExportStream>),
    /// `deliver` — the batch was accepted by the sink (nothing to read back).
    Delivered,
    /// `routes` — the HTTP routes this instance serves (collected once at load).
    Routes(Vec<Route>),
    /// `http_endpoint` — the plugin's response to a dispatched inbound request, relayed verbatim.
    Http(HttpEndpointResponse),
}

#[cfg(test)]
#[path = "tests/export_tests.rs"]
mod tests;
