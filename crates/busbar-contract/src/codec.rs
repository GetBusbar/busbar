// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CODEC-CELL SHAPES (DECISIONS #83: contract = shapes) — the values a protocol's codec cells
//! and the kernel's dispatch hand each other: the resolved-primitives egress context a request
//! handler renders the upstream path from, and the two refusals a cell reports.
//!
//! Relocated, module-path-only and byte-identical, from `busbar-substrate-values` (`wire` and
//! `handlers`), which re-exports each under its historical path so every caller compiles unchanged.
//! The codec-cell TRAITS themselves stay there for now: their signatures hand out the sealed IR
//! handle, whose byte-carrier methods name a buffer type this crate does not take.

use crate::operation::Operation;

/// What routing hands a request handler so it can render the upstream URL path. RESOLVED PRIMITIVES
/// ONLY — never the `Lane` or a config handle: a codec/handler touching routing state is exactly the
/// coupling this fixes. Grows a field (region, api-version, …) when a protocol needs more; the trait
/// signature does not. Routing populates it from the lane and applies any `lane.path` override itself.
pub struct EgressCtx<'a> {
    /// Which operation's endpoint to render — the template selector.
    pub operation: Operation,
    /// The resolved wire model id (routing calls `Lane::wire_model()`), for protocols that carry the
    /// model in the URL path rather than the body.
    pub model: &'a str,
    /// Whether the caller asked to stream (chat/audio path variants); `false` for the JSON ops.
    pub stream: bool,
    /// Optional per-provider path-BASE override (the lane's `path_base`). For URL-model protocols it
    /// replaces the protocol's hardcoded base segment (e.g. `/v1beta/models`) so a provider can be
    /// pointed at a different layout — a host that serves the same dialect under a
    /// project/location-scoped path. `None` uses the protocol default.
    /// Distinct from the full-path `path` override, which is static and ignores the per-request model.
    pub path_base: Option<&'a str>,
}

/// A request that could not be parsed into this operation's IR — rendered as a caller-dialect 4xx
/// (via the existing `proxy::ingress_error`). `UnsupportedSubOp` is the second 404 site
/// (`ImageIr.op` unsupported for the model) — distinct from handler-absence, same terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressReject {
    BadRequest(String),
    UnsupportedSubOp { op: Operation, model: String },
}

/// An upstream response body this OperationHandler could not decode into its operation's IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Malformed(String),
}
