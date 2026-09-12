// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The three WIRE-FORMAT NAMES the transport axis and the plane declaration share. The CUT: the rest
//! of `plane` is the declaration/registry surface, which names the host seams and the route mount and
//! therefore stays with them in `busbar-substrate` — but [`transport::Transport::name`] reads these
//! three constants (that is the whole point of them: one spelling for the metric label, the plane's
//! wire-format list and the served card's `protocolBinding`), so they crossed with the axis.
//! `busbar-substrate`'s own `plane` re-exports all three, so `busbar_substrate::plane::WIRE_JSONRPC`
//! and its siblings resolve unchanged.

/// THE WIRE FORMAT both mounted planes speak: JSON-RPC 2.0. Named once, here, because it is read
/// twice as a `wire_format_names` entry and once more by the error-shaping boundary, which
/// decides that a refusal on a mounted plane is a JSON-RPC error object rather than a vendor
/// envelope. A literal spelled per site is how those two answers start to differ.
pub const WIRE_JSONRPC: &str = "jsonrpc";

/// THE SECOND WIRE FORMAT THE A2A PLANE SPEAKS: A2A's HTTP+JSON binding, where the REQUEST LINE
/// names the operation rather than a body member. Named once, here, because it is read three ways
/// and all three must agree — as a `wire_format_names` entry, as the
/// `busbar_core::transport::Transport::HttpJson` label, and (upper-cased by
/// `a2a::serve::servable_bindings`) as the `protocolBinding` a served agent card advertises. The
/// card spelling is `HTTP+JSON`, so this is that string lower-cased and nothing else.
pub const WIRE_HTTP_JSON: &str = "http+json";

/// The A2A specification's gRPC binding, as a wire-format name. Lower-case here and upper-cased
/// once, by `busbar_core::a2a::serve::servable_bindings`, into the `GRPC` an agent card advertises
/// — so the card cannot claim a binding the plane does not list, which is the whole reason that
/// function reads this list rather than writing one of its own.
pub const WIRE_GRPC: &str = "grpc";

/// AN UPSTREAM ENDPOINT THE COMPOSITION ROOT ALREADY RESOLVED — the origin of the provider serving a
/// model, and the credential that authenticates the busbar↔provider hop.
///
/// The credential is the RESOLVED value, not the reference: it crossed the deployment's own secret
/// resolver once, at the same point in the build every other upstream credential does. It stays
/// server-side — nothing here renders it, and a plane that holds one is holding what its own dial
/// needs and nothing a caller can see.
#[derive(Clone, Debug)]
pub struct ResolvedUpstream {
    /// The provider origin (scheme + authority, e.g. `https://api.example.com`).
    pub base_url: String,
    /// The resolved provider credential, held server-side.
    pub api_key: String,
}

/// THE DEPLOYMENT'S MODEL→UPSTREAM CATALOG — implemented by the composition over the resolved
/// `models:`/`providers:` sections and the deployment's secret resolver, and read by a plane's `build`
/// through [`BuildCtx::upstream_for_model`].
///
/// One question, and the plane supplies the model name: a plane whose grammar pins a model gets that
/// model's origin and credential without a second copy of the provider catalog, a second parse of it,
/// or a process-wide write the next config apply cannot move.
pub trait UpstreamCatalog {
    /// The upstream serving `model`. `Ok(None)` when the deployment declares no such model; `Err`
    /// with the resolver's own message when it does and the credential reference will not resolve.
    ///
    /// # Errors
    /// The secret resolver's message for a declared-but-unresolvable credential reference.
    fn upstream_for_model(&self, model: &str) -> Result<Option<ResolvedUpstream>, String>;
}
