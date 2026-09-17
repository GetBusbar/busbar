// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FULL-FIDELITY NEUTRAL EGRESS INTERFACE.
//!
//! `egress::seam` is deliberately LOSSY — its `Buffered`/`HopSpec` projection is the right shape
//! for the plugin ABI vtable, but it cannot carry what a native (in-process) consumer needs: the
//! full `http::Response<Incoming>` header map a streaming relay reads, a persistent pooled
//! [`engine::EngineClient`] handle a hot path holds across requests, or the non-pinned
//! `pooled_webpki` posture a plane's own outbound client runs under. Today's native consumers
//! therefore still name `egress::engine::*` directly — `busbar_substrate::egress::engine::…` —
//! which is exactly the coupling that blocks ever relocating the engine out of substrate: every
//! caller of a concrete module path is a caller a relocation has to rewrite.
//!
//! This module is the fix: [`EgressEngine`], a trait whose methods are the engine's FULL public
//! surface today's native consumers use, implemented by [`Engine`] as a thin pass-through over
//! the unchanged `egress::engine` free functions. Nothing here changes engine behavior and no
//! consumer is moved onto it yet (see the module-level doc on `egress` for the staging). This is
//! purely additive scaffolding: a later stage can (a) route `busbar-mcp`/`busbar-streaming`/
//! `busbar-llm` onto [`EgressEngine`] instead of `egress::engine::*`, and only once every native
//! consumer names the trait can (b) relocate the engine behind it, with zero fidelity loss at
//! either step — the trait already carries everything a full-fidelity caller needs:
//!
//! * [`EgressEngine::build_client`] + [`EgressEngine::Client`] — build the ONE pooled client
//!   ([`engine::EngineClient`]) from an [`engine::EngineSpec`], covering BOTH postures a native
//!   consumer builds today: [`engine::EngineSpec::pooled_webpki`] (busbar-streaming's own outbound
//!   client, `crates/busbar-streaming/src/mount.rs::egress_client`) and
//!   [`engine::EngineSpec::pinned`] (busbar-mcp's per-destination pinned pool,
//!   `crates/busbar-mcp/src/mcp/client/pool.rs::client_for`). `EngineSpec` itself is already
//!   neutral (lives in this crate) so its constructors need no trait indirection — only the BUILD
//!   step, which is the one call naming the concrete engine module, is on the trait.
//! * [`EgressEngine::request`] / [`EgressEngine::egress_request`] — assemble a request from
//!   precomputed parts. Two methods, not one, because they are two DIFFERENT shapes on purpose:
//!   `request` runs the reqwest-parity userinfo-to-`Authorization` rewrite for operator-spelled
//!   URLs (busbar-mcp's per-hop assembly, `mcp/upstream.rs`), while `egress_request` is the
//!   boot-precomputed, ZERO-per-request-branch POST assembly busbar-llm's hot path depends on
//!   (`busbar-llm/src/engine/attempt/assemble.rs`, `.../health.rs`) — collapsing them would put a
//!   branch back on a path that was hand-tuned to have none.
//! * [`EgressEngine::send_bounded`] — the full `http::Response<hyper::body::Incoming>` (the raw
//!   incoming, header map and all) under a deadline, classified into [`engine::HopError`] on
//!   failure. This is the exact fidelity `egress::seam::Buffered` cannot carry: busbar-mcp reads
//!   the upstream's real header map off this response (`mcp/upstream.rs`), and busbar-streaming's
//!   minted-credential HTTPS fetch (`topology/minter_https.rs`) does the same.
//! * [`EgressEngine::install_proxy_tunnel_if_configured`] — the boot-time CONNECT-tunnel env
//!   read every consumer's composition root calls once (busbar-llm:
//!   `engine/build_runtime.rs`); a no-op-safe call, re-exposed verbatim.
//!
//! Types the trait's methods traffic in — [`engine::EngineSpec`], [`engine::EngineClient`],
//! [`engine::HopError`], [`engine::ClientIdentity`], and the buffered [`super::Response`] /
//! [`super::StreamHead`] / [`super::ChunkFlow`] family — already live in this crate and are
//! already protocol-blind; the trait names them, it does not duplicate them. The pooled-client
//! cache a multi-destination consumer wants ([`super::PinnedClientPool`]) is likewise already
//! neutral and already keyed on the engine's own client handle; it needs no change to compose
//! with this trait.
//!
//! BYTE-IDENTITY: every method here is a direct, uninlined-in-spirit forward to the unchanged
//! `egress::engine` function of the same name. No consumer calls through this trait yet (that is
//! a later, separate stage), so today this module changes nothing any running binary does.

use bytes::Bytes;
use http_body_util::Full;

use super::engine::{self, EngineClient, EngineSpec, HopError};

/// THE FULL-FIDELITY NEUTRAL EGRESS ENGINE INTERFACE.
///
/// Associated functions, not `&self` methods: today's engine is a stack of free functions over
/// value types ([`EngineSpec`] in, [`EngineClient`]/[`http::Request`]/[`http::Response`] out), not
/// an object with instance state — an implementor is a zero-sized marker that names which
/// concrete engine backs the trait ([`Engine`] today; a relocated engine crate implements the
/// same trait unchanged tomorrow). A consumer that must hold a value (the pooled client itself)
/// already holds [`EgressEngine::Client`], not the marker.
pub trait EgressEngine {
    /// The pooled, cheap-clone client handle a native consumer holds across requests — today's
    /// [`engine::EngineClient`]. Bounded exactly as that type already is: cloning shares one pool,
    /// dropping the last clone closes its idle sockets.
    type Client: Clone + Send + Sync + 'static;

    /// Build ONE client for the spec's posture ([`EngineSpec::pooled_webpki`] or
    /// [`EngineSpec::pinned`]) — the one call that names the concrete engine module, so relocating
    /// the engine only ever touches this method's body.
    fn build_client(spec: &EngineSpec) -> Result<Self::Client, String>;

    /// Assemble one egress request from precomputed parts, running the reqwest-parity
    /// userinfo-to-`Authorization` rewrite for operator-spelled URLs. See [`engine::request`].
    fn request(
        method: http::Method,
        uri: http::Uri,
        headers: http::HeaderMap,
        body: Bytes,
    ) -> http::Request<Full<Bytes>>;

    /// Assemble one egress request from BOOT-PRECOMPUTED parts, POST only, with ZERO
    /// per-request branches — deliberately not [`EgressEngine::request`]. See
    /// [`engine::egress_request`].
    fn egress_request(
        uri: http::Uri,
        headers: http::HeaderMap,
        body: Bytes,
    ) -> http::Request<Full<Bytes>>;

    /// Send one request under an absolute deadline, returning the FULL raw incoming response
    /// (status, header map, and streaming body) or a classified [`HopError`]. The full-fidelity
    /// return this trait exists for — see [`engine::send_bounded`].
    fn send_bounded(
        client: &Self::Client,
        req: http::Request<Full<Bytes>>,
        deadline: tokio::time::Instant,
    ) -> impl std::future::Future<Output = Result<http::Response<hyper::body::Incoming>, HopError>> + Send;

    /// Resolve the boot-time proxy env once, installing it for every later
    /// [`EgressEngine::build_client`] call. See [`engine::install_proxy_tunnel_if_configured`].
    fn install_proxy_tunnel_if_configured() -> Result<(), String>;
}

/// THE CURRENT ENGINE, behind [`EgressEngine`] — a zero-sized marker; every method is a
/// byte-identical, no-logic-change forward to the `egress::engine` free function of the same
/// name. The neutral name later consumers call instead of naming `egress::engine::*` directly.
#[derive(Clone, Copy, Debug, Default)]
pub struct Engine;

impl EgressEngine for Engine {
    type Client = EngineClient;

    fn build_client(spec: &EngineSpec) -> Result<Self::Client, String> {
        engine::build_client(spec)
    }

    fn request(
        method: http::Method,
        uri: http::Uri,
        headers: http::HeaderMap,
        body: Bytes,
    ) -> http::Request<Full<Bytes>> {
        engine::request(method, uri, headers, body)
    }

    fn egress_request(
        uri: http::Uri,
        headers: http::HeaderMap,
        body: Bytes,
    ) -> http::Request<Full<Bytes>> {
        engine::egress_request(uri, headers, body)
    }

    async fn send_bounded(
        client: &Self::Client,
        req: http::Request<Full<Bytes>>,
        deadline: tokio::time::Instant,
    ) -> Result<http::Response<hyper::body::Incoming>, HopError> {
        engine::send_bounded(client, req, deadline).await
    }

    fn install_proxy_tunnel_if_configured() -> Result<(), String> {
        engine::install_proxy_tunnel_if_configured()
    }
}
