// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL ROUTE-MOUNT SEAM (S4a Option A): the vocabulary a plane uses to DECLARE the data
//! routes it answers on WITHOUT naming a core router type or `Arc<AppHandle>`.
//!
//! Before this seam a plane's data routes were contributed through `PlaneDecl::mount`, a
//! `fn(CoreRouter, &dyn Any) -> CoreRouter` — a field whose TYPE named `busbar_core::core_routes::CoreRouter`
//! and whose handlers extracted `axum::State<Arc<busbar_core::state::AppHandle>>`. Both bound the
//! plane to core: the field could not live in a neutral crate, and the handler bodies reached the
//! whole engine through the router state.
//!
//! This module replaces that with a flat, transport-agnostic DESCRIPTION. A plane returns a
//! [`Vec<PlaneRouteSpec>`] — each spec is a `(path, method, auth, handler)` quadruple where the
//! handler is a neutral async fn over a [`PlaneReqCtx`]. The CORE-side adapter
//! (`busbar_core::router`) is the single place that still names `CoreRouter` / `Arc<AppHandle>`: it
//! iterates the specs, and per spec calls the EXISTING `CoreRouter::route(path, method, auth, …)` —
//! so the security-critical `CoreRouteTable` rows (path, method, [`RouteAuth`]) are recorded by the
//! same act as before and stay BYTE-IDENTICAL. Only the handler's SHAPE changed: it receives a
//! [`PlaneReqCtx`] the adapter builds from the request extractors, never the extractors themselves.
//!
//! The seam names only neutral vocabulary — `axum` (already a substrate dependency), the
//! `busbar-plugin` route enums, and the `busbar-api` request-context types — so a `PlaneDecl` field
//! typed `fn(&dyn Any) -> Vec<PlaneRouteSpec>` names no core type and can travel to this crate.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::HeaderMap;
use busbar_plugin::cold::http_endpoint::{RouteAuth, RouteMethod};

/// A plane route's response — an ordinary `axum` response, returned verbatim by the core adapter.
/// `axum::response::Response` is already a substrate-visible type (the JSON-RPC ingress returns it),
/// so a plane frames its answer with no re-encode at the seam.
pub type PlaneResponse = axum::response::Response;

/// The boxed, `Send` future a plane handler returns. Boxed because the handler is stored behind a
/// `dyn Fn` (a plane contributes a heterogeneous list of them); `Send` because the core adapter
/// awaits it inside an `axum` handler future, which must be `Send`.
pub type PlaneRouteFuture = Pin<Box<dyn Future<Output = PlaneResponse> + Send>>;

/// One plane data-route HANDLER: a neutral async fn over a [`PlaneReqCtx`]. `Arc<dyn Fn…>` because a
/// plane returns many of them in one `Vec` and the core adapter clones each into the per-request
/// `axum` closure it mounts.
pub type PlaneRouteFn = Arc<dyn Fn(PlaneReqCtx) -> PlaneRouteFuture + Send + Sync>;

/// One data route a plane DECLARES: the exact path, the method, the admission bar, and the neutral
/// handler. The first three are handed VERBATIM to `CoreRouter::route` by the core adapter, so the
/// `CoreRouteTable` row this route records is identical to the one the old `mount` fn recorded.
pub struct PlaneRouteSpec {
    /// The exact axum path pattern this route is mounted at. Owned because a plane's paths are
    /// derived at mount time from its runtime slot (the MCP door is the operator's canonical URI).
    pub path: String,
    /// The declared HTTP method.
    pub method: RouteMethod,
    /// The admission bar the core auth middleware enforces BEFORE the handler runs — the value that
    /// lands in the `CoreRouteTable` and that `declared_auth` reads. Must match the old mount's
    /// declaration exactly, or the route's security posture drifts.
    pub auth: RouteAuth,
    /// The neutral handler the core adapter awaits, having built a [`PlaneReqCtx`] from the request.
    pub handler: PlaneRouteFn,
}

/// The per-request context the core adapter builds and hands a plane handler — everything the handler
/// needs to answer, sourced from the SAME extractors the old typed handlers used, but assembled by
/// core so the plane names no `axum` extractor and no `Arc<AppHandle>` router state.
///
/// The auth-carried fields ([`Self::gov`], [`Self::principal`], [`Self::caller_principal`]) are the
/// ALREADY-RESOLVED identity the auth middleware attached to the request BEFORE the handler runs —
/// surfaced here rather than re-derived, so a `Key`-auth handler reads the resolved caller without
/// re-running the identity chain (which would double-run it and change behaviour). They are `Option`
/// because a `RouteAuth::None` route (an open metadata document) reaches its handler WITHOUT the auth
/// middleware attaching them — exactly as the old open handlers took only `CurrentApp`.
pub struct PlaneReqCtx {
    /// The request path this route was matched at.
    pub path: String,
    /// The request method.
    pub method: RouteMethod,
    /// The request headers.
    pub headers: HeaderMap,
    /// The buffered request body (already subject to the router's body-size cap layer, which fires
    /// BEFORE this handler, exactly as before).
    pub body: Bytes,
    /// Any path-template captures (`{name}` → value), in match order. Empty for a concrete-path
    /// route (every current MCP route). Present so a parameterised plane route can read its captures
    /// without an `axum::extract::Path` extractor.
    pub path_params: Vec<(String, String)>,
    /// The resolved caller principal id — the authenticated key id, or `None` on an ungoverned or
    /// open route. The one identity fact a `Key`-auth handler needs to bind request-scoped state to
    /// the caller, surfaced from the middleware-resolved [`Self::gov`] so the handler never re-runs
    /// the identity chain.
    pub caller_principal: Option<String>,
    /// The middleware-resolved governance request context (the caller's virtual key), or `None` on a
    /// `RouteAuth::None` route where the middleware bypassed the chain and attached nothing.
    pub gov: Option<busbar_api::PlaneRequestCtx>,
    /// The middleware-resolved auth principal, or `None` on a `RouteAuth::None` route.
    pub principal: Option<busbar_api::AuthPrincipal>,
    /// The live engine handle, type-erased. The core adapter erases the router's `Arc<AppHandle>`
    /// state here; a plane still coupled to the engine downcasts it (a transitional reach that the
    /// per-subsystem App-sever removes), but the SEAM names no core type.
    pub engine: Arc<dyn Any + Send + Sync>,
    /// The NEUTRAL host seam — the `EngineHost` the core adapter minted over the request's live
    /// engine snapshot, so the plane reaches host capabilities (the clock, and later gate/govern/…)
    /// by calling typed methods on it rather than naming `busbar_core::plane_host::*_over`. Carried
    /// alongside `engine` during the transition: `engine` is the residual downcast the per-subsystem
    /// App-sever removes, `host` is the durable seam that replaces it.
    pub host: Arc<dyn crate::plane_host::EngineHost>,
    /// The plane's own per-generation runtime slot (the same `Arc<dyn Any>` the plane's `build` fn
    /// produced), so the handler reads its plane state without a host round-trip.
    pub slot: Arc<dyn Any + Send + Sync>,
}
