// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL ROUTE-MOUNT SEAM (S4a Option A): the vocabulary a plane uses to DECLARE the data
//! routes it answers on WITHOUT naming a core router type or `Arc<AppHandle>`.
//!
//! Before this seam a plane's data routes were contributed through `PlaneDecl::mount`, a
//! `fn(CoreRouter, &dyn Any) -> CoreRouter` — a field whose TYPE named `busbar_kernel::core_routes::CoreRouter`
//! and whose handlers extracted `axum::State<Arc<busbar_kernel::state::AppHandle>>`. Both bound the
//! plane to core: the field could not live in a neutral crate, and the handler bodies reached the
//! whole engine through the router state.
//!
//! This module replaces that with a flat, transport-agnostic DESCRIPTION. A plane returns a
//! [`Vec<PlaneRouteSpec>`] — each spec is a `(path, method, auth, handler)` quadruple where the
//! handler is a neutral async fn over a [`PlaneReqCtx`]. The CORE-side adapter
//! (`busbar_kernel::router`) is the single place that still names `CoreRouter` / `Arc<AppHandle>`: it
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
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};

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

/// A DOOR ROUTE'S UNIT-LESS REFUSAL (spec Part 3 section 12, "Refusals"): the response its plane
/// renders, through its `refusal` op in the route's refusal dialect, for a refusal the kernel decided
/// before any unit exists — `reason`, for the request `target` (path and query). The kernel's auth
/// chokepoint still decides; this only words its answer in the plane's dialect.
pub type PlaneRefuseFn =
    Arc<dyn Fn(busbar_contract::caps::ReasonCode, &str) -> PlaneResponse + Send + Sync>;

/// THE ROUTE IDENTITY a door route and its unit-less refusal share: the route's axum path pattern,
/// as mounted, and its method. One key for both, so the two cannot name different routes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DoorRouteId {
    /// The axum path pattern.
    pub path: String,
    /// The method.
    pub method: RouteMethod,
}

/// One door route's unit-less refusal, keyed by the route's identity ([`DoorRouteId`]): the data
/// router records it beside the route's admission bar, and the auth middleware renders a `401` it
/// decides on that route through it, instead of the residual data plane's envelope.
#[derive(Clone)]
pub struct PlaneRefusalSpec {
    /// The door route it words the `401` of.
    pub route: DoorRouteId,
    /// Its plane's rendering.
    pub refuse: PlaneRefuseFn,
}

impl std::fmt::Debug for PlaneRefusalSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneRefusalSpec")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

/// THE DOOR ROUTES AND THEIR REFUSALS, PAIRED (ARCHITECT 2026-10-06): every door route that takes a
/// credential (`RouteAuth::Key`; its request routes, and its session routes, which answer `GET`) has
/// exactly one refusal spec under its identity, and every refusal spec names such a route. Checked
/// at boot, before the data router is built, so the side table cannot drift from the routes it
/// words.
///
/// # Errors
///
/// The first door route with no refusal, refusal with no door route, or identity refused twice.
pub fn pair_door_refusals(
    routes: &[PlaneRouteSpec],
    sessions: &[PlaneSessionSpec],
    refusals: &[PlaneRefusalSpec],
) -> Result<(), String> {
    let credentialed: Vec<DoorRouteId> = routes
        .iter()
        .filter(|r| matches!(r.auth, RouteAuth::Key))
        .map(PlaneRouteSpec::route_id)
        .chain(
            sessions
                .iter()
                .filter(|s| matches!(s.auth, RouteAuth::Key))
                .map(PlaneSessionSpec::route_id),
        )
        .collect();
    let mut seen: std::collections::HashSet<&DoorRouteId> = std::collections::HashSet::new();
    for r in refusals {
        if !seen.insert(&r.route) {
            return Err(format!(
                "the door route {} {} has two refusal specs; one route words its 401 once",
                r.route.method.as_str(),
                r.route.path
            ));
        }
        if !credentialed.contains(&r.route) {
            return Err(format!(
                "a refusal spec names {} {}, which is no door route that takes a credential",
                r.route.method.as_str(),
                r.route.path
            ));
        }
    }
    if let Some(bare) = credentialed.iter().find(|id| !seen.contains(id)) {
        return Err(format!(
            "the door route {} {} takes a credential and has no refusal spec: its 401 would be \
             worded in another plane's dialect",
            bare.method.as_str(),
            bare.path
        ));
    }
    Ok(())
}

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

impl PlaneRouteSpec {
    /// Its identity ([`DoorRouteId`]): the path pattern it is mounted at and its method.
    #[must_use]
    pub fn route_id(&self) -> DoorRouteId {
        DoorRouteId {
            path: self.path.clone(),
            method: self.method,
        }
    }
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
    /// The full request URI (path + query). Present so a plane route can read its query string
    /// (`uri.query()`) without an `axum::extract::Query` extractor — the A2A REST task/list/push
    /// handlers parse their query params off this. Additive; planes that need only the path ignore it.
    pub uri: axum::http::Uri,
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
    pub gov: Option<busbar_contract::records::PlaneRequestCtx>,
    /// The middleware-resolved auth principal, or `None` on a `RouteAuth::None` route.
    pub principal: Option<busbar_contract::auth::AuthPrincipal>,
    /// The caller's verified credential as the auth gate extracted it, lent for the host's egress
    /// alone (a passthrough member's outbound auth call); `None` when the caller presented none or
    /// the route bypassed the gate. A plane handler never reads it.
    pub caller_credential: Option<busbar_contract::redacted::Redacted<Vec<u8>>>,
    /// The live engine handle, type-erased. The core adapter erases the router's `Arc<AppHandle>`
    /// state here; a plane still coupled to the engine downcasts it (a transitional reach that the
    /// per-subsystem App-sever removes), but the SEAM names no core type.
    pub engine: Arc<dyn Any + Send + Sync>,
    /// The NEUTRAL host seam — the `EngineHost` the core adapter minted over the request's live
    /// engine snapshot, so the plane reaches host capabilities (the clock, and later gate/govern/…)
    /// by calling typed methods on it rather than naming `busbar_kernel::plane_host::*_over`. Carried
    /// alongside `engine` during the transition: `engine` is the residual downcast the per-subsystem
    /// App-sever removes, `host` is the durable seam that replaces it.
    pub host: Arc<dyn crate::plane_host::EngineHost>,
    /// The plane's own per-generation runtime slot (the same `Arc<dyn Any>` the plane's `build` fn
    /// produced), so the handler reads its plane state without a host round-trip.
    pub slot: Arc<dyn Any + Send + Sync>,
}

// ── SESSION ROUTES (TRANSITIONAL: deleted when INBOUND-LISTEN's accepted::Caller serves) ─────────

/// One frame toward a session route's caller: its bytes, and whether they are ONE text message
/// (the plane answered `PIECE_OUT_TEXT`); otherwise one binary message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOut {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// One text message.
    pub text: bool,
}

/// THE CALLER'S SIDE OF AN ADMITTED SESSION ROUTE, as the core adapter carries it over today's
/// hyper upgrade (ARCHITECT Q-L5B-SESSION-SERVE 2026-10-03, the `IngressCaller` pattern): each
/// message the caller sends goes into `from_caller` (dropped when the caller closes); every frame the
/// session writes comes out of `to_caller` (the socket closes when its sender is dropped).
#[derive(Debug)]
pub struct SessionPipe {
    /// The caller's messages, one per message, text or binary, as bytes.
    pub from_caller: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// The frames toward the caller.
    pub to_caller: tokio::sync::mpsc::Receiver<SessionOut>,
}

/// What a session route's handler answers, before any upgrade: refused with a finished response (no
/// socket ever binds), or admitted with the pipe the upgraded socket is bridged onto.
pub enum SessionAnswer {
    /// Refused before the upgrade: this response goes out as it is.
    Refused(PlaneResponse),
    /// Admitted: the core answers the upgrade and bridges the socket onto this pipe.
    Accepted(SessionPipe),
}

/// The boxed future a session route's handler returns.
pub type PlaneSessionFuture = Pin<Box<dyn Future<Output = SessionAnswer> + Send>>;

/// One session route's HANDLER: a neutral async fn over the route's [`PlaneReqCtx`] (its body empty:
/// an upgrade carries none).
pub type PlaneSessionFn = Arc<dyn Fn(PlaneReqCtx) -> PlaneSessionFuture + Send + Sync>;

/// One SESSION route a door plane's claim declares: its path and admission bar (recorded in the
/// `CoreRouteTable` exactly as a data route's), answered on GET by an upgrade the core adapter
/// accepts only once the handler admitted the session.
pub struct PlaneSessionSpec {
    /// The exact axum path pattern.
    pub path: String,
    /// The admission bar the core auth middleware enforces before the handler runs.
    pub auth: RouteAuth,
    /// The handler.
    pub handler: PlaneSessionFn,
}

impl PlaneSessionSpec {
    /// Its identity ([`DoorRouteId`]): the path pattern it is mounted at, and `GET` (an upgrade is
    /// an HTTP GET).
    #[must_use]
    pub fn route_id(&self) -> DoorRouteId {
        DoorRouteId {
            path: self.path.clone(),
            method: RouteMethod::Get,
        }
    }
}

#[cfg(test)]
#[path = "tests/plane_routes_pairing.rs"]
mod pairing_tests;
