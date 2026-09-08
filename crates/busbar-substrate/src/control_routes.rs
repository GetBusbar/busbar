// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONTROL-ROUTE SEAM — how an unmetered CONTROL SURFACE contributes the routes it answers on,
//! without naming a router, a transport, or the act of mounting.
//!
//! ## What a control surface is, and why it needed a seam of its own
//!
//! There are two families of served things. A **data plane** (`llm`, `mcp`, `a2a`, `streams`) is
//! metered and runs the full step list; a **control surface** (the admin API, and the OAuth 2.1
//! issuer) is UNMETERED, declares its routes as data, and runs the control path — verify, admit,
//! audit, answer — and nothing else.
//!
//! The plane axis already had a route seam ([`crate::plane_routes`]). A control surface cannot use
//! it, and the reason is not a type mismatch: `PlaneRouteSpec` arrives through
//! [`crate::plane::registry::PlaneDecl`], whose other twenty-odd fields are the METERED vocabulary —
//! `scope_kinds`, `audit_kind`, `admission`, `claims`, `meter`. A control surface that registered as
//! a plane would be declaring a scope kind it has no meter for and an audience binding it does not
//! bind, and the boot seal would either refuse it or, worse, admit it as a plane with the meter
//! silently vacuous. So the declaration is separate, and it is deliberately SMALLER: a key, and the
//! routes.
//!
//! ## Why NOT the root's admin wrapper, which is the other thing that looks like this
//!
//! The composition root already mounts one control surface — the admin API — and it does it by
//! WRAPPING the finished router in a fallback that claims a path prefix and passes everything else
//! through. That shape is not reusable here, and the reason is a security one rather than a
//! stylistic one: the wrapper sits OUTSIDE the node's auth middleware, so a route mounted through it
//! carries no row in the core route table and gets no declared admission bar. The admin API can
//! afford that because it re-authenticates every request in its own kernel steps. The OAuth issuer
//! cannot: its consent screen's whole design is that the OPERATOR has already been identified by the
//! node's existing admin chain before the handler runs, and moving it outside the middleware would
//! either drop that bar or make the surface grow a second opinion about who an operator is — which
//! is the exact duplication that surface was built not to have.
//!
//! So a control route is mounted through the SAME `CoreRouter::route` call a plane route is,
//! recording the same `(path, method, auth)` row in the same table. Only the DECLARATION differs,
//! and only in being smaller.
//!
//! ## The rule this seam makes checkable
//!
//! **A control surface answers on exactly the paths it declares, and the composition mounts exactly
//! what it declared.** No `mount`, no `serve`, no `bind` appears on a control surface's ABI; the
//! composition reads [`ControlDecl::routes`] and mounts the rows verbatim.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::HeaderMap;
use busbar_plugin::cold::http_endpoint::{RouteAuth, RouteMethod};

/// A control route's response — an ordinary `axum` response, returned verbatim by the core adapter.
pub type ControlResponse = axum::response::Response;

/// The boxed, `Send` future a control handler returns. Boxed because the handler is stored behind a
/// `dyn Fn`; `Send` because the core adapter awaits it inside an `axum` handler future.
pub type ControlRouteFuture = Pin<Box<dyn Future<Output = ControlResponse> + Send>>;

/// One control-route HANDLER: a neutral async fn over a [`ControlReqCtx`].
pub type ControlRouteFn = Arc<dyn Fn(ControlReqCtx) -> ControlRouteFuture + Send + Sync>;

/// One route a control surface DECLARES.
///
/// The first three fields are handed VERBATIM to `CoreRouter::route` by the core adapter, so the
/// route-table row this records is identical to the one a hand-written mount recorded — which is the
/// property that lets a surface move out of core without any of its admission bars moving with it.
pub struct ControlRouteSpec {
    /// The exact axum path pattern this route is mounted at. Owned because a control surface's paths
    /// are derived at mount time from its own configuration (the OAuth issuer's paths hang off the
    /// operator's `issuer`, so a tenant-prefixed one mounts under that prefix).
    pub path: String,
    /// The declared HTTP method.
    pub method: RouteMethod,
    /// The admission bar the core auth middleware enforces BEFORE the handler runs. Must match what
    /// the surface declared, or its security posture drifts.
    pub auth: RouteAuth,
    /// The neutral handler the core adapter awaits, having built a [`ControlReqCtx`] from the
    /// request.
    pub handler: ControlRouteFn,
}

/// The per-request context the core adapter builds and hands a control handler.
///
/// DELIBERATELY SMALLER than [`crate::plane_routes::PlaneReqCtx`], and the difference is the point:
/// there is no `gov`, no `principal`, no `caller_principal`, no `host` and no `engine` here. A
/// control surface is unmetered and reaches node state through contracts, so handing it the resolved
/// governance context would be handing it the vocabulary it is defined by not having. What it gets
/// is the request and its own surface object, and nothing else.
pub struct ControlReqCtx {
    /// The full request URI (path + query), exactly as it arrived.
    pub uri: axum::http::Uri,
    /// The request headers, verbatim.
    pub headers: HeaderMap,
    /// The buffered request body (already subject to the router's body-size cap layer, which fires
    /// BEFORE this handler).
    pub body: Bytes,
    /// The surface's own runtime object for this config generation, type-erased. The surface
    /// downcasts it to its own type; the SEAM names no surface type.
    pub surface: Arc<dyn Any + Send + Sync>,
}

/// EVERYTHING THE COMPOSITION KNOWS ABOUT A CONTROL SURFACE, declared once.
///
/// Two fields. That is not an omission — it is the difference between a control surface and a plane
/// written down: a plane declares a meter class, a scope kind, an audit kind, an audience binding
/// and a claim ladder, and a control surface declares a name and a route table.
pub struct ControlDecl {
    /// The registry key — the surface's one word, in a log line and in the boot seal. Also the key
    /// its runtime object is held under, so the composition can find the slot a route belongs to.
    pub key: &'static str,

    /// THE ROUTES THIS SURFACE ANSWERS ON, computed from its own type-erased runtime object.
    ///
    /// Called ONCE per config generation, at mount time, only when the surface has a slot this
    /// generation. A surface the operator did not configure has no slot and this is never called —
    /// which is what "costs nothing when it is off" means at the routing layer.
    #[allow(clippy::type_complexity)]
    pub routes: fn(&dyn Any) -> Vec<ControlRouteSpec>,
}

impl std::fmt::Debug for ControlDecl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlDecl")
            .field("key", &self.key)
            .finish()
    }
}

/// The composition root's ONE write into the control axis.
static INSTALLED: std::sync::OnceLock<&'static [&'static ControlDecl]> = std::sync::OnceLock::new();

/// INSTALL CONTROL-SURFACE DECLARATIONS — the composition root's one write, and the seam a control
/// crate registers through.
///
/// There is no built-in list to merge with, and there is not going to be one: a control surface is a
/// plugin by construction, so "the built-in control surfaces" would be the same closed match the
/// plane registry exists to have removed. An empty install is a legal, and cheap, deployment.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
pub fn install_control_surfaces(decls: &'static [&'static ControlDecl]) {
    assert!(
        INSTALLED.set(decls).is_ok(),
        "install_control_surfaces called twice: there is one composition root, and it registers once"
    );
}

/// The process control-surface list, in registration order. Empty until the root writes, and empty
/// forever in a build that installs none.
///
/// Registration order is preserved rather than sorted: it is the order routes are mounted in, and a
/// route table an operator read in one release should not reorder itself in the next.
pub fn control_decls() -> &'static [&'static ControlDecl] {
    INSTALLED.get().copied().unwrap_or(&[])
}

#[cfg(test)]
#[path = "tests/control_routes_tests.rs"]
mod control_routes_tests;
