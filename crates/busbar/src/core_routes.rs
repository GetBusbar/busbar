// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The CORE route-auth table: every first-party route a router mounts, DECLARED as it is mounted.
//!
//! Plugin routes have carried their own declared [`RouteAuth`] since Wave 2.3
//! ([`crate::plugin_routes::PluginRouteTable::declared_auth`]). Core routes did not: the auth
//! middleware carried two hand-written path equalities (`path == "/healthz"`,
//! `path == "/auth/token"`) that were a PROCESS-wide statement about a route only one ROUTER
//! mounts. Two consequences, both real:
//!
//! - **Drift.** A core route added later gets whatever the middleware happens to say about its
//!   path, which is nothing, so the route's admission bar lives somewhere other than the route.
//! - **Plane leakage.** `/auth/token` is mounted on the data router alone, yet the process-wide
//!   bypass also waved it through on the admin listener, where an unauthenticated caller got a 404
//!   (the path is unknown here) rather than a 401 (you are not admitted here).
//!
//! This module makes the declaration and the mount ONE ACT. [`CoreRouter`] is the only way core
//! routes reach an axum [`Router`]: `route()` takes the handler AND the auth level together and
//! records the pair, so a mounted route without a declared bar cannot be written. The resulting
//! [`CoreRouteTable`] travels with the router it describes, is consulted by
//! `auth::auth_middleware`, and is ENUMERABLE — which is what lets a test walk the real mounted
//! surface and assert a property over every route, rather than over a hand-listed sample that a new
//! route silently escapes.
//!
//! The method mapping (`http::Method` → the declared method, HEAD folded onto GET because axum's
//! `MethodRouter` serves HEAD from the GET arm) is REUSED from `plugin_routes`, not re-derived: the
//! two tables answer the same question and a second copy is a second place to get HEAD wrong.

use crate::plugin_routes::{method_filter_of, route_method_of};
use crate::state::AppHandle;
use axum::http::Method;
use axum::routing::{on, MethodRouter};
use axum::Router;
use busbar_plugin_loader::{RouteAuth, RouteMethod};
use std::sync::Arc;

/// One core route as DECLARED at mount time: the exact axum path pattern, the method, and the
/// admission bar the auth middleware enforces before the handler runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreRoute {
    /// The axum path pattern this route is mounted at (`/stats`, `/{name}/v1/messages`, …).
    pub(crate) path: &'static str,
    /// The declared method. HEAD is not a separate entry: it resolves onto `Get` on lookup, exactly
    /// as axum resolves a HEAD request onto the GET arm.
    pub(crate) method: RouteMethod,
    /// The admission bar: `None` bypasses the chain, `Key` takes the data-plane bar, `Admin` is
    /// forced down the operator chain.
    pub(crate) auth: RouteAuth,
}

/// Every core route ONE router mounts, with its declared bar. Built only by [`CoreRouter`] (so the
/// table cannot disagree with the mount) and carried alongside the router it describes, because the
/// data plane and the admin plane mount different sets and a bypass belongs to the plane that
/// serves the route.
#[derive(Clone, Debug, Default)]
pub(crate) struct CoreRouteTable {
    routes: Vec<CoreRoute>,
}

impl CoreRouteTable {
    /// The declared auth level for `(path, method)`, or `None` when this router mounts no core
    /// route there — in which case the caller falls through to the plugin table and then to the
    /// normal data-plane bar. Exact path match only, never a prefix: a bypass that matched a prefix
    /// would hand every path below it the same free pass.
    pub(crate) fn declared_auth(&self, path: &str, method: &Method) -> Option<RouteAuth> {
        let rm = route_method_of(method)?;
        self.routes
            .iter()
            .find(|r| r.path == path && r.method == rm)
            .map(|r| r.auth)
    }

    /// Every declared route, in mount order. The enumeration a router-walking test iterates so a
    /// newly mounted route JOINS the assertion instead of escaping it. Read by the plane-boundary
    /// ratchet; production never enumerates (it only ever asks about one path).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn routes(&self) -> &[CoreRoute] {
        &self.routes
    }
}

/// The core-route builder: an axum [`Router`] and its [`CoreRouteTable`] grown together.
///
/// Nothing else may mount a core route. `route()` is the single act that both wires the handler and
/// records its bar, so "the router serves a path the table does not describe" is not a state this
/// type can produce.
pub(crate) struct CoreRouter {
    router: Router<Arc<AppHandle>>,
    table: CoreRouteTable,
}

impl CoreRouter {
    /// An empty router + empty table.
    pub(crate) fn new() -> Self {
        Self {
            router: Router::new(),
            table: CoreRouteTable::default(),
        }
    }

    /// Mount `handler` at `path` for `method`, declaring its admission bar in the same act.
    ///
    /// Calling this twice for one path with different methods MERGES into that path's single
    /// `MethodRouter` (axum's documented behaviour), so a wrong-method hit still yields the native
    /// 405 rather than the catch-all.
    pub(crate) fn route<H, T>(
        mut self,
        path: &'static str,
        method: RouteMethod,
        auth: RouteAuth,
        handler: H,
    ) -> Self
    where
        H: axum::handler::Handler<T, Arc<AppHandle>>,
        T: 'static,
    {
        self.table.routes.push(CoreRoute { path, method, auth });
        let mr: MethodRouter<Arc<AppHandle>> = on(method_filter_of(method), handler);
        self.router = self.router.route(path, mr);
        self
    }

    /// Apply an arbitrary router transformation that mounts NO core route — the plugin-route mount,
    /// the admin-transport nest, the catch-all fallback. Each is either separately declared (plugin
    /// routes keep their own table; the admin surface is gated by its `/api` prefix rule) or is not
    /// a route at all (a fallback claims no path).
    pub(crate) fn map_router(
        mut self,
        f: impl FnOnce(Router<Arc<AppHandle>>) -> Router<Arc<AppHandle>>,
    ) -> Self {
        self.router = f(self.router);
        self
    }

    /// Split into the mounted router and the table describing it.
    pub(crate) fn into_parts(self) -> (Router<Arc<AppHandle>>, CoreRouteTable) {
        (self.router, self.table)
    }
}
