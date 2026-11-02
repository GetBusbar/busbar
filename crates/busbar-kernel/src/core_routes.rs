// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::plugin_routes::{method_filter_of, route_method_of};
use crate::state::AppHandle;
use axum::http::Method;
use axum::routing::{on, MethodRouter};
use axum::Router;
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use std::sync::Arc;

/// One core route as DECLARED at mount time: the exact axum path pattern, the method, and the
/// admission bar the auth middleware enforces before the handler runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreRoute {
    /// The axum path pattern this route is mounted at (`/stats`, `/{name}/v1/messages`, …).
    ///
    /// OWNED rather than `&'static str`, because not every core route's path is a literal: a plane's
    /// ingress can mount at a path component derived from operator config (a canonical URI), plus a
    /// companion metadata document at a well-known path with that path appended. Those
    /// are knowable at mount time and nowhere earlier. The alternative — leaking a `String` to get a
    /// `'static` — would leak once per config apply, forever, to satisfy a lifetime nothing needs;
    /// the alternative to THAT (a prefix exemption under `/.well-known/`) would hand a free pass to
    /// every path beneath it, which is exactly the discipline this table exists to hold.
    pub(crate) path: String,
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
    /// The LOOKUP INDEX over `routes`, maintained in the same single act that grows it
    /// ([`CoreRouter::route`]), so the two cannot disagree. Keyed by the exact path, with the tiny
    /// per-path method list inline: [`declared_auth`] sits on the auth middleware's per-request hot
    /// path, and the linear `routes` scan it replaced was a per-request O(N) String-compare walk —
    /// measurable at benchmark rates precisely because every request pays it whether or not it
    /// names a core route. A `HashMap<String, _>` is queried by `&str` through `Borrow`, so the
    /// lookup allocates nothing.
    by_path: std::collections::HashMap<String, Vec<(RouteMethod, RouteAuth)>>,
    /// THE DOOR ROUTES' UNIT-LESS REFUSALS (spec Part 3 section 12): each door route's plane
    /// rendering, at the route's own path and method. Empty on every router that serves no door.
    door_refusals: Vec<busbar_kernel::plane_routes::PlaneRefusalSpec>,
}

impl CoreRouteTable {
    pub(crate) fn declared_auth(&self, path: &str, method: &Method) -> Option<RouteAuth> {
        let rm = route_method_of(method)?;
        self.by_path
            .get(path)?
            .iter()
            .find(|(m, _)| *m == rm)
            .map(|(_, a)| *a)
    }

    #[must_use]
    pub(crate) fn with_door_refusals(
        mut self,
        refusals: Vec<busbar_kernel::plane_routes::PlaneRefusalSpec>,
    ) -> Self {
        self.door_refusals = refusals;
        self
    }

    pub(crate) fn door_refusal(
        &self,
        path: &str,
        method: &Method,
    ) -> Option<&busbar_kernel::plane_routes::PlaneRefuseFn> {
        if self.door_refusals.is_empty() {
            return None;
        }
        let rm = route_method_of(method)?;
        self.door_refusals
            .iter()
            .find(|r| r.route.method == rm && route_matches(&r.route.path, path))
            .map(|r| &r.refuse)
    }

    pub(crate) fn door_ticket(&self, path: &str, method: &Method) -> Option<&str> {
        if self.door_refusals.is_empty() {
            return None;
        }
        let rm = route_method_of(method)?;
        self.door_refusals
            .iter()
            .find(|r| r.route.method == rm && route_matches(&r.route.path, path))
            .and_then(|r| r.ticket_prefix.as_deref())
    }

    pub(crate) fn signed_ingress(&self, path: &str) -> bool {
        use busbar_contract::abi::plane::check::raw_affix_matches;
        self.door_refusals
            .iter()
            .flat_map(|r| r.signed_ingress.iter())
            .any(|target| raw_affix_matches(target, path))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn routes(&self) -> &[CoreRoute] {
        &self.routes
    }
}

pub struct CoreRouter {
    router: Router<Arc<AppHandle>>,
    table: CoreRouteTable,
}

impl CoreRouter {
    pub(crate) fn new() -> Self {
        Self {
            router: Router::new(),
            table: CoreRouteTable::default(),
        }
    }

    pub fn route<H, T>(
        mut self,
        path: impl Into<String>,
        method: RouteMethod,
        auth: RouteAuth,
        handler: H,
    ) -> Self
    where
        H: axum::handler::Handler<T, Arc<AppHandle>>,
        T: 'static,
    {
        let path = path.into();
        let mr: MethodRouter<Arc<AppHandle>> = on(method_filter_of(method), handler);
        self.router = self.router.route(&path, mr);

        self.table
            .by_path
            .entry(path.clone())
            .or_default()
            .push((method, auth));
        self.table.routes.push(CoreRoute { path, method, auth });
        self
    }

    pub fn map_router(
        mut self,
        f: impl FnOnce(Router<Arc<AppHandle>>) -> Router<Arc<AppHandle>>,
    ) -> Self {
        self.router = f(self.router);
        self
    }

    pub(crate) fn methods_at(&self, path: &str) -> Vec<RouteMethod> {
        self.table
            .by_path
            .get(path)
            .map(|rows| rows.iter().map(|(m, _)| *m).collect())
            .unwrap_or_default()
    }

    pub(crate) fn into_parts(self) -> (Router<Arc<AppHandle>>, CoreRouteTable) {
        (self.router, self.table)
    }
}

fn route_matches(route: &str, path: &str) -> bool {
    let mut want = route.split('/');
    let mut got = path.split('/');
    loop {
        match (want.next(), got.next()) {
            (None, None) => return true,
            (Some(w), Some(g)) if w.starts_with("{*") && w.ends_with('}') => {
                return !g.is_empty() || got.next().is_some();
            }
            (Some(w), Some(g)) if w.starts_with('{') && w.ends_with('}') => {
                if g.is_empty() {
                    return false;
                }
            }
            (Some(w), Some(g)) if w == g => {}
            _ => return false,
        }
    }
}

#[cfg(test)]
#[path = "tests/core_routes_door_refusal.rs"]
mod door_refusal_tests;
