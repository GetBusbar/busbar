// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE VOCABULARY every kind that serves a route declares it in: a path, a method and the
//! auth bar the host enforces before a matched request reaches the plugin. One plain type, shared
//! by the mechanism (`BUSBAR-1.6.0.md` THE DESIGN, the closed ABI layout: the mechanism, one folder
//! per kind, the host tables and the SDK): hooks, export sinks and planes declare routes, and the
//! host's own routes are named in the same words. Each kind's `repr(C)` table form
//! carries the same three facts.

use serde::{Deserialize, Serialize};

/// The HTTP method a plugin route declares, and the method an inbound dispatch carries.
/// `#[serde(rename_all = "UPPERCASE")]` pins the wire spelling (`"GET"`/`"POST"`/…) so a plugin author
/// in any language matches a stable token, never the Rust variant name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RouteMethod {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
}

impl RouteMethod {
    /// The canonical uppercase HTTP method token (`"GET"`, …) — the same spelling that rides the wire,
    /// used verbatim in collision diagnostics (`GET /metrics`) and method matching.
    pub fn as_str(&self) -> &'static str {
        match self {
            RouteMethod::Get => "GET",
            RouteMethod::Post => "POST",
            RouteMethod::Put => "PUT",
            RouteMethod::Patch => "PATCH",
            RouteMethod::Delete => "DELETE",
        }
    }
}

/// The auth level busbar enforces (via its EXISTING auth middleware chain) BEFORE forwarding a request
/// to the plugin route. `#[serde(rename_all = "snake_case")]` pins the wire spelling
/// (`"none"`/`"key"`/`"admin"`).
///
/// - `None`: unauthenticated — busbar bypasses the auth chain for this exact route (like `/healthz`).
/// - `Key`: a valid busbar client token, the same bar every data-plane route enforces.
/// - `Admin`: the operator admin chain, and the route is confined to the ADMIN listener exactly like
///   `/api/v1/admin/*` (physically absent from the data listener).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAuth {
    /// Unauthenticated — the auth chain is bypassed for this exact route.
    None,
    /// A valid busbar client token (the data-plane bar).
    Key,
    /// The operator admin chain; the route is confined to the admin listener.
    Admin,
}

/// One HTTP route a plugin DECLARES it will serve. Collected once at load (an export sink via its
/// `routes` op, a hook via the same), collision-checked in the deterministic plugin scan order, and
/// namespace-confined by the registrar (a hook under `/hooks/<name>/*`; a metrics export sink may claim
/// the well-known `/metrics`). The plugin's self-report is never trusted to place a route OUTSIDE its
/// namespace — the confinement is enforced host-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// The absolute request path this route claims (e.g. `/metrics`, `/hooks/smart-router/feedback`).
    pub path: String,
    /// The HTTP method this route serves. A `{path, method}` pair is the collision key.
    pub method: RouteMethod,
    /// The auth level busbar enforces before forwarding a matched request to the plugin.
    pub auth: RouteAuth,
}

#[cfg(test)]
#[path = "../tests/route_tests.rs"]
mod tests;
