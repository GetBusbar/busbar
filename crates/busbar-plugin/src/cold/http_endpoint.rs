// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **HTTP endpoint** wire (kind = [`crate::cold::kind::EXPORT`] / [`crate::cold::kind::HOOK`]) that rides the
//! kind-neutral `call`: plugin HTTP route registration ([`Route`]) and the inbound-request dispatch
//! pair ([`HttpEndpointRequest`] / [`HttpEndpointResponse`]).
//!
//! ## Why a general primitive, not a metrics special-case
//!
//! `/metrics` (a pull exporter's exposition) and a routing hook's `/feedback` (external → plugin
//! input) are the SAME shape: an inbound HTTP request matched to a plugin-declared route, forwarded to
//! the plugin, its response relayed. This module is that one primitive. A plugin DECLARES its routes at
//! load ([`Route`], queried once, exactly like an export sink's `streams`), busbar reserves + collision-
//! checks them against the real route table, and a matched inbound request is dispatched to the plugin
//! via the [`HttpEndpointRequest`]/[`HttpEndpointResponse`] pair.
//!
//! ## Off the data-plane hot path
//!
//! Dispatch fires ONLY for a request that matched a REGISTERED plugin route — never for the
//! `/{name}/v1/messages` data-plane paths. busbar enforces the route's declared [`RouteAuth`] BEFORE
//! forwarding (a plugin never sees a request that failed its declared auth bar), and the forwarded
//! header set is a bounded, pre-filtered projection — never the raw `Authorization` header.

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

/// One inbound HTTP request forwarded to a plugin on a matched, registered route. Built host-side from
/// the axum request AFTER the declared [`RouteAuth`] passed; `headers` is a BOUNDED, pre-filtered set
/// (never the raw `Authorization` header — busbar enforced the grant before forwarding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEndpointRequest {
    /// The uppercase HTTP method (`"GET"` | `"POST"` | …), validated host-side against the DECLARED
    /// method before dispatch.
    pub method: String,
    /// The full matched path (post-namespace-confinement).
    pub path: String,
    /// The raw query string (no leading `?`); the plugin parses its own params.
    pub query: String,
    /// A bounded, pre-filtered header set. Never carries the raw `Authorization` header.
    pub headers: Vec<(String, String)>,
    /// The request body bytes (subject to the host's request-body cap before it reaches here).
    pub body: Vec<u8>,
}

/// A plugin's response to a dispatched [`HttpEndpointRequest`], relayed verbatim by busbar (subject to
/// the same response-body-size and header-count caps every other proxied response respects).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEndpointResponse {
    /// The HTTP status code the plugin chose.
    pub status: u16,
    /// The response headers the plugin set (bounded host-side on relay).
    pub headers: Vec<(String, String)>,
    /// The response body bytes.
    pub body: Vec<u8>,
}

/// The safe HTTP status a host relay must use for a plugin-chosen status, so an out-of-range or
/// nonsensical value maps to `502` (Bad Gateway) rather than panicking. `502` is the neutral
/// "upstream (here, the plugin) misbehaved" code, matching the relay's existing over-cap rejection.
///
/// The vulnerability this closes: a naive relay doing `StatusCode::from_u16(status).unwrap()` PANICS
/// on attacker data — `from_u16` rejects anything outside `100..=999`, and `0` / `65535` / `9` are
/// all trivially plugin-chosen. Validating at the plugin-response boundary means the relay never sees
/// an unrepresentable status. The accepted range is the real HTTP status range (`100..=599`), a
/// strict subset of what `StatusCode::from_u16` accepts, so the result can never itself fail a later
/// `from_u16`.
#[must_use]
pub fn safe_relay_status(status: u16) -> u16 {
    match status {
        100..=599 => status,
        _ => 502,
    }
}

impl HttpEndpointResponse {
    /// The plugin-chosen [`status`](Self::status), VALIDATED via [`safe_relay_status`] — a real HTTP
    /// status code, or `502` when the plugin returned an out-of-range value. THE conversion a host
    /// relay must use instead of `StatusCode::from_u16(self.status).unwrap()`.
    #[must_use]
    pub fn safe_status(&self) -> u16 {
        safe_relay_status(self.status)
    }
}

#[cfg(test)]
#[path = "tests/http_endpoint_tests.rs"]
mod tests;
