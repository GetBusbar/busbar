// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **HTTP endpoint** wire (kind = [`crate::kind::EXPORT`] / [`crate::kind::HOOK`]) that rides the
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The method tokens are the stable UPPERCASE wire spellings a non-Rust author matches on, and
    /// [`RouteMethod::as_str`] agrees with the serde spelling (the diagnostic + wire cannot drift).
    #[test]
    fn method_wire_spellings_are_pinned() {
        for (m, tok) in [
            (RouteMethod::Get, "GET"),
            (RouteMethod::Post, "POST"),
            (RouteMethod::Put, "PUT"),
            (RouteMethod::Patch, "PATCH"),
            (RouteMethod::Delete, "DELETE"),
        ] {
            assert_eq!(serde_json::to_value(m).unwrap(), serde_json::json!(tok));
            assert_eq!(m.as_str(), tok);
        }
    }

    /// The auth tokens are the stable snake_case wire spellings.
    #[test]
    fn auth_wire_spellings_are_pinned() {
        for (a, tok) in [
            (RouteAuth::None, "none"),
            (RouteAuth::Key, "key"),
            (RouteAuth::Admin, "admin"),
        ] {
            assert_eq!(serde_json::to_value(a).unwrap(), serde_json::json!(tok));
        }
    }

    /// A route declaration round-trips through JSON unchanged.
    #[test]
    fn route_json_roundtrip() {
        let r = Route {
            path: "/hooks/smart-router/feedback".into(),
            method: RouteMethod::Post,
            auth: RouteAuth::Key,
        };
        let j = serde_json::to_vec(&r).unwrap();
        let back: Route = serde_json::from_slice(&j).unwrap();
        assert_eq!(back, r);
    }

    /// The request/response dispatch pair round-trips through JSON unchanged (the wire is stable).
    #[test]
    fn request_response_json_roundtrip() {
        let req = HttpEndpointRequest {
            method: "GET".into(),
            path: "/metrics".into(),
            query: "format=prometheus".into(),
            headers: vec![("accept".into(), "text/plain".into())],
            body: Vec::new(),
        };
        let j = serde_json::to_vec(&req).unwrap();
        let back: HttpEndpointRequest = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);

        let resp = HttpEndpointResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"busbar_up 1\n".to_vec(),
        };
        let j = serde_json::to_vec(&resp).unwrap();
        let back: HttpEndpointResponse = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);
    }
}
