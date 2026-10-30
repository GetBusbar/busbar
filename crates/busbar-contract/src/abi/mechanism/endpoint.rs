// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **endpoint** pair (an export sink's or a hook's served route): plugin route registration ([`Route`](crate::abi::mechanism::route::Route)) and the inbound-request dispatch
//! pair ([`EndpointRequest`] / [`EndpointResponse`]).
//!
//! ## Why a general primitive, not a metrics special-case
//!
//! `/metrics` (a pull exporter's exposition) and a routing hook's `/feedback` (external → plugin
//! input) are the SAME shape: an inbound HTTP request matched to a plugin-declared route, forwarded to
//! the plugin, its response relayed. This module is that one primitive. A plugin DECLARES its routes at
//! load ([`Route`](crate::abi::mechanism::route::Route), queried once, exactly like an export sink's `streams`), busbar reserves + collision-
//! checks them against the real route table, and a matched inbound request is dispatched to the plugin
//! via the [`EndpointRequest`]/[`EndpointResponse`] pair.
//!
//! ## Off the data-plane hot path
//!
//! Dispatch fires ONLY for a request that matched a REGISTERED plugin route — never for the
//! `/{name}/v1/messages` data-plane paths. busbar enforces the route's declared [`RouteAuth`](crate::abi::mechanism::route::RouteAuth) BEFORE
//! forwarding (a plugin never sees a request that failed its declared auth bar), and the forwarded
//! header set is a bounded, pre-filtered projection — never the raw `Authorization` header.

use serde::{Deserialize, Serialize};

/// One inbound HTTP request forwarded to a plugin on a matched, registered route. Built host-side from
/// the axum request AFTER the declared [`RouteAuth`](crate::abi::mechanism::route::RouteAuth) passed; `headers` is a BOUNDED, pre-filtered set
/// (never the raw `Authorization` header — busbar enforced the grant before forwarding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRequest {
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

/// A plugin's response to a dispatched [`EndpointRequest`], relayed verbatim by busbar (subject to
/// the same response-body-size and header-count caps every other proxied response respects).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointResponse {
    /// The HTTP status code the plugin chose.
    pub status: u16,
    /// The response headers the plugin set (bounded host-side on relay).
    pub headers: Vec<(String, String)>,
    /// The response body bytes.
    pub body: Vec<u8>,
}

#[cfg(test)]
#[path = "../tests/endpoint_tests.rs"]
mod tests;
