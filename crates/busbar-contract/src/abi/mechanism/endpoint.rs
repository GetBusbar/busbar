// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **endpoint** pair (an export sink's or a hook's served route): plugin route registration ([`Route`](crate::abi::mechanism::route::Route)) and the inbound-request dispatch

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
