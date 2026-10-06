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

impl EndpointResponse {
    /// The plugin-chosen [`status`](Self::status), VALIDATED via [`safe_relay_status`] — a real HTTP
    /// status code, or `502` when the plugin returned an out-of-range value. THE conversion a host
    /// relay must use instead of `StatusCode::from_u16(self.status).unwrap()`.
    #[must_use]
    pub fn safe_status(&self) -> u16 {
        safe_relay_status(self.status)
    }
}

#[cfg(test)]
#[path = "../tests/endpoint_tests.rs"]
mod tests;
