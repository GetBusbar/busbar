// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-abi/src/http_endpoint.rs`.

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

/// Plugin#6 regression: a plugin-chosen `status` is validated at the response boundary. An
/// out-of-range value maps to `502`, never to a status that would panic a host relay's
/// `StatusCode::from_u16(status).unwrap()`; a real HTTP status passes through unchanged.
#[test]
fn out_of_range_plugin_status_maps_to_502() {
    // Out-of-range / nonsensical statuses all become 502.
    for bad in [0u16, 9, 99, 600, 999, 65535] {
        assert_eq!(
            safe_relay_status(bad),
            502,
            "status {bad} must clamp to 502"
        );
        let resp = HttpEndpointResponse {
            status: bad,
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert_eq!(resp.safe_status(), 502);
        // Proof it never panics a real relay conversion.
        assert!(axum_status_ok(resp.safe_status()));
    }
    // Real HTTP statuses pass through untouched.
    for ok in [100u16, 200, 204, 302, 404, 429, 500, 599] {
        assert_eq!(safe_relay_status(ok), ok);
        assert!(axum_status_ok(ok));
    }
}

/// The relay contract, checked without an `http` dep (busbar-plugin carries none): a validated status
/// is always in `100..=599`, a strict subset of the `100..=999` a host relay's `StatusCode::from_u16`
/// accepts — so the conversion the real relay performs can never fail (never `.unwrap()`-panic).
fn axum_status_ok(status: u16) -> bool {
    (100..=599).contains(&status)
}
