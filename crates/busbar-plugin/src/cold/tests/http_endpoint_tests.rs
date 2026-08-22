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
