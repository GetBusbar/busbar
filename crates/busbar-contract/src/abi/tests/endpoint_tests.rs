// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `abi/mechanism/endpoint.rs`.

use super::*;

/// The request/response dispatch pair round-trips through JSON unchanged (the wire is stable).
#[test]
fn request_response_json_roundtrip() {
    let req = EndpointRequest {
        method: "GET".into(),
        path: "/metrics".into(),
        query: "format=prometheus".into(),
        headers: vec![("accept".into(), "text/plain".into())],
        body: Vec::new(),
    };
    let j = serde_json::to_vec(&req).unwrap();
    let back: EndpointRequest = serde_json::from_slice(&j).unwrap();
    assert_eq!(serde_json::to_vec(&back).unwrap(), j);

    let resp = EndpointResponse {
        status: 200,
        headers: vec![("content-type".into(), "text/plain".into())],
        body: b"busbar_up 1\n".to_vec(),
    };
    let j = serde_json::to_vec(&resp).unwrap();
    let back: EndpointResponse = serde_json::from_slice(&j).unwrap();
    assert_eq!(serde_json::to_vec(&back).unwrap(), j);
}
