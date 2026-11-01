// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `abi/mechanism/endpoint.rs`.

use super::*;

/// Independently authored JSON fixes the field names, ordered header pairs and byte-array body.
#[test]
fn endpoint_request_json_preserves_the_dispatch_fields() {
    let wire = serde_json::json!({
        "method": "POST",
        "path": "/hooks/example/submit",
        "query": "key=a%2Fb&key=c+d",
        "headers": [["x-tag", "first"], ["x-tag", "second"]],
        "body": [0, 127, 128, 255]
    });
    let decoded: EndpointRequest = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(decoded.method, "POST");
    assert_eq!(decoded.path, "/hooks/example/submit");
    assert_eq!(decoded.query, "key=a%2Fb&key=c+d");
    assert_eq!(
        decoded
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
        [("x-tag", "first"), ("x-tag", "second")]
    );
    assert_eq!(decoded.body, [0, 127, 128, 255]);

    let req = EndpointRequest {
        method: "POST".into(),
        path: "/hooks/example/submit".into(),
        query: "key=a%2Fb&key=c+d".into(),
        headers: vec![
            ("x-tag".into(), "first".into()),
            ("x-tag".into(), "second".into()),
        ],
        body: vec![0, 127, 128, 255],
    };
    assert_eq!(serde_json::to_value(&req).unwrap(), wire);
}

#[test]
fn endpoint_response_json_preserves_status_headers_and_arbitrary_body_bytes() {
    let wire = serde_json::json!({
        "status": 409,
        "headers": [["content-type", "application/octet-stream"], ["x-tag", "first"], ["x-tag", "second"]],
        "body": [255, 0, 128, 10]
    });
    let decoded: EndpointResponse = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(decoded.status, 409);
    assert_eq!(
        decoded
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
        [
            ("content-type", "application/octet-stream"),
            ("x-tag", "first"),
            ("x-tag", "second")
        ]
    );
    assert_eq!(decoded.body, [255, 0, 128, 10]);
    let resp = EndpointResponse {
        status: 409,
        headers: vec![
            ("content-type".into(), "application/octet-stream".into()),
            ("x-tag".into(), "first".into()),
            ("x-tag".into(), "second".into()),
        ],
        body: vec![255, 0, 128, 10],
    };
    assert_eq!(serde_json::to_value(&resp).unwrap(), wire);
}
