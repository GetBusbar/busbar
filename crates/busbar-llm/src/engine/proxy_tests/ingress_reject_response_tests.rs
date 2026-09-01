// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `ingress_reject_response` — the one place `IngressReject` becomes a caller-dialect HTTP response.
//! `BadRequest` must keep today's exact 400; `UnsupportedSubOp` (the second 404 site) must become
//! a 404 naming both the operation and the model, not collapse into the generic 400 the two
//! `proxy/wire.rs` `Err(_)` call sites used to produce for every `IngressReject` alike.

use super::*;

#[tokio::test]
async fn unsupported_sub_op_rejects_with_404_naming_op_and_model() {
    let resp = ingress_reject_response(
        "openai",
        &busbar_core::handlers::IngressReject::UnsupportedSubOp {
            op: busbar_core::operation::Operation::IMAGE,
            model: "dall-e-2".into(),
        },
    );
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let detail = v["error"]["message"].as_str().unwrap_or_default();
    assert!(
        detail.contains("image") && detail.contains("dall-e-2"),
        "detail must name both the operation and the model: {detail}"
    );
    // AND IT MUST NAME IT WITH THE PUBLISHED IDENTIFIER, not with a Rust `Debug` rendering. Until
    // 1.6.0 this string was `format!("{op:?}")`, so it read `Image` — the enum variant's spelling
    // on the wire in front of a customer. The moment the axis grew a field that same expression
    // rendered `Verb { op: Invoke, name: "image" }`, which is what caught it. Assert the leak is
    // gone rather than only that the word is present, because `contains("image")` alone is true of
    // the leaking form too.
    assert!(
        !detail.contains("Verb") && !detail.contains("OpShape") && !detail.contains("Invoke"),
        "the 404 detail must carry `Operation::name`, never the type's Debug shape: {detail}"
    );
}

#[tokio::test]
async fn bad_request_reject_keeps_the_unchanged_generic_400() {
    let resp = ingress_reject_response(
        "openai",
        &busbar_core::handlers::IngressReject::BadRequest("x".into()),
    );
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v["error"]["message"].as_str(),
        Some("We could not process the content of your request.")
    );
}
