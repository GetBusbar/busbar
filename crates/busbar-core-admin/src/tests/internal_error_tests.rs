// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::internal_error;
use busbar_kernel::governance::RecordStoreError;

#[tokio::test]
async fn projects_a_500_internal_error_envelope() {
    let resp = internal_error("test_op", &RecordStoreError("boom".to_string()));
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "a store failure must answer 500, not the 200 `Response::default()` would give"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !body.is_empty(),
        "the body must carry the error envelope, not be empty like `Response::default()`"
    );
    let v: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON body");
    assert_eq!(v["error"]["code"], "internal");
}
