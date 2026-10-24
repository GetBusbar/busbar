// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's one JSON-RPC body: a refusal made before any envelope was read.

use super::*;

/// The transport's status survives (only the body is JSON-RPC's), the id is Null because none was
/// established, and the code is `-32600`, never a parse error for a body nothing parsed.
#[tokio::test]
async fn a_transport_refusal_keeps_its_status_and_names_no_id() {
    for status in [
        StatusCode::PAYLOAD_TOO_LARGE,
        StatusCode::NOT_FOUND,
        StatusCode::METHOD_NOT_ALLOWED,
    ] {
        let r = transport_refusal(status, "no");
        assert_eq!(r.status(), status);
        let bytes = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).expect("a JSON body");
        assert_eq!(body["jsonrpc"], "2.0", "{body}");
        assert_eq!(body["id"], Value::Null, "{body}");
        assert_eq!(body["error"]["code"], INVALID_REQUEST, "{body}");
        assert_eq!(body["error"]["message"], "no", "{body}");
    }
}
