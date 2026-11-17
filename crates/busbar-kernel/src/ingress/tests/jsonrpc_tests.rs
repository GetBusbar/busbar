// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::json::Value;

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
        let body: Value = busbar_contract::json::parse_value(&bytes).expect("a JSON body");
        assert_eq!(body["jsonrpc"], "2.0", "{body}");
        assert_eq!(body["id"], Value::new(), "{body}");
        assert_eq!(body["error"]["code"], INVALID_REQUEST, "{body}");
        assert_eq!(body["error"]["message"], "no", "{body}");
    }
}
