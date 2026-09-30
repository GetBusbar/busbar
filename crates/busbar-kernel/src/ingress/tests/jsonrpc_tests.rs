// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's half of the envelope: the HTTP answers built from the reader's verdicts. What the
//! reader decides is proven beside it, in `busbar-contract`'s `jsonrpc_tests`.

use super::*;

#[test]
fn a_refusal_is_a_400_and_a_notification_ack_is_a_202_with_no_body() {
    assert_eq!(
        refused(&Invalid {
            code: INVALID_REQUEST,
            message: "no",
            id: serde_json::Value::Null,
        })
        .status(),
        axum::http::StatusCode::BAD_REQUEST
    );
    assert_eq!(parse_error().status(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(accepted().status(), axum::http::StatusCode::ACCEPTED);
}
