// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use busbar_contract::jsonrpc::{error_body, INVALID_REQUEST};
use serde_json::Value;

pub fn transport_refusal(status: StatusCode, message: &str) -> Response {
    (
        status,
        axum::Json(error_body(Value::Null, INVALID_REQUEST, message, None)),
    )
        .into_response()
}

#[cfg(test)]
#[path = "tests/jsonrpc_tests.rs"]
mod jsonrpc_tests;
