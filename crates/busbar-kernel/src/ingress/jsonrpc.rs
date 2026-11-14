// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use busbar_contract::jsonrpc::INVALID_REQUEST;

/// The JSON-RPC error envelope of a transport refusal, borrowed and serialized in member order:
/// `{"error":{"code":..,"message":..},"id":null,"jsonrpc":"2.0"}`.
#[derive(serde::Serialize)]
struct Refusal<'a> {
    error: RefusalError<'a>,
    id: (),
    jsonrpc: &'static str,
}

#[derive(serde::Serialize)]
struct RefusalError<'a> {
    code: i64,
    message: &'a str,
}

pub fn transport_refusal(status: StatusCode, message: &str) -> Response {
    (
        status,
        axum::Json(Refusal {
            error: RefusalError {
                code: INVALID_REQUEST,
                message,
            },
            id: (),
            jsonrpc: "2.0",
        }),
    )
        .into_response()
}

#[cfg(test)]
#[path = "tests/jsonrpc_tests.rs"]
mod jsonrpc_tests;
