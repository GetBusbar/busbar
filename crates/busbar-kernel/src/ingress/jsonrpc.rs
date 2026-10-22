// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE JSON-RPC BODY THE KERNEL STILL WRITES: a refusal on a mounted plane's path that was made
//! before any envelope could be read (`crate::ingress::native::native_error`'s mounted arm).
//!
//! The envelope reader, its codes and the notification acknowledgement are not the kernel's: the
//! pure reader is `busbar_contract::jsonrpc` (legacy fold ruling F4), and the sequence that read an
//! envelope and answered a notification `202` is each plane's own arrive check (BUSBAR-1.6.0.md
//! l.5024).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use busbar_contract::jsonrpc::{error_body, INVALID_REQUEST};
use serde_json::Value;

/// The JSON-RPC answer to a refusal made BEFORE any envelope could be read — an oversized body the
/// transport capped, a path with no handler, a method the transport does not allow.
///
/// Three decisions, and each for its own reason:
///
/// * **`id` is Null.** Section 5: *"If there was an error in detecting the id in the Request object
///   … it MUST be Null."* No body was read, so no id was ever established. This is exactly the case
///   the clause describes, rather than a convenient default.
/// * **The code is `-32600`.** The message is one the server will not honour. `-32700` would claim
///   the JSON failed to parse, which is a different and untrue statement about a body that was
///   never parsed at all.
/// * **The STATUS is the caller's**, not `400`. The transport's own refusal (`413`, `404`, `405`)
///   is a fact about the HTTP hop that every proxy and dashboard between the peers reads, and
///   flattening it to `400` would discard it. Only the BODY is JSON-RPC's.
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
