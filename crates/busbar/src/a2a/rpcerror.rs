// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE ERROR ENVELOPE THIS PLANE ANSWERS IN.
//!
//! busbar's A2A ingress is a JSON-RPC 2.0 endpoint: a caller POSTs `{"jsonrpc":"2.0","id":…,
//! "method":…}` and, per JSON-RPC 2.0 §5, is owed either a `result` or an `error` object carrying an
//! INTEGER `code`, a `message`, and optionally `data` — in the same envelope, quoting the same `id`.
//!
//! It did not. Every refusal on this plane was answered as `{"error":{"code":"refused","message":…}}`
//! — busbar's ordinary gateway error body, with a STRING code, no `jsonrpc` member and no `id`. A
//! conformant A2A client reading it finds no error code at all, so a task that does not exist and a
//! caller with no grant are indistinguishable from a malformed server. Measured against the official
//! A2A TCK, that is what `JSONRPC-FMT-001` ("$.jsonrpc: expected '2.0', got None"),
//! `JSONRPC-ERR-001` ("Additional properties are not allowed ('param', 'type' were unexpected)"),
//! `JSONRPC-SSE-002` ("TaskNotFoundError should map to -32001, got None") and `JSONRPC-ERR-003`
//! ("error.data is absent") each report.
//!
//! ## The codes are the specification's, not ours
//!
//! A2A §5.4 binds each error type to a JSON-RPC code, an HTTP status and a gRPC status at once, and
//! carries a `google.rpc.ErrorInfo` in `error.data` naming the reason in a transport-independent
//! spelling. [`A2aError`] is that table, transcribed once. Nothing in this file invents a code, and
//! a busbar-specific condition is mapped to the NEAREST binding with the real reason in the message
//! rather than to a code the specification does not define — an invented code in the A2A range is
//! indistinguishable, to a client, from one the specification will define later.
//!
//! ## The HTTP status is kept, and that is deliberate
//!
//! Plain JSON-RPC convention answers `200` and puts everything in the body. This plane does not: a
//! refusal here is also an authorization event and an operator reading a proxy log is entitled to
//! see a `403` as a `403`. §5.4 defines an HTTP status for every error type precisely because A2A is
//! ALSO an HTTP+JSON protocol, so the status and the body come from the same row of one table and
//! cannot disagree. The TCK's JSON-RPC client reads the body regardless of status.

use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

/// The ProtoJSON type URL a `google.rpc.ErrorInfo` is tagged with, as A2A §5.4 requires it.
const ERROR_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ErrorInfo";

/// The domain every A2A `ErrorInfo` carries. Fixed by the specification, never this deployment's.
const ERROR_INFO_DOMAIN: &str = "a2a-protocol.org";

/// ONE ROW OF A2A §5.4: the error type, its JSON-RPC code, its HTTP status and its `ErrorInfo`
/// reason. A variant exists only where the specification defines one.
///
/// ## WHAT IS NOT BUILT, stated here rather than left to be discovered
///
/// `TaskNotFound`, `InvalidRequest` and `MethodNotFound` are **constructed by no production call
/// site on this plane**, and that is a statement about busbar's A2A ingress rather than about this
/// table. busbar is CONTENT-BLIND on the receiving side: it admits, meters, records and then relays
/// the caller's envelope to the backend agent VERBATIM, so it never reads `method`, never resolves
/// a task id of its own for a read, and therefore has no place from which to say "no such task" or
/// "no such method" — the backend says them, and busbar carries its answer back. The consequence
/// is real and is not hidden: a `GetTask` for a task busbar DID open but the backend never heard of
/// answers with the backend's opinion, not busbar's. Answering the task verbs locally out of
/// [`super::taskstore`] is the change that would give these three a caller; it is not made here.
/// The rows are kept because they are the specification's, and a table that omitted the codes we
/// do not yet emit would be a table somebody re-derives wrongly later.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum A2aError {
    /// The named task is not one this deployment holds for this caller.
    TaskNotFound,
    /// The task exists and is in a state from which cancellation is not defined.
    TaskNotCancelable,
    /// The caller asked for something this deployment does not do, or may not do for them. The
    /// nearest binding for busbar's own admission refusals; the message names the real reason.
    UnsupportedOperation,
    /// The backend agent did not answer something busbar could relay.
    InvalidAgentResponse,
    /// JSON-RPC §5.1: the body was not JSON.
    Parse,
    /// JSON-RPC §5.1: the body was JSON but not a JSON-RPC request object.
    InvalidRequest,
    /// JSON-RPC §5.1: no such method on this endpoint.
    MethodNotFound,
    /// JSON-RPC §5.1: the method exists and the params do not fit it.
    InvalidParams,
    /// JSON-RPC §5.1: busbar failed.
    Internal,
}

impl A2aError {
    /// The JSON-RPC code. A2A-specific errors live in `-32001..=-32099`, the rest are JSON-RPC's own.
    pub(crate) fn code(self) -> i32 {
        match self {
            A2aError::TaskNotFound => -32001,
            A2aError::TaskNotCancelable => -32002,
            A2aError::UnsupportedOperation => -32004,
            A2aError::InvalidAgentResponse => -32006,
            A2aError::InvalidRequest => -32600,
            A2aError::MethodNotFound => -32601,
            A2aError::InvalidParams => -32602,
            A2aError::Internal => -32603,
            A2aError::Parse => -32700,
        }
    }

    /// The `ErrorInfo.reason`, for the A2A-specific errors that have one. Standard JSON-RPC errors
    /// carry NO reason — the specification's own table leaves it unset, and inventing one would put
    /// a string in `error.data` that no conformant client knows.
    pub(crate) fn reason(self) -> Option<&'static str> {
        match self {
            A2aError::TaskNotFound => Some("TASK_NOT_FOUND"),
            A2aError::TaskNotCancelable => Some("TASK_NOT_CANCELABLE"),
            A2aError::UnsupportedOperation => Some("UNSUPPORTED_OPERATION"),
            A2aError::InvalidAgentResponse => Some("INVALID_AGENT_RESPONSE"),
            A2aError::Parse
            | A2aError::InvalidRequest
            | A2aError::MethodNotFound
            | A2aError::InvalidParams
            | A2aError::Internal => None,
        }
    }

    /// The HTTP status §5.4 binds this error to. `Parse` has none in the table — a body that is not
    /// JSON is a client fault, so `400`.
    pub(crate) fn http_status(self) -> u16 {
        match self {
            A2aError::TaskNotFound => 404,
            A2aError::TaskNotCancelable => 409,
            A2aError::UnsupportedOperation
            | A2aError::Parse
            | A2aError::InvalidRequest
            | A2aError::InvalidParams => 400,
            A2aError::InvalidAgentResponse => 502,
            A2aError::MethodNotFound => 404,
            A2aError::Internal => 500,
        }
    }
}

/// THE ERROR BODY, and nothing else builds one on this plane.
///
/// `id` is the caller's own, echoed as JSON-RPC 2.0 §5 requires; `Null` where the request could not
/// be parsed far enough to have one, which is what the specification says to send.
pub(crate) fn body(id: &Value, err: A2aError, message: impl Into<String>) -> Value {
    let mut error = json!({ "code": err.code(), "message": message.into() });
    if let Some(reason) = err.reason() {
        // `data` IS AN ARRAY. A2A §5.4 carries `google.rpc.ErrorInfo` in a ProtoJSON `details`
        // array, and the JSON-RPC binding puts that same array in `data`. An object here would be
        // the same information in a shape no conformant client unpacks.
        error["data"] = json!([{
            "@type": ERROR_INFO_TYPE,
            "domain": ERROR_INFO_DOMAIN,
            "reason": reason,
        }]);
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

/// The ProtoJSON type URL of `google.rpc.ResourceInfo`, which is how the task a refusal is about
/// travels. See [`about_task`].
const RESOURCE_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ResourceInfo";

/// The busbar task id this resource name is built under, so a reader can tell an A2A task from
/// anything else that might one day travel the same way.
const TASK_RESOURCE_TYPE: &str = "a2a.busbar/task";

/// THE SAME ERROR, NAMING THE TASK BUSBAR OPENED.
///
/// A relayed submission that fails has already produced a durable task row, and the caller needs
/// its id to correlate what they were told with what busbar recorded. That id used to ride as a
/// `taskId` member of the error object — which JSON-RPC 2.0 §5 does not admit (`code`, `message`,
/// `data`, and nothing else) and which the TCK rejects by schema. It is not dropped: `data` is a
/// ProtoJSON ARRAY, so the id travels as a `google.rpc.ResourceInfo` beside the `ErrorInfo`, which
/// is both machine-readable and exactly where a conformant client looks for it.
pub(crate) fn about_task(
    id: &Value,
    err: A2aError,
    message: impl Into<String>,
    task_id: &str,
) -> Value {
    let mut doc = body(id, err, message);
    let entry = json!({
        "@type": RESOURCE_INFO_TYPE,
        "resourceType": TASK_RESOURCE_TYPE,
        "resourceName": task_id,
    });
    match doc["error"]["data"].as_array_mut() {
        Some(data) => data.push(entry),
        None => doc["error"]["data"] = json!([entry]),
    }
    doc
}

/// The same body, as a response, with the status §5.4 binds to this error.
pub(crate) fn respond(id: &Value, err: A2aError, message: impl Into<String>) -> Response {
    (
        axum::http::StatusCode::from_u16(err.http_status())
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        axum::Json(body(id, err, message)),
    )
        .into_response()
}

/// The caller's JSON-RPC `id`, or `Null`. Read from a body that may be anything at all, because the
/// error path is reached for bodies that are not requests.
pub(crate) fn id_of(envelope: &Value) -> Value {
    envelope.get("id").cloned().unwrap_or(Value::Null)
}

#[cfg(test)]
#[path = "tests/rpcerror_tests.rs"]
mod rpcerror_tests;
