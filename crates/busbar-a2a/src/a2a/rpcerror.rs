// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE ERROR ENVELOPE THIS PLANE ANSWERS IN.
//!
//! busbar's A2A ingress is a JSON-RPC 2.0 endpoint: a caller POSTs `{"jsonrpc":"2.0","id":…,
//! "method":…}` and, per JSON-RPC 2.0 section 5, is owed either a `result` or an `error` object
//! carrying an INTEGER `code`, a `message`, and optionally `data` — in the same envelope, quoting
//! the same `id`.
//!
//! It did not. Every refusal on this plane was answered as
//! `{"error":{"code":"refused","message":…}}` — busbar's ordinary gateway error body, with a STRING
//! code, no `jsonrpc` member and no `id`. A conformant A2A client reading it finds no error code at
//! all, so a task that does not exist and a caller with no grant are indistinguishable from a
//! malformed server. Measured against the official A2A TCK, that is what `JSONRPC-FMT-001`
//! ("$.jsonrpc: expected '2.0', got None"), `JSONRPC-ERR-001` ("Additional properties are not
//! allowed ('param', 'type' were unexpected)"), `JSONRPC-SSE-002` ("TaskNotFoundError should map to
//! -32001, got None") and `JSONRPC-ERR-003` ("error.data is absent") each report.
//!
//! ## The codes are the specification's, not ours
//!
//! A2A section 5.4 binds each error type to a JSON-RPC code, an HTTP status and a gRPC status at
//! once, and carries a `google.rpc.ErrorInfo` in `error.data` naming the reason in a
//! transport-independent spelling. [`A2aError`] is that table, transcribed once. Nothing in this
//! file invents a code, and a busbar-specific condition is mapped to the NEAREST binding with the
//! real reason in the message rather than to a code the specification does not define — an invented
//! code in the A2A range is indistinguishable, to a client, from one the specification will define
//! later.
//!
//! ## The HTTP status is kept, and that is deliberate
//!
//! Plain JSON-RPC convention answers `200` and puts everything in the body. This plane does not: a
//! refusal here is also an authorization event and an operator reading a proxy log is entitled to
//! see a `403` as a `403`. section 5.4 defines an HTTP status for every error type precisely
//! because A2A is ALSO an HTTP+JSON protocol, so the status and the body come from the same row of
//! one table and cannot disagree. The TCK's JSON-RPC client reads the body regardless of status.

use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

/// The ProtoJSON type URL a `google.rpc.ErrorInfo` is tagged with, as A2A section 5.4 requires it.
pub(crate) const ERROR_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ErrorInfo";

/// The domain every A2A `ErrorInfo` carries. Fixed by the specification, never this deployment's.
const ERROR_INFO_DOMAIN: &str = "a2a-protocol.org";

/// ONE ROW OF A2A section 5.4: the error type, its JSON-RPC code, its HTTP status and its
/// `ErrorInfo` reason. A variant exists only where the specification defines one.
///
/// ## WHAT IS NOT BUILT, stated here rather than left to be discovered
///
/// `TaskNotFound` and `MethodNotFound` are **constructed by no production call site on this
/// plane**, and that is a statement about busbar's A2A ingress rather than about this
/// table. busbar is CONTENT-BLIND on the receiving side: it admits, meters, records and then relays
/// the caller's envelope to the backend agent VERBATIM, so it never reads `method`, never resolves
/// a task id of its own for a read, and therefore has no place from which to say "no such task" or
/// "no such method" — the backend says them, and busbar carries its answer back. The consequence
/// is real and is not hidden: a `GetTask` for a task busbar DID open but the backend never heard of
/// answers with the backend's opinion, not busbar's. Answering the task verbs locally out of
/// [`busbar_core::plane::taskstore`] is the change that would give these two a caller; it is not made here.
/// The rows are kept because they are the specification's, and a table that omitted the codes we
/// do not yet emit would be a table somebody re-derives wrongly later.
///
/// `InvalidRequest` USED to be on that list and no longer is: the ingress now runs every body past
/// `busbar_substrate::ingress::jsonrpc::read` before admission, so an envelope that is JSON and is not a
/// JSON-RPC request is refused here, on this plane's own wire, with this code. Being content-blind
/// about a caller's `params` never meant being blind to the ENVELOPE those params arrive in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum A2aError {
    /// The named task is not one this deployment holds for this caller.
    TaskNotFound,
    /// The task exists and is in a state from which cancellation is not defined.
    TaskNotCancelable,
    /// A2A section 5.4 `PushNotificationNotSupportedError`: the caller asked to configure push
    /// notifications for a task on a backend that does not offer them. section 5.4 binds it to gRPC
    /// `UNIMPLEMENTED` / HTTP 400 — a capability the server does not implement. A variant so a
    /// relayed backend `-32003` carries through with its own semantics rather than collapsing to a
    /// gateway fault.
    PushNotificationNotSupported,
    /// A2A section 5.4 `ExtensionSupportRequiredError`: the request needs a protocol extension the
    /// served endpoint does not support. section 5.4 binds it to gRPC `FAILED_PRECONDITION` / HTTP 400 —
    /// a well-formed request the served configuration cannot satisfy.
    ExtensionSupportRequired,
    /// The caller asked for something this deployment does not do, or may not do for them. The
    /// nearest binding for busbar's own admission refusals; the message names the real reason.
    UnsupportedOperation,
    /// The request's media type is not one this endpoint reads. A2A's JSON-RPC binding carries
    /// `application/json` and nothing else; this is the answer owed to a caller that sent something
    /// else, and it is DISTINCT from [`A2aError::Parse`] — "I will not read this" is a different
    /// fact from "I read it and it was not JSON", and only the first tells the caller to fix a
    /// header rather than a body.
    ContentTypeNotSupported,
    /// The backend agent did not answer something busbar could relay.
    InvalidAgentResponse,
    /// The card declares `capabilities.extendedAgentCard` and this deployment has no extended card
    /// to give. See [`super::serve::extended_card`]: busbar always HAS one when it fronts anything
    /// at all, so the one deployment shape that reaches this is one that fronts nothing.
    ExtendedAgentCardNotConfigured,
    /// The caller's `A2A-Version` names a protocol version this endpoint does not speak. See
    /// [`super::receive`] for which versions busbar claims and what makes each claim true.
    VersionNotSupported,
    /// JSON-RPC section 5.1: the body was not JSON.
    Parse,
    /// JSON-RPC section 5.1: the body was JSON but not a JSON-RPC request object.
    InvalidRequest,
    /// JSON-RPC section 5.1: no such method on this endpoint.
    MethodNotFound,
    /// JSON-RPC section 5.1: the method exists and the params do not fit it.
    InvalidParams,
    /// JSON-RPC section 5.1: busbar failed.
    Internal,
}

impl A2aError {
    /// The JSON-RPC code. A2A-specific errors live in `-32001..=-32099`, the rest are JSON-RPC's
    /// own.
    pub(crate) fn code(self) -> i32 {
        match self {
            A2aError::TaskNotFound => -32001,
            A2aError::TaskNotCancelable => -32002,
            A2aError::PushNotificationNotSupported => -32003,
            A2aError::UnsupportedOperation => -32004,
            A2aError::ContentTypeNotSupported => -32005,
            A2aError::InvalidAgentResponse => -32006,
            A2aError::ExtendedAgentCardNotConfigured => -32007,
            A2aError::ExtensionSupportRequired => -32008,
            A2aError::VersionNotSupported => -32009,
            A2aError::InvalidRequest => -32600,
            A2aError::MethodNotFound => -32601,
            A2aError::InvalidParams => -32602,
            A2aError::Internal => -32603,
            A2aError::Parse => -32700,
        }
    }

    /// THE gRPC STATUS CODE for this error — the third column of the same A2A section 5.4 table the
    /// JSON-RPC code and the HTTP status are read out of, transcribed here rather than re-derived
    /// beside the gRPC service.
    ///
    /// It is a `tonic::Code` and not a string because the wire value is a number: a `grpc-status`
    /// trailer carries the integer, and spelling the name at the boundary would put a second
    /// mapping between this table and the wire for a client to disagree with.
    ///
    /// THE FOUR ROWS THE SPECIFICATION LEAVES BLANK are the standard JSON-RPC errors, which A2A
    /// gives no gRPC binding because JSON-RPC's envelope does not exist on this transport. They
    /// still have to answer SOMETHING, so each takes the gRPC status that means the same thing —
    /// a malformed request is `INVALID_ARGUMENT`, an unknown method is `UNIMPLEMENTED`, a server
    /// fault is `INTERNAL`. That is a decision about what to SAY where the table is silent, and it
    /// is made once, here, rather than at each of eleven call sites.
    pub(crate) fn grpc_status(self) -> tonic::Code {
        match self {
            A2aError::TaskNotFound => tonic::Code::NotFound,
            // FAILED_PRECONDITION for exactly the three rows section 5.4 binds to it: the request is
            // well formed and the deployment's configuration is what cannot satisfy it. See the
            // spec's own section 5.4 table (`specification.md`): `TaskNotCancelableError`,
            // `ExtendedAgentCardNotConfiguredError` and `ExtensionSupportRequiredError` are
            // FAILED_PRECONDITION; the three "…NotSupported"/version rows below are NOT.
            A2aError::TaskNotCancelable
            | A2aError::ExtendedAgentCardNotConfigured
            | A2aError::ExtensionSupportRequired => tonic::Code::FailedPrecondition,
            // UNIMPLEMENTED, and it is the SPECIFICATION'S own binding, not a guess. A2A section 5.4 maps
            // `PushNotificationNotSupportedError` (-32003), `UnsupportedOperationError` (-32004) and
            // `VersionNotSupportedError` (-32009) to gRPC `UNIMPLEMENTED` — a capability the server
            // does not implement, which is what each of these three refusals is. These once mapped
            // to FAILED_PRECONDITION here, transcribed from the busbar harness's own (wrong)
            // `a2aht/spec.py::ERROR_MAP`; that disagreed with the publisher's section 5.4 table and the
            // official TCK's `GRPC-ERR-002`, which is what it cost. The HTTP status stays 400 — a
            // different column of the same row, and already correct.
            A2aError::PushNotificationNotSupported
            | A2aError::UnsupportedOperation
            | A2aError::VersionNotSupported => tonic::Code::Unimplemented,
            A2aError::ContentTypeNotSupported => tonic::Code::InvalidArgument,
            A2aError::InvalidAgentResponse | A2aError::Internal => tonic::Code::Internal,
            A2aError::MethodNotFound => tonic::Code::Unimplemented,
            A2aError::Parse | A2aError::InvalidRequest | A2aError::InvalidParams => {
                tonic::Code::InvalidArgument
            }
        }
    }

    /// The `ErrorInfo.reason`, for the A2A-specific errors that have one. Standard JSON-RPC errors
    /// carry NO reason — the specification's own table leaves it unset, and inventing one would put
    /// a string in `error.data` that no conformant client knows.
    pub(crate) fn reason(self) -> Option<&'static str> {
        match self {
            A2aError::TaskNotFound => Some("TASK_NOT_FOUND"),
            A2aError::TaskNotCancelable => Some("TASK_NOT_CANCELABLE"),
            A2aError::PushNotificationNotSupported => Some("PUSH_NOTIFICATION_NOT_SUPPORTED"),
            A2aError::ExtensionSupportRequired => Some("EXTENSION_SUPPORT_REQUIRED"),
            A2aError::UnsupportedOperation => Some("UNSUPPORTED_OPERATION"),
            A2aError::ContentTypeNotSupported => Some("CONTENT_TYPE_NOT_SUPPORTED"),
            A2aError::InvalidAgentResponse => Some("INVALID_AGENT_RESPONSE"),
            A2aError::ExtendedAgentCardNotConfigured => Some("EXTENDED_AGENT_CARD_NOT_CONFIGURED"),
            A2aError::VersionNotSupported => Some("VERSION_NOT_SUPPORTED"),
            A2aError::Parse
            | A2aError::InvalidRequest
            | A2aError::MethodNotFound
            | A2aError::InvalidParams
            | A2aError::Internal => None,
        }
    }

    /// THE CANONICAL STATUS NAME — the `gRPC Status` column of A2A section 5.4, which AIP-193 puts
    /// in `error.status` on the HTTP+JSON binding.
    ///
    /// It is the SAME column for both bindings, and that is why it is a method on this table rather
    /// than a second table beside the REST framing: section 5.4 binds one error type to a JSON-RPC
    /// code, a gRPC status and an HTTP status AT ONCE, so a REST refusal and the JSON-RPC refusal
    /// for the same condition cannot disagree about which condition it was.
    ///
    /// The standard JSON-RPC errors have no row of their own in that table. Each is mapped to the
    /// canonical name for what it IS — a malformed request is `INVALID_ARGUMENT`, an unknown method
    /// is `UNIMPLEMENTED` — rather than to a name invented for the occasion.
    pub(crate) fn status(self) -> &'static str {
        match self {
            A2aError::TaskNotFound => "NOT_FOUND",
            // FAILED_PRECONDITION for exactly the three rows section 5.4 binds to it: a well-formed
            // request the served configuration cannot satisfy. This is the SAME row `grpc_status`
            // reads `Code::FailedPrecondition` out of, kept in lockstep with it by construction.
            A2aError::TaskNotCancelable
            | A2aError::ExtendedAgentCardNotConfigured
            | A2aError::ExtensionSupportRequired => "FAILED_PRECONDITION",
            // UNIMPLEMENTED, the section 5.4 canonical name for a capability the server does not implement.
            // The three "…NotSupported"/version rows share it with `MethodNotFound`, and it is the
            // same binding `grpc_status` answers `Code::Unimplemented` with — one row, one name.
            A2aError::PushNotificationNotSupported
            | A2aError::UnsupportedOperation
            | A2aError::VersionNotSupported
            | A2aError::MethodNotFound => "UNIMPLEMENTED",
            A2aError::ContentTypeNotSupported
            | A2aError::Parse
            | A2aError::InvalidRequest
            | A2aError::InvalidParams => "INVALID_ARGUMENT",
            A2aError::InvalidAgentResponse | A2aError::Internal => "INTERNAL",
        }
    }

    /// THE ERROR TYPE A BACKEND'S JSON-RPC CODE NAMES, or `None` for a code A2A does not define.
    ///
    /// Used to carry a relayed backend's error SEMANTICS through busbar without carrying its words.
    /// A gateway that collapsed every backend error to "the upstream failed" would report a task
    /// that does not exist as a gateway fault — the caller cannot tell a typo from an outage, and
    /// the specification's whole section 5.4 mapping is lost at the hop. The code is a protocol
    /// fact and is carried; the backend's `message` is its own prose and is not. The REASON is
    /// re-derived from the code through the table below rather than echoed, so nothing a backend
    /// writes reaches a caller even inside `data`.
    pub(crate) fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            -32001 => A2aError::TaskNotFound,
            -32002 => A2aError::TaskNotCancelable,
            -32003 => A2aError::PushNotificationNotSupported,
            -32004 => A2aError::UnsupportedOperation,
            -32005 => A2aError::ContentTypeNotSupported,
            -32006 => A2aError::InvalidAgentResponse,
            -32007 => A2aError::ExtendedAgentCardNotConfigured,
            -32008 => A2aError::ExtensionSupportRequired,
            -32009 => A2aError::VersionNotSupported,
            -32600 => A2aError::InvalidRequest,
            -32601 => A2aError::MethodNotFound,
            -32602 => A2aError::InvalidParams,
            -32603 => A2aError::Internal,
            -32700 => A2aError::Parse,
            _ => return None,
        })
    }

    /// The HTTP status section 5.4 binds this error to. `Parse` has none in the table — a body that
    /// is not JSON is a client fault, so `400`.
    pub(crate) fn http_status(self) -> u16 {
        match self {
            A2aError::TaskNotFound => 404,
            A2aError::TaskNotCancelable => 409,
            A2aError::UnsupportedOperation
            | A2aError::Parse
            | A2aError::InvalidRequest
            | A2aError::InvalidParams
            // section 5.4's own row for this one is also 400: the request is well formed and the
            // agent's configuration is what cannot satisfy it.
            | A2aError::ExtendedAgentCardNotConfigured
            // section 5.4 binds both of these to HTTP 400. Their gRPC columns differ —
            // `PushNotificationNotSupported` is UNIMPLEMENTED, `ExtensionSupportRequired` is
            // FAILED_PRECONDITION — but the HTTP status is the same for both.
            | A2aError::PushNotificationNotSupported
            | A2aError::ExtensionSupportRequired
            // A2A section 5.4's own row: a version this server does not speak is a CLIENT fault and
            // answers 400, not 505 — the HTTP version and the A2A version are different facts.
            | A2aError::VersionNotSupported => 400,
            // section 5.4 binds this one to 415, the status whose entire meaning is "the media type
            // is the problem". Answering 400 would put a media-type refusal in the same bucket as a
            // malformed body, which is the confusion this code exists to end.
            A2aError::ContentTypeNotSupported => 415,
            A2aError::InvalidAgentResponse => 502,
            A2aError::MethodNotFound => 404,
            A2aError::Internal => 500,
        }
    }
}

/// THE ERROR BODY, and nothing else builds one on this plane.
///
/// `id` is the caller's own, echoed as JSON-RPC 2.0 section 5 requires; `Null` where the request
/// could not be parsed far enough to have one, which is what the specification says to send.
pub(crate) fn body(id: &Value, err: A2aError, message: impl Into<String>) -> Value {
    let mut error = json!({ "code": err.code(), "message": message.into() });
    if let Some(reason) = err.reason() {
        // `data` IS AN ARRAY. A2A section 5.4 carries `google.rpc.ErrorInfo` in a ProtoJSON
        // `details` array, and the JSON-RPC binding puts that same array in `data`. An object here
        // would be the same information in a shape no conformant client unpacks.
        error["data"] = json!([{
            "@type": ERROR_INFO_TYPE,
            "domain": ERROR_INFO_DOMAIN,
            "reason": reason,
        }]);
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

/// THE SAME REFUSAL, IN THE OTHER BINDING'S SHAPE — A2A section 11.6's AIP-193 representation.
///
/// ## This is the error half of the re-framing, and it is a RE-SHAPE of one answer, not a second one
///
/// Both A2A bindings answer the same refusals, because section 5.4 binds each error type to a
/// JSON-RPC code, a canonical status and an HTTP status in ONE row. So this takes the JSON-RPC error
/// object [`body`] already built and moves its three parts to where AIP-193 keeps them, and it
/// invents nothing:
///
/// * `error.code` becomes THE HTTP STATUS. That is section 11.6's own instruction ("Error Code:
///   mapped to the HTTP status code and the `error.code` field"), and it is the one member whose
///   value genuinely differs between the bindings — a REST client reads an integer status here, not
///   a JSON-RPC code, and putting `-32001` in it would hand every conformant client a number outside
///   the range this field is defined over.
/// * `error.data` becomes `error.details`, VERBATIM. It is already the ProtoJSON array of
///   `google.rpc.ErrorInfo` (and, where the refusal names one, `ResourceInfo`) that AIP-193 asks
///   for; only the member name differs between the bindings.
/// * `error.status` is added — the canonical name, from [`A2aError::status`].
///
/// ## Why the status is recovered from the CODE rather than passed in
///
/// The refusal has already been decided by the time it gets here, and it was decided ONCE, on the
/// shared path both bindings run. Taking the error type as a second argument would let a caller
/// hand in a status that disagrees with the code in the body it is re-shaping — two answers to a
/// question already answered, which is the defect the shared envelope reader exists to prevent one
/// layer up. A code this table does not define (a relayed backend's own, or a busbar refusal shaped
/// with a string code) falls back to the canonical name for the HTTP STATUS, which is the only other
/// fact the answer actually carries.
fn status_for_http(status: u16) -> &'static str {
    match status {
        400 | 415 => "INVALID_ARGUMENT",
        401 => "UNAUTHENTICATED",
        403 => "PERMISSION_DENIED",
        404 => "NOT_FOUND",
        409 => "FAILED_PRECONDITION",
        429 => "RESOURCE_EXHAUSTED",
        503 => "UNAVAILABLE",
        504 => "DEADLINE_EXCEEDED",
        _ => "INTERNAL",
    }
}

/// See [`status_for_http`] for the whole of the argument; this is the function that applies it.
pub(crate) fn aip193(http_status: u16, error: &Value) -> Value {
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let status = error
        .get("code")
        .and_then(Value::as_i64)
        .and_then(A2aError::from_code)
        .map_or_else(|| status_for_http(http_status), A2aError::status);
    let mut out = json!({
        "code": http_status,
        "status": status,
        "message": message,
    });
    // ONLY WHEN THERE IS ONE. AIP-193 makes `details` optional, and an empty array would assert
    // "there is structured context and it is nothing", which is a different claim from "there is
    // none" to a client that branches on the member's presence.
    if let Some(details) = error.get("data").filter(|d| d.is_array()) {
        out["details"] = details.clone();
    }
    json!({ "error": out })
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
/// `taskId` member of the error object — which JSON-RPC 2.0 section 5 does not admit (`code`,
/// `message`, `data`, and nothing else) and which the TCK rejects by schema. It is not dropped:
/// `data` is a ProtoJSON ARRAY, so the id travels as a `google.rpc.ResourceInfo` beside the
/// `ErrorInfo`, which is both machine-readable and exactly where a conformant client looks for it.
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

/// The same body, as a response, with the status section 5.4 binds to this error.
pub(crate) fn respond(id: &Value, err: A2aError, message: impl Into<String>) -> Response {
    (
        axum::http::StatusCode::from_u16(err.http_status())
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        axum::Json(body(id, err, message)),
    )
        .into_response()
}

// THE CALLER'S `id` IS NOT READ HERE. This module used to own an `id_of` that recovered it with
// `envelope.get("id").cloned().unwrap_or(Value::Null)` — the very `unwrap_or` that collapsed a
// request whose id is `null` into a NOTIFICATION, which is the defect the shared reader exists to
// close. The id now arrives already decided by `busbar_substrate::ingress::jsonrpc::read`: `Envelope::Request`
// carries an id that is a string or a number by construction, and `Invalid` carries the `Null` that
// JSON-RPC 2.0 section 5 mandates when the id could not be determined. This plane renders what the
// reader decided; a second reading of `id` here would be a second answer to a question already
// answered.

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/rpcerror_tests.rs"]
mod rpcerror_tests;
