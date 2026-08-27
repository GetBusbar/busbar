// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC binding's own facts: the path it claims, the status table it answers with, and the SSE
//! re-framing that turns the plane's one streaming answer into this transport's.

use super::*;

/// THE PATH IS THE `.proto`'S. If this ever stops being the string a generated client dials, the
/// binding is mounted somewhere no client will ever knock, and every gRPC leg reports as unreachable
/// rather than as wrong — the failure that is hardest to read off a conformance run.
#[test]
fn the_route_pattern_covers_the_generated_service_path() {
    assert_eq!(route_path(), "/lf.a2a.v1.A2AService/{method}");
    // The generated service's own constant, so this is a comparison against the code a client is
    // built from rather than against a literal somebody typed twice.
    assert_eq!(
        a2a_pb::proto::a2a_service_server::SERVICE_NAME,
        "lf.a2a.v1.A2AService"
    );
    assert!(crate::a2a::serve::GRPC_MOUNT_PATH
        .ends_with(a2a_pb::proto::a2a_service_server::SERVICE_NAME));
}

/// EVERY A2A ERROR HAS A gRPC STATUS, and it is section 5.4's rather than a guess made at the call
/// site. The five rows the specification binds explicitly are pinned here; a sixth row added to
/// `A2aError` without a status is a compile error, not a silent `Unknown`.
#[test]
fn the_error_table_carries_the_specifications_grpc_column() {
    use crate::a2a::rpcerror::A2aError;
    assert_eq!(A2aError::TaskNotFound.grpc_status(), tonic::Code::NotFound);
    assert_eq!(
        A2aError::TaskNotCancelable.grpc_status(),
        tonic::Code::FailedPrecondition
    );
    // -32004/-32009 bind to FAILED_PRECONDITION (HTTP 400) per section 5.4's table — consistent
    // with their http_status; a bare UNIMPLEMENTED would contradict the 400 they answer with.
    assert_eq!(
        A2aError::UnsupportedOperation.grpc_status(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        A2aError::ContentTypeNotSupported.grpc_status(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        A2aError::InvalidAgentResponse.grpc_status(),
        tonic::Code::Internal
    );
    assert_eq!(
        A2aError::VersionNotSupported.grpc_status(),
        tonic::Code::FailedPrecondition
    );
}

/// A REFUSAL THAT NEVER REACHED THE JSON-RPC LAYER still answers in this transport's vocabulary.
/// `NOT_FOUND` mapping to `UNIMPLEMENTED` is the gRPC specification's own table and reads oddly
/// until you see why: an HTTP 404 means the SERVICE is not there, which to a gRPC caller is "this
/// method is not implemented here", not "your task does not exist".
#[test]
fn an_http_refusal_takes_the_grpc_specifications_own_mapping() {
    use axum::http::StatusCode;
    assert_eq!(
        status_for_http(StatusCode::UNAUTHORIZED).code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(
        status_for_http(StatusCode::FORBIDDEN).code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        status_for_http(StatusCode::NOT_FOUND).code(),
        tonic::Code::Unimplemented
    );
    assert_eq!(
        status_for_http(StatusCode::PAYLOAD_TOO_LARGE).code(),
        tonic::Code::ResourceExhausted
    );
    assert_eq!(
        status_for_http(StatusCode::SERVICE_UNAVAILABLE).code(),
        tonic::Code::Unavailable
    );
}

/// THE JSON-RPC CODE DECIDES, not the HTTP status. A relayed backend error arrives with the
/// specification's code and busbar's own HTTP status beside it, and reading the status would collapse
/// a task-not-found and a not-cancelable into one answer.
#[test]
fn a_json_rpc_error_takes_its_status_from_its_code() {
    let err = serde_json::json!({ "code": -32002, "message": "the task is terminal" });
    let status = status_for_error(&err, axum::http::StatusCode::CONFLICT);
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(), "the task is terminal");
}

/// A CODE A2A DOES NOT DEFINE falls back to the HTTP status rather than to `Unknown`, so a backend's
/// own extension code still produces the answer a client would have derived itself.
#[test]
fn an_unknown_json_rpc_code_falls_back_to_the_http_status() {
    let err = serde_json::json!({ "code": -31000, "message": "vendor error" });
    let status = status_for_error(&err, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(status.code(), tonic::Code::Unavailable);
}

/// AN A2A REFUSAL CARRIES ITS `google.rpc.ErrorInfo` IN THE STATUS DETAILS — the protobuf copy,
/// in `grpc-status-details-bin`, of the same fact the JSON-RPC binding already carries in
/// `error.data`. A2A section 10.6 makes it a MUST ("implementations MUST include a
/// google.rpc.ErrorInfo message in the status.details array"), and it is the TCK's `GRPC-ERR-001`
/// — the one requirement that kept the gRPC transport off 72/72.
///
/// TRANSCRIBED FROM THE ENVELOPE, not re-derived from the code, and the distinction is the design:
/// the JSON error object arriving here already carries the ProtoJSON `ErrorInfo` that
/// `rpcerror::body` built from the one section 5.4 table — or that a fronted backend relayed,
/// metadata and all. Re-deriving from the code would be a second copy of the table for the two to
/// disagree over, and would drop a relayed backend's metadata on the floor.
#[test]
fn an_a2a_refusal_carries_error_info_in_the_status_details_trailer() {
    use tonic_types::StatusExt as _;
    let err = serde_json::json!({
        "code": -32001,
        "message": "no task with id t-404",
        "data": [{
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "domain": "a2a-protocol.org",
            "reason": "TASK_NOT_FOUND",
            "metadata": { "taskId": "t-404" },
        }],
    });
    let status = status_for_error(&err, axum::http::StatusCode::NOT_FOUND);
    assert_eq!(status.code(), tonic::Code::NotFound);
    let details = status.get_error_details();
    let info = details.error_info().unwrap_or_else(|| {
        panic!(
            "an A2A-specific refusal must carry google.rpc.ErrorInfo in \
             grpc-status-details-bin (A2A 10.6, GRPC-ERR-001); the trailer held: {:?}",
            status.details()
        )
    });
    assert_eq!(info.reason, "TASK_NOT_FOUND");
    assert_eq!(info.domain, "a2a-protocol.org");
    assert_eq!(
        info.metadata.get("taskId").map(String::as_str),
        Some("t-404"),
        "a relayed refusal's metadata survives into the protobuf copy"
    );
}

/// AND A STANDARD JSON-RPC ERROR CARRIES NONE, because the specification's own table leaves its
/// reason unset — an invented reason would put a string on the wire no conformant client knows.
/// The control without which the test above cannot tell "transcribed from the envelope" from
/// "invented for every refusal".
#[test]
fn a_standard_json_rpc_error_carries_no_error_info_in_the_trailer() {
    use tonic_types::StatusExt as _;
    let err = serde_json::json!({ "code": -32602, "message": "params are malformed" });
    let status = status_for_error(&err, axum::http::StatusCode::BAD_REQUEST);
    assert!(
        status.get_error_details().error_info().is_none(),
        "a standard JSON-RPC error has no ErrorInfo row in section 5.4, so the trailer must not \
         invent one"
    );
}

/// SSE FRAMES ARE TAKEN WHOLE OR NOT AT ALL. A frame split across two network chunks must not be
/// delivered as two, and a buffer holding half a frame must yield nothing rather than a truncated
/// one — which is what a naive line-split does and how a stream loses its first event.
#[test]
fn a_frame_is_taken_only_once_it_is_complete() {
    let mut buf = b"data: {\"a\":1}\n\ndata: {\"b\"".to_vec();
    assert_eq!(take_frame(&mut buf).as_deref(), Some("data: {\"a\":1}"));
    assert_eq!(take_frame(&mut buf), None);
    buf.extend_from_slice(b":2}\n\n");
    assert_eq!(take_frame(&mut buf).as_deref(), Some("data: {\"b\":2}"));
    assert_eq!(take_frame(&mut buf), None);
}

/// AND IN EVERY LINE-ENDING THE SSE GRAMMAR ALLOWS. A backend that frames with CRLF is not a broken
/// backend, and a reader that only knew `\n\n` would hang on it forever.
#[test]
fn every_sse_frame_terminator_is_recognised() {
    for terminator in ["\r\n\r\n", "\n\n", "\r\r"] {
        let mut buf = format!("data: {{\"x\":1}}{terminator}").into_bytes();
        assert_eq!(
            take_frame(&mut buf).as_deref(),
            Some("data: {\"x\":1}"),
            "terminator {terminator:?} was not recognised"
        );
    }
}

/// THE SSE READER IS THE PLANE'S, not a second one. Asserted by driving the same continuation-line
/// case the relay's reader is written for, through the path this module actually uses.
#[test]
fn the_sse_reader_is_the_planes_own() {
    let frame = "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1}";
    assert_eq!(
        crate::a2a::relay::sse_data(frame).as_deref(),
        Some("{\"jsonrpc\":\"2.0\",\n\"id\":1}")
    );
}

/// THE NARROWING DROPS EXACTLY WHAT PROTOBUF CANNOT CARRY AND NOTHING ELSE.
///
/// The end-to-end proof that this rpc now answers a card at all is
/// `served_methods_tests::the_extended_card_is_served_over_grpc_at_the_path_the_proto_defines`. This
/// is the other half: a narrowing that removed one member too many would still transcode, still
/// answer `200`, and would quietly stop telling a gRPC caller something the card does say.
#[test]
fn the_card_narrowing_removes_only_the_member_the_proto_has_no_field_for() {
    let card = serde_json::json!({
        "name": "busbar",
        "capabilities": {
            "streaming": true,
            "pushNotifications": true,
            "stateTransitionHistory": true,
            "extendedAgentCard": true,
        },
        "skills": [{ "id": "planner" }],
    });
    let narrowed = narrowed_to_the_proto(card);

    assert!(
        narrowed["capabilities"]
            .get("stateTransitionHistory")
            .is_none(),
        "the v0.3 member `a2a.proto` has no field for must not reach the transcode: {narrowed}"
    );
    // EVERY OTHER CAPABILITY SURVIVES. `extendedAgentCard` most of all: this rpc denying the very
    // capability it implements would be the card contradicting itself on its own binding.
    for kept in ["streaming", "pushNotifications", "extendedAgentCard"] {
        assert_eq!(
            narrowed["capabilities"][kept],
            serde_json::Value::Bool(true),
            "the narrowing dropped `{kept}`, which the proto DOES model: {narrowed}"
        );
    }
    assert_eq!(narrowed["name"], "busbar");
    assert_eq!(narrowed["skills"][0]["id"], "planner");

    // AND THE LIST IS NOT EMPTY. A narrowing with nothing in it is a function that cannot fail and
    // cannot help, and it would leave this rpc answering `Internal` exactly as it did before.
    assert!(
        !UNMODELLED_CARD_MEMBERS.is_empty(),
        "an empty list means nothing is narrowed and the transcode fails again"
    );
}
