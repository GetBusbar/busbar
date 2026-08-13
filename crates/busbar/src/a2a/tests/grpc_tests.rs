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
    assert_eq!(
        A2aError::UnsupportedOperation.grpc_status(),
        tonic::Code::Unimplemented
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
        tonic::Code::Unimplemented
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
