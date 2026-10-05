// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC line's codec: the service path, the transcoding both ways, and the status table it
//! answers with (the engine's `grpc_tests.rs`, ported).

use super::*;
use crate::proto::pb;

/// THE PATH IS THE `.proto`'S: the generated service's own constant, never a literal typed twice.
#[test]
fn the_service_path_is_the_generated_services() {
    assert_eq!(
        SERVICE_PATH.strip_prefix('/'),
        Some(crate::proto::SERVICE_NAME)
    );
    assert_eq!(
        crate::door::ROUTES
            .iter()
            .filter(|r| r.carrier == crate::claims::FRAMED_TRANSPORT)
            .map(|r| r.target)
            .collect::<Vec<_>>(),
        [format!("{SERVICE_PATH}/{{method}}").as_str()]
    );
}

/// Every rpc is found by its target, and nothing else is.
#[test]
fn an_rpc_is_named_by_its_target_alone() {
    for rpc in RPCS {
        assert_eq!(
            Rpc::of_target(&format!("{SERVICE_PATH}/{}", rpc.name())),
            Some(rpc)
        );
    }
    assert_eq!(Rpc::of_target(&format!("{SERVICE_PATH}/Nope")), None);
    assert_eq!(Rpc::of_target("/other.Service/SendMessage"), None);
    assert_eq!(Rpc::of_target(SERVICE_PATH), None);
    assert!(Rpc::SendStreamingMessage.streams() && Rpc::SubscribeToTask.streams());
    assert!(!Rpc::SendMessage.streams());
    assert_eq!(unimplemented().code(), Code::Unimplemented);
}

/// A REQUEST MESSAGE IS THE v1.0 JSON-RPC REQUEST IT IS: the rpc's name as the method, its
/// ProtoJSON as the params.
#[test]
fn a_request_message_composes_the_json_rpc_request_it_is() {
    let message = pb::GetTaskRequest {
        id: "t-1".into(),
        history_length: Some(2),
        ..Default::default()
    }
    .encode_to_vec();
    let composed: Value =
        serde_json::from_slice(&compose(Rpc::GetTask, &message).expect("composes")).unwrap();
    assert_eq!(composed["jsonrpc"], "2.0");
    assert_eq!(composed["id"], COMPOSED_ID);
    assert_eq!(composed["method"], "GetTask");
    assert_eq!(composed["params"]["id"], "t-1");
    assert_eq!(composed["params"]["historyLength"], 2);
}

/// Bytes that are not the rpc's message are `INTERNAL`, as the engine mapped a protobuf parse error.
#[test]
fn a_message_that_does_not_decode_is_internal() {
    let status = compose(Rpc::GetTask, &[0xff, 0xff, 0xff]).expect_err("refused");
    assert_eq!(status.code(), Code::Internal);
}

/// THE ANSWER'S RESULT IS THE RPC'S RESPONSE MESSAGE, in its protobuf bytes.
#[test]
fn a_result_answers_the_rpcs_response_message() {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": COMPOSED_ID,
        "result": { "id": "t-1", "contextId": "c-1", "status": { "state": "TASK_STATE_COMPLETED" } },
    });
    let bytes = answer(Rpc::GetTask, 200, body.to_string().as_bytes()).expect("answers");
    let task = pb::Task::decode(bytes.as_slice()).expect("a Task");
    assert_eq!(task.id, "t-1");
    assert_eq!(task.context_id, "c-1");
    // `google.protobuf.Empty` answers nothing.
    let deleted = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": null });
    assert_eq!(
        answer(
            Rpc::DeleteTaskPushNotificationConfig,
            200,
            deleted.to_string().as_bytes()
        )
        .expect("answers"),
        Vec::<u8>::new()
    );
}

/// THE JSON-RPC CODE DECIDES, not the HTTP status.
#[test]
fn a_json_rpc_error_takes_its_status_from_its_code() {
    let err = serde_json::json!({ "code": -32002, "message": "the task is terminal" });
    let status = status_for_error(&err, 409);
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), "the task is terminal");
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": err });
    let refused = answer(Rpc::CancelTask, 409, body.to_string().as_bytes()).expect_err("an error");
    assert_eq!(refused.code(), Code::FailedPrecondition);
}

/// EVERY A2A ERROR HAS section 5.4's gRPC STATUS.
#[test]
fn the_error_table_carries_the_specifications_grpc_column() {
    let rows = [
        (-32001, Code::NotFound),
        (-32002, Code::FailedPrecondition),
        (-32003, Code::Unimplemented),
        (-32004, Code::Unimplemented),
        (-32005, Code::InvalidArgument),
        (-32006, Code::Internal),
        (-32007, Code::FailedPrecondition),
        (-32008, Code::FailedPrecondition),
        (-32009, Code::Unimplemented),
        (-32600, Code::InvalidArgument),
        (-32601, Code::Unimplemented),
        (-32602, Code::InvalidArgument),
        (-32603, Code::Internal),
        (-32700, Code::InvalidArgument),
    ];
    for (code, want) in rows {
        assert_eq!(grpc_code(code), Some(want), "code {code}");
    }
    assert_eq!(grpc_code(-31000), None);
}

/// A CODE A2A DOES NOT DEFINE falls back to the HTTP status.
#[test]
fn an_unknown_json_rpc_code_falls_back_to_the_http_status() {
    let err = serde_json::json!({ "code": -31000, "message": "vendor error" });
    assert_eq!(status_for_error(&err, 503).code(), Code::Unavailable);
}

/// An answer that is not a JSON-RPC answer takes the gRPC specification's own HTTP mapping.
#[test]
fn an_http_refusal_takes_the_grpc_specifications_own_mapping() {
    for (http, want) in [
        (401, Code::Unauthenticated),
        (403, Code::PermissionDenied),
        (404, Code::Unimplemented),
        (413, Code::ResourceExhausted),
        (503, Code::Unavailable),
        (400, Code::Internal),
        (418, Code::Unknown),
    ] {
        assert_eq!(status_for_http(http).code(), want, "HTTP {http}");
    }
    assert_eq!(
        answer(Rpc::GetTask, 502, b"not json")
            .expect_err("refused")
            .code(),
        Code::Unavailable
    );
}

/// AN A2A REFUSAL CARRIES ITS `google.rpc.ErrorInfo` IN THE STATUS DETAILS (A2A 10.6, TCK
/// `GRPC-ERR-001`), transcribed from the envelope with its metadata.
#[test]
fn an_a2a_refusal_carries_error_info_in_the_status_details() {
    let err = serde_json::json!({
        "code": -32001,
        "message": "no task with id t-404",
        "data": [{
            "@type": crate::ERROR_INFO_TYPE,
            "domain": crate::ERROR_INFO_DOMAIN,
            "reason": "TASK_NOT_FOUND",
            "metadata": { "taskId": "t-404" },
        }],
    });
    let status = status_for_error(&err, 404);
    assert_eq!(status.code(), Code::NotFound);
    let info = status.error_info().expect("ErrorInfo in the details");
    assert_eq!(info.reason, "TASK_NOT_FOUND");
    assert_eq!(info.domain, crate::ERROR_INFO_DOMAIN);
    assert_eq!(
        info.metadata.get("taskId").map(String::as_str),
        Some("t-404")
    );
}

/// AND A STANDARD JSON-RPC ERROR CARRIES NONE.
#[test]
fn a_standard_json_rpc_error_carries_no_error_info() {
    let err = serde_json::json!({ "code": -32602, "message": "params are malformed" });
    let status = status_for_error(&err, 400);
    assert!(status.error_info().is_none());
    assert!(status.details().is_empty());
}

/// ONE EVENT IS ONE `StreamResponse`; a frame with no result is skipped; an error ends the stream.
#[test]
fn an_event_is_one_stream_response() {
    let frame = format!(
        "data: {}",
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "task": { "id": "t-1", "contextId": "c-1",
                                   "status": { "state": "TASK_STATE_WORKING" } } },
        })
    );
    let bytes = event(&frame).expect("an event").expect("a message");
    let response = pb::StreamResponse::decode(bytes.as_slice()).expect("a StreamResponse");
    assert!(response.payload.is_some());
    assert!(event(": keep-alive").is_none());
    let failed = format!(
        "data: {}",
        serde_json::json!({ "jsonrpc": "2.0", "id": 1,
                            "error": { "code": -32001, "message": "gone" } })
    );
    assert_eq!(
        event(&failed).expect("an event").expect_err("ends").code(),
        Code::NotFound
    );
}

/// THE CARD NARROWING removes only the member the proto has no field for.
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
    assert!(narrowed["capabilities"]
        .get("stateTransitionHistory")
        .is_none());
    for kept in ["streaming", "pushNotifications", "extendedAgentCard"] {
        assert_eq!(narrowed["capabilities"][kept], Value::Bool(true), "{kept}");
    }
    assert_eq!(narrowed["skills"][0]["id"], "planner");
    assert!(!UNMODELLED_CARD_MEMBERS.is_empty());
}

/// A send with no message mints its id as the SDK's model did: a version-7 UUID over the clock.
#[test]
fn a_send_with_no_message_mints_a_v7_id() {
    let none = pb::SendMessageRequest::default().encode_to_vec();
    assert!(mints_message_id(Rpc::SendMessage, &none));
    assert!(!mints_message_id(Rpc::GetTask, &none));
    let some = pb::SendMessageRequest {
        message: Some(pb::Message::default()),
        ..Default::default()
    }
    .encode_to_vec();
    assert!(!mints_message_id(Rpc::SendMessage, &some));
    let id = message_id_v7(0x0190_1234_5678, &[0xff; 10]);
    assert_eq!(id, "01901234-5678-7fff-bfff-ffffffffffff");
    let composed: Value =
        serde_json::from_slice(&compose(Rpc::SendMessage, &none).expect("composes")).unwrap();
    let minted = with_message_id(&composed, &id);
    assert_eq!(minted["params"]["message"]["messageId"], id);
    assert_eq!(minted["params"]["message"]["role"], "ROLE_USER");
    assert!(minted["params"]["message"].get("parts").is_none());
}
