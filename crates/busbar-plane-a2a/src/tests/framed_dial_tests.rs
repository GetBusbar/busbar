// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC line's codec in the direction that DIALS: the hop's params as the rpc's request
//! message, each answered message as its ProtoJSON result, the length prefix, and the status the
//! trailers state (the engine's `relay::GrpcFraming`). The oracle is the generated `pb` messages,
//! decoded and encoded with `prost` directly, never this module's own reader.

use super::*;
use crate::proto::pb;
use serde_json::json;

/// Both A2A dialects name the same rpc; a method the service does not have names none.
#[test]
fn a_method_in_either_dialect_names_its_rpc() {
    for rpc in RPCS {
        assert_eq!(Rpc::of_method(rpc.name()), Some(rpc));
    }
    assert_eq!(Rpc::of_method("message/send"), Some(Rpc::SendMessage));
    assert_eq!(
        Rpc::of_method("message/stream"),
        Some(Rpc::SendStreamingMessage)
    );
    assert_eq!(
        Rpc::of_method("tasks/resubscribe"),
        Some(Rpc::SubscribeToTask)
    );
    assert_eq!(
        Rpc::of_method("agent/getAuthenticatedExtendedCard"),
        Some(Rpc::GetExtendedAgentCard)
    );
    assert_eq!(Rpc::of_method("vendor/Thing"), None);
    assert_eq!(
        Rpc::GetTask.target(),
        "/lf.a2a.v1.A2AService/GetTask",
        "the service's own path, absolute"
    );
}

/// THE HOP'S PARAMS ARE THE REQUEST MESSAGE: a v1.0 send's content survives the transcode, and a
/// task read names exactly the id the params name.
#[test]
fn the_params_are_written_as_the_rpcs_request_message() {
    let params = json!({
        "message": {
            "messageId": "m-1",
            "role": "ROLE_USER",
            "parts": [{ "text": "PLAN THE MIGRATION" }]
        }
    });
    let bytes = request_message(Rpc::SendMessage, &params).expect("a send is written");
    let sent = pb::SendMessageRequest::decode(bytes.as_slice()).expect("it decodes");
    let message = sent.message.expect("the message");
    assert_eq!(message.message_id, "m-1");
    assert_eq!(message.role, pb::Role::User as i32);
    assert_eq!(
        message.parts[0].content,
        Some(pb::part::Content::Text("PLAN THE MIGRATION".into()))
    );
    let bytes = request_message(Rpc::GetTask, &json!({ "id": "BACKEND-OWN-TASK-ID" }))
        .expect("a read is written");
    assert_eq!(
        pb::GetTaskRequest::decode(bytes.as_slice())
            .expect("it decodes")
            .id,
        "BACKEND-OWN-TASK-ID"
    );
    let config = json!({
        "taskId": "b-1", "id": "busbar-b-1", "url": "https://busbar.example/a2a/push",
        "authentication": { "scheme": "Bearer", "credentials": "t-1.sig" },
    });
    let bytes = request_message(Rpc::CreateTaskPushNotificationConfig, &config)
        .expect("a config is written");
    let sent = pb::TaskPushNotificationConfig::decode(bytes.as_slice()).expect("it decodes");
    assert_eq!(
        (sent.task_id.as_str(), sent.id.as_str(), sent.url.as_str()),
        ("b-1", "busbar-b-1", "https://busbar.example/a2a/push")
    );
    assert_eq!(
        sent.authentication.map(|a| a.credentials).as_deref(),
        Some("t-1.sig")
    );
    // A v0.3 document is not the request message's ProtoJSON: there is nothing to write.
    let v03 = json!({ "message": { "kind": "message", "role": "user", "parts": [] } });
    assert!(request_message(Rpc::SendMessage, &v03).is_err());
}

/// EACH ANSWERED MESSAGE IS ITS RESULT: the rpc's response message read back as ProtoJSON; a
/// delete's `Empty` is `null`; a message that is not the rpc's response is refused.
#[test]
fn an_answered_message_is_read_as_the_rpcs_result() {
    let task = pb::Task {
        id: "BACKEND-OWN-TASK-ID".into(),
        context_id: "BACKEND-OWN-CONTEXT".into(),
        status: Some(pb::TaskStatus {
            state: pb::TaskState::Completed as i32,
            ..Default::default()
        }),
        ..Default::default()
    };
    let answer = pb::SendMessageResponse {
        payload: Some(pb::send_message_response::Payload::Task(task.clone())),
    }
    .encode_to_vec();
    let result = response_result(Rpc::SendMessage, &answer).expect("it reads");
    assert_eq!(result["task"]["id"], "BACKEND-OWN-TASK-ID");
    assert_eq!(result["task"]["status"]["state"], "TASK_STATE_COMPLETED");
    let read = response_result(Rpc::GetTask, &task.encode_to_vec()).expect("it reads");
    assert_eq!(read["contextId"], "BACKEND-OWN-CONTEXT");
    assert_eq!(
        response_result(Rpc::DeleteTaskPushNotificationConfig, &[]),
        Ok(Value::Null)
    );
    assert!(response_result(Rpc::GetTask, &[0xff, 0xff, 0xff]).is_err());
    // The model refuses an answer with no payload.
    assert!(response_result(Rpc::SendMessage, &[]).is_err());
}

/// THE LENGTH PREFIX: a message is taken only once it is whole; a compressed one is refused.
#[test]
fn a_message_is_taken_whole_off_its_length_prefix() {
    let mut buf = vec![0, 0, 0, 0, 3, b'a', b'b'];
    assert_eq!(take_message(&buf), Ok(None));
    buf.push(b'c');
    assert_eq!(take_message(&buf), Ok(Some((3, 8))));
    assert_eq!(take_message(&[0, 0, 0]), Ok(None));
    assert_eq!(take_message(&[0, 0, 0, 0, 0]), Ok(Some((0, 5))));
    assert!(take_message(&[1, 0, 0, 0, 0]).is_err());
}

/// The trailers' field block, `name: value` per line, as the grpc transport renders it.
fn block(fields: &[(&str, &str)]) -> Vec<u8> {
    use busbar_contract::abi::transport::fields::{LINE_END, SEPARATOR};
    let mut out = Vec::new();
    for (name, value) in fields {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(SEPARATOR);
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(LINE_END);
    }
    out
}

/// THE STATUS THE TRAILERS STATE: the code the host passes beside them (the kernel hands on the
/// status the transport read off them), with the `ErrorInfo` of the details' `google.rpc.Status`.
/// The details never state the code: trailers handed on with no status state nothing, whatever
/// their details say (RED: the details' own code was read as the call's status).
#[test]
fn the_trailers_state_the_calls_status_and_its_error_info() {
    use base64::Engine as _;
    assert_eq!(ended(&[], None), None);
    assert_eq!(
        ended(&[], Some(0)),
        Some(Ended {
            code: 0,
            info: None
        })
    );
    assert!(ended(&[], Some(0)).is_some_and(|e| e.ok()));
    let refused = Status::with_error_info(
        Code::NotFound,
        "no such task",
        ErrorInfo {
            reason: "TASK_NOT_FOUND".into(),
            domain: crate::ERROR_INFO_DOMAIN.into(),
            metadata: std::collections::BTreeMap::new(),
        },
    );
    let details = base64::engine::general_purpose::STANDARD_NO_PAD.encode(refused.details());
    let trailers = block(&[("x-other", "1"), (DETAILS_FIELD, &details)]);
    assert_eq!(
        ended(&trailers, None),
        None,
        "the details are no status of their own"
    );
    let got = ended(&trailers, Some(Code::NotFound as u32)).expect("the stated status");
    assert_eq!(got.code, Code::NotFound as u32);
    assert_eq!(
        got.info.as_ref().map(|i| i.reason.as_str()),
        Some("TASK_NOT_FOUND")
    );
    assert_eq!(got.a2a_code(), Some(-32001));
    // A padded value reads the same; the code is the one the host states, never the details'.
    let padded = base64::engine::general_purpose::STANDARD.encode(refused.details());
    let stated = ended(&block(&[(DETAILS_FIELD, &padded)]), Some(14)).expect("stated");
    assert_eq!(stated.code, 14);
    assert_eq!(
        stated.info.map(|i| i.reason),
        Some("TASK_NOT_FOUND".to_string())
    );
    assert_eq!(ended(&block(&[("x-other", "1")]), None), None);
}

/// THE A2A CODE A STATUS CARRIES: the reason's, else the one section 5.4 binds to the status
/// alone; a status several A2A codes share, with no reason, names none.
#[test]
fn a_status_names_the_a2a_code_its_reason_or_its_row_binds() {
    let bare = |code: Code| Ended {
        code: code as u32,
        info: None,
    };
    assert_eq!(bare(Code::NotFound).a2a_code(), Some(-32001));
    assert_eq!(bare(Code::FailedPrecondition).a2a_code(), None);
    assert_eq!(bare(Code::Unimplemented).a2a_code(), None);
    assert_eq!(bare(Code::Unavailable).a2a_code(), None);
    let reasoned = Ended {
        code: Code::FailedPrecondition as u32,
        info: Some(ErrorInfo {
            reason: "TASK_NOT_CANCELABLE".into(),
            domain: crate::ERROR_INFO_DOMAIN.into(),
            metadata: std::collections::BTreeMap::new(),
        }),
    };
    assert_eq!(reasoned.a2a_code(), Some(-32002));
}
