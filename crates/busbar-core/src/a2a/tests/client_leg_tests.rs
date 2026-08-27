// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR AS AN A2A **CLIENT**, over all three of A2A's bindings.
//!
//! Every test here drives busbar's REAL router — the same `crate::build_router`, the same admission,
//! the same egress gate, the same SSRF guard, the same audit chain, the same task store — and then
//! reads what busbar ASKED TO HAVE SENT off the recording seam. That is what makes these tests
//! evidence for a coverage cell rather than evidence that a function exists: the claim
//! `a2a|<binding>|client|client|<Method>` is *busbar issues this operation on this binding*, and the
//! only thing that can prove it is the request on the wire.
//!
//! ## NOTHING HERE CAN SKIP
//!
//! [`issued`] PANICS when no outbound request was recorded, and every assertion runs against a
//! `Recorded` that therefore exists. A test that quietly asserted nothing because the hop never
//! happened would report a green over a client leg that does not work, which is the exact failure
//! this battery exists to prevent — and it is not hypothetical: a verb this plane answers LOCALLY
//! makes no hop at all, so "the call returned 200" proves nothing whatsoever about the client leg.
//!
//! ## WHY THE SAME TEST SHAPE THREE TIMES IS THE POINT, NOT DUPLICATION
//!
//! The three bindings are ONE dispatch. The deployment differs in exactly one member of one cached
//! agent card ([`harness_on`]) and in nothing else — no second router, no second seam, no second
//! ingress — so a per-binding test that finds a correctly re-framed request on the wire has proved
//! that the framing was the only thing that varied. Writing the assertions out per binding is what
//! makes the re-framing legible: `GetTask` is a body member on one leg, a path segment plus a `GET`
//! on the second, and a protobuf message under an rpc path on the third, and those are three
//! different claims about three different bytes.

use super::relay_harness::*;
use crate::a2a::relay::{BINDING_GRPC, BINDING_HTTP_JSON, BINDING_JSONRPC};

/// The base every framing composes against: the operator's `url:` for the `planner` registration.
const BASE: &str = "https://backend.agent.test/a2a";

// ══ DRIVING ONE OPERATION, AND READING WHAT WENT OUT ═════════════════════════════════════════════

/// Call `planner` with `envelope` and hand back EVERY request busbar asked to have sent.
///
/// PANICS when there were none. See the module note: a locally-answered verb makes no hop, so an
/// empty log is the one answer this battery must never treat as a pass.
async fn issued(h: &Harness, envelope: &serde_json::Value) -> Vec<Recorded> {
    let (status, body) = call_agent(h, "planner", envelope).await;
    let sent = h.sent();
    assert!(
        !sent.is_empty(),
        "busbar made NO outbound hop for {:?}. It answered {status} with {body}. A client-leg cell \
         is a claim about a request on the wire, and there was none — this test must fail rather \
         than assert nothing.",
        envelope.get("method")
    );
    sent
}

/// The LAST request busbar asked to have sent. The addressed verbs need a task to address, so their
/// tests make a submission first; the operation under test is the one that went out last.
async fn issued_last(h: &Harness, envelope: &serde_json::Value) -> Recorded {
    issued(h, envelope)
        .await
        .pop()
        .expect("`issued` refuses an empty log")
}

/// The JSON body of a recorded request, or a panic naming what was there instead.
fn body_json(r: &Recorded) -> serde_json::Value {
    serde_json::from_slice(&r.body).unwrap_or_else(|e| {
        panic!(
            "the outbound body is not JSON ({e}): {:?}",
            String::from_utf8_lossy(&r.body)
        )
    })
}

/// The path (and query) of a recorded request's URL, with the origin removed.
fn path_of(r: &Recorded) -> String {
    let url = reqwest::Url::parse(&r.url).expect("the recorded URL parses");
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    }
}

/// THE SUBMISSION A v1.0 CALLER SENDS.
///
/// A2A v0.3's `message/send` params — `role: "user"`, `parts: [{kind, text}]` — are NOT the
/// protobuf message's ProtoJSON, and the gRPC binding is a v1.0 construct with no v0.3 protobuf to
/// transcode to. So a caller reaching a gRPC backend speaks v1.0, which is what this composes:
/// `content`, `ROLE_USER`, and a `Part` oneof. That is not a limitation this test works around — it
/// is the honest boundary `super::super::grpc`'s own header states, that this binding cannot be a
/// courier, applied in the direction that sends.
fn v10_envelope() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 7, "method": "SendMessage",
        "params": {
            "message": {
                "messageId": "m-1",
                "role": "ROLE_USER",
                "parts": [{ "text": "PLAN THE MIGRATION" }]
            }
        }
    })
}

/// The backend's answer for a task that is still RUNNING. A resubscribe to a task busbar holds as
/// TERMINAL is refused locally (`local::subscribe_refusal`) and makes no hop at all, so a fixture
/// that completed the task would make every subscribe test assert nothing.
fn backend_working() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 7,
        "result": {
            "id": "BACKEND-OWN-TASK-ID", "contextId": "BACKEND-OWN-CONTEXT", "kind": "task",
            "status": { "state": "working" }
        }
    })
    .to_string()
}

/// The same, in the shape A2A section 11.3 gives the REST binding: the `result`, bare.
fn backend_rest_working() -> String {
    serde_json::json!({
        "id": "BACKEND-OWN-TASK-ID", "contextId": "BACKEND-OWN-CONTEXT", "kind": "task",
        "status": { "state": "working" }
    })
    .to_string()
}

/// A submission envelope naming `method`, with `params`.
fn envelope_for(method: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params })
}

/// A `message/send` that opens one task, and the busbar task id it was answered with.
///
/// Every addressed verb needs a task that busbar issued and that this caller owns — a `GetTask` for
/// anything else resolves to nothing and takes a different path — so this is the setup those tests
/// share. It asserts the id came back, because a test that went on to address `""` would be
/// addressing nothing and would pass for the wrong reason.
async fn open_a_task(h: &Harness, submission: &serde_json::Value) -> String {
    let (status, answer) = call_agent(h, "planner", submission).await;
    assert_eq!(status, 200, "the submission must succeed: {answer}");
    // BOTH SHAPES. A2A v0.3 makes the `result` the Task itself; v1.0 WRAPS it under `task`, and the
    // wrapper is what a v1.0 caller — every gRPC caller — gets back.
    let id = answer
        .pointer("/result/id")
        .or_else(|| answer.pointer("/result/task/id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the submission answered no task id: {answer}"));
    assert!(!id.is_empty(), "the submission answered an empty task id");
    id.to_string()
}

// ══ THE JSON-RPC BINDING ═════════════════════════════════════════════════════════════════════════
//
// The courier. busbar sends the caller's own bytes, so what is asserted here is that the hop happens
// AT ALL, that it goes to the operator's endpoint as a `POST`, and that the envelope on the wire is
// the caller's — content-blindness is the property of this leg and a re-serialization would spend it.

/// One JSON-RPC hop, asserted whole: the verb, the endpoint, and the method the envelope names.
fn assert_jsonrpc(r: &Recorded, method: &str) {
    assert_eq!(r.http_method, "POST", "JSON-RPC is a POST to one endpoint");
    assert_eq!(r.url, BASE.to_string(), "the operator's endpoint, verbatim");
    let body = body_json(r);
    assert_eq!(
        body.get("method").and_then(serde_json::Value::as_str),
        Some(method),
        "the envelope on the wire must name `{method}`: {body}"
    );
    assert_eq!(
        body.get("jsonrpc").and_then(serde_json::Value::as_str),
        Some("2.0"),
        "a JSON-RPC hop carries the `jsonrpc` member"
    );
}

#[tokio::test]
async fn jsonrpc_client_issues_send_message() {
    let h = harness_on(
        Outcome::AnswersCorrelated(200, backend_ok()),
        BINDING_JSONRPC,
    )
    .await;
    let sent = issued_last(&h, &envelope()).await;
    assert_jsonrpc(&sent, "message/send");
    assert!(
        contains(&sent.body, b"PLAN THE MIGRATION"),
        "the caller's own content reaches the backend on this leg"
    );
}

#[tokio::test]
async fn jsonrpc_client_issues_send_streaming_message() {
    let h = harness_on(
        Outcome::Streams(vec![format!(
            "data: {}\n\n",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 11,
                "result": { "id": "B", "contextId": "C", "kind": "task",
                            "status": { "state": "completed" } }
            })
        )]),
        BINDING_JSONRPC,
    )
    .await;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 11, "method": "message/stream",
        "params": { "message": { "role": "user", "parts": [{ "kind": "text", "text": "GO" }] } }
    });
    let (status, _, _) = call_raw(&h, "planner", &body).await;
    assert_eq!(status, 200, "the streaming submission must be served");
    let sent = h.sent();
    assert!(!sent.is_empty(), "busbar made no streaming hop");
    let last = sent.last().expect("just checked");
    assert!(last.streaming, "a `message/stream` must go out as a STREAM");
    assert_jsonrpc(last, "message/stream");
}

#[tokio::test]
async fn jsonrpc_client_issues_get_task() {
    let h = harness_on(
        Outcome::AnswersCorrelated(200, backend_ok()),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_a_task(&h, &envelope()).await;
    let sent = issued_last(
        &h,
        &envelope_for("tasks/get", serde_json::json!({ "id": task })),
    )
    .await;
    assert_jsonrpc(&sent, "tasks/get");
}

#[tokio::test]
async fn jsonrpc_client_issues_cancel_task() {
    let h = harness_on(
        Outcome::AnswersCorrelated(200, backend_ok()),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_a_task(&h, &envelope()).await;
    let sent = issued_last(
        &h,
        &envelope_for("tasks/cancel", serde_json::json!({ "id": task })),
    )
    .await;
    assert_jsonrpc(&sent, "tasks/cancel");
}

#[tokio::test]
async fn jsonrpc_client_issues_subscribe_to_task() {
    let h = harness_on(
        Outcome::AnswersThenStreams(
            200,
            backend_working(),
            vec![format!(
                "data: {}\n\n",
                serde_json::json!({ "jsonrpc": "2.0", "id": 7,
                                    "result": { "id": "B", "status": { "state": "working" } } })
            )],
        ),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_a_task(&h, &envelope()).await;
    let body = envelope_for("tasks/resubscribe", serde_json::json!({ "id": task }));
    let (status, _, _) = call_raw(&h, "planner", &body).await;
    assert_eq!(status, 200, "a resubscribe to a live task must be served");
    let last = h
        .sent()
        .pop()
        .expect("busbar made no hop for a resubscribe");
    assert_jsonrpc(&last, "tasks/resubscribe");
}

// ══ THE HTTP+JSON BINDING ════════════════════════════════════════════════════════════════════════
//
// A2A section 11.3: the REST request body IS the JSON-RPC `params` verbatim. So what is asserted per
// operation is the REQUEST LINE — the verb and the path the specification binds the operation to —
// and, where there is one, that the body is the params and nothing else.

#[tokio::test]
async fn http_json_client_issues_send_message() {
    let h = harness_on(
        Outcome::Answers(200, backend_rest_task()),
        BINDING_HTTP_JSON,
    )
    .await;
    let sent = issued_last(&h, &envelope()).await;
    assert_eq!(sent.http_method, "POST");
    assert_eq!(path_of(&sent), "/a2a/message:send");
    let body = body_json(&sent);
    assert!(
        body.get("message").is_some(),
        "section 11.3: the body IS the params, so the caller's `message` is at the top: {body}"
    );
    assert!(
        body.get("method").is_none() && body.get("jsonrpc").is_none(),
        "the REST body must carry no JSON-RPC envelope members: {body}"
    );
}

#[tokio::test]
async fn http_json_client_issues_send_streaming_message() {
    let h = harness_on(
        Outcome::Streams(vec![format!(
            "data: {}\n\n",
            serde_json::json!({ "id": "B", "contextId": "C", "kind": "task",
                                "status": { "state": "completed" } })
        )]),
        BINDING_HTTP_JSON,
    )
    .await;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 11, "method": "message/stream",
        "params": { "message": { "role": "user", "parts": [{ "kind": "text", "text": "GO" }] } }
    });
    let (status, ct, sse) = call_raw(&h, "planner", &body).await;
    assert_eq!(
        status, 200,
        "the streaming submission must be served: {sse}"
    );
    assert!(
        ct.starts_with("text/event-stream"),
        "the caller is answered a stream, whatever binding the backend spoke: {ct}"
    );
    let last = h.sent().pop().expect("busbar made no streaming hop");
    assert!(last.streaming, "the hop must be a STREAM");
    assert_eq!(last.http_method, "POST");
    assert_eq!(path_of(&last), "/a2a/message:stream");
    // THE RE-FRAMING, IN THE ANSWERING DIRECTION. The backend streamed BARE events — that is what
    // A2A's REST binding puts in a `data:` — and the caller got a JSON-RPC stream, because
    // `RestSseReader` wrapped each one before `read_event` ever saw it.
    assert!(
        sse.contains("\"jsonrpc\""),
        "a bare REST event must reach the caller re-framed as a JSON-RPC response: {sse}"
    );
}

#[tokio::test]
async fn http_json_client_issues_get_task() {
    let h = harness_on(
        Outcome::Answers(200, backend_rest_task()),
        BINDING_HTTP_JSON,
    )
    .await;
    let task = open_a_task(&h, &envelope()).await;
    let sent = issued_last(
        &h,
        &envelope_for("tasks/get", serde_json::json!({ "id": task })),
    )
    .await;
    assert_eq!(
        sent.http_method, "GET",
        "A2A binds `GetTask` to a GET; a POST here is a different request"
    );
    // The backend's OWN task id, not busbar's: `idmap` translates the addressed id on the way out,
    // and a path carrying busbar's id would address a task the backend has never heard of.
    assert_eq!(path_of(&sent), "/a2a/tasks/BACKEND-OWN-TASK-ID");
    assert!(
        sent.body.is_empty(),
        "a GET carries no body: {:?}",
        String::from_utf8_lossy(&sent.body)
    );
}

#[tokio::test]
async fn http_json_client_issues_cancel_task() {
    let h = harness_on(
        Outcome::Answers(200, backend_rest_task()),
        BINDING_HTTP_JSON,
    )
    .await;
    let task = open_a_task(&h, &envelope()).await;
    let sent = issued_last(
        &h,
        &envelope_for("tasks/cancel", serde_json::json!({ "id": task })),
    )
    .await;
    assert_eq!(sent.http_method, "POST");
    assert_eq!(path_of(&sent), "/a2a/tasks/BACKEND-OWN-TASK-ID:cancel");
}

#[tokio::test]
async fn http_json_client_issues_subscribe_to_task() {
    let h = harness_on(
        Outcome::AnswersThenStreams(
            200,
            backend_rest_working(),
            vec!["data: {\"id\":\"B\",\"status\":{\"state\":\"working\"}}\n\n".to_string()],
        ),
        BINDING_HTTP_JSON,
    )
    .await;
    let task = open_a_task(&h, &envelope()).await;
    let body = envelope_for("tasks/resubscribe", serde_json::json!({ "id": task }));
    let (status, _, _) = call_raw(&h, "planner", &body).await;
    assert_eq!(status, 200, "a resubscribe to a live task must be served");
    let last = h
        .sent()
        .pop()
        .expect("busbar made no hop for a resubscribe");
    assert_eq!(last.http_method, "POST");
    assert_eq!(path_of(&last), "/a2a/tasks/BACKEND-OWN-TASK-ID:subscribe");
}

/// A REST-shaped answer: section 11.3 makes the success body the `result` VERBATIM, so there is no
/// envelope around it. The ids are the backend's own, exactly as [`backend_ok`]'s are.
fn backend_rest_task() -> String {
    serde_json::json!({
        "id": "BACKEND-OWN-TASK-ID",
        "contextId": "BACKEND-OWN-CONTEXT",
        "kind": "task",
        "status": { "state": "completed" }
    })
    .to_string()
}

// ══ THE gRPC BINDING ═════════════════════════════════════════════════════════════════════════════
//
// The one binding that cannot be a courier: the peer speaks protobuf, so busbar authors the frame.
// The conversions are the SDK's — `a2a_pb` — and they are the SAME ones `super::grpc` uses to READ a
// request in the other direction, so what is asserted here is that the frame busbar composed decodes
// back to the operation the caller asked for. The decode is done with `a2a_pb` directly rather than
// with busbar's own reader, so the oracle is the SDK and not the code under test.

/// The rpc path a recorded request addresses, and the length-prefixed message it carries, decoded
/// with the SDK. PANICS on anything that is not a well-formed gRPC frame.
fn grpc_message<T>(r: &Recorded) -> T
where
    T: prost::Message + Default,
{
    assert_eq!(r.http_method, "POST", "a gRPC call is always a POST");
    assert!(
        r.body.len() >= 5,
        "a gRPC frame is a flag byte, a four-byte length and a message; got {} bytes",
        r.body.len()
    );
    assert_eq!(
        r.body[0], 0,
        "busbar offers no compression, so the flag is 0"
    );
    let len = u32::from_be_bytes([r.body[1], r.body[2], r.body[3], r.body[4]]) as usize;
    assert_eq!(
        r.body.len(),
        5 + len,
        "the frame's length prefix must describe the frame"
    );
    <T as prost::Message>::decode(&r.body[5..])
        .expect("the frame decodes as the rpc's request message")
}

/// One gRPC frame, as a backend answers it.
fn grpc_frame<M: prost::Message>(message: &M) -> Vec<u8> {
    let len = prost::Message::encoded_len(message);
    let mut out = vec![0u8];
    out.extend_from_slice(
        &(u32::try_from(len).expect("a test fixture fits in a frame")).to_be_bytes(),
    );
    prost::Message::encode(message, &mut out).expect("the message encodes");
    out
}

/// What a healthy gRPC backend answers a submission with, as a `String` the fixture can carry.
///
/// The recording transport hands back `String` bytes, and a protobuf frame is not UTF-8 — so it
/// travels as latin-1, byte for byte, and is turned back into bytes on the way out. Ugly and
/// EXACT: no byte is lost, which is the only property that matters for a frame.
fn as_fixture(bytes: &[u8]) -> String {
    bytes.iter().map(|b| *b as char).collect()
}

/// The backend's own task, in the shape its gRPC binding answers with.
fn grpc_task(state: a2a_pb::proto::TaskState) -> a2a_pb::proto::Task {
    a2a_pb::proto::Task {
        id: "BACKEND-OWN-TASK-ID".to_string(),
        context_id: "BACKEND-OWN-CONTEXT".to_string(),
        status: Some(a2a_pb::proto::TaskStatus {
            state: state as i32,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn grpc_task_answer() -> String {
    as_fixture(&grpc_frame(&grpc_task(a2a_pb::proto::TaskState::Completed)))
}

/// The same, for a task the backend is still WORKING on. See [`backend_working`].
fn grpc_working_answer() -> String {
    as_fixture(&grpc_frame(&a2a_pb::proto::SendMessageResponse {
        payload: Some(a2a_pb::proto::send_message_response::Payload::Task(
            grpc_task(a2a_pb::proto::TaskState::Working),
        )),
    }))
}

fn grpc_send_answer() -> String {
    as_fixture(&grpc_frame(&a2a_pb::proto::SendMessageResponse {
        payload: Some(a2a_pb::proto::send_message_response::Payload::Task(
            grpc_task(a2a_pb::proto::TaskState::Completed),
        )),
    }))
}

/// One streamed event, as the backend's gRPC binding frames it.
fn grpc_stream_frame(state: a2a_pb::proto::TaskState) -> String {
    as_fixture(&grpc_frame(&a2a_pb::proto::StreamResponse {
        payload: Some(a2a_pb::proto::stream_response::Payload::Task(grpc_task(
            state,
        ))),
    }))
}

#[tokio::test]
async fn grpc_client_issues_send_message() {
    let h = harness_on(Outcome::Answers(200, grpc_send_answer()), BINDING_GRPC).await;
    let sent = issued_last(&h, &v10_envelope()).await;
    assert_eq!(path_of(&sent), "/lf.a2a.v1.A2AService/SendMessage");
    let req: a2a_pb::proto::SendMessageRequest = grpc_message(&sent);
    let text = req
        .message
        .as_ref()
        .map(|m| format!("{m:?}"))
        .unwrap_or_default();
    assert!(
        text.contains("PLAN THE MIGRATION"),
        "the caller's own content must survive the transcode: {text}"
    );
}

#[tokio::test]
async fn grpc_client_issues_get_task() {
    let h = harness_on(
        in_turn(200, vec![grpc_send_answer(), grpc_task_answer()]),
        BINDING_GRPC,
    )
    .await;
    let task = open_a_task(&h, &v10_envelope()).await;
    let sent = issued_last(
        &h,
        &envelope_for("GetTask", serde_json::json!({ "id": task })),
    )
    .await;
    assert_eq!(path_of(&sent), "/lf.a2a.v1.A2AService/GetTask");
    let req: a2a_pb::proto::GetTaskRequest = grpc_message(&sent);
    assert_eq!(
        req.id, "BACKEND-OWN-TASK-ID",
        "the rpc must name the BACKEND's own task id, not busbar's"
    );
}

#[tokio::test]
async fn grpc_client_issues_cancel_task() {
    let h = harness_on(
        in_turn(200, vec![grpc_send_answer(), grpc_task_answer()]),
        BINDING_GRPC,
    )
    .await;
    let task = open_a_task(&h, &v10_envelope()).await;
    let sent = issued_last(
        &h,
        &envelope_for("CancelTask", serde_json::json!({ "id": task })),
    )
    .await;
    assert_eq!(path_of(&sent), "/lf.a2a.v1.A2AService/CancelTask");
    let req: a2a_pb::proto::CancelTaskRequest = grpc_message(&sent);
    assert_eq!(req.id, "BACKEND-OWN-TASK-ID");
}

#[tokio::test]
async fn grpc_client_issues_send_streaming_message() {
    let frame = grpc_stream_frame(a2a_pb::proto::TaskState::Completed);
    let h = harness_on(Outcome::Streams(vec![frame]), BINDING_GRPC).await;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 11, "method": "SendStreamingMessage",
        "params": { "message": { "messageId": "m-2", "role": "ROLE_USER",
                                 "parts": [{ "text": "GO" }] } }
    });
    let (status, _, sse) = call_raw(&h, "planner", &body).await;
    assert_eq!(
        status, 200,
        "the streaming submission must be served: {sse}"
    );
    let last = h.sent().pop().expect("busbar made no streaming hop");
    assert!(last.streaming, "the hop must be a STREAM");
    assert_eq!(path_of(&last), "/lf.a2a.v1.A2AService/SendStreamingMessage");
    let _: a2a_pb::proto::SendMessageRequest = grpc_message(&last);
    // THE RE-FRAMING, IN THE ANSWERING DIRECTION: a length-prefixed protobuf message reached the
    // caller as one JSON-RPC response in an SSE frame, because `GrpcFrameReader` produced the same
    // dialect the other two legs produce.
    assert!(
        sse.contains("\"jsonrpc\""),
        "a gRPC stream message must reach the caller as a JSON-RPC response: {sse}"
    );
}

#[tokio::test]
async fn grpc_client_issues_subscribe_to_task() {
    let frame = grpc_stream_frame(a2a_pb::proto::TaskState::Working);
    let h = harness_on(
        Outcome::AnswersThenStreams(200, grpc_working_answer(), vec![frame]),
        BINDING_GRPC,
    )
    .await;
    let task = open_a_task(&h, &v10_envelope()).await;
    let body = envelope_for("SubscribeToTask", serde_json::json!({ "id": task }));
    let (status, _, _) = call_raw(&h, "planner", &body).await;
    assert_eq!(status, 200, "a resubscribe to a live task must be served");
    let last = h
        .sent()
        .pop()
        .expect("busbar made no hop for a resubscribe");
    assert_eq!(path_of(&last), "/lf.a2a.v1.A2AService/SubscribeToTask");
    let req: a2a_pb::proto::SubscribeToTaskRequest = grpc_message(&last);
    assert_eq!(req.id, "BACKEND-OWN-TASK-ID");
}

// ══ THE PROPERTIES THAT HOLD ACROSS ALL THREE LEGS ═══════════════════════════════════════════════

/// THE CALLER'S CREDENTIAL NEVER TRAVELS, ON ANY BINDING.
///
/// The adversarial scan in `relay_tests` proves this for the JSON-RPC leg in five encodings. Arming
/// two more bindings is arming two more places for a header set to be assembled, so the scan is
/// re-run against each of them here — a defence that holds on the leg it was written for and not on
/// the legs that came later is a defence with two thirds of a hole in it.
#[tokio::test]
async fn no_binding_leaks_the_callers_busbar_key() {
    for (binding, outcome) in [
        (
            BINDING_JSONRPC,
            Outcome::AnswersCorrelated(200, backend_ok()),
        ),
        (
            BINDING_HTTP_JSON,
            Outcome::Answers(200, backend_rest_task()),
        ),
        (BINDING_GRPC, Outcome::Answers(200, grpc_send_answer())),
    ] {
        let h = harness_on(outcome, binding).await;
        // The v1.0 shape on every leg: the gRPC binding cannot transcode a v0.3 `message/send`, and
        // a scan whose gRPC arm never reached the wire would be a scan that proved nothing there.
        let sent = issued(&h, &v10_envelope()).await;
        assert!(!sent.is_empty(), "{binding}: no hop was made");
        let wire = h.all_wire();
        for (encoding, needle) in encodings(&h.bearer) {
            assert!(
                !contains(&wire, &needle),
                "{binding}: the caller's busbar key reached the backend hop, {encoding}-encoded"
            );
        }
    }
}

/// A CARD DECLARING A BINDING BUSBAR CANNOT SPEAK IS A NAMED REFUSAL, NOT A JSON-RPC HOP.
///
/// The fail-open here would be silent and would look like it worked: fall back to JSON-RPC, send an
/// envelope to a peer that has just said in its own card that it does not read one, and report the
/// backend's `400` as the backend's fault. So the lookup returns `None` and the hop never happens —
/// and this test asserts the ABSENCE of the request, which is the only thing that can tell the two
/// apart.
#[tokio::test]
async fn a_binding_busbar_cannot_speak_refuses_before_the_socket() {
    let h = harness_on(
        Outcome::Answers(200, backend_ok()),
        "SOAP-1.2-OVER-CARRIER-PIGEON",
    )
    .await;
    let (status, body) = call_agent(&h, "planner", &envelope()).await;
    assert_eq!(
        status, 502,
        "a binding busbar cannot speak is busbar's failure to carry the request, not the caller's"
    );
    assert!(
        h.sent().is_empty(),
        "busbar must not fall back to a binding the card did not offer: {:?}",
        h.sent()
    );
    assert!(
        body.to_string().contains("SOAP-1.2-OVER-CARRIER-PIGEON"),
        "the refusal must name the word an operator has to act on: {body}"
    );
}

/// THE BINDING COMES FROM THE CARD AND THE ADDRESS COMES FROM THE OPERATOR.
///
/// A card may say HOW to talk to an agent; it may not say WHERE. This drives a registration whose
/// card declares an interface at a completely different host and asserts that the hop still goes to
/// the host the operator wrote down — because a card that could re-point the outbound hop is an
/// upstream choosing busbar's peer, which is the rug-pull the pinning apparatus exists to refuse.
#[tokio::test]
async fn the_cards_interface_url_never_moves_the_hop() {
    let h = harness_granting(
        Outcome::Answers(200, backend_rest_task()),
        false,
        &["planner"],
    )
    .await;
    let mut card = a_card();
    card["supportedInterfaces"] = serde_json::json!([{
        "url": "https://attacker.example/a2a",
        "protocolBinding": BINDING_HTTP_JSON,
    }]);
    h.plane.with_registrations_mut(|regs| {
        for reg in regs.iter_mut() {
            approve_card(reg, card.clone());
        }
    });
    let sent = issued_last(&h, &envelope()).await;
    let url = reqwest::Url::parse(&sent.url).expect("the recorded URL parses");
    assert_eq!(
        url.host_str(),
        Some("backend.agent.test"),
        "the hop must go to the OPERATOR's host, whatever the card's interface says: {}",
        sent.url
    );
    assert_eq!(
        sent.http_method, "POST",
        "the card's BINDING is still honoured — only its address is ignored"
    );
    assert_eq!(path_of(&sent), "/a2a/message:send");
}

// ══ CARD DISCOVERY: THE ONE CLIENT VERB THAT IS NOT AN RPC ═══════════════════════════════════════

/// `GET /.well-known/agent-card.json`, ON BOTH HTTP BINDINGS.
///
/// A2A defines card discovery as an HTTP resource at a well-known path rather than as an operation,
/// so it is the ONE client cell whose framing is the same on both HTTP legs — and that sameness is
/// the claim, not an omission. (The inventory marks the gRPC column `na` for exactly this reason:
/// gRPC has no well-known-path concept and the proto service block does not declare it.)
///
/// Driven through [`crate::a2a::fetch::fetch_card`], which is the production fetch — the one the
/// re-verification sweep and the `connect`/`approve` verbs both reach through
/// `transport::LiveCardFetch` — with the SSRF guard and the resolve-then-pin in place. What is
/// asserted is the request line busbar issued and the address it was pinned to, because "busbar
/// fetches a card" is a claim about a `GET` at a path, and a fetch that went anywhere else would
/// satisfy a test that only checked the card came back.
#[test]
fn both_http_bindings_discover_the_card_at_the_well_known_path() {
    use crate::a2a::fetch::{discovery_urls, fetch_card, FetchPolicy, HttpResponse, Resolver};
    use std::cell::RefCell;
    use std::net::{IpAddr, Ipv4Addr};

    const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    struct One;
    impl Resolver for One {
        fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
            Ok(vec![PUBLIC])
        }
    }
    #[derive(Default)]
    struct Seen(RefCell<Vec<(String, IpAddr)>>);
    impl crate::a2a::fetch::Transport for Seen {
        fn get(&self, url: &reqwest::Url, addr: IpAddr) -> Result<HttpResponse, String> {
            self.0.borrow_mut().push((url.to_string(), addr));
            Ok(HttpResponse {
                status: 200,
                location: None,
                body: br#"{"protocolVersion":"0.3.0","name":"planner","skills":[{"id":"plan"}]}"#
                    .to_vec(),
                peer_spki: None,
                client_identity_offered: false,
            })
        }
    }

    // The two bindings' registrations differ in the card they cache and NOT in their endpoint, so
    // the discovery URL derived from that endpoint is the same string — which is the property.
    for binding in [BINDING_JSONRPC, BINDING_HTTP_JSON] {
        let urls = discovery_urls(BASE).expect("the endpoint is a URL");
        assert_eq!(
            urls.first().map(String::as_str),
            Some("https://backend.agent.test/.well-known/agent-card.json"),
            "{binding}: the canonical discovery path is tried first"
        );
        let seen = Seen::default();
        let got = fetch_card(&urls[0], &One, &seen, &FetchPolicy::default())
            .expect("the card must be fetched");
        assert_eq!(
            got.addr, PUBLIC,
            "{binding}: the fetch must be pinned to the address the guard judged"
        );
        assert_eq!(
            seen.0.into_inner(),
            vec![(
                "https://backend.agent.test/.well-known/agent-card.json".to_string(),
                PUBLIC
            )],
            "{binding}: busbar must issue exactly one GET, at the well-known path, to the pinned \
             address"
        );
    }
}

// ══ `ListTasks`: THE POLL BEHIND THE LOCAL ANSWER ════════════════════════════════════════════════
//
// `super::super::local` answers `ListTasks` from busbar's own store and gives the argument for
// why the rows are busbar's: busbar issues its own task ids, and the backend's names for the same
// work are never client-visible. What that section also said out loud is that those rows carry THE
// LAST STATE THE BACKEND REPORTED and are NOT a live poll. This is the poll — busbar asks the agent
// what it now holds, refreshes the rows it can match, and then renders its own scoped rows exactly
// as before.
//
// So the cell `a2a|<binding>|client|client|ListTasks` is a real hop with a real consequence, and the
// three tests below assert the hop while `the_refreshed_state_reaches_the_callers_own_list` asserts
// the consequence and `a_backend_row_busbar_cannot_match_moves_nothing` asserts the boundary.

/// The caller's `ListTasks`, addressed to the agent whose work it is about.
fn list_tasks_call() -> serde_json::Value {
    envelope_for("ListTasks", serde_json::json!({}))
}

/// Call, and hand back the LAST request busbar asked to have sent — PANICKING unless the count
/// moved. The submission that opens the task has already made a hop, so "the log is not empty"
/// would pass for a `ListTasks` that never reached the wire, which is exactly the false green this
/// battery exists to prevent.
async fn issued_after(h: &Harness, before: usize, envelope: &serde_json::Value) -> Recorded {
    let (status, body) = call_agent(h, "planner", envelope).await;
    let sent = h.sent();
    assert!(
        sent.len() > before,
        "busbar made NO NEW outbound hop for {:?}. It answered {status} with {body}. This verb is \
         also answered locally, so a `200` proves nothing whatsoever about the client leg.",
        envelope.get("method")
    );
    sent.into_iter().next_back().expect("just checked")
}

/// A backend that is still WORKING. A task busbar holds as TERMINAL has nothing left to learn, so a
/// fixture that completed the task would make busbar skip the hop and every test here assert
/// nothing.
fn jsonrpc_list_answer(state: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 0,
        "result": { "tasks": [{ "id": "BACKEND-OWN-TASK-ID", "kind": "task",
                                "status": { "state": state } }],
                    "nextPageToken": "" }
    })
    .to_string()
}

#[tokio::test]
async fn jsonrpc_client_issues_list_tasks() {
    let h = harness_on(
        in_turn(200, vec![backend_working(), jsonrpc_list_answer("working")]),
        BINDING_JSONRPC,
    )
    .await;
    let _ = open_a_task(&h, &envelope()).await;
    let before = h.sent().len();
    let sent = issued_after(&h, before, &list_tasks_call()).await;
    assert_jsonrpc(&sent, "ListTasks");
}

#[tokio::test]
async fn http_json_client_issues_list_tasks() {
    let h = harness_on(
        in_turn(
            200,
            vec![
                backend_rest_working(),
                serde_json::json!({ "tasks": [], "nextPageToken": "" }).to_string(),
            ],
        ),
        BINDING_HTTP_JSON,
    )
    .await;
    let _ = open_a_task(&h, &envelope()).await;
    let before = h.sent().len();
    let sent = issued_after(&h, before, &list_tasks_call()).await;
    assert_eq!(
        sent.http_method, "GET",
        "A2A binds `ListTasks` to a GET of the collection"
    );
    assert_eq!(path_of(&sent), "/a2a/tasks");
    assert!(
        sent.body.is_empty(),
        "a GET carries no body: {:?}",
        String::from_utf8_lossy(&sent.body)
    );
}

#[tokio::test]
async fn grpc_client_issues_list_tasks() {
    let answer = as_fixture(&grpc_frame(&a2a_pb::proto::ListTasksResponse {
        tasks: vec![grpc_task(a2a_pb::proto::TaskState::Working)],
        ..Default::default()
    }));
    let h = harness_on(
        in_turn(200, vec![grpc_working_answer(), answer]),
        BINDING_GRPC,
    )
    .await;
    let _ = open_a_task(&h, &v10_envelope()).await;
    let before = h.sent().len();
    let sent = issued_after(&h, before, &list_tasks_call()).await;
    assert_eq!(path_of(&sent), "/lf.a2a.v1.A2AService/ListTasks");
    let _: a2a_pb::proto::ListTasksRequest = grpc_message(&sent);
}

/// THE CONSEQUENCE. The backend has moved the task on out of band — no reply to busbar, no stream
/// event — and the caller's next `ListTasks` says so, because busbar asked.
///
/// Before this hop existed the same call answered `working` forever, and `local`'s own header said
/// why: the store holds the last state busbar OBSERVED, and busbar observes one only while it is
/// holding a relayed request open.
#[tokio::test]
async fn the_refreshed_state_reaches_the_callers_own_list() {
    let h = harness_on(
        in_turn(
            200,
            vec![backend_working(), jsonrpc_list_answer("completed")],
        ),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_a_task(&h, &envelope()).await;
    let before = h.sent().len();
    let _ = issued_after(&h, before, &list_tasks_call()).await;
    let (status, answer) = call_agent(&h, "planner", &list_tasks_call()).await;
    assert_eq!(status, 200, "the list must be served: {answer}");
    let listed = answer
        .pointer("/result/tasks")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mine = listed
        .iter()
        .find(|t| t.get("id").and_then(serde_json::Value::as_str) == Some(task.as_str()))
        .unwrap_or_else(|| panic!("the caller's own task is not in its own list: {answer}"));
    assert_eq!(
        mine.pointer("/status/state")
            .and_then(serde_json::Value::as_str),
        Some("TASK_STATE_COMPLETED"),
        "the state the agent reported must reach the caller's list: {answer}"
    );
}

/// **THE BOUNDARY, AND IT IS THE REASON THIS HOP IS SAFE ON A SHARED BACKEND.**
///
/// One backend fronts many of busbar's callers, so its `ListTasks` — answered to BUSBAR'S OWN
/// credential — enumerates work belonging to every tenant busbar ever sent it. The refresh takes a
/// state from that answer ONLY for a row busbar already holds, that this principal already owns, on
/// this agent, whose backend id busbar itself recorded. Everything else is ignored in silence.
///
/// This drives the case that matters: an answer naming a task id busbar cannot match must move
/// NOTHING, and in particular must not create a row, so the caller's list is exactly the list it
/// was.
#[tokio::test]
async fn a_backend_row_busbar_cannot_match_moves_nothing() {
    let stranger = serde_json::json!({
        "jsonrpc": "2.0", "id": 0,
        "result": { "tasks": [
            { "id": "SOMEBODY-ELSES-TASK", "status": { "state": "completed" } },
            { "id": "ANOTHER-TENANTS-TASK", "status": { "state": "failed" } }
        ], "nextPageToken": "" }
    })
    .to_string();
    let h = harness_on(
        in_turn(200, vec![backend_working(), stranger]),
        BINDING_JSONRPC,
    )
    .await;
    let task = open_a_task(&h, &envelope()).await;
    let before = h.sent().len();
    let _ = issued_after(&h, before, &list_tasks_call()).await;
    let (_, answer) = call_agent(&h, "planner", &list_tasks_call()).await;
    let listed = answer
        .pointer("/result/tasks")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        listed.len(),
        1,
        "a backend's own rows must never become rows in a caller's list: {answer}"
    );
    assert_eq!(listed[0]["id"], task);
    assert_eq!(
        listed[0]
            .pointer("/status/state")
            .and_then(serde_json::Value::as_str),
        Some("TASK_STATE_WORKING"),
        "an unmatched backend row must not move the caller's own task: {answer}"
    );
}

/// A CALLER WITH NOTHING OUTSTANDING ON THIS AGENT ASKS THE AGENT NOTHING.
///
/// The hop is worth making when there is a row it could refresh, and asking a backend to enumerate
/// its work for a caller with none is a request with no possible consequence. This asserts the
/// ABSENCE of the hop, which is the only thing that can tell "did not ask" from "asked and the
/// fixture happened to answer".
#[tokio::test]
async fn a_list_with_no_open_task_of_this_callers_makes_no_hop() {
    let h = harness_on(
        Outcome::AnswersCorrelated(200, backend_ok()),
        BINDING_JSONRPC,
    )
    .await;
    let (status, answer) = call_agent(&h, "planner", &list_tasks_call()).await;
    assert_eq!(status, 200, "the empty list is still served: {answer}");
    assert!(
        h.sent().is_empty(),
        "busbar asked the agent for a list it could learn nothing from: {:?}",
        h.sent()
    );
}

// ══ THE EQUALITY CELL `audit-chain × a2a-client` ═════════════════════════════════════════════════
//
// This module's own header claims every test here drives "the same audit chain". Until this test,
// nothing in the file asserted it: every assertion above reads the recording seam — what busbar
// asked to SEND — and a relay that made a perfect hop and chained nothing would pass all of them.
// That is precisely the ledger's note for this cell ("no test proves originate or push-delivery
// outcomes are chained"), and it is what the two tests below close for the DELEGATION HOP: the leg
// busbar itself issues to a registered backend agent.

/// A task-event sink for the process-global [`crate::plane::taskstore::TASKS`].
///
/// The shipped `busbar-store-memory` implements NONE of the task methods — it is documented as
/// genuinely ephemeral and the boot-restore path relies on that — so a sink is the only way to read
/// the chain back from outside the engine. Every non-task method takes the trait's own default or
/// delegates to the real `MemoryStore`; only the two task-event methods are backed, because those
/// are the whole subject.
///
/// Reads are TASK-SCOPED (`list_task_events(task_id)`), which is what makes this safe against the
/// global sink: a sibling test dispatching through `TASKS` at the same time writes rows for ITS
/// task ids, and they cannot enter this test's assertions.
struct ChainSink {
    inner: busbar_store_memory::MemoryStore,
    /// `(task_id, body)` — the OPAQUE stored task-event bodies a durable backend holds (the neutral
    /// `{seq,prev_hash,hash,content}` the P5-C9 seam persists), kept verbatim and reconstructed to a
    /// typed view on read via [`crate::plane::store::task_event_row_from_body`].
    events: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
}

impl ChainSink {
    fn new() -> Self {
        Self {
            inner: busbar_store_memory::MemoryStore::new(),
            events: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl busbar_api::Store for ChainSink {
    fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    // ── The neutral kind-tagged verbs, delegating to the named task-event methods above ──────────
    fn append_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
        match record.kind.as_str() {
            crate::plane::store::KIND_TASK_EVENT => {
                let task_id = record.parent.clone().unwrap_or_else(|| record.id.clone());
                self.events
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((task_id, record.body.clone()));
                Ok(())
            }
            _ => Ok(()),
        }
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &busbar_api::PlaneSelector,
    ) -> busbar_api::StoreResult<Vec<Vec<u8>>> {
        match (kind, selector) {
            (crate::plane::store::KIND_TASK_EVENT, busbar_api::PlaneSelector::Parent(p)) => {
                Ok(self
                    .events
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .filter(|(id, _)| id == p)
                    .map(|(_, body)| body.clone())
                    .collect())
            }
            _ => Ok(Vec::new()),
        }
    }
}

impl ChainSink {
    fn list_task_events(
        &self,
        task_id: &str,
    ) -> busbar_api::StoreResult<Vec<busbar_api::TaskEventRow>> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(id, _)| id == task_id)
            .map(|(id, body)| crate::plane::store::task_event_row_from_body(id, body))
            .collect()
    }
}

/// THE CELL. The hop busbar issues to a backend agent lands in the per-task tamper-evident chain,
/// naming WHO delegated and TO WHICH registered agent — and it is recorded BEFORE the socket, so a
/// hop that never comes back still left the record that it was made.
///
/// ## What would pass without this test, and must not
///
/// An engine that relayed perfectly and chained nothing. Every other test in this file reads the
/// recording seam, which sees the request busbar composed; none of them can tell whether an
/// investigator would afterwards find any record of the delegation at all.
///
/// ## Why the `task.delegated` event specifically, and not just "some events exist"
///
/// `task.submitted` is the INBOUND fact — the caller asked. It is written on the server plane's
/// path and proves nothing about the client leg. The event that belongs to the leg busbar issued is
/// `task.delegated`, whose whole purpose (`taskstore.rs`: "the single most important fact the
/// delegating side's provenance has to carry: who delegated, to which registered agent") is the
/// outbound hop. So the assertions below name that event, name the agent on it, and require it to
/// sit in a chain that verifies.
#[tokio::test]
async fn the_delegation_hop_lands_in_the_per_task_chain_naming_the_agent_it_was_issued_to() {
    // THE ONE LOCK EVERY TEST THAT ATTACHES A SINK TO THE PROCESS-WIDE `TASKS` TAKES. This test
    // reads back what IT wrote, and the registry is process state, so a concurrent test swapping
    // (or clearing) the sink mid-flight makes this one read an empty chain and fail for a reason
    // that has nothing to do with the client leg. See `taskstore::TASKS_SINK_LOCK`.
    let _sink_guard = crate::plane::taskstore::TASKS_SINK_LOCK.lock().await;
    let sink = std::sync::Arc::new(ChainSink::new());
    // Aim the process-wide `task_event` stream the front door writes through at THIS sink (a swap, not
    // a re-register) and attach the row-upsert sink.
    crate::plane::taskstore::aim_global_task_sink(Some(
        busbar_substrate::plane::store::PlaneStoreView::narrow(sink.clone()),
    ));
    crate::plane::taskstore::TASKS.set_sink(
        busbar_substrate::plane::store::PlaneStoreView::narrow(sink.clone()),
    );

    let h = harness_on(
        Outcome::AnswersCorrelated(200, backend_ok()),
        BINDING_JSONRPC,
    )
    .await;
    let task_id = open_a_task(&h, &envelope()).await;

    // THE LEG REALLY WENT OUT. Without this the chain assertions could be satisfied by an engine
    // that recorded a delegation it never performed, which is a worse failure than recording none.
    assert!(
        !h.sent().is_empty(),
        "no outbound hop was recorded, so there is no client leg for the chain to be about"
    );

    let events = sink
        .list_task_events(&task_id)
        .expect("the sink lists the events it was given");
    assert!(
        !events.is_empty(),
        "the delegating side wrote NOTHING to the per-task chain for {task_id}. This is the \
         `audit-chain × a2a-client` cell: busbar made an outbound hop and an investigator has no \
         tamper-evident record that it happened."
    );

    let delegated: Vec<_> = events
        .iter()
        .filter(|e| e.kind == crate::plane::provenance::EV_DELEGATED)
        .collect();
    assert_eq!(
        delegated.len(),
        1,
        "exactly one `{}` event for one hop; got kinds {:?}",
        crate::plane::provenance::EV_DELEGATED,
        events.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
    assert_eq!(
        delegated[0].agent_id, "planner",
        "the chained hop must name WHICH registered agent busbar delegated to — a delegation \
         record that does not say to whom answers the only question it exists to answer with \
         nothing"
    );
    assert!(
        !delegated[0].principal.is_empty(),
        "and WHO delegated: an unattributed hop cannot be investigated"
    );

    // ── AND IT IS A CHAIN. The core verifier, over the rows the sink actually kept. ─────────────
    crate::plane::taskstore::verify_task_event_rows(&events)
        .expect("the a2a-client leg's persisted chain must verify against its own hashes");
    assert!(
        events
            .iter()
            .any(|e| e.kind == crate::plane::provenance::EV_SUBMITTED),
        "the hop's record must sit in the SAME chain as the submission it serves, not a second \
         log of its own: {:?}",
        events.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );

    crate::plane::taskstore::aim_global_task_sink(None);
    crate::plane::taskstore::TASKS.set_sink(
        busbar_substrate::plane::store::PlaneStoreView::narrow(std::sync::Arc::new(
            busbar_store_memory::MemoryStore::new(),
        )),
    );
}

/// THE OTHER HALF, and the one an operator cares about more: a hop that FAILED is chained too, and
/// the chain carries the outcome rather than stopping at the optimistic record.
///
/// A chain that recorded only hops that worked would be an activity feed. The backend here refuses
/// the hop, and the task must still end — terminally, in the same verified chain — so the record
/// distinguishes "busbar asked and the backend failed" from "busbar never asked".
#[tokio::test]
async fn a_failed_hop_is_chained_too_and_the_chain_carries_its_terminal_outcome() {
    // THE ONE LOCK EVERY TEST THAT ATTACHES A SINK TO THE PROCESS-WIDE `TASKS` TAKES. This test
    // reads back what IT wrote, and the registry is process state, so a concurrent test swapping
    // (or clearing) the sink mid-flight makes this one read an empty chain and fail for a reason
    // that has nothing to do with the client leg. See `taskstore::TASKS_SINK_LOCK`.
    let _sink_guard = crate::plane::taskstore::TASKS_SINK_LOCK.lock().await;
    let sink = std::sync::Arc::new(ChainSink::new());
    // Aim the process-wide `task_event` stream the front door writes through at THIS sink (a swap, not
    // a re-register) and attach the row-upsert sink.
    crate::plane::taskstore::aim_global_task_sink(Some(
        busbar_substrate::plane::store::PlaneStoreView::narrow(sink.clone()),
    ));
    crate::plane::taskstore::TASKS.set_sink(
        busbar_substrate::plane::store::PlaneStoreView::narrow(sink.clone()),
    );

    // A backend that answers a transport-level failure to the hop busbar issues.
    let h = harness_on(
        Outcome::Fails("the backend refused the hop".to_string()),
        BINDING_JSONRPC,
    )
    .await;
    let (status, answer) = call_agent(&h, "planner", &envelope()).await;
    assert!(
        !h.sent().is_empty(),
        "the hop must have been attempted for this test to be about a failed hop: {status} {answer}"
    );

    // busbar's own task id, off the refusal that names it. The refusal carries it as a
    // `google.rpc.ResourceInfo` detail — the same structured shape the gRPC binding puts in its
    // trailer — so it is read out of the details array rather than guessed at a fixed index.
    let task_id = answer
        .pointer("/error/data")
        .and_then(serde_json::Value::as_array)
        .and_then(|details| {
            details
                .iter()
                .find_map(|d| d.get("resourceName").and_then(serde_json::Value::as_str))
        })
        .unwrap_or_default()
        .to_string();
    assert!(
        !task_id.is_empty(),
        "the refusal must name the task busbar opened, or the caller cannot correlate the failure \
         with the record busbar kept: {answer}"
    );

    let events = sink
        .list_task_events(&task_id)
        .expect("the sink lists the events it was given");
    assert!(
        events
            .iter()
            .any(|e| e.kind == crate::plane::provenance::EV_DELEGATED),
        "the hop was ATTEMPTED, so it must be chained — the record is written before the socket \
         precisely so a hop that fails is not invisible: {:?}",
        events.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
    assert!(
        events
            .iter()
            .any(|e| e.kind == crate::plane::provenance::EV_TERMINAL),
        "a failed hop must END the task in the chain rather than leave it open forever: {:?}",
        events
            .iter()
            .map(|e| (&e.kind, &e.state))
            .collect::<Vec<_>>()
    );
    crate::plane::taskstore::verify_task_event_rows(&events)
        .expect("the failed leg's persisted chain must verify against its own hashes");

    crate::plane::taskstore::aim_global_task_sink(None);
    crate::plane::taskstore::TASKS.set_sink(
        busbar_substrate::plane::store::PlaneStoreView::narrow(std::sync::Arc::new(
            busbar_store_memory::MemoryStore::new(),
        )),
    );
}
