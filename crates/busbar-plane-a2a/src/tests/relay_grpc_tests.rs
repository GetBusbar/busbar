// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR AS AN A2A CLIENT OVER gRPC (the engine's `client_leg_tests.rs` `grpc_client_issues_*`,
//! ported to the door's hop): what each attempt asks to have sent (the rpc's path, its request
//! message) and the caller's answer read off the grpc transport's pieces (its head, each message
//! length-prefixed, its trailers). The oracle is the generated `pb` messages, decoded and encoded
//! with `prost` directly, never the code under test.

use super::*;
use crate::proto::pb;
use prost::Message as _;
use serde_json::json;

/// The operator's `url:` for the agent: its path is never the rpc's.
const URL: &str = "https://backend.agent.test/a2a";

/// The backend's own task id, which every addressed rpc must name.
const BACKEND: &str = "BACKEND-OWN-TASK-ID";

fn kernel(url: Option<&str>) -> Piece<'_> {
    Piece {
        from: From::Kernel(url),
        bytes: &[],
        status: None,
        last: false,
    }
}

fn caller(bytes: &[u8]) -> Piece<'_> {
    Piece {
        from: From::Caller,
        bytes,
        status: None,
        last: true,
    }
}

fn far(status: Option<u32>, bytes: &[u8], last: bool) -> Piece<'_> {
    Piece {
        from: From::FarEnd,
        bytes,
        status,
        last,
    }
}

/// One message in its length-prefixed form, as the grpc transport hands an answer back.
fn framed<M: prost::Message>(message: &M) -> Vec<u8> {
    let body = message.encode_to_vec();
    let mut out = vec![0u8];
    out.extend_from_slice(&u32::try_from(body.len()).expect("small").to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn task(state: pb::TaskState) -> pb::Task {
    pb::Task {
        id: BACKEND.into(),
        context_id: "BACKEND-OWN-CONTEXT".into(),
        status: Some(pb::TaskStatus {
            state: state as i32,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn send_answer(state: pb::TaskState) -> Vec<u8> {
    framed(&pb::SendMessageResponse {
        payload: Some(pb::send_message_response::Payload::Task(task(state))),
    })
}

fn stream_event(state: pb::TaskState) -> Vec<u8> {
    framed(&pb::StreamResponse {
        payload: Some(pb::stream_response::Payload::Task(task(state))),
    })
}

/// The v1.0 submission a caller reaching a gRPC agent sends: its params ARE the request message's
/// ProtoJSON.
fn submission(method: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0", "id": 7, "method": method,
        "params": { "message": { "messageId": "m-1", "role": "ROLE_USER",
                                 "parts": [{ "text": "PLAN THE MIGRATION" }] } }
    })
}

/// A hop bound to the gRPC binding for `envelope` (`translated`: the envelope with the far end's
/// own task id, as the door hands it over), through its attempt and the caller's body: the request
/// and the message it sends.
fn dialled(
    envelope: &serde_json::Value,
    translated: Option<&serde_json::Value>,
    events: bool,
) -> (Relay, Attempt, Vec<u8>) {
    let mut r = Relay::new(json!(7), "1.0");
    if events {
        r.expect_events();
    }
    if let Some(t) = translated {
        r.send_instead(serde_json::to_vec(t).expect("json"));
    }
    r.bind(Binding::Grpc, envelope);
    let Answer::Attempt(attempt) = r.on_piece(kernel(Some(URL))) else {
        panic!("no attempt on the gRPC binding");
    };
    let bytes = serde_json::to_vec(envelope).expect("json");
    // A request message whose every field is its default is zero bytes: nothing to send beside the
    // head (the grpc transport frames the empty message).
    let message = match r.on_piece(caller(&bytes)) {
        Answer::ToFarEnd(message) => message,
        Answer::Nothing => Vec::new(),
        other => panic!("no message for the far end: {other:?}"),
    };
    (r, attempt, message)
}

/// The far end's answer, piece by piece as the grpc transport hands it: its head (no status of
/// its own: `0`), `messages`, its trailers (stating `code`), then the end.
fn answer(r: &mut Relay, messages: &[Vec<u8>], code: Option<u32>) -> Vec<Answer> {
    let mut answers = vec![r.on_piece(far(Some(0), &[], false))];
    for m in messages {
        answers.push(r.on_piece(far(None, m, false)));
    }
    answers.push(r.on_far_fields(&[], code, false));
    answers.push(r.on_piece(far(None, &[], true)));
    answers
}

fn whole(answers: Vec<Answer>) -> Reply {
    answers
        .into_iter()
        .find_map(|a| match a {
            Answer::ToCaller(reply) => Some(reply),
            _ => None,
        })
        .expect("the caller is answered")
}

fn body(reply: &Reply) -> serde_json::Value {
    serde_json::from_slice(&reply.body).expect("the answer is JSON")
}

/// `grpc_client_issues_send_message`: the rpc's own path under the service (never the operator's
/// path), a POST, the gRPC media type, and the caller's content surviving the transcode into the
/// request message; the far end's message reaches the caller as the JSON-RPC result it is.
#[test]
fn grpc_client_issues_send_message() {
    let (mut r, attempt, message) = dialled(&submission("SendMessage"), None, false);
    assert_eq!(attempt.verb, "POST");
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/SendMessage");
    assert_eq!(
        attempt.fields,
        vec![
            ("content-type", "application/grpc+proto".to_string()),
            ("accept", "application/grpc+proto".to_string()),
            ("a2a-version", "1.0".to_string()),
        ]
    );
    let req = pb::SendMessageRequest::decode(message.as_slice())
        .expect("the message decodes as the rpc's request");
    assert!(
        format!("{:?}", req.message).contains("PLAN THE MIGRATION"),
        "the caller's own content must survive the transcode"
    );
    let reply = whole(answer(
        &mut r,
        &[send_answer(pb::TaskState::Completed)],
        Some(0),
    ));
    assert_eq!(reply.status, 200);
    let got = body(&reply);
    assert_eq!(got["id"], 7);
    assert_eq!(got["result"]["task"]["id"], BACKEND);
    assert_eq!(
        got["result"]["task"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );
}

/// A task hop's answer leaves under busbar's identity and settles the task on what the far end
/// reported, as on the other bindings.
#[test]
fn a_grpc_answer_about_a_task_leaves_under_busbars_identity() {
    let (mut r, _, _) = dialled(&submission("SendMessage"), None, false);
    r.for_task(TaskHop {
        task_id: "busbar-t".into(),
        context_id: "busbar-c".into(),
        addressed: false,
        skill: None,
    });
    let reply = whole(answer(
        &mut r,
        &[send_answer(pb::TaskState::Completed)],
        Some(0),
    ));
    assert_eq!(body(&reply)["result"]["task"]["id"], "busbar-t");
    assert_eq!(
        r.take_settled(),
        vec![Settled::Reported {
            state: TaskState::Completed,
            backend_id: Some(BACKEND.into()),
        }]
    );
}

/// `grpc_client_issues_get_task`: the rpc names the BACKEND's own task id, not busbar's.
#[test]
fn grpc_client_issues_get_task() {
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": "busbar-t" } });
    let translated =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": BACKEND } });
    let (mut r, attempt, message) = dialled(&asked, Some(&translated), false);
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/GetTask");
    let req = pb::GetTaskRequest::decode(message.as_slice()).expect("a GetTaskRequest");
    assert_eq!(
        req.id, BACKEND,
        "the rpc must name the BACKEND's own task id, not busbar's"
    );
    let reply = whole(answer(
        &mut r,
        &[framed(&task(pb::TaskState::Completed))],
        None,
    ));
    assert_eq!(body(&reply)["result"]["id"], BACKEND);
}

/// `grpc_client_issues_cancel_task`.
#[test]
fn grpc_client_issues_cancel_task() {
    let asked = json!({ "jsonrpc": "2.0", "id": 7, "method": "tasks/cancel", "params": { "id": "busbar-t" } });
    let translated =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "tasks/cancel", "params": { "id": BACKEND } });
    let (_, attempt, message) = dialled(&asked, Some(&translated), false);
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/CancelTask");
    let req = pb::CancelTaskRequest::decode(message.as_slice()).expect("a CancelTaskRequest");
    assert_eq!(req.id, BACKEND);
}

/// `grpc_client_issues_send_stream_message`: the streaming rpc, and each length-prefixed message
/// of its answer reaching the caller as one JSON-RPC response in an event-stream frame.
#[test]
fn grpc_client_issues_send_stream_message() {
    let (mut r, attempt, message) = dialled(&submission("SendStreamingMessage"), None, true);
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/SendStreamingMessage");
    let _ = pb::SendMessageRequest::decode(message.as_slice()).expect("a SendMessageRequest");
    let answers = answer(&mut r, &[stream_event(pb::TaskState::Completed)], Some(0));
    let parts: Vec<Part> = answers
        .into_iter()
        .filter_map(|a| match a {
            Answer::Part(p) => Some(p),
            _ => None,
        })
        .collect();
    assert!(parts[0].head, "the first event starts the caller's stream");
    let sse = String::from_utf8(parts.iter().flat_map(|p| p.body.clone()).collect()).expect("text");
    assert!(sse.starts_with("data: "), "{sse}");
    assert!(
        sse.contains("\"jsonrpc\"") && sse.contains("TASK_STATE_COMPLETED"),
        "a gRPC stream message must reach the caller as a JSON-RPC response: {sse}"
    );
    assert!(parts.last().is_some_and(|p| p.last), "the stream ends");
}

/// A message split across pieces is read once it is whole, and two in one piece are two events.
#[test]
fn a_streamed_message_is_read_once_whole_whatever_the_pieces() {
    let (mut r, _, _) = dialled(&submission("SendStreamingMessage"), None, true);
    let _ = r.on_piece(far(Some(0), &[], false));
    let first = stream_event(pb::TaskState::Working);
    let (a, b) = first.split_at(7);
    assert_eq!(r.on_piece(far(None, a, false)), Answer::Nothing);
    let Answer::Part(part) = r.on_piece(far(None, b, false)) else {
        panic!("the whole message is an event");
    };
    assert!(part.head);
    let two = [
        stream_event(pb::TaskState::Working),
        stream_event(pb::TaskState::Completed),
    ]
    .concat();
    let Answer::Part(part) = r.on_piece(far(None, &two, false)) else {
        panic!("two events");
    };
    assert_eq!(
        String::from_utf8_lossy(&part.body)
            .matches("data: ")
            .count(),
        2
    );
}

/// `grpc_client_issues_subscribe_to_task`: the rpc names the backend's own task id.
#[test]
fn grpc_client_issues_subscribe_to_task() {
    let asked = json!({ "jsonrpc": "2.0", "id": 7, "method": "SubscribeToTask", "params": { "id": "busbar-t" } });
    let translated = json!({ "jsonrpc": "2.0", "id": 7, "method": "SubscribeToTask", "params": { "id": BACKEND } });
    let (mut r, attempt, message) = dialled(&asked, Some(&translated), true);
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/SubscribeToTask");
    let req = pb::SubscribeToTaskRequest::decode(message.as_slice()).expect("a subscribe");
    assert_eq!(req.id, BACKEND);
    let answers = answer(&mut r, &[stream_event(pb::TaskState::Working)], Some(0));
    assert!(answers
        .iter()
        .any(|a| matches!(a, Answer::Part(p) if p.head)));
}

/// `grpc_client_issues_get_extended_agent_card`: a task-less hop; the card the far end answers is
/// the caller's result.
#[test]
fn grpc_client_issues_get_extended_agent_card() {
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetExtendedAgentCard", "params": {} });
    let (mut r, attempt, message) = dialled(&asked, None, false);
    assert_eq!(attempt.target, "/lf.a2a.v1.A2AService/GetExtendedAgentCard");
    let _ = pb::GetExtendedAgentCardRequest::decode(message.as_slice()).expect("the request");
    let card = framed(&pb::AgentCard {
        name: "planner-extended".into(),
        ..Default::default()
    });
    let reply = whole(answer(&mut r, &[card], Some(0)));
    assert_eq!(body(&reply)["result"]["name"], "planner-extended");
}

/// THE STATUS THE TRAILERS STATE IS READ: a call that ends with an error is the backend refusing
/// the request (its A2A code where the status binds one, the task's own refusal on a task hop),
/// never a reply busbar cannot read.
#[test]
fn a_grpc_error_status_is_the_backends_refusal_with_its_a2a_code() {
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": BACKEND } });
    let (mut r, _, _) = dialled(&asked, None, false);
    r.for_task(TaskHop {
        task_id: "busbar-t".into(),
        context_id: "busbar-c".into(),
        addressed: true,
        skill: None,
    });
    let reply = whole(answer(&mut r, &[], Some(5)));
    let got = body(&reply);
    assert_eq!(
        got["error"]["code"], -32001,
        "NOT_FOUND is TaskNotFound: {got}"
    );
    assert_eq!(reply.status, 404);
    assert!(
        r.take_settled().is_empty(),
        "an addressed task is never failed"
    );
    // Task-less: the backend's refusal in the engine's fixed words.
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetExtendedAgentCard", "params": {} });
    let (mut r, _, _) = dialled(&asked, None, false);
    let reply = whole(answer(&mut r, &[], Some(13)));
    assert_eq!(reply, HopRefusal::BackendError.reply(&json!(7)));
}

/// A gRPC agent refusing busbar at the HTTP layer (`401`/`403`, no gRPC answer) refuses busbar
/// itself, as on every binding (predev `relay.rs:1583`: `RelayRefusal::Status`, read by the one
/// status table, an auth status hard): the hop's reading is hard, so the kernel takes the member
/// out of its pool's walk. RED: no reading at all, and the member stayed in the walk.
#[test]
fn a_grpc_agent_refusing_busbar_at_the_http_layer_reads_hard() {
    let asked = submission("SendMessage");
    for status in [401, 403] {
        let (mut r, _, _) = dialled(&asked, None, false);
        let reply = whole(vec![r.on_piece(far(Some(status), b"denied", true))]);
        assert_eq!(reply.status, 502, "status {status}");
        assert_eq!(r.take_reading(), Some(Reading::Hard), "status {status}");
    }
}

/// An answer with no message and no status to read is the engine's `Unframable`: refused by name.
#[test]
fn a_grpc_answer_with_no_message_is_refused_by_name() {
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetExtendedAgentCard", "params": {} });
    let (mut r, _, _) = dialled(&asked, None, false);
    let reply = whole(answer(&mut r, &[], None));
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply)["error"]["message"],
        "a2a.hop.unframable: `GetExtendedAgentCard` could not be carried to this agent over its \
         `GRPC` binding"
    );
}

/// A request whose params are not the rpc's request message (a v0.3 document) cannot be framed:
/// refused by name before anything is sent.
#[test]
fn params_that_are_not_the_request_message_are_refused_before_the_hop() {
    let v03 = json!({
        "jsonrpc": "2.0", "id": 7, "method": "message/send",
        "params": { "message": { "kind": "message", "role": "user", "parts": [] } }
    });
    let mut r = Relay::new(json!(7), "0.3");
    r.bind(Binding::Grpc, &v03);
    let Answer::ToCaller(reply) = r.on_piece(kernel(Some(URL))) else {
        panic!("refused before the hop");
    };
    assert_eq!(reply.status, 502);
    assert!(r.answered());
}

/// THE TRAILERS ARE NEVER BYTES OF THE ANSWER: on the JSON-RPC binding a field block after the
/// body is ignored. RED: the trailers were appended to the body, which then was not JSON.
#[test]
fn trailers_after_a_json_rpc_answer_are_not_read_as_its_body() {
    let mut r = Relay::new(json!(7), "1.0");
    let _ = r.on_piece(kernel(Some(URL)));
    let _ = r.on_piece(caller(br#"{"jsonrpc":"2.0","id":7,"method":"GetTask"}"#));
    let _ = r.on_piece(far(
        Some(200),
        br#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
        false,
    ));
    assert_eq!(
        r.on_far_fields(b"x-trailer: 1\r\n", None, false),
        Answer::Nothing
    );
    let Answer::ToCaller(reply) = r.on_piece(far(None, &[], true)) else {
        panic!("the caller is answered");
    };
    assert_eq!(reply.status, 200);
}

/// THE NEED AN ATTEMPT RIDES: the gRPC binding names the door's gRPC need; the others name none
/// (the member's own).
#[test]
fn a_grpc_attempt_rides_the_doors_grpc_need() {
    use crate::plane_door::attempt_need;
    assert_eq!(attempt_need(Binding::Grpc), crate::door::NEED_GRPC + 1);
    assert_eq!(attempt_need(Binding::JsonRpc), 0);
    assert_eq!(attempt_need(Binding::HttpJson), 0);
}

/// THE CALL'S END AS THE KERNEL HANDS IT ON (`BUSBAR-1.6.0.md` l.394, l.747): a call that ends
/// with an error status reaches the plane as its trailers, the answer's LAST piece, with the status
/// the transport read off them beside them. The caller is answered the A2A error the status binds,
/// and the breaker is handed the destination ANSWERING (the engine's `classify_hop`: a well-formed
/// backend error is a success to the breaker, never a transient); UNAUTHENTICATED refuses busbar
/// itself, as a 401 does. Trailers handed on with NO status state no code, whatever their details
/// carry (RED: the details' own `google.rpc.Status` code was read as the call's status).
#[test]
fn a_status_handed_on_with_the_last_trailers_ends_the_call() {
    use crate::framed::{Code, ErrorInfo, Status, DETAILS_FIELD};
    use base64::Engine as _;
    use busbar_contract::abi::transport::fields::{LINE_END, SEPARATOR};
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetTask", "params": { "id": BACKEND } });
    let hop = || {
        let (mut r, _, _) = dialled(&asked, None, false);
        r.for_task(TaskHop {
            task_id: "busbar-t".into(),
            context_id: "busbar-c".into(),
            addressed: true,
            skill: None,
        });
        assert_eq!(r.on_piece(far(Some(0), &[], false)), Answer::Nothing);
        r
    };
    let answered = |a: Answer| match a {
        Answer::ToCaller(reply) => reply,
        other => panic!("the last trailers answer the caller: {other:?}"),
    };
    // NOT_FOUND: TaskNotFound, the destination answering.
    let mut r = hop();
    let reply = answered(r.on_far_fields(&[], Some(Code::NotFound as u32), true));
    assert_eq!(body(&reply)["error"]["code"], -32001, "{:?}", body(&reply));
    assert_eq!(reply.status, 404);
    assert_eq!(r.take_reading(), Some(Reading::Healthy));
    // UNAUTHENTICATED: busbar itself refused.
    let mut r = hop();
    let _ = answered(r.on_far_fields(&[], Some(Code::Unauthenticated as u32), true));
    assert_eq!(r.take_reading(), Some(Reading::Hard));
    // Details naming NOT_FOUND, handed on with no status: no code is read off them.
    let details = Status::with_error_info(
        Code::NotFound,
        "no such task",
        ErrorInfo {
            reason: "TASK_NOT_FOUND".into(),
            domain: crate::ERROR_INFO_DOMAIN.into(),
            metadata: std::collections::BTreeMap::new(),
        },
    );
    let mut block = DETAILS_FIELD.as_bytes().to_vec();
    block.extend_from_slice(SEPARATOR);
    block.extend_from_slice(
        base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(details.details())
            .as_bytes(),
    );
    block.extend_from_slice(LINE_END);
    let mut r = hop();
    let reply = answered(r.on_far_fields(&block, None, true));
    assert_ne!(
        body(&reply)["error"]["code"],
        -32001,
        "the details state no status: {:?}",
        body(&reply)
    );
}

/// MONEY (this cell touches money: it reads the count the door reports as the hop's billed
/// `bytes` class, `relay::moved`). A RELAYED gRPC CALL BILLS THE BODIES PREDEV BILLED, BOTH WAYS,
/// AND NEVER ITS TRAILERS. Predev's hop counted the request body it handed the transport and the
/// response body the transport handed back (origin/predev `crates/busbar-a2a/src/a2a/relay.rs:1795-1802`,
/// `add_sent(request.body.len())` + `add_received(resp.body.len())`), where on the gRPC binding the
/// request body was the length-prefixed message (`relay.rs:1319-1341` `grpc_frame`; the billing
/// rule, `relay_billing.rs:15-18`) and every header in both directions was excluded
/// (`relay_billing.rs:23-24`). The lane's grpc transport frames the plane's message itself (one
/// prefix, even for an empty message), so the hop bills `prefix + message` sent and the prefixed
/// answer received; the trailers' field block is no payload.
///
/// RED before the fix: the hop billed the bare message (5 bytes short) and added the trailers'
/// field block to the received bytes.
#[test]
fn a_grpc_hop_bills_its_framed_request_and_answer_and_never_its_trailers() {
    use busbar_contract::abi::transport::fields::{LINE_END, SEPARATOR};
    let mut trailers = b"grpc-status".to_vec();
    trailers.extend_from_slice(SEPARATOR);
    trailers.extend_from_slice(b"0");
    trailers.extend_from_slice(LINE_END);
    let billed = |asked: &serde_json::Value, answered: &[u8]| {
        let (mut r, _, message) = dialled(asked, None, false);
        assert_eq!(r.moved(), 0, "nothing was exchanged yet");
        let _ = r.on_piece(far(Some(0), &[], false));
        let _ = r.on_piece(far(None, answered, false));
        let _ = r.on_far_fields(&trailers, Some(0), false);
        let _ = r.on_piece(far(None, &[], true));
        (r.moved(), message.len())
    };
    let answer = send_answer(pb::TaskState::Working);
    let (moved, message) = billed(&submission("SendMessage"), &answer);
    assert!(message > 0, "the submission carries a message");
    assert_eq!(
        moved,
        (crate::framed::MESSAGE_PREFIX + message + answer.len()) as u64,
        "the prefixed request message plus the prefixed answer, and not one trailer byte"
    );
    // An rpc whose request message is all defaults is zero bytes; the wire still carries its
    // prefix, as predev's `grpc_frame` wrote it.
    let card = framed(&pb::AgentCard {
        name: "planner-extended".into(),
        ..Default::default()
    });
    let asked =
        json!({ "jsonrpc": "2.0", "id": 7, "method": "GetExtendedAgentCard", "params": {} });
    let (moved, message) = billed(&asked, &card);
    assert_eq!(message, 0, "the empty request message");
    assert_eq!(
        moved,
        (crate::framed::MESSAGE_PREFIX + card.len()) as u64,
        "the empty message's prefix plus the prefixed answer"
    );
}
