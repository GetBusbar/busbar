// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unary hop, piece by piece: the request each attempt sends, the body relayed verbatim, and
//! the caller's answer in the served engine's bytes (`busbar-a2a` `relay`, `refusal_client`,
//! `receive::refuse_hop_early`).

use super::*;
use serde_json::json;

const URL: &str = "https://vendor.example/a2a/v1?tenant=t1";
const ASK: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"GetExtendedAgentCard"}"#;

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

/// A hop through its attempt and the caller's body, waiting on the far end.
fn sent() -> Relay {
    let mut r = Relay::new(json!(7), "1.0");
    assert!(matches!(r.on_piece(kernel(Some(URL))), Answer::Attempt(_)));
    assert_eq!(r.on_piece(caller(ASK)), Answer::ToFarEnd(ASK.to_vec()));
    r
}

fn answered(r: &mut Relay, status: u32, body: &[u8]) -> Reply {
    match r.on_piece(far(Some(status), body, true)) {
        Answer::ToCaller(reply) => reply,
        other => panic!("no answer: {other:?}"),
    }
}

/// The engine's refused-hop body for `code` and `sentence`, under id 7.
fn refused(code: &str, sentence: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 7,
        "error": {
            "code": -32006,
            "message": format!("{code}: {sentence}"),
            "data": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org",
                "reason": "INVALID_AGENT_RESPONSE",
            }],
        },
    }))
    .expect("json")
}

#[test]
fn an_attempt_posts_to_the_agents_own_path_with_the_engines_three_fields_in_order() {
    let mut r = Relay::new(json!(7), "1.0");
    assert_eq!(
        r.on_piece(kernel(Some(URL))),
        Answer::Attempt(Attempt {
            verb: "POST",
            target: "/a2a/v1?tenant=t1".to_string(),
            fields: vec![
                ("content-type", "application/json".to_string()),
                ("accept", "application/json".to_string()),
                ("a2a-version", "1.0".to_string()),
            ],
        })
    );
}

#[test]
fn an_agent_url_with_no_path_is_posted_to_at_its_root() {
    assert_eq!(target_of("https://vendor.example").as_deref(), Some("/"));
    assert_eq!(target_of("not a url"), None);
}

#[test]
fn an_attempt_at_an_agent_the_section_does_not_name_is_refused() {
    let mut r = Relay::new(json!(7), "0.3");
    assert_eq!(r.on_piece(kernel(None)), Answer::Refused);
}

#[test]
fn the_callers_body_reaches_the_far_end_verbatim() {
    let odd = br#"{ "jsonrpc" : "2.0", "id":7, "method":"GetExtendedAgentCard", "x":[1,2] }"#;
    let mut r = Relay::new(json!(7), "0.3");
    let _ = r.on_piece(kernel(Some(URL)));
    assert_eq!(r.on_piece(caller(odd)), Answer::ToFarEnd(odd.to_vec()));
}

#[test]
fn a_correlated_result_is_relayed_whole_under_the_callers_id() {
    let mut r = sent();
    assert_eq!(
        r.on_piece(far(Some(200), br#"{"jsonrpc":"2.0","id":7,"#, false)),
        Answer::Nothing
    );
    let reply = match r.on_piece(far(
        None,
        br#""result":{"name":"Vendor","skills":[]}}"#,
        true,
    )) {
        Answer::ToCaller(reply) => reply,
        other => panic!("no answer: {other:?}"),
    };
    assert_eq!(reply.status, 200);
    assert_eq!(reply.content_type, "application/json");
    let expected = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 7,
        "result": {"name": "Vendor", "skills": []},
    }))
    .expect("json");
    assert_eq!(reply.body, expected);
    assert!(r.answered());
    assert_eq!(r.on_piece(far(None, b"late", true)), Answer::Nothing);
}

#[test]
fn a_status_outside_2xx_is_the_engines_backend_status_refusal() {
    let reply = answered(&mut sent(), 404, br#"{"jsonrpc":"2.0","id":7,"result":{}}"#);
    assert_eq!(reply.status, 502);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.backend_status",
            "this agent's backend refused busbar's request"
        )
    );
}

#[test]
fn an_answer_to_another_request_is_refused_not_relayed() {
    let reply = answered(
        &mut sent(),
        200,
        br#"{"jsonrpc":"2.0","id":8,"result":{"s":1}}"#,
    );
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_uncorrelated",
            "this agent's backend answered something busbar cannot correlate to the request it \
             sent, so it is refused rather than relayed"
        )
    );
}

#[test]
fn the_backends_own_error_is_refused_without_its_words() {
    let reply = answered(
        &mut sent(),
        200,
        br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"internal host db.vendor"}}"#,
    );
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.backend_refused",
            "this agent's backend refused the request"
        )
    );
    assert!(!String::from_utf8_lossy(&reply.body).contains("db.vendor"));
}

#[test]
fn a_reply_that_is_not_a_json_rpc_answer_is_refused() {
    let sentence = "this agent's backend replied with something that is not a JSON-RPC answer";
    for body in [&b"<html>"[..], br#"{"id":7,"result":{}}"#] {
        let reply = answered(&mut sent(), 200, body);
        assert_eq!(reply.body, refused("a2a.hop.reply_not_json", sentence));
    }
}

#[test]
fn a_reply_over_the_ceiling_is_refused_and_a_refused_status_is_judged_first() {
    let mut big = br#"{"jsonrpc":"2.0","id":7,"result":""#.to_vec();
    big.resize(MAX_REPLY_BYTES + 10, b'a');
    let reply = answered(&mut sent(), 200, &big);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_too_large",
            "this agent's backend replied with more than the configured ceiling"
        )
    );
    let reply = answered(&mut sent(), 500, &big);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.backend_status",
            "this agent's backend refused busbar's request"
        )
    );
}

#[test]
fn the_bytes_moved_count_both_ways_once_the_far_end_answers() {
    let mut r = sent();
    assert_eq!(r.moved(), 0, "nothing was exchanged yet");
    let body = br#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
    let _ = answered(&mut r, 200, body);
    assert_eq!(r.moved(), (ASK.len() + body.len()) as u64);
}

#[test]
fn a_new_attempt_forgets_the_previous_far_end() {
    let mut r = sent();
    let _ = r.on_piece(far(Some(200), br#"{"jsonrpc":"2.0","#, false));
    assert!(matches!(r.on_piece(kernel(Some(URL))), Answer::Attempt(_)));
    let _ = r.on_piece(caller(ASK));
    assert_eq!(r.moved(), 0);
    let reply = answered(&mut r, 200, br#"{"jsonrpc":"2.0","id":7,"result":1}"#);
    assert_eq!(reply.status, 200);
}

#[test]
fn a_last_far_end_piece_with_no_status_is_refused() {
    let mut r = sent();
    assert_eq!(r.on_piece(far(None, b"{}", true)), Answer::Refused);
}

// ── a hop about a task (ARCHITECT ruling B1) ─────────────────────────────────────────────────────

const SEND: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"SendMessage","params":{}}"#;

fn task(addressed: bool) -> TaskHop {
    TaskHop {
        task_id: "a2a-p-0102030405060708".into(),
        context_id: "ctx-1".into(),
        addressed,
        skill: None,
    }
}

/// A task hop through its attempt and the caller's body, waiting on the far end.
fn task_sent(addressed: bool) -> Relay {
    let mut r = Relay::new(json!(7), "1.0");
    r.for_task(task(addressed));
    assert!(matches!(r.on_piece(kernel(Some(URL))), Answer::Attempt(_)));
    assert_eq!(r.on_piece(caller(SEND)), Answer::ToFarEnd(SEND.to_vec()));
    r
}

fn body(reply: &Reply) -> serde_json::Value {
    serde_json::from_slice(&reply.body).expect("json")
}

#[test]
fn a_task_hops_answer_leaves_under_busbars_identity_and_says_what_the_far_end_reported() {
    let mut r = task_sent(false);
    let far = br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"task","id":"far-1","contextId":"far-c","status":{"state":"completed"}}}"#;
    let reply = answered(&mut r, 200, far);
    assert_eq!(reply.status, 200);
    assert_eq!(
        body(&reply),
        json!({ "jsonrpc": "2.0", "id": 7, "result": { "kind": "task",
            "id": "a2a-p-0102030405060708", "contextId": "ctx-1",
            "status": { "state": "completed" } } })
    );
    assert_eq!(
        r.take_settled(),
        vec![Settled::Reported {
            state: TaskState::Completed,
            backend_id: Some("far-1".into()),
        }]
    );
    assert_eq!(r.take_settled(), Vec::new());
}

/// The engine's task-hop refusal body: `code`, `message`, its `ErrorInfo` when A2A defines the code,
/// and the task's `ResourceInfo`.
fn about(code: i64, reason: &str, message: &str) -> serde_json::Value {
    json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": code, "message": message,
        "data": [
            { "@type": "type.googleapis.com/google.rpc.ErrorInfo",
              "domain": "a2a-protocol.org", "reason": reason },
            { "@type": "type.googleapis.com/google.rpc.ResourceInfo",
              "resourceType": "a2a.busbar/task", "resourceName": "a2a-p-0102030405060708" },
        ] } })
}

#[test]
fn a_failed_hop_ends_the_task_it_opened_and_names_it() {
    let mut r = task_sent(false);
    let reply = answered(&mut r, 500, b"oops");
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        about(
            -32006,
            "INVALID_AGENT_RESPONSE",
            "the backend agent did not complete this task"
        )
    );
    assert_eq!(r.take_settled(), vec![Settled::Failed]);
}

#[test]
fn the_far_ends_own_a2a_error_code_travels_and_its_prose_does_not() {
    let mut r = task_sent(false);
    let far =
        br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"secret backend words"}}"#;
    let reply = answered(&mut r, 200, far);
    assert_eq!(reply.status, 404);
    assert_eq!(
        body(&reply),
        about(
            -32001,
            "TASK_NOT_FOUND",
            "the backend agent refused this task"
        )
    );
    assert_eq!(r.take_settled(), vec![Settled::Failed]);

    let mut r = task_sent(false);
    let far = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32050,"message":"custom"}}"#;
    let reply = answered(&mut r, 200, far);
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        about(
            -32006,
            "INVALID_AGENT_RESPONSE",
            "the backend agent did not complete this task"
        )
    );
}

#[test]
fn a_failed_hop_about_a_held_task_fails_the_request_never_the_task() {
    let mut r = task_sent(true);
    let far = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32002,"message":"no"}}"#;
    let reply = answered(&mut r, 200, far);
    assert_eq!(reply.status, 409);
    assert_eq!(
        body(&reply),
        about(
            -32002,
            "TASK_NOT_CANCELABLE",
            "the backend agent refused this request"
        )
    );
    assert_eq!(r.take_settled(), Vec::new());

    let mut r = task_sent(true);
    let reply = answered(&mut r, 503, b"");
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        about(
            -32006,
            "INVALID_AGENT_RESPONSE",
            "the backend agent refused this request"
        )
    );
    assert_eq!(r.take_settled(), Vec::new());
}

#[test]
fn a_translated_request_is_sent_once_per_attempt_in_place_of_the_callers_pieces() {
    let mut r = Relay::new(json!(7), "1.0");
    r.for_task(task(true));
    r.send_instead(b"translated".to_vec());
    assert!(matches!(r.on_piece(kernel(Some(URL))), Answer::Attempt(_)));
    let first = Piece {
        from: From::Caller,
        bytes: b"part-1",
        status: None,
        last: false,
    };
    assert_eq!(r.on_piece(first), Answer::ToFarEnd(b"translated".to_vec()));
    assert_eq!(r.on_piece(caller(b"part-2")), Answer::Nothing);
    assert!(matches!(r.on_piece(kernel(Some(URL))), Answer::Attempt(_)));
    assert_eq!(
        r.on_piece(caller(b"again")),
        Answer::ToFarEnd(b"translated".to_vec())
    );
}

// ── the outbound binding (ARCHITECT ruling B4) ───────────────────────────────────────────────────

const GET: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"GetTask","params":{"id":"t1"}}"#;

fn rest_relay(task_hop: Option<TaskHop>) -> Relay {
    let mut r = Relay::new(json!(7), "1.0");
    if let Some(t) = task_hop {
        r.for_task(t);
    }
    r.bind(
        Binding::HttpJson,
        &serde_json::from_slice::<serde_json::Value>(GET).unwrap(),
    );
    r
}

#[test]
fn an_http_json_attempt_is_the_operations_request_line_and_sends_no_body_for_a_read() {
    let mut r = rest_relay(None);
    assert_eq!(
        r.on_piece(kernel(Some(URL))),
        Answer::Attempt(Attempt {
            verb: "GET",
            target: "/a2a/v1/tasks/t1".into(),
            fields: vec![
                ("accept", "application/json".into()),
                ("a2a-version", "1.0".into()),
            ],
        })
    );
    assert_eq!(r.on_piece(caller(GET)), Answer::Nothing);
    let reply = answered(&mut r, 200, br#"{"id":"t1","status":{"state":"working"}}"#);
    assert_eq!(
        body(&reply),
        json!({ "jsonrpc": "2.0", "id": 7, "result": { "id": "t1", "status": { "state": "working" } } })
    );
}

#[test]
fn an_http_json_answer_that_is_not_json_is_unframable_and_fails_the_task_it_opened() {
    let mut r = rest_relay(Some(task(false)));
    assert!(matches!(r.on_piece(kernel(Some(URL))), Answer::Attempt(_)));
    let reply = answered(&mut r, 200, b"<html>");
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        about(
            -32006,
            "INVALID_AGENT_RESPONSE",
            "the backend agent did not complete this task"
        )
    );
    assert_eq!(r.take_settled(), vec![Settled::Failed]);

    let mut r = rest_relay(None);
    assert!(matches!(r.on_piece(kernel(Some(URL))), Answer::Attempt(_)));
    let reply = answered(&mut r, 200, b"<html>");
    assert_eq!(
        body(&reply)["error"]["message"],
        "a2a.hop.unframable: `GetTask` could not be carried to this agent over its `HTTP+JSON` binding"
    );
}

#[test]
fn a_request_the_binding_cannot_carry_is_refused_at_the_attempt() {
    let mut r = Relay::new(json!(7), "1.0");
    r.bind(
        Binding::HttpJson,
        &json!({ "jsonrpc": "2.0", "id": 7, "method": "vendor/Thing" }),
    );
    let Answer::ToCaller(reply) = r.on_piece(kernel(Some(URL))) else {
        panic!("not refused");
    };
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply)["error"]["message"],
        "a2a.hop.unframable: `vendor/Thing` could not be carried to this agent over its `HTTP+JSON` binding"
    );
}

#[test]
fn a_card_naming_only_grpc_is_refused_by_name_before_the_hop() {
    let mut r = Relay::new(json!(7), "1.0");
    r.for_task(task(false));
    r.bind(Binding::JsonRpc, &serde_json::from_slice(SEND).unwrap());
    let Answer::ToCaller(reply) = r.refuse_unspeakable("GRPC") else {
        panic!("not refused");
    };
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": -32006,
            "message": "a2a.hop.unframable: `SendMessage` could not be carried to this agent over its `GRPC` binding",
            "data": [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org", "reason": "INVALID_AGENT_RESPONSE" }] } })
    );
    assert_eq!(r.take_settled(), Vec::new(), "the task stays as it is");
    assert_eq!(r.on_piece(caller(SEND)), Answer::Nothing);
}

// ── a hop whose answer is events (the engine's event-stream hop) ────────────────────────────────

const STREAM: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"message/stream","params":{}}"#;

/// An events hop about a task, through its attempt and the caller's body.
fn events_sent() -> (Relay, Attempt) {
    let mut r = Relay::new(json!(7), "1.0");
    r.expect_events();
    r.for_task(task(false));
    let Answer::Attempt(attempt) = r.on_piece(kernel(Some(URL))) else {
        panic!("no attempt");
    };
    assert_eq!(
        r.on_piece(caller(STREAM)),
        Answer::ToFarEnd(STREAM.to_vec())
    );
    (r, attempt)
}

/// One far-end event answering request 7 with `result`.
fn event(result: serde_json::Value) -> Vec<u8> {
    format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 7, "result": result })
    )
    .into_bytes()
}

fn part(answer: Answer) -> Part {
    match answer {
        Answer::Part(part) => part,
        other => panic!("not a part: {other:?}"),
    }
}

/// The data of each event in `body`.
fn datas(body: &[u8]) -> Vec<serde_json::Value> {
    std::str::from_utf8(body)
        .unwrap()
        .split("\n\n")
        .filter_map(|e| e.strip_prefix("data: "))
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}

/// The attempt accepts an event stream or one document (the engine's `ACCEPT_STREAM`).
#[test]
fn an_events_attempt_accepts_an_event_stream_or_one_document() {
    let (_, attempt) = events_sent();
    assert!(attempt
        .fields
        .contains(&(H_ACCEPT, "text/event-stream, application/json".to_string())));
}

/// Each event goes out as it is framed, under busbar's identity: the first starts the caller's
/// answer, the last piece ends it, and every state the events report is settled as it passes.
#[test]
fn events_are_answered_as_they_come_and_settled_as_they_pass() {
    let (mut r, _) = events_sent();
    let first = event(
        json!({ "kind": "status-update", "id": "far-1", "contextId": "far-c",
        "status": { "state": "working" } }),
    );
    let (head, tail) = first.split_at(10);
    assert_eq!(
        r.on_piece(far(Some(200), head, false)),
        Answer::Nothing,
        "half an event"
    );
    let one = part(r.on_piece(far(None, tail, false)));
    assert!(one.head && !one.last);
    let got = datas(&one.body);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["result"]["id"], "a2a-p-0102030405060708");
    assert_eq!(got[0]["result"]["contextId"], "ctx-1");
    assert_eq!(
        r.take_settled(),
        vec![Settled::Event {
            state: Some(TaskState::Working),
            artifact: false,
            backend_id: Some("far-1".into()),
        }]
    );
    let mut rest = event(json!({ "artifactUpdate": { "taskId": "far-1", "artifact": {} } }));
    rest.extend(event(json!({ "statusUpdate": { "taskId": "far-1",
        "status": { "state": "completed" } } })));
    let two = part(r.on_piece(far(None, &rest, true)));
    assert!(!two.head && two.last);
    assert_eq!(datas(&two.body).len(), 2);
    assert_eq!(
        r.take_settled(),
        vec![
            Settled::Event {
                state: None,
                artifact: true,
                backend_id: Some("far-1".into()),
            },
            Settled::Event {
                state: Some(TaskState::Completed),
                artifact: false,
                backend_id: Some("far-1".into()),
            },
        ]
    );
    assert!(r.answered());
    assert_eq!(r.moved(), (STREAM.len() + first.len() + rest.len()) as u64);
}

/// A far end that answers one document to an events hop is answered as the unary hop answers it.
#[test]
fn one_document_to_an_events_hop_is_the_unary_answer() {
    let (mut r, _) = events_sent();
    let doc = br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"task","id":"far-1","status":{"state":"completed"}}}"#;
    let reply = answered(&mut r, 200, doc);
    assert_eq!(reply.content_type, "application/json");
    assert_eq!(body(&reply)["result"]["id"], "a2a-p-0102030405060708");
    assert_eq!(
        r.take_settled(),
        vec![Settled::Reported {
            state: TaskState::Completed,
            backend_id: Some("far-1".into()),
        }]
    );
}

/// A frame answering another request refuses the hop before its answer started, the task failed;
/// after it started, the answer ends there and the task fails.
#[test]
fn an_uncorrelated_event_refuses_before_the_answer_and_ends_it_after() {
    let other = b"data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n\n";
    let (mut before, _) = events_sent();
    let reply = answered(&mut before, 200, other);
    assert_eq!(reply.status, 502);
    assert_eq!(before.take_settled(), vec![Settled::Failed]);

    let (mut after, _) = events_sent();
    let first = event(json!({ "kind": "status-update", "status": { "state": "working" } }));
    assert!(part(after.on_piece(far(Some(200), &first, false))).head);
    let _ = after.take_settled();
    let end = part(after.on_piece(far(None, other, false)));
    assert!(end.last && !end.head && end.body.is_empty());
    assert_eq!(after.take_settled(), vec![Settled::Failed]);
    assert_eq!(
        after.on_piece(far(None, b"", true)),
        Answer::Nothing,
        "nothing after the end"
    );
}

/// A status outside 2xx is the unary hop's backend-status refusal, whatever the body.
#[test]
fn an_events_hop_answered_outside_2xx_is_refused() {
    let (mut r, _) = events_sent();
    let reply = answered(&mut r, 503, &event(json!({})));
    assert_eq!(reply.status, 502);
}

/// An HTTP+JSON far end's events carry the bare result: each is read as the result of the request.
#[test]
fn an_http_json_far_ends_bare_events_are_read_as_results() {
    let mut r = Relay::new(json!(7), "1.0");
    r.expect_events();
    r.for_task(task(false));
    let envelope: serde_json::Value = serde_json::from_slice(STREAM).unwrap();
    r.bind(Binding::HttpJson, &envelope);
    assert!(matches!(r.on_piece(kernel(Some(URL))), Answer::Attempt(_)));
    let _ = r.on_piece(caller(STREAM));
    let bare = b"data: {\"kind\":\"status-update\",\"status\":{\"state\":\"working\"}}\n\n";
    let one = part(r.on_piece(far(Some(200), bare, true)));
    let got = datas(&one.body);
    assert_eq!(got[0]["id"], 7);
    assert_eq!(got[0]["result"]["id"], "a2a-p-0102030405060708");
}

/// THE BREAKER'S READING (ARCHITECT ruling: the engine's `classify_hop` table, stated by the plane;
/// its ORDER per the COORDINATOR ruling 2026-10-07 on finding A, predev `relay.rs:1813-1819` and
/// `classify_hop` `:1575`/`:1583-1586`): the STATUS FIRST. Outside `2xx` the status table alone
/// reads the answer, whatever its body — a TaskNotFound error under a `502` or a `500` is a
/// transient failure, under a `404` the caller's, under a `401` hard; `408`, `429` and `529` are
/// transient; a `3xx` is the caller's (`ClientError`, nothing recorded). Only on a `2xx` is the body
/// read: a result or a protocol error is the destination answering, and a body that is no usable
/// answer is transient. Nothing is read before the answer is whole.
#[test]
fn the_far_ends_whole_answer_states_the_breakers_reading() {
    let not_found =
        br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"Task not found"}}"#;
    let result = br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"message"}}"#;
    let cases: &[(u32, &[u8], Option<Reading>)] = &[
        (200, result, Some(Reading::Healthy)),
        (200, not_found, Some(Reading::Healthy)),
        (502, not_found, Some(Reading::Transient)),
        (500, not_found, Some(Reading::Transient)),
        (529, not_found, Some(Reading::Transient)),
        (408, b"", Some(Reading::Transient)),
        (404, not_found, Some(Reading::Caller)),
        (502, b"SyntaxError: not JSON", Some(Reading::Transient)),
        (503, br#"{"error":"down"}"#, Some(Reading::Transient)),
        (429, b"", Some(Reading::Transient)),
        (401, not_found, Some(Reading::Hard)),
        (403, b"", Some(Reading::Hard)),
        (404, b"no such path", Some(Reading::Caller)),
        (200, b"not json", Some(Reading::Transient)),
        (
            200,
            br#"{"jsonrpc":"2.0","id":8,"result":{}}"#,
            Some(Reading::Transient),
        ),
        (302, b"", Some(Reading::Caller)),
        (302, not_found, Some(Reading::Caller)),
    ];
    for (status, body, want) in cases {
        let mut r = sent();
        assert_eq!(r.on_piece(far(Some(*status), &[], false)), Answer::Nothing);
        assert_eq!(r.take_reading(), None, "the head alone states nothing");
        let _ = r.on_piece(far(None, body, true));
        assert_eq!(
            r.take_reading(),
            *want,
            "{status} {}",
            String::from_utf8_lossy(body)
        );
        assert_eq!(r.take_reading(), None, "stated once");
    }
}

/// A HOP THE KERNEL REFUSED FOR BUSBAR'S OWN CREDENTIAL (`credential_unavailable`: the agent's
/// `upstream_credential` no longer resolves), in the engine's bytes (`receive.rs`, the `mint_from`
/// arm): a task hop is `fail_task`'s answer, `502` `-32006` "the backend agent did not complete this
/// task" naming the task, and the task ends `failed` — whether the hop opened it or addressed it, as
/// `fail_task` ended either; the extended-card read opened no task, so it is refused in its own
/// words and nothing is settled.
#[test]
fn a_hop_refused_for_busbars_own_credential_answers_in_the_engines_words() {
    for addressed in [false, true] {
        let mut r = task_sent(addressed);
        let (reply, failed) = r.refuse_credential();
        assert_eq!(reply.status, 502);
        assert_eq!(reply.content_type, JSON_MEDIA_TYPE);
        assert_eq!(
            body(&reply),
            about(
                -32006,
                "INVALID_AGENT_RESPONSE",
                "the backend agent did not complete this task"
            ),
            "addressed: {addressed}"
        );
        assert!(failed, "the task ends failed (addressed: {addressed})");
        assert!(r.answered());
    }

    let mut r = sent();
    let (reply, failed) = r.refuse_credential();
    assert_eq!(reply.status, 502);
    assert_eq!(
        body(&reply),
        json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": -32006,
            "message": "the extended agent card could not be fetched",
            "data": [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org", "reason": "INVALID_AGENT_RESPONSE" }] } }),
        "no task is named: the card read opened none"
    );
    assert!(!failed, "a card read settles nothing");
    assert!(r.take_settled().is_empty());
}
/// Ported from busbar-a2a a2a/tests/rpcerror_tests.rs::push_notification_not_supported_and_extension_support_required_round_trip.
/// The relay path looks the backend's code up and re-emits it: a backend `-32003`/`-32008` reaches
/// the caller as itself (HTTP 400), not as the gateway fault `-32006` (502).
#[test]
fn a_far_ends_push_and_extension_refusals_are_relayed_as_themselves() {
    for (code, reason) in [
        (-32003, "PUSH_NOTIFICATION_NOT_SUPPORTED"),
        (-32008, "EXTENSION_SUPPORT_REQUIRED"),
    ] {
        for addressed in [false, true] {
            let mut r = task_sent(addressed);
            let far = format!(
                r#"{{"jsonrpc":"2.0","id":7,"error":{{"code":{code},"message":"backend words"}}}}"#
            );
            let reply = answered(&mut r, 200, far.as_bytes());
            assert_eq!(reply.status, 400, "{code} addressed={addressed}");
            let got = body(&reply);
            assert_eq!(got["error"]["code"], code, "relayed code carried through");
            assert_eq!(got["error"]["data"][0]["reason"], reason);
            assert!(
                !reply_text(&reply).contains("backend words"),
                "the far end's prose never travels"
            );
        }
    }
}

fn reply_text(reply: &Reply) -> String {
    String::from_utf8_lossy(&reply.body).into_owned()
}

/// Ported from busbar-a2a a2a/tests/transport_tests.rs::a_buffered_hop_that_dies_mid_answer_bills_its_request_and_the_bytes_received.
/// The far end reads the whole request, answers a head promising a long body, sends part of it and
/// is cut: nothing is relayed, but the request crossed the wire and so did the bytes received, so
/// the hop moved both (the rule a cut stream already followed).
#[test]
fn a_buffered_hop_that_dies_mid_answer_bills_its_request_and_the_bytes_received() {
    const DELIVERED: usize = 300;
    let mut r = sent();
    let partial = vec![b'x'; DELIVERED];
    assert_eq!(
        r.on_piece(far(Some(200), &partial, false)),
        Answer::Nothing,
        "the answer is incomplete, so nothing is relayed"
    );
    // The connection dies here: no last piece ever arrives.
    assert!(!r.answered(), "an answer cut short is not an answer");
    assert_eq!(
        r.moved(),
        (ASK.len() + DELIVERED) as u64,
        "the hop bills the request it carried and the bytes that arrived before the reset"
    );
}

/// Ported from busbar-a2a a2a/tests/refusal_leak_tests.rs::every_hop_refusal_carries_its_own_stable_code.
#[test]
fn every_hop_refusal_carries_its_own_stable_code() {
    let arms = [
        HopRefusal::Status,
        HopRefusal::BodyTooLarge,
        HopRefusal::NotJson,
        HopRefusal::BackendError,
        HopRefusal::Uncorrelated,
        HopRefusal::NotServing,
        HopRefusal::EndpointRefused,
        HopRefusal::Transport,
    ];
    // Exhaustive by construction: a new arm fails to compile here until it is listed above.
    for arm in arms {
        match arm {
            HopRefusal::Status
            | HopRefusal::BodyTooLarge
            | HopRefusal::NotJson
            | HopRefusal::BackendError
            | HopRefusal::Uncorrelated
            | HopRefusal::NotServing
            | HopRefusal::EndpointRefused
            | HopRefusal::Transport => {}
        }
    }
    let mut seen: Vec<&'static str> = Vec::new();
    for refusal in arms {
        let code = refusal.client_code();
        assert!(
            code.starts_with("a2a.hop."),
            "{refusal:?} has code `{code}`, outside the plane's `a2a.hop.` family"
        );
        assert!(
            !seen.contains(&code),
            "{refusal:?} reuses the code `{code}`; a code that names two refusals tells an \
             operator nothing"
        );
        assert!(
            refusal.client_text().contains(code),
            "{refusal:?}'s caller-facing text does not carry its own code `{code}`"
        );
        seen.push(code);
    }
    assert_eq!(seen.len(), 8);
}

/// A well-formed far-end answer of exactly `len` bytes.
fn answer_of_len(len: usize) -> Vec<u8> {
    let head = br#"{"jsonrpc":"2.0","id":7,"result":""#;
    let tail = br#""}"#;
    let mut body = head.to_vec();
    body.resize(len - tail.len(), b'a');
    body.extend_from_slice(tail);
    assert_eq!(body.len(), len);
    body
}

/// Ported from busbar-a2a a2a/tests/transport_tests.rs::an_oversized_body_is_cut_one_byte_past_the_ceiling_so_the_driver_can_refuse_it.
/// An over-cap body is kept ONE BYTE past the ceiling, which is what lets the answer's own size
/// check refuse it: a body that ends at the ceiling and one that overran it must not look alike.
#[test]
fn an_oversized_body_is_cut_one_byte_past_the_ceiling_so_the_driver_can_refuse_it() {
    // At the ceiling: relayed whole.
    let at_cap = answer_of_len(MAX_REPLY_BYTES);
    let reply = answered(&mut sent(), 200, &at_cap);
    assert_eq!(reply.status, 200, "a body AT the ceiling is not over it");

    // One byte over: refused.
    let over = answer_of_len(MAX_REPLY_BYTES + 1);
    let reply = answered(&mut sent(), 200, &over);
    assert_eq!(reply.status, 502);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_too_large",
            "this agent's backend replied with more than the configured ceiling"
        )
    );

    // Far over, in pieces: only one byte past the ceiling is ever held, and it is refused.
    let huge = answer_of_len(MAX_REPLY_BYTES * 3);
    let mut r = sent();
    let (a, b) = huge.split_at(MAX_REPLY_BYTES * 2);
    assert_eq!(r.on_piece(far(Some(200), a, false)), Answer::Nothing);
    assert_eq!(
        r.far.len(),
        MAX_REPLY_BYTES + 1,
        "cut one byte past the cap"
    );
    let reply = match r.on_piece(far(None, b, true)) {
        Answer::ToCaller(reply) => reply,
        other => panic!("no answer: {other:?}"),
    };
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_too_large",
            "this agent's backend replied with more than the configured ceiling"
        )
    );
    assert_eq!(r.far.len(), MAX_REPLY_BYTES + 1);
}

// ── the operator's journal names the backend; the caller's answer never does ───────────────────

/// Every event's level and rendered fields (the plane holds no subscriber dependency, so the
/// `tracing` trait is implemented by hand).
struct Capture(std::sync::mpsc::Sender<(tracing::Level, String)>);

struct Render<'a>(&'a mut String);

impl tracing::field::Visit for Render<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = String::new();
        event.record(&mut Render(&mut line));
        let _ = self.0.send((*event.metadata().level(), line));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// What `run` answers the caller, and the lines it journaled.
fn journaled(run: impl FnOnce() -> Reply) -> (Reply, Vec<(tracing::Level, String)>) {
    let (sent, heard) = std::sync::mpsc::channel();
    let reply = tracing::subscriber::with_default(Capture(sent), run);
    (reply, heard.try_iter().collect())
}

/// Ported from origin/predev `crates/busbar-a2a/src/a2a/tests/refusal_leak_tests.rs`
/// `the_operator_rendering_still_names_the_backend` (`receive.rs:3300`, `:3326`, `relay.rs:499`
/// `Display`): a refused hop's journal line names the backend's url at debug, and the caller's
/// answer, the one the wire-scan cells read, names no backend. RED arm: nothing was journaled.
#[test]
fn a_refused_hops_journal_line_names_the_backend_and_the_callers_answer_does_not() {
    let host = "vendor.example";
    let submission = crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED
        .banner()
        .to_string();
    let stream = crate::diagnostics::A2A_RELAYED_STREAM_REFUSED
        .banner()
        .to_string();
    let other = b"data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n\n";
    type Run = Box<dyn FnOnce() -> Reply>;
    let cases: Vec<(&str, String, Run)> = vec![
        (
            "a task-less hop's backend status",
            submission.clone(),
            Box::new(|| answered(&mut sent(), 503, b"{}")),
        ),
        (
            "a task-less hop that heard nothing back",
            submission.clone(),
            Box::new(|| sent().refuse_transport().0),
        ),
        (
            "a task hop's backend status",
            submission.clone(),
            Box::new(|| answered(&mut task_sent(false), 503, b"{}")),
        ),
        (
            "a stream refused after its answer began",
            stream,
            Box::new(move || {
                let (mut r, _) = events_sent();
                let first =
                    event(json!({ "kind": "status-update", "status": { "state": "working" } }));
                let _ = r.on_piece(far(Some(200), &first, false));
                let _ = r.on_piece(far(None, other, false));
                Reply {
                    status: 0,
                    content_type: "",
                    body: Vec::new(),
                }
            }),
        ),
    ];
    for (what, banner, run) in cases {
        let (reply, lines) = journaled(run);
        let journal = lines
            .iter()
            .find(|(_, line)| line.contains(&banner))
            .unwrap_or_else(|| panic!("{what}: nothing journaled under {banner}: {lines:?}"));
        assert_eq!(journal.0, tracing::Level::DEBUG, "{what}: at debug");
        assert!(
            journal.1.contains(host),
            "{what}: the operator's line names the backend: {}",
            journal.1
        );
        assert!(
            !String::from_utf8_lossy(&reply.body).contains(host),
            "{what}: the caller's answer names no backend"
        );
    }
}
