// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's own glue over the relay: what a unit's line does to the caller's answer.

use super::*;
use serde_json::{json, Value};

fn reply(status: u32, doc: &Value) -> Answer {
    Answer::ToCaller(relay::Reply {
        status,
        content_type: crate::arrival::JSON_MEDIA_TYPE,
        body: serde_json::to_vec(doc).unwrap(),
    })
}

fn body_of(answer: Answer) -> (u32, Value) {
    match answer {
        Answer::ToCaller(r) => (r.status, serde_json::from_slice(&r.body).unwrap()),
        other => panic!("not the caller's answer: {other:?}"),
    }
}

/// On the HTTP+JSON line a relayed answer leaves as its bare `result` (A2A section 11.3), and a
/// refusal as the AIP-193 document at its own status, as the engine re-frames them.
#[test]
fn the_target_line_answers_the_bare_result_and_an_aip193_refusal() {
    let task =
        json!({ "id": "a2a-planner-01", "contextId": "c", "status": { "state": "completed" } });
    let ok = json!({ "jsonrpc": "2.0", "id": 7, "result": task.clone() });
    assert_eq!(body_of(for_line(reply(200, &ok), true)), (200, task));

    let refused = json!({
        "jsonrpc": "2.0", "id": 7,
        "error": { "code": -32001, "message": "no task with that id is open for this caller" },
    });
    let (status, doc) = body_of(for_line(reply(404, &refused), true));
    assert_eq!(status, 404);
    assert_eq!(doc, crate::arrival::aip193(404, &refused["error"]));
}

/// On the JSON-RPC line the answer is the relay's, byte for byte; and a piece that is not the
/// caller's whole answer is never touched, on either line.
#[test]
fn the_document_line_and_a_partial_answer_are_left_alone() {
    let ok = json!({ "jsonrpc": "2.0", "id": 7, "result": { "kind": "task" } });
    assert_eq!(for_line(reply(200, &ok), false), reply(200, &ok));
    let to_far = Answer::ToFarEnd(b"{}".to_vec());
    assert_eq!(for_line(to_far.clone(), true), to_far);
    assert_eq!(for_line(Answer::Nothing, true), Answer::Nothing);
}

/// On the HTTP+JSON line each event of an answer in events leaves as its bare result.
#[test]
fn the_target_line_answers_each_event_as_its_bare_result() {
    let event = b"data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"kind\":\"task\"}}\n\n".to_vec();
    let part = |body: Vec<u8>| {
        Answer::Part(relay::Part {
            head: true,
            body,
            last: false,
        })
    };
    assert_eq!(
        for_line(part(event.clone()), true),
        part(b"data: {\"kind\":\"task\"}\n\n".to_vec())
    );
    assert_eq!(for_line(part(event.clone()), false), part(event));
}

fn request(method: &str) -> Disposition {
    Disposition::Request {
        row: crate::ops::row_for(method).expect("a listed method"),
        id: json!(7),
        version: "1.0",
    }
}

fn envelope(method: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": { "id": "t1" } })
}

/// A request whose answer is events gets an events hop about its task: the vocabulary's
/// multi-frame rows in both spellings, a subscribe answering busbar's own refusal first, and an
/// unlisted method named as a stream. A one-reply request gets a unary task hop; a verb the plane
/// answers itself gets none.
#[test]
fn a_request_whose_answer_is_events_gets_an_events_hop() {
    for method in ["message/stream", "tasks/resubscribe"] {
        let hop = hop_of(&request(method), false, Some(envelope(method))).expect(method);
        assert!(hop.opening.is_some(), "{method}: about a task");
        assert_eq!(hop.subscribe, method == "tasks/resubscribe", "{method}");
    }
    let unlisted = Disposition::Unlisted {
        method: "vendor/stream".into(),
        id: json!(7),
        version: "1.0",
    };
    let hop = hop_of(&unlisted, false, Some(envelope("vendor/stream"))).expect("relayed");
    assert!(!hop.subscribe);

    let unary = hop_of(
        &request("message/send"),
        false,
        Some(envelope("message/send")),
    );
    assert!(unary.is_some_and(|h| !h.subscribe && h.opening.is_some()));
    assert!(hop_of(&request("tasks/list"), false, Some(envelope("tasks/list"))).is_none());
    assert!(
        hop_of(&request("message/stream"), false, None).is_none(),
        "no request, no hop"
    );
}

/// The hook projection is the engine gate's: the method as the tool and `params` verbatim as the
/// arguments (`null` when absent); a body that is no JSON object projects nothing.
#[test]
fn the_hook_projection_is_the_method_and_its_params() {
    let send = br#"{"jsonrpc":"2.0","id":7,"method":"message/send","params":{"message":{"parts":[{"kind":"text","text":"hi"}]}}}"#;
    let got: Value = serde_json::from_slice(&projection(send).unwrap()).unwrap();
    assert_eq!(
        got,
        json!({ "tool": "message/send",
            "arguments": { "message": { "parts": [{ "kind": "text", "text": "hi" }] } } })
    );
    let bare: Value =
        serde_json::from_slice(&projection(br#"{"jsonrpc":"2.0","method":"tasks/list"}"#).unwrap())
            .unwrap();
    assert_eq!(bare, json!({ "tool": "tasks/list", "arguments": null }));
    assert_eq!(projection(b"not json"), None);
    assert_eq!(projection(b"[1]"), None);
}

/// THE INVOKE REWRITE CONTRACT, as the served engine applied a `prompt: rw` hook's reply to an A2A
/// submission's params: an object `content`, a JSON-string `content` that parses to an object, or
/// a role-less entry itself; the last usable entry wins; nothing usable is not applied.
#[test]
fn a_rewrite_replaces_the_params_by_the_invoke_contract() {
    let params = |reply: Value| rewritten_params(&serde_json::to_vec(&reply).unwrap());
    let object = json!({ "message": { "parts": [{ "text": "[redacted]" }] } });
    assert_eq!(
        params(json!({ "messages": [{ "role": "user", "content": object }] })),
        Some(object.clone())
    );
    assert_eq!(
        params(json!({ "messages": [{ "role": "user", "content": object.to_string() }] })),
        Some(object.clone())
    );
    assert_eq!(
        params(json!({ "messages": [object.clone()] })),
        Some(object.clone())
    );
    assert_eq!(
        params(json!({ "messages": [
            { "role": "user", "content": { "first": true } },
            { "role": "user", "content": "plain words" },
            { "role": "user", "content": object },
        ] })),
        Some(object.clone())
    );
    assert_eq!(params(json!({ "messages": [{ "role": "user" }] })), None);
    assert_eq!(
        params(json!({ "messages": [{ "role": "user", "content": "7" }] })),
        None
    );
    assert_eq!(params(json!({ "tools": [] })), None);
    assert_eq!(rewritten_params(b"not json"), None);

    // The envelope keeps every member but its params, re-serialized.
    let send = br#"{"jsonrpc":"2.0","id":7,"method":"message/send","params":{"message":{}}}"#;
    let (value, bytes) = with_params(send, object.clone()).unwrap();
    assert_eq!(
        value,
        json!({ "jsonrpc": "2.0", "id": 7, "method": "message/send", "params": object })
    );
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), value);
    assert_eq!(with_params(b"[1]", object.clone()), None);
}

/// On the HTTP+JSON line the body the kernel keeps is the params where the line's body is the
/// params (a message sent or streamed, a push config posted), and nothing where the path and the
/// query spell them.
#[test]
fn the_target_line_keeps_the_rewritten_params_as_its_body() {
    let route = |verb: &str, suffix: &str| {
        let target = format!("{}{suffix}", crate::MOUNT_PATH);
        door::ROUTES
            .iter()
            .find(|r| r.verb == verb && r.target == target)
            .unwrap_or_else(|| panic!("{verb} {target}"))
    };
    let params = json!({ "message": { "parts": [] } });
    let bytes = serde_json::to_vec(&params).unwrap();
    for (verb, suffix) in [
        ("POST", crate::ROUTE_MESSAGE_SEND),
        ("POST", crate::ROUTE_MESSAGE_STREAM),
        ("POST", crate::ROUTE_PUSH_CONFIGS),
    ] {
        assert_eq!(
            target_body(route(verb, suffix), &params),
            Some(bytes.clone()),
            "{suffix}"
        );
    }
    assert_eq!(target_body(route("GET", crate::ROUTE_TASKS), &params), None);
    assert_eq!(target_body(route("POST", crate::ROUTE_TASK), &params), None);
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

#[test]
fn one_look_flies_per_agent_and_its_waiters_land_with_it() {
    let flights = Flights::default();
    assert_eq!(
        flights.join("planner", ticket(1)),
        None,
        "the first unit looks"
    );
    assert_eq!(
        flights.join("planner", ticket(2)),
        Some(0),
        "the second waits"
    );
    assert_eq!(flights.join("planner", ticket(3)), Some(0), "and the third");
    assert_eq!(
        flights.join("scout", ticket(4)),
        None,
        "another agent flies apart"
    );
    assert_eq!(
        flights.state("planner", 0, ticket(2)),
        FlightState::InFlight,
        "still in flight"
    );
    assert_eq!(
        flights.land("planner"),
        vec![ticket(2), ticket(3)],
        "the waiters are woken"
    );
    assert_eq!(
        flights.state("planner", 0, ticket(2)),
        FlightState::Landed,
        "landed: the verdict is taken"
    );
    assert_eq!(
        flights.join("planner", ticket(5)),
        None,
        "the next due unit looks again"
    );
}

#[test]
fn an_abandoned_look_releases_its_flight_and_wakes_every_waiter_at_once() {
    let flights = Flights::default();
    assert_eq!(flights.join("planner", ticket(1)), None);
    assert_eq!(flights.join("planner", ticket(2)), Some(0));
    assert_eq!(flights.join("planner", ticket(3)), Some(0));
    assert_eq!(flights.join("scout", ticket(1)), None);
    let mut woken = flights.abandon(ticket(1));
    woken.sort_by_key(|t| t.slot);
    assert_eq!(
        woken,
        vec![ticket(2), ticket(3)],
        "every waiter, of every flight it held"
    );
    assert_eq!(
        flights.state("planner", 0, ticket(2)),
        FlightState::Released,
        "no verdict landed: the waiter looks again"
    );
    assert_eq!(
        flights.join("planner", ticket(2)),
        None,
        "and takes the flight over"
    );
    assert_eq!(
        flights.join("scout", ticket(4)),
        None,
        "the other flight was released too"
    );
}

/// THE gRPC LINE'S OUTBOX: a whole answer is the rpc's one message at `OK` (no media type, no
/// length), or the status its error binds with the details field; an answer in events is one
/// message per event, each emitted on an answer of its own.
#[test]
fn the_framed_line_answers_messages_and_statuses() {
    use crate::framed::{Rpc, DETAILS_FIELD};
    use prost::Message as _;
    let task =
        json!({ "id": "t-1", "contextId": "c-1", "status": { "state": "TASK_STATE_COMPLETED" } });
    let ok = json!({ "jsonrpc": "2.0", "id": 1, "result": task });
    let ob = Outbox::framed(reply(200, &ok), Rpc::GetTask).expect("an outbox");
    assert!(matches!(ob.head, Some(Head::Framed(0, None))));
    assert!(ob.done && ob.queue.is_empty());
    let decoded = crate::proto::pb::Task::decode(ob.bytes.as_slice()).expect("a Task");
    assert_eq!(decoded.id, "t-1");

    let refused = json!({
        "jsonrpc": "2.0", "id": 1,
        "error": { "code": -32001, "message": "no task", "data": [{
            "@type": crate::ERROR_INFO_TYPE, "domain": crate::ERROR_INFO_DOMAIN,
            "reason": "TASK_NOT_FOUND" }] },
    });
    let ob = Outbox::framed(reply(404, &refused), Rpc::GetTask).expect("an outbox");
    let Some(Head::Framed(code, Some(details))) = &ob.head else {
        panic!("a status with details: {:?}", ob.head);
    };
    assert_eq!(*code, crate::framed::Code::NotFound as u32);
    assert!(!details.is_empty() && !details.ends_with('='));
    assert_eq!(ob.bytes, b"no task");
    assert_eq!(DETAILS_FIELD, "grpc-status-details-bin");

    let event = |state: &str| {
        format!(
            "data: {}\n\n",
            json!({ "jsonrpc": "2.0", "id": 1, "result": { "statusUpdate": {
                "taskId": "t", "contextId": "c", "status": { "state": state } } } })
        )
    };
    let body = format!(
        "{}: ping\n\n{}",
        event("TASK_STATE_WORKING"),
        event("TASK_STATE_COMPLETED")
    );
    let part = Answer::Part(relay::Part {
        head: true,
        body: body.into_bytes(),
        last: true,
    });
    let ob = Outbox::framed(part, Rpc::SubscribeToTask).expect("an outbox");
    assert!(matches!(ob.head, Some(Head::Framed(0, None))));
    assert_eq!(
        ob.queue.len(),
        1,
        "the second event waits for an answer of its own"
    );
    assert!(crate::proto::pb::StreamResponse::decode(ob.bytes.as_slice()).is_ok());
    assert!(ob.done);

    let failed = format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32001, "message": "gone" } })
    );
    let part = Answer::Part(relay::Part {
        head: true,
        body: failed.into_bytes(),
        last: false,
    });
    let ob = Outbox::framed(part, Rpc::SubscribeToTask).expect("an outbox");
    assert!(
        matches!(ob.head, Some(Head::Framed(5, _))) && ob.done,
        "an error before any message ends the call with its status: {:?}",
        ob.head
    );
}

/// THE gRPC LINE'S BOUNDARIES (SEAM-4l): a whole OK answer is one message, a status's text is no
/// message, and a stream that fails after its first message ends with its own final status.
#[test]
fn the_framed_line_marks_its_messages_and_a_late_failure() {
    use crate::framed::Rpc;
    let ok = json!({ "jsonrpc": "2.0", "id": 1, "result": {
        "id": "t-1", "contextId": "c-1", "status": { "state": "TASK_STATE_WORKING" } } });
    let whole = Outbox::framed(reply(200, &ok), Rpc::GetTask).expect("an outbox");
    assert!(whole.messages && whole.final_status.is_none());
    let refused = json!({ "jsonrpc": "2.0", "id": 1,
        "error": { "code": -32001, "message": "no task" } });
    let status = Outbox::framed(reply(404, &refused), Rpc::GetTask).expect("an outbox");
    assert!(!status.messages, "a status's text is no message");

    let event = format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "statusUpdate": {
            "taskId": "t", "contextId": "c", "status": { "state": "TASK_STATE_WORKING" } } } })
    );
    let failed = format!(
        "data: {}\n\n",
        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32603, "message": "boom" } })
    );
    let part = Answer::Part(relay::Part {
        head: true,
        body: format!("{event}{failed}").into_bytes(),
        last: false,
    });
    let late = Outbox::framed(part, Rpc::SubscribeToTask).expect("an outbox");
    assert!(late.messages && late.done);
    let end = late
        .final_status
        .expect("the stream ends with its own status");
    assert_eq!(end.code, crate::framed::Code::Internal as u32);
    assert_eq!(end.body, b"boom");
    // A later part that fails with no message of its own ends the stream the same way.
    let part = Answer::Part(relay::Part {
        head: false,
        body: failed.into_bytes(),
        last: false,
    });
    let after = Outbox::framed(part, Rpc::SubscribeToTask).expect("an outbox");
    assert!(after.done && after.bytes.is_empty() && after.final_status.is_some());
}

/// A long-running task streams many events and re-records the same pair each time. Re-recording a
/// held key must not evict any other, or one chatty task would push every other one out at the cap.
/// Ported from busbar-a2a a2a/tests/idmap_tests.rs::re_recording_the_same_pair_does_not_churn_the_map.
#[test]
fn re_recording_the_same_pair_does_not_churn_the_map() {
    let map: Keyed<String, String> = Keyed::new();
    for k in ["a", "b", "c"] {
        keep(&map, 3, k.to_string(), format!("far-{k}"));
    }
    for _ in 0..1000 {
        keep(&map, 3, "b".to_string(), "far-b".to_string());
    }
    assert_eq!(
        map.len(),
        3,
        "the map is still at its cap and nothing left it"
    );
    for k in ["a", "b", "c"] {
        assert_eq!(map.get(&k.to_string()), Some(format!("far-{k}")), "{k}");
    }
    // A NEW key past the cap still makes room, so the bound holds.
    keep(&map, 3, "d".to_string(), "far-d".to_string());
    assert_eq!(map.len(), 3);
    assert_eq!(map.get(&"d".to_string()), Some("far-d".to_string()));
}
