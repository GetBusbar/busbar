// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The negotiator driven against FAKE upstreams, one per revision: the fake hop the adapter
//! contract describes, answering as each revision's server would.

use super::*;
use crate::client::jsonrpc::envelope;
use crate::codec::{H_PROTOCOL_VERSION, META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION};
use serde_json::json;

const URL: &str = "https://up.example/rpc";

fn call() -> OutboundRequest {
    envelope(
        URL,
        "tools/call",
        Some("echo"),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{
            "name":"echo","arguments":{},
            "_meta":{META_PROTOCOL_VERSION:"2026-07-28",META_CLIENT_CAPABILITIES:{}}}}),
        Some("tok"),
    )
}

fn answer(status: u16, body: Value) -> Option<HopAnswer> {
    Some(HopAnswer {
        status,
        fields: Vec::new(),
        body: serde_json::to_vec(&body).unwrap(),
    })
}

fn with_session(status: u16, body: Value, sid: &str) -> Option<HopAnswer> {
    Some(HopAnswer {
        status,
        fields: vec![("mcp-session-id".to_string(), sid.to_string())],
        body: serde_json::to_vec(&body).unwrap(),
    })
}

fn accepted() -> Option<HopAnswer> {
    Some(HopAnswer {
        status: 202,
        fields: Vec::new(),
        body: Vec::new(),
    })
}

fn sent(a: &Action) -> (&OutboundRequest, Value) {
    match a {
        Action::Send { request, .. } => (
            request,
            serde_json::from_slice(&request.body).unwrap_or(Value::Null),
        ),
        other => panic!("expected a Send, got {other:?}"),
    }
}

fn header<'a>(r: &'a OutboundRequest, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn result(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn event(name: Option<&str>, data: &str) -> StreamEvent {
    StreamEvent {
        event: name.map(str::to_string),
        id: None,
        data: data.to_string(),
    }
}

#[test]
fn a_stateless_upstream_is_answered_by_the_request_itself() {
    let mut n = Negotiator::new(call(), None, "1.6.0");
    let first = n.start();
    assert_eq!(
        sent(&first).0,
        &call(),
        "the stateless request goes out unchanged"
    );
    let done = n.on_answer(answer(200, result(json!(5), json!({"content":[]}))));
    assert!(matches!(done, Action::Finish(ref a) if a.status == 200));
    assert_eq!(n.remembered().unwrap().revision, Revision::R2026_07_28);
}

#[test]
fn a_session_upstream_is_initialized_and_the_call_lowered_into_its_session() {
    let mut n = Negotiator::new(call(), None, "1.6.0");
    n.start();
    let init = n.on_answer(answer(
        400,
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"no session"}}),
    ));
    let (req, body) = sent(&init);
    assert_eq!(body["method"], "initialize");
    assert_eq!(body["params"]["protocolVersion"], "2025-11-25");
    assert_eq!(header(req, "authorization"), Some("Bearer tok"));
    let done_init = n.on_answer(with_session(
        200,
        result(body["id"].clone(), json!({"protocolVersion":"2025-06-18"})),
        "abc",
    ));
    let (req, body) = sent(&done_init);
    assert_eq!(body["method"], "notifications/initialized");
    assert_eq!(header(req, "mcp-session-id"), Some("abc"));
    assert_eq!(header(req, H_PROTOCOL_VERSION), Some("2025-06-18"));
    let the_call = n.on_answer(accepted());
    let (req, body) = sent(&the_call);
    assert_eq!(body["method"], "tools/call");
    assert!(
        body["params"].get("_meta").is_none(),
        "lowered: the stateless _meta is gone"
    );
    assert_eq!(header(req, "mcp-session-id"), Some("abc"));
    let fin = n.on_answer(answer(200, result(json!(5), json!({"content":[]}))));
    assert!(matches!(fin, Action::Finish(_)));
    let r = n.remembered().unwrap();
    assert_eq!(
        (r.revision, r.session.as_deref()),
        (Revision::R2025_06_18, Some("abc"))
    );
}

#[test]
fn a_lost_session_is_reinitialized_once_and_never_looped() {
    let memo = Remembered {
        revision: Revision::R2025_11_25,
        session: Some("old".into()),
        message_address: None,
    };
    let mut n = Negotiator::new(call(), Some(memo), "1.6.0");
    let first = n.start();
    let (req, _) = sent(&first);
    assert_eq!(header(req, "mcp-session-id"), Some("old"));
    let init = n.on_answer(answer(404, json!({})));
    assert_eq!(sent(&init).1["method"], "initialize");
    let id = sent(&init).1["id"].clone();
    n.on_answer(with_session(
        200,
        result(id, json!({"protocolVersion":"2025-11-25"})),
        "new",
    ));
    let again = n.on_answer(accepted());
    assert_eq!(header(sent(&again).0, "mcp-session-id"), Some("new"));
    // The fresh session is lost too: the answer is handed back, not a second re-initialise.
    let fin = n.on_answer(answer(404, json!({})));
    assert!(matches!(fin, Action::Finish(ref a) if a.status == 404));
}

#[test]
fn an_outage_does_not_move_the_ladder() {
    let mut n = Negotiator::new(call(), None, "1.6.0");
    n.start();
    assert!(matches!(
        n.on_answer(answer(503, json!({}))),
        Action::Fail(Refusal::Unreachable(_))
    ));
    let mut n = Negotiator::new(call(), None, "1.6.0");
    n.start();
    assert_eq!(n.on_answer(None), Action::Fail(Refusal::Unreachable(None)));
    assert_eq!(n.remembered(), None);
}

#[test]
fn an_offer_this_plane_cannot_carry_is_a_disconnect() {
    let mut n = Negotiator::new(call(), None, "1.6.0");
    n.start();
    let init = n.on_answer(answer(400, json!({})));
    let id = sent(&init).1["id"].clone();
    let fin = n.on_answer(answer(
        200,
        result(id, json!({"protocolVersion":"2025-03-26"})),
    ));
    assert_eq!(fin, Action::Fail(Refusal::OfferedUnsupported));
}

#[test]
fn an_event_stream_upstream_is_reached_through_the_address_its_stream_names() {
    let mut n = Negotiator::new(call(), None, "1.6.0");
    n.start();
    n.on_answer(answer(404, json!({})));
    let open = n.on_answer(answer(404, json!({})));
    let Action::OpenStream { request } = open else {
        panic!("expected the stream, got {open:?}")
    };
    assert!(request.body.is_empty());
    assert_eq!(header(&request, "accept"), Some("text/event-stream"));
    assert_eq!(header(&request, "authorization"), Some("Bearer tok"));
    assert_eq!(n.on_answer(answer(200, json!(null))), Action::AwaitEvent);
    let init = n.on_event(&event(Some("endpoint"), "/messages?sessionId=s1"));
    let (req, body) = sent(&init);
    assert_eq!(req.url, "https://up.example/messages?sessionId=s1");
    assert_eq!(body["params"]["protocolVersion"], "2024-11-05");
    assert_eq!(header(req, H_PROTOCOL_VERSION), None);
    let id = body["id"].clone();
    assert_eq!(n.on_answer(accepted()), Action::AwaitEvent);
    let initialized = n.on_event(&event(
        Some("message"),
        &result(id, json!({"protocolVersion":"2024-11-05"})).to_string(),
    ));
    assert_eq!(sent(&initialized).1["method"], "notifications/initialized");
    let the_call = n.on_answer(accepted());
    let (req, body) = sent(&the_call);
    assert_eq!(req.url, "https://up.example/messages?sessionId=s1");
    assert_eq!(body["id"], 5);
    assert_eq!(n.on_answer(accepted()), Action::AwaitEvent);
    let unrelated = result(json!(77), json!({})).to_string();
    assert_eq!(
        n.on_event(&event(Some("message"), &unrelated)),
        Action::AwaitEvent
    );
    let fin = n.on_event(&event(
        Some("message"),
        &result(json!(5), json!({"content":[]})).to_string(),
    ));
    let Action::Finish(a) = fin else {
        panic!("expected the answer, got {fin:?}")
    };
    assert_eq!(serde_json::from_slice::<Value>(&a.body).unwrap()["id"], 5);
    assert_eq!(n.remembered().unwrap().revision, Revision::R2024_11_05);
}

/// RED: a stream naming a message address on another origin gets nothing POSTed to it, so the
/// credential never leaves for a host the operator did not register.
#[test]
fn red_a_cross_origin_message_address_gets_no_request() {
    let memo = Remembered {
        revision: Revision::R2024_11_05,
        session: None,
        message_address: None,
    };
    let mut n = Negotiator::new(call(), Some(memo), "1.6.0");
    assert!(matches!(n.start(), Action::OpenStream { .. }));
    n.on_answer(answer(200, json!(null)));
    let a = n.on_event(&event(Some("endpoint"), "https://evil.example/steal"));
    assert_eq!(a, Action::Fail(Refusal::AddressRefused));
}
