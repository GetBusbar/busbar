// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::client::jsonrpc::envelope;
use serde_json::json;

fn stateless_call() -> OutboundRequest {
    envelope(
        "https://up.example/rpc",
        "tools/call",
        Some("echo"),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{
            "name":"echo","arguments":{"x":"y"},
            "_meta":{META_PROTOCOL_VERSION:"2026-07-28",META_CLIENT_CAPABILITIES:{},"progressToken":3}}}),
        Some("tok"),
    )
}

fn header<'a>(r: &'a OutboundRequest, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[test]
fn a_refusal_moves_the_ladder_and_an_outage_does_not() {
    assert_eq!(probe_outcome(400, b""), StepOutcome::Refused4xx);
    assert_eq!(probe_outcome(404, b"{}"), StepOutcome::Refused4xx);
    assert_eq!(probe_outcome(502, b""), StepOutcome::Unreachable);
    for code in [-32601, -32600, -32602, -32022] {
        let body = json!({"jsonrpc":"2.0","id":1,"error":{"code":code,"message":"m"}}).to_string();
        assert_eq!(
            probe_outcome(200, body.as_bytes()),
            StepOutcome::Refused4xx,
            "{code}"
        );
    }
    let other = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"m"}}).to_string();
    assert_eq!(probe_outcome(200, other.as_bytes()), StepOutcome::Answered);
    assert_eq!(
        probe_outcome(200, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
        StepOutcome::Answered
    );
}

#[test]
fn lowering_drops_the_stateless_meta_and_mirror_and_keeps_the_credential() {
    let lowered = lower_request(
        &stateless_call(),
        "https://up.example/rpc",
        Revision::R2025_06_18,
        Some("sid1"),
    );
    let body: Value = serde_json::from_slice(&lowered.body).unwrap();
    assert_eq!(
        body["params"]["_meta"],
        json!({"progressToken":3}),
        "only the client's own _meta survives"
    );
    assert_eq!(body["params"]["arguments"], json!({"x":"y"}));
    assert_eq!(header(&lowered, H_PROTOCOL_VERSION), Some("2025-06-18"));
    assert_eq!(header(&lowered, H_SESSION), Some("sid1"));
    assert_eq!(header(&lowered, H_MCP_METHOD), None);
    assert_eq!(header(&lowered, H_MCP_NAME), None);
    assert_eq!(header(&lowered, "authorization"), Some("Bearer tok"));
}

#[test]
fn the_event_stream_revision_carries_no_version_header_and_an_empty_meta_goes() {
    let mut req = stateless_call();
    let mut body: Value = serde_json::from_slice(&req.body).unwrap();
    body["params"]["_meta"] =
        json!({META_PROTOCOL_VERSION:"2026-07-28",META_CLIENT_CAPABILITIES:{}});
    req.body = serde_json::to_vec(&body).unwrap();
    let lowered = lower_request(
        &req,
        "https://up.example/messages?sessionId=a",
        Revision::R2024_11_05,
        None,
    );
    assert_eq!(lowered.url, "https://up.example/messages?sessionId=a");
    assert_eq!(header(&lowered, H_PROTOCOL_VERSION), None);
    let body: Value = serde_json::from_slice(&lowered.body).unwrap();
    assert!(body["params"].get("_meta").is_none());
}

#[test]
fn initialize_asks_for_a_revision_and_names_busbar() {
    let init = initialize_request(
        &stateless_call(),
        "https://up.example/rpc",
        Revision::R2025_11_25,
        9,
        "1.6.0",
    );
    let body: Value = serde_json::from_slice(&init.body).unwrap();
    assert_eq!(body["method"], "initialize");
    assert_eq!(body["params"]["protocolVersion"], "2025-11-25");
    assert_eq!(body["params"]["clientInfo"]["version"], "1.6.0");
    assert_eq!(
        header(&init, H_PROTOCOL_VERSION),
        None,
        "initialize precedes the header"
    );
    assert_eq!(header(&init, "authorization"), Some("Bearer tok"));
    let done = initialized_notification(
        &init,
        "https://up.example/rpc",
        Revision::R2025_11_25,
        Some("s"),
    );
    let body: Value = serde_json::from_slice(&done.body).unwrap();
    assert!(body.get("id").is_none());
    assert_eq!(header(&done, H_SESSION), Some("s"));
}

#[test]
fn only_a_revision_this_plane_carries_is_accepted_from_initialize() {
    let ok = json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}).to_string();
    assert_eq!(offered_revision(ok.as_bytes()), Some(Revision::R2025_06_18));
    let old = json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}).to_string();
    assert_eq!(offered_revision(old.as_bytes()), None);
    assert_eq!(offered_revision(b"not json"), None);
}

/// RED: the message address a `2024-11-05` stream names can never move busbar's POSTs (and the
/// credential on them) to another origin.
#[test]
fn red_a_message_address_on_another_origin_is_refused() {
    let base = "https://up.example:8443/events";
    assert_eq!(
        message_address(base, "/messages?sessionId=1").as_deref(),
        Ok("https://up.example:8443/messages?sessionId=1")
    );
    assert_eq!(
        message_address(base, "https://UP.example:8443/m").as_deref(),
        Ok("https://UP.example:8443/m")
    );
    for hostile in [
        "https://evil.example/m",
        "https://up.example/m",
        "//evil.example/m",
    ] {
        assert!(message_address(base, hostile).is_err(), "{hostile}");
    }
    assert_eq!(
        message_address(base, "https://evil.example/m"),
        Err(AddressRefused::CrossOrigin)
    );
    assert_eq!(
        message_address(base, "messages"),
        Err(AddressRefused::Malformed)
    );
    assert_eq!(
        message_address(base, "/a b"),
        Err(AddressRefused::Malformed)
    );
}

#[test]
fn the_event_reader_joins_split_chunks_and_is_bounded() {
    let mut r = EventReader::new(64);
    assert!(r.feed(b"event: endpoint\r\ndata: /m?s").is_empty());
    let got = r.feed(b"=1\r\n\r\n: keepalive\n\nid: 0-1\ndata: {\"a\":\ndata: 1}\n\n");
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].event.as_deref(), Some("endpoint"));
    assert_eq!(got[0].data, "/m?s=1");
    assert_eq!(got[1].id.as_deref(), Some("0-1"));
    assert_eq!(got[1].data, "{\"a\":\n1}");
    assert!(r.feed(&[b'x'; 100]).is_empty());
    assert!(
        r.overflowed(),
        "an event that never ends is dropped, not buffered forever"
    );
}

fn ev(event: Option<&str>, data: &str) -> StreamEvent {
    StreamEvent {
        event: event.map(str::to_string),
        id: None,
        data: data.to_string(),
    }
}

#[test]
fn a_link_is_ready_once_and_answers_only_what_it_waits_for() {
    let mut link = EventStreamLink::new("https://up.example/events", 2);
    assert_eq!(link.address(), None);
    assert_eq!(
        link.on_event(&ev(Some("endpoint"), "/messages?sessionId=a")),
        LinkEffect::Ready("https://up.example/messages?sessionId=a".to_string())
    );
    assert_eq!(
        link.on_event(&ev(Some("endpoint"), "/elsewhere")),
        LinkEffect::Ignored,
        "the address is named once"
    );
    assert!(link.expect(&json!(7)));
    assert!(!link.expect(&json!(7)), "one waiter per id");
    assert!(link.expect(&json!("x")));
    assert!(!link.expect(&json!(9)), "bounded");
    let answer = r#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
    assert!(
        matches!(link.on_event(&ev(Some("message"), answer)), LinkEffect::Answer { ref id, .. } if id == "7")
    );
    assert_eq!(
        link.on_event(&ev(Some("message"), answer)),
        LinkEffect::Ignored,
        "answered once"
    );
    let unsolicited = r#"{"jsonrpc":"2.0","id":99,"result":{}}"#;
    assert_eq!(link.on_event(&ev(None, unsolicited)), LinkEffect::Ignored);
    let note = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
    assert!(matches!(
        link.on_event(&ev(Some("message"), note)),
        LinkEffect::FromPeer(_)
    ));
    link.abandon(&json!("x"));
    assert!(link.expect(&json!(9)));
}

#[test]
fn red_a_link_refuses_a_cross_origin_endpoint() {
    let mut link = EventStreamLink::new("https://up.example/events", 2);
    assert_eq!(
        link.on_event(&ev(Some("endpoint"), "https://evil.example/m")),
        LinkEffect::Refused(AddressRefused::CrossOrigin)
    );
    assert_eq!(link.address(), None);
}
