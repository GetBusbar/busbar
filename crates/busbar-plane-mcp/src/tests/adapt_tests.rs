// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use serde_json::json;

#[test]
fn a_stateless_request_keeps_the_stateless_reading_whatever_else_it_carries() {
    let stateless = json!({"jsonrpc":"2.0","id":1,"method":"tools/list",
        "params":{"_meta":{META_PROTOCOL_VERSION: "2026-07-28"}}});
    assert_eq!(classify_post(&stateless, None, None), PostKind::Stateless);
    // The stateless revision ignores a session header (it has no sessions).
    assert_eq!(
        classify_post(&stateless, Some("abc"), None),
        PostKind::Stateless
    );
    // A request with no marker, no session and no initialize is answered as it always was.
    let bare = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
    assert_eq!(classify_post(&bare, None, None), PostKind::Stateless);
}

#[test]
fn initialize_session_and_message_address_posts_are_told_apart() {
    let init = json!({"jsonrpc":"2.0","id":0,"method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}});
    assert_eq!(classify_post(&init, None, None), PostKind::Initialize);
    let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
    assert_eq!(classify_post(&call, Some("s"), None), PostKind::InSession);
    assert_eq!(
        classify_post(&init, None, Some("s")),
        PostKind::EventStreamMessage
    );
}

#[test]
fn the_message_address_session_is_read_from_the_query() {
    assert_eq!(message_session_of(Some("sessionId=abc")), Some("abc"));
    assert_eq!(
        message_session_of(Some("x=1&sessionId=abc&y=2")),
        Some("abc")
    );
    assert_eq!(message_session_of(Some("sessionId=")), None);
    assert_eq!(message_session_of(Some("session=abc")), None);
    assert_eq!(message_session_of(None), None);
}

#[test]
fn red_no_stateless_only_method_reaches_a_session_client() {
    for m in [
        "server/discover",
        "subscriptions/listen",
        "tasks/get",
        "tasks/update",
        "tasks/cancel",
        "initialize",
    ] {
        assert_eq!(
            session_method(Some(m), true),
            SessionMethod::NotFound,
            "{m}"
        );
    }
    assert_eq!(
        session_method(Some("tools/call"), true),
        SessionMethod::Dispatch
    );
    assert_eq!(session_method(Some("ping"), true), SessionMethod::Ping);
    assert_eq!(
        session_method(Some(METHOD_INITIALIZED), false),
        SessionMethod::Accept
    );
    assert_eq!(session_method(None, true), SessionMethod::Accept);
}

#[test]
fn raising_adds_the_stateless_meta_and_mirrors_the_name() {
    let mut m = json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"echo","arguments":{},"_meta":{"progressToken":7}}});
    let mirror = raise(&mut m).unwrap();
    assert_eq!(mirror.version, "2026-07-28");
    assert_eq!(mirror.method, "tools/call");
    assert_eq!(mirror.name.as_deref(), Some("echo"));
    let meta = &m["params"]["_meta"];
    assert_eq!(meta[META_PROTOCOL_VERSION], "2026-07-28");
    assert_eq!(meta[META_CLIENT_CAPABILITIES], json!({}));
    assert_eq!(meta["progressToken"], 7, "the client's own _meta survives");

    let mut bare = json!({"jsonrpc":"2.0","id":4,"method":"tools/list"});
    let mirror = raise(&mut bare).unwrap();
    assert_eq!(mirror.name, None);
    assert!(bare["params"]["_meta"].is_object());

    let mut bad = json!({"jsonrpc":"2.0","id":5,"method":"tools/list","params":[1]});
    assert_eq!(raise(&mut bad), None);
}

#[test]
fn lowering_strips_stateless_members_and_refuses_incomplete_results() {
    let mut r = json!({"tools":[],"resultType":"complete","cacheScope":"caller","ttlMs":1000});
    lower_result(&mut r).unwrap();
    assert_eq!(r, json!({"tools":[]}));
    let mut ir = json!({"resultType":"input_required","inputRequests":{}});
    assert_eq!(lower_result(&mut ir), Err(NotExpressible));
    let mut task = json!({"resultType":"task"});
    assert_eq!(lower_result(&mut task), Err(NotExpressible));
}

#[test]
fn red_initialize_declares_no_stateless_only_capability() {
    let discovery = json!({
        "protocolVersion":"2026-07-28",
        "serverInfo":{"name":"busbar","version":"1.6.0"},
        "capabilities":{
            "tools":{"listChanged":true},"prompts":{"listChanged":true},
            "resources":{"listChanged":true,"subscribe":true},
            "completions":{},"logging":{},"extensions":{"x":{}}
        },
        "methods":["server/discover"]
    });
    let r = initialize_result(&discovery, Revision::R2025_11_25, false);
    assert_eq!(r["protocolVersion"], "2025-11-25");
    assert_eq!(r["serverInfo"]["name"], "busbar");
    let caps = r["capabilities"].as_object().unwrap();
    let mut keys: Vec<&str> = caps.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["completions", "prompts", "resources", "tools"]);
    assert_eq!(caps["resources"], json!({"listChanged": false}));
    assert!(r.get("methods").is_none());

    let old = initialize_result(&discovery, Revision::R2024_11_05, true);
    assert!(old["capabilities"].get("completions").is_none());
    assert_eq!(old["capabilities"]["tools"], json!({"listChanged": true}));

    let none = initialize_result(&json!({"capabilities":{}}), Revision::R2025_06_18, true);
    assert_eq!(none["capabilities"], json!({}));
}

#[test]
fn event_stream_framing() {
    assert_eq!(
        frame(Some("0-1"), None, "{\"a\":1}"),
        "id: 0-1\ndata: {\"a\":1}\n\n"
    );
    assert_eq!(
        frame(None, Some(EVENT_MESSAGE), "a\nb"),
        "event: message\ndata: a\ndata: b\n\n"
    );
    assert_eq!(
        endpoint_event("/mcp", "0123"),
        "event: endpoint\ndata: /mcp?sessionId=0123\n\n"
    );
}
