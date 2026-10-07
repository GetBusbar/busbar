// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_json::{json, Value};

use super::*;

fn events(bytes: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .map(|d| serde_json::from_str(d).expect("each event is one JSON document"))
        .collect()
}

#[test]
fn the_ordinary_accept_prefers_json() {
    assert!(!prefers_event_stream(Some(
        "application/json, text/event-stream"
    )));
    assert!(!prefers_event_stream(None));
    assert!(!prefers_event_stream(Some("application/json")));
}

#[test]
fn a_stream_first_or_alone_is_preferred() {
    assert!(prefers_event_stream(Some(
        "text/event-stream, application/json"
    )));
    assert!(prefers_event_stream(Some("text/event-stream")));
}

#[test]
fn a_q_value_decides_before_the_written_order() {
    assert!(prefers_event_stream(Some(
        "application/json;q=0.5, text/event-stream"
    )));
    assert!(!prefers_event_stream(Some(
        "text/event-stream;q=0.4, application/json"
    )));
    assert!(!prefers_event_stream(Some("text/event-stream;q=0")));
}

#[test]
fn the_level_is_the_callers_or_the_default() {
    assert_eq!(requested_level(None), DEFAULT_LEVEL);
    let meta = json!({ META_LOGGING_LEVEL: "debug" });
    assert_eq!(requested_level(Some(&meta)), "debug");
    let meta = json!({ META_LOGGING_LEVEL: "loud" });
    assert_eq!(requested_level(Some(&meta)), DEFAULT_LEVEL);
    assert!(level_allows("info", "warning"));
    assert!(!level_allows("info", "debug"));
    assert!(level_allows("info", "unheard-of"));
}

#[test]
fn a_json_caller_is_not_framed() {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {}}});
    assert_eq!(
        Framing::of(Some("application/json"), "tools/list", &body),
        None
    );
}

#[test]
fn a_progress_token_asks_for_a_stream_whatever_the_accept() {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "fs_read", "_meta": {"progressToken": "p"}}});
    let framing = Framing::of(Some("application/json"), "tools/call", &body).expect("framed");
    assert_eq!(framing.target, Some(json!("fs_read")));
    assert_eq!(framing.level, DEFAULT_LEVEL);
}

#[test]
fn the_stream_carries_progress_then_the_records_then_the_answer() {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": {"_meta": {META_LOGGING_LEVEL: "debug"}}});
    let framing = Framing::of(Some(EVENT_STREAM), "tools/list", &body).expect("framed");
    let answer = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#.to_vec();
    let progress = [json!({"jsonrpc": "2.0", "method": "notifications/progress"})];
    let (bytes, framed) = framing.frame(200, answer, &progress);
    assert!(framed);
    let e = events(&bytes);
    assert_eq!(
        e.len(),
        4,
        "one progress frame, two records at debug, the answer"
    );
    assert_eq!(e[0]["method"], "notifications/progress");
    assert_eq!(e[1]["params"]["level"], "debug");
    assert_eq!(e[2]["params"]["data"]["message"], "MCP method completed");
    assert_eq!(e[3]["id"], 1);
}

#[test]
fn the_default_level_drops_the_debug_record() {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {}}});
    let framing = Framing::of(Some(EVENT_STREAM), "tools/list", &body).expect("framed");
    let (bytes, _) = framing.frame(
        200,
        br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec(),
        &[],
    );
    let e = events(&bytes);
    assert_eq!(e.len(), 2);
    assert_eq!(e[0]["params"]["level"], "info");
}

#[test]
fn a_refusal_or_an_unreadable_body_goes_out_as_it_was() {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {}}});
    let framing = Framing::of(Some(EVENT_STREAM), "tools/list", &body).expect("framed");
    let refused = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"no"}}"#.to_vec();
    assert_eq!(framing.frame(403, refused.clone(), &[]), (refused, false));
    assert_eq!(
        framing.frame(200, b"not json".to_vec(), &[]),
        (b"not json".to_vec(), false)
    );
}
