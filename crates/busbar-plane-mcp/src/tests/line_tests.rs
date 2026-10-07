// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The line carrier's meanings: the fields a body implies, the stdio-era verbs, busbar's own asks
//! issued in order and their retry, and what a line that answers busbar is.

use serde_json::json;

use super::*;

#[test]
fn the_stdio_era_verbs_are_answered_here_and_others_go_to_the_dispatch() {
    let init = json!({ "jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {} });
    let Era::Answer(answer) = era(&init) else {
        panic!("initialize is answered here");
    };
    assert_eq!(answer["id"], 7);
    assert_eq!(answer["result"]["protocolVersion"], PROTOCOL_VERSION);
    let ping = json!({ "jsonrpc": "2.0", "id": "p", "method": "ping" });
    assert_eq!(era(&ping), Era::Answer(result(&json!("p"), json!({}))));
    let level = json!({ "jsonrpc": "2.0", "id": 1, "method": "logging/setLevel", "params": { "level": "info" } });
    assert!(matches!(era(&level), Era::Level(l, _) if l == "info"));
    let no_level = json!({ "jsonrpc": "2.0", "id": 1, "method": "logging/setLevel", "params": {} });
    assert!(matches!(era(&no_level), Era::Answer(v) if v["error"]["code"] == INVALID_PARAMS));
    let sub = json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/subscribe", "params": { "uri": "file:///a" } });
    assert_eq!(era(&sub), Era::Subscribe("file:///a".to_string()));
    let long = "x".repeat(MAX_RESOURCE_SUB_URI_BYTES + 1);
    let sub_long = json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/subscribe", "params": { "uri": long } });
    assert!(
        matches!(era(&sub_long), Era::Answer(_)),
        "a uri past the ceiling is refused"
    );
    let list = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} });
    assert_eq!(era(&list), Era::Dispatch);
    // A notification is not a stdio-era request.
    let note = json!({ "jsonrpc": "2.0", "method": "ping" });
    assert_eq!(era(&note), Era::Dispatch);
}

#[test]
fn a_line_answers_busbar_only_under_an_id_busbar_minted() {
    let answer = json!({ "jsonrpc": "2.0", "id": "busbar:4", "result": { "action": "accept" } });
    assert_eq!(
        reply(&answer),
        Some(Reply::Answered(4, json!({ "action": "accept" })))
    );
    let error =
        json!({ "jsonrpc": "2.0", "id": "busbar:5", "error": { "code": -1, "message": "no" } });
    assert_eq!(reply(&error), Some(Reply::Failed(5)));
    let theirs = json!({ "jsonrpc": "2.0", "id": 4, "result": {} });
    assert_eq!(
        reply(&theirs),
        None,
        "an id busbar did not mint answers nothing of busbar's"
    );
    let request = json!({ "jsonrpc": "2.0", "id": "busbar:4", "method": "ping" });
    assert_eq!(reply(&request), None, "a request is not an answer");
    let oob = json!({
        "jsonrpc": "2.0", "method": "notifications/elicitation/response",
        "params": { "requestId": "busbar:9", "response": { "action": "decline" } }
    });
    assert_eq!(
        reply(&oob),
        Some(Reply::Answered(9, json!({ "action": "decline" })))
    );
    let cancel = json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": 3 } });
    assert_eq!(cancelled(&cancel), Some(json!(3)));
    assert_ne!(id_key(&json!("1")), id_key(&json!(1)));
}

#[test]
fn a_live_round_issues_its_asks_in_order_and_its_retry_carries_the_answers_and_the_state() {
    let original = json!({
        "jsonrpc": "2.0", "id": "call-0", "method": "prompts/get",
        "params": { "name": "ws_greet", "_meta": {} }
    });
    let result = json!({
        "resultType": "input_required",
        "inputRequests": {
            "a": { "method": "elicitation/create", "params": { "message": "first" } },
            "b": { "method": "roots/list", "params": {} }
        },
        "requestState": "sealed"
    });
    let mut ask = LiveAsk::of("p", original, b"{}".to_vec(), &result, 0).expect("a round");
    let first: Value = serde_json::from_slice(&ask.issue(10).expect("the first ask")).unwrap();
    assert_eq!(first["id"], "busbar:10");
    assert_eq!(first["method"], "elicitation/create");
    assert_eq!(ask.current_n, 10);
    ask.answered(json!({ "action": "accept" }));
    let second: Value = serde_json::from_slice(&ask.issue(11).expect("the second ask")).unwrap();
    assert_eq!(second["method"], "roots/list");
    ask.answered(json!({ "roots": [] }));
    assert!(ask.issue(12).is_none(), "the round is spent");
    let retry = ask.retry().expect("the retry");
    assert_eq!(
        retry["id"], "call-0",
        "the retry's answer is the caller's answer"
    );
    assert_eq!(retry["params"]["requestState"], "sealed");
    assert_eq!(retry["params"]["inputResponses"]["a"]["action"], "accept");
    assert_eq!(retry["params"]["inputResponses"]["b"]["roots"], json!([]));
    // A result naming no asks, or no state, is no round: it is handed to the caller as it is.
    let no_state =
        json!({ "resultType": "input_required", "inputRequests": { "a": { "method": "m" } } });
    assert!(LiveAsk::of("p", json!({}), Vec::new(), &no_state, 0).is_none());
}

#[test]
fn the_session_floor_fills_only_the_slot_the_request_left_empty() {
    let bare = json!({ "params": { "_meta": {} } });
    assert_eq!(
        with_level(bare, Some("info"))["params"]["_meta"][META_LOGGING_LEVEL],
        "info"
    );
    let own = json!({ "params": { "_meta": { META_LOGGING_LEVEL: "error" } } });
    assert_eq!(
        with_level(own, Some("info"))["params"]["_meta"][META_LOGGING_LEVEL],
        "error"
    );
}

/// `initialize` naming a session revision this plane carries is answered in it (THE DESIGN section 2,
/// the mcp bullet: revision by negotiation); naming none, or the stateless one, keeps the stateless
/// answer.
#[test]
fn initialize_negotiates_a_session_revision() {
    let init = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } });
    let Era::Opened(revision, answer) = era(&init) else {
        panic!("a session revision is opened");
    };
    assert_eq!(revision, crate::revision::Revision::R2025_06_18);
    assert_eq!(answer["result"]["protocolVersion"], "2025-06-18");
    let stateless = json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": { "protocolVersion": "2026-07-28" } });
    assert_eq!(era(&stateless), Era::Answer(initialize_result(&json!(2))));
}
