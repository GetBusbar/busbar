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
    for (method, params) in [
        ("logging/setLevel", json!({ "level": "info" })),
        ("logging/setLevel", json!({})),
        ("resources/subscribe", json!({ "uri": "file:///a" })),
        ("resources/unsubscribe", json!({ "uri": "file:///a" })),
    ] {
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let Era::Answer(refusal) = era(&req) else {
            panic!("{method} is refused here, never dispatched or acknowledged");
        };
        assert_eq!(refusal["error"]["code"], -32601, "{method}");
        assert!(
            refusal.get("result").is_none(),
            "{method} is not acknowledged"
        );
    }
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
fn initialize_advertises_neither_subscribe_nor_logging() {
    let answer = initialize_result(&json!(1));
    let caps = &answer["result"]["capabilities"];
    assert!(caps["resources"].get("subscribe").is_none());
    assert!(caps.get("logging").is_none());
}

#[test]
fn a_live_ask_lapses_at_its_timeout_and_a_request_is_livened_a_bounded_number_of_times() {
    let result = json!({
        "resultType": "input_required",
        "inputRequests": { "a": { "method": "roots/list", "params": {} } },
        "requestState": "sealed"
    });
    let mut ask = LiveAsk::of("p", json!({}), b"{}".to_vec(), &result, 0).expect("a round");
    ask.issue(1).expect("the ask");
    assert!(!ask.lapsed(u64::MAX), "an ask never armed has no deadline");
    ask.arm(1_000);
    assert!(!ask.lapsed(1_000 + ASK_TIMEOUT_NS - 1));
    assert!(ask.lapsed(1_000 + ASK_TIMEOUT_NS));
    assert!(may_liven(MAX_LIVE_ASK_ROUNDS - 1));
    assert!(!may_liven(MAX_LIVE_ASK_ROUNDS));
}

/// `initialize` naming a session revision this plane carries is answered in it (THE DESIGN section 2,
/// the mcp bullet: revision by negotiation), and the carrier still declares neither `subscribe` nor
/// `logging` in it; naming none, or the stateless one, keeps the stateless answer.
#[test]
fn initialize_negotiates_a_session_revision() {
    let init = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } });
    let Era::Opened(revision, answer) = era(&init) else {
        panic!("a session revision is opened");
    };
    assert_eq!(revision, crate::revision::Revision::R2025_06_18);
    assert_eq!(answer["result"]["protocolVersion"], "2025-06-18");
    let caps = &answer["result"]["capabilities"];
    assert!(caps["resources"].get("subscribe").is_none());
    assert!(caps.get("logging").is_none());
    let stateless = json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": { "protocolVersion": "2026-07-28" } });
    assert_eq!(era(&stateless), Era::Answer(initialize_result(&json!(2))));
}
