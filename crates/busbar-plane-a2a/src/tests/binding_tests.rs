// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The outbound binding off a held card, and the HTTP+JSON framing, against the served engine's
//! own cases (`busbar-a2a` `relay::binding_of`, `HttpJsonFraming`).

use serde_json::json;

use super::*;

fn card(words: &[&str]) -> Value {
    json!({ "supportedInterfaces": words.iter()
        .map(|w| json!({ "url": "https://ignored.example", "protocolBinding": w }))
        .collect::<Vec<_>>() })
}

#[test]
fn no_card_or_no_interfaces_is_json_rpc() {
    assert_eq!(binding_of(None), BINDING_JSONRPC);
    assert_eq!(binding_of(Some(&json!({}))), BINDING_JSONRPC);
    assert_eq!(binding_of(Some(&card(&[" "]))), BINDING_JSONRPC);
}

#[test]
fn the_first_binding_the_plane_frames_is_taken_in_the_cards_order() {
    assert_eq!(
        binding_of(Some(&card(&["HTTP+JSON", "JSONRPC"]))),
        "HTTP+JSON"
    );
    assert_eq!(
        binding_of(Some(&card(&["JSONRPC", "HTTP+JSON"]))),
        "JSONRPC"
    );
    assert_eq!(speakable("http+json"), Some(Binding::HttpJson));
    assert_eq!(speakable(" jsonrpc "), Some(Binding::JsonRpc));
}

/// gRPC IS SPOKEN (the engine's `relay::framing_for` answered all three words): a card that lists
/// it first is reached on it; a card listing only bindings the plane does not frame names its first,
/// and is refused by name. RED: `speakable("GRPC")` answered `None` and a gRPC-only card was refused.
#[test]
fn grpc_is_framed_so_a_card_that_lists_it_first_is_reached_on_it() {
    assert_eq!(speakable(BINDING_GRPC), Some(Binding::Grpc));
    assert_eq!(speakable(" grpc "), Some(Binding::Grpc));
    assert_eq!(Binding::Grpc.word(), BINDING_GRPC);
    assert_eq!(binding_of(Some(&card(&["GRPC", "HTTP+JSON"]))), "GRPC");
    assert_eq!(binding_of(Some(&card(&["GRPC"]))), "GRPC");
    assert_eq!(binding_of(Some(&card(&["SOAP", "GRPC"]))), "GRPC");
    // A card that lists only bindings the plane does not frame names its first: refused by name.
    let only = binding_of(Some(&card(&["SOAP", "CORBA"])));
    assert_eq!(only, "SOAP");
    assert_eq!(speakable(&only), None);
}

#[test]
fn the_unframable_sentence_bounds_both_words() {
    assert_eq!(
        unframable_text("GetTask", "SOAP 1.2 ://x"),
        "a2a.hop.unframable: `GetTask` could not be carried to this agent over its \
         `SOAP?1.2??//x` binding"
    );
    assert_eq!(bounded_word(""), "?");
    assert_eq!(bounded_word(&"a".repeat(60)).len(), 48);
}

const BASE: &str = "https://vendor.example/a2a/v1?tenant=t1";

#[test]
fn a_send_posts_its_params_as_the_body_under_the_operators_path() {
    let f = compose(
        BASE,
        "SendMessage",
        &json!({ "message": { "messageId": "m" } }),
    )
    .unwrap();
    assert_eq!(f.verb, "POST");
    assert_eq!(f.target, "/a2a/v1/message:send");
    assert!(f.has_body);
    assert_eq!(f.body, br#"{"message":{"messageId":"m"}}"#);
}

#[test]
fn a_read_takes_its_id_into_the_path_and_its_options_onto_the_query() {
    let f = compose(
        BASE,
        "tasks/get",
        &json!({ "id": "t/1", "historyLength": 5 }),
    )
    .unwrap();
    assert_eq!(f.verb, "GET");
    assert_eq!(f.target, "/a2a/v1/tasks/t%2F1?historyLength=5");
    assert!(!f.has_body);
    assert!(f.body.is_empty());
    let f = compose(BASE, "GetTask", &json!({ "task_id": "t1" })).unwrap();
    assert_eq!(f.target, "/a2a/v1/tasks/t1");
}

#[test]
fn a_push_config_route_keeps_the_config_id_apart_from_the_task() {
    let f = compose(
        BASE,
        "DeleteTaskPushNotificationConfig",
        &json!({ "taskId": "t1", "id": "c1" }),
    )
    .unwrap();
    assert_eq!(f.verb, "DELETE");
    assert_eq!(f.target, "/a2a/v1/tasks/t1/pushNotificationConfigs/c1");
}

#[test]
fn what_the_binding_cannot_carry_is_refused_not_dropped() {
    assert!(compose(BASE, "GetTask", &json!({})).is_err());
    assert!(compose(BASE, "GetTask", &json!({ "id": "t", "extra": 1 })).is_err());
    assert!(compose(BASE, "vendor/Thing", &json!({})).is_err());
    assert!(compose(BASE, "GetTask", &json!({ "id": "" })).is_err());
}

#[test]
fn a_success_body_is_rewrapped_as_the_result_and_an_empty_one_is_null() {
    let id = json!(7);
    assert_eq!(
        serde_json::from_slice::<Value>(&rewrap(br#"{"id":"t"}"#, &id).unwrap()).unwrap(),
        json!({ "jsonrpc": "2.0", "id": 7, "result": { "id": "t" } })
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&rewrap(b" \n", &id).unwrap()).unwrap(),
        json!({ "jsonrpc": "2.0", "id": 7, "result": null })
    );
    assert!(rewrap(b"<html>", &id).is_err());
}

/// The operator's `url:` for the engine's client-leg cells.
const AGENT: &str = "https://backend.agent.test/a2a";

/// `http_json_client_issues_send_stream_message`: the stream submission is a POST to
/// `/message:stream`, its body the params with no JSON-RPC envelope member.
#[test]
fn http_json_client_issues_send_stream_message() {
    let f = compose(
        AGENT,
        "message/stream",
        &json!({ "message": { "role": "user", "parts": [{ "kind": "text", "text": "GO" }] } }),
    )
    .unwrap();
    assert_eq!((f.verb, f.target.as_str()), ("POST", "/a2a/message:stream"));
    let body: Value = serde_json::from_slice(&f.body).unwrap();
    assert!(body.get("message").is_some());
    assert!(body.get("jsonrpc").is_none() && body.get("method").is_none());
}

/// `http_json_client_issues_cancel_task`: a POST to the task's `:cancel`, naming the id it was
/// handed (the far end's own, once the door translated it).
#[test]
fn http_json_client_issues_cancel_task() {
    let f = compose(
        AGENT,
        "tasks/cancel",
        &json!({ "id": "BACKEND-OWN-TASK-ID" }),
    )
    .unwrap();
    assert_eq!(
        (f.verb, f.target.as_str()),
        ("POST", "/a2a/tasks/BACKEND-OWN-TASK-ID:cancel")
    );
    assert!(f.body.is_empty() && !f.has_body);
}

/// `http_json_client_issues_subscribe_to_task` (and its v1.0 spelling, `task_id`): a POST to the
/// task's `:subscribe`.
#[test]
fn http_json_client_issues_subscribe_to_task() {
    for (method, member) in [("tasks/resubscribe", "id"), ("SubscribeToTask", "task_id")] {
        let mut params = Map::new();
        params.insert(member.to_string(), json!("BACKEND-OWN-TASK-ID"));
        let f = compose(AGENT, method, &Value::Object(params)).unwrap();
        assert_eq!(
            (f.verb, f.target.as_str()),
            ("POST", "/a2a/tasks/BACKEND-OWN-TASK-ID:subscribe"),
            "{method}"
        );
    }
}

/// `http_json_client_issues_list_tasks`: a GET of the collection, its options on the query, no
/// body.
#[test]
fn http_json_client_issues_list_tasks() {
    let f = compose(AGENT, "ListTasks", &json!({})).unwrap();
    assert_eq!((f.verb, f.target.as_str()), ("GET", "/a2a/tasks"));
    assert!(f.body.is_empty() && !f.has_body);
    let f = compose(AGENT, "tasks/list", &json!({ "pageSize": 5 })).unwrap();
    assert_eq!(f.target, "/a2a/tasks?pageSize=5");
}

/// `http_json_client_issues_get_extended_agent_card`: a GET of the extended card, no body.
#[test]
fn http_json_client_issues_get_extended_agent_card() {
    let f = compose(AGENT, "GetExtendedAgentCard", &json!({})).unwrap();
    assert_eq!(
        (f.verb, f.target.as_str()),
        ("GET", "/a2a/extendedAgentCard")
    );
    assert!(f.body.is_empty() && !f.has_body);
}

/// `the_cards_interface_url_never_moves_the_hop`: a card says HOW, never WHERE. A card naming its
/// interface at another host is read for its binding word alone, and the request is composed under
/// the operator's own URL (the door hands the kernel a path; the kernel joins it onto the agent's
/// sealed origin).
#[test]
fn the_cards_interface_url_never_moves_the_hop() {
    let card = json!({ "supportedInterfaces": [{
        "url": "https://attacker.example/elsewhere",
        "protocolBinding": "HTTP+JSON",
    }] });
    assert_eq!(binding_of(Some(&card)), BINDING_HTTP_JSON);
    let f = compose(AGENT, "SendMessage", &json!({ "message": {} })).unwrap();
    assert_eq!(f.target, "/a2a/message:send");
    assert!(
        !f.target.contains("attacker") && !f.target.contains("elsewhere"),
        "the card's address never reaches the request: {}",
        f.target
    );
}
