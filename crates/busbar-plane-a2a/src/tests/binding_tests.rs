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

#[test]
fn grpc_is_not_framed_until_the_grpc_door_so_the_next_binding_is_taken() {
    assert_eq!(speakable(BINDING_GRPC), None);
    assert_eq!(binding_of(Some(&card(&["GRPC", "HTTP+JSON"]))), "HTTP+JSON");
    assert_eq!(binding_of(Some(&card(&["GRPC", "JSONRPC"]))), "JSONRPC");
    // A card that lists only bindings the plane does not frame names its first: refused by name.
    let only = binding_of(Some(&card(&["GRPC", "SOAP"])));
    assert_eq!(only, "GRPC");
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
