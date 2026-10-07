// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The inbound Responses webhook receiver: the routes the plane's own section states, and the
//! event a verified delivery is read as (ported from the retired engine's receiver tests; its
//! signature checks are the `webhook-signature` auth plugin's, its replay refusal the kernel's).

use busbar_contract::abi::plane::ROUTE_PUBLIC;
use busbar_plane_llm::exchange::webhook::{
    parse_event, receive, routes, MalformedEvent, OPENAI_PATH, SECTION,
};
use serde_json::json;

fn owned(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("json")
}

/// CONFIG-REACHED: no owned sections, or none naming the receiver, state no route; the configured
/// receiver is one public POST route naming the scheme its callers are verified under.
#[test]
fn the_receiver_is_stated_only_by_its_own_section() {
    assert!(routes(b"").expect("none").is_empty());
    assert!(routes(&owned(&json!({}))).expect("none").is_empty());
    let stated = routes(&owned(
        &json!({SECTION: {"openai": {"style": "webhook-signature"}}}),
    ))
    .expect("reads");
    assert_eq!(stated.len(), 1);
    assert_eq!(stated[0].verb, "POST");
    assert_eq!(stated[0].target, OPENAI_PATH);
    assert_eq!(stated[0].flags, ROUTE_PUBLIC);
    assert_eq!(stated[0].style, "webhook-signature");
}

/// A section that does not read refuses the open: an unknown sender, a sender with no scheme, an
/// unknown setting, and a non-map.
#[test]
fn a_receiver_section_that_does_not_read_is_refused() {
    for bad in [
        json!({SECTION: {"stripe": {"style": "webhook-signature"}}}),
        json!({SECTION: {"openai": {}}}),
        json!({SECTION: {"openai": {"style": ""}}}),
        json!({SECTION: {"openai": {"style": "webhook-signature", "secret": "x"}}}),
        json!({SECTION: ["openai"]}),
    ] {
        assert!(routes(&owned(&bad)).is_err(), "{bad}");
    }
}

fn completed_body() -> Vec<u8> {
    owned(&json!({
        "id": "evt_abc123",
        "type": "response.completed",
        "created_at": 1_700_000_900u64,
        "data": { "id": "resp_stored_xyz" }
    }))
}

/// Legacy `body_parses_the_load_bearing_fields`.
#[test]
fn body_parses_the_load_bearing_fields() {
    let event = parse_event(&completed_body()).expect("well-formed body must parse");
    assert_eq!(event.response_id, "resp_stored_xyz");
    assert_eq!(event.event_type, "response.completed");
    assert_eq!(event.event_id.as_deref(), Some("evt_abc123"));
    assert_eq!(event.created_at, Some(1_700_000_900));
}

/// Legacy `body_tolerates_absent_and_unknown_fields`.
#[test]
fn body_tolerates_absent_and_unknown_fields() {
    let body = owned(&json!({
        "type": "response.failed",
        "data": { "id": "resp_1", "status": "failed" },
        "some_future_field": { "nested": true }
    }));
    let event = parse_event(&body).expect("absent optionals + unknown keys must be lenient");
    assert_eq!(event.response_id, "resp_1");
    assert_eq!(event.event_id, None);
    assert_eq!(event.created_at, None);
}

/// Legacy `body_rejects_present_but_wrong_typed_modeled_fields`.
#[test]
fn body_rejects_present_but_wrong_typed_modeled_fields() {
    for (label, body) in [
        (
            "type wrong-typed",
            json!({ "type": 5, "data": { "id": "resp_1" } }),
        ),
        (
            "type empty",
            json!({ "type": "", "data": { "id": "resp_1" } }),
        ),
        (
            "data.id wrong-typed",
            json!({ "type": "response.completed", "data": { "id": 7 } }),
        ),
        (
            "data non-object",
            json!({ "type": "response.completed", "data": "resp_1" }),
        ),
        (
            "created_at wrong-typed",
            json!({ "type": "response.completed", "created_at": "yesterday", "data": { "id": "resp_1" } }),
        ),
        ("data absent", json!({ "type": "response.completed" })),
        ("body not object", json!(["response.completed"])),
    ] {
        assert_eq!(parse_event(&owned(&body)), Err(MalformedEvent), "{label}");
    }
}

/// Legacy `reject_http_statuses_are_honest`, for what the plane still judges: a verified event is
/// acknowledged 200 with its correlation id; a body that is not an event is 400. (A missing or wrong
/// signature is the auth plugin's, answered 401 before the plane is called.)
#[test]
fn the_receivers_answers_are_honest() {
    let (status, body) = receive(&completed_body());
    assert_eq!(status, 200);
    let ack: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        ack,
        json!({"received": true, "response_id": "resp_stored_xyz", "type": "response.completed"})
    );
    assert_eq!(receive(b"not json"), (400, Vec::new()));
}
