// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A gate that refuses is the caller's answer, and it answers before money: no unit is opened, no
//! limit is spent, no provider is asked and nothing is minted. On a billed route (a chat request
//! through a pool) and on a route that bills nothing (the realtime ticket mint).

#![cfg(unix)]
#![cfg(all(
    linked_section_pools,
    linked_section_tools,
    linked_section_agents,
    linked_section_decisions,
    linked_section_streams
))]

mod common;
mod e2e_support;

use e2e_support::{
    abstain, chat_answer, gate_hook, llm, post_json, realtime, reject, streams_section, Deployment,
    Scripted, CHAT, WEBREQUEST_HOOK_IMAGE,
};
use serde_json::{json, Value};

const REFUSAL: &str = "refused by the e2e gate";

/// Every string in `value` that starts with `prefix`.
fn strings_starting(value: &Value, prefix: &str, found: &mut Vec<String>) {
    match value {
        Value::String(text) if text.starts_with(prefix) => found.push(text.clone()),
        Value::Array(items) => items
            .iter()
            .for_each(|item| strings_starting(item, prefix, found)),
        Value::Object(members) => members
            .values()
            .for_each(|member| strings_starting(member, prefix, found)),
        _ => {}
    }
}

#[test]
fn a_refusing_gate_answers_a_billed_route_before_any_money_moves() {
    let upstream = Scripted::start(200, &chat_answer(3, 2));
    let gate = Scripted::start(200, &reject(451, REFUSAL));
    // The key may make one request, ever: a refused request that spent it would leave none.
    let node = llm("gate-billed", &upstream, Some(&gate))
        .section("groups:\n  once:\n    limits:\n      - { requests: 1, per: total }\n")
        .boot();
    let key = node.mint(&json!({ "name": "e2e-gate-billed", "group": "once" }));

    let refused = post_json(node.data, "/v1/chat/completions", &key.token, CHAT);

    assert_eq!(refused.status, 451, "the gate's status: {}", refused.text());
    assert!(
        refused.text().contains(REFUSAL),
        "the gate's message: {}",
        refused.text()
    );
    assert_eq!(
        upstream.posts("chat/completions"),
        0,
        "a refused request reached the provider"
    );

    // The gate now has no opinion. The key's one request is still its to make.
    gate.set(200, &abstain());
    let served = post_json(node.data, "/v1/chat/completions", &key.token, CHAT);
    assert_eq!(
        served.status,
        200,
        "the refused request spent the key's one request: {}",
        served.text()
    );
    let records = node.settled(&key, 1);
    assert_eq!(
        records.len(),
        1,
        "the refused request opened no unit; only the served one did: {records:?}"
    );
    assert_eq!(records[0]["status"], 200, "{records:?}");
    // And the limit is real: with its one request made, the key is refused by its group.
    let over = post_json(node.data, "/v1/chat/completions", &key.token, CHAT);
    assert_eq!(
        over.status,
        429,
        "the key's second request: {}",
        over.text()
    );
}

#[test]
fn a_refusing_gate_answers_an_unbilled_route_before_anything_is_minted() {
    let gate = Scripted::start(200, &reject(451, REFUSAL));
    let node = realtime(
        Deployment::new("gate-unbilled"),
        // The mint dials nobody: a provider that is not there is never missed.
        &format!("http://127.0.0.1:{}", e2e_support::closed_port()),
    )
    .plugin("hook", WEBREQUEST_HOOK_IMAGE)
    .section(&gate_hook(&gate))
    .section(&streams_section("  hooks: [gate]\n"))
    .boot();
    let key = node.mint(&json!({ "name": "e2e-gate-unbilled" }));
    let mint = br#"{"session":{"type":"realtime","model":"test-model"}}"#;

    let refused = post_json(node.data, "/v1/realtime/client_secrets", &key.token, mint);

    assert_eq!(refused.status, 451, "the gate's status: {}", refused.text());
    assert!(
        refused.text().contains(REFUSAL),
        "the gate's message: {}",
        refused.text()
    );
    assert!(
        !refused.text().contains("ek_"),
        "a refused mint handed out a ticket: {}",
        refused.text()
    );
    assert!(
        gate.posts("/decide") >= 1,
        "the gate was asked about a route that bills nothing"
    );

    // The same request once the gate has no opinion is served: the route was held by its gate.
    gate.set(200, &abstain());
    let served = post_json(node.data, "/v1/realtime/client_secrets", &key.token, mint);
    assert_eq!(served.status, 200, "the mint: {}", served.text());
    let mut tickets = Vec::new();
    strings_starting(&served.json(), "ek_", &mut tickets);
    assert_eq!(
        tickets.len(),
        1,
        "a served mint states one ticket: {}",
        served.text()
    );
    assert!(
        node.records_of(&key).is_empty(),
        "a route that bills nothing opened a unit: {:?}",
        node.records_of(&key)
    );
}
