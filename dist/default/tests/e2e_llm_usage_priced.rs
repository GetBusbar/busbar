// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MONEY: a priced LLM call is metered under its model's lane at the rate card's exact price,
//! through the real binary, after the operator's admin changes have rebuilt the running
//! configuration (a key minted, a group created, a reload): the shape the Console drives against a
//! live engine (its proof H3). A rebuild must keep the configured models, and the usage read must
//! price every call; a call filed under no lane is a call the engine cannot bill.

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

use std::time::Instant;

use e2e_support::{chat_answer, post_json, Deployment, Scripted, WAIT};
use serde_json::{json, Value};

/// The model the calls name, the only lane the rate card prices.
const MODEL: &str = "proof-evidence-model";
/// The rate card's per-token prices, in micro-units (`input_utok`, `output_utok`).
const INPUT_UTOK: u128 = 2000;
const OUTPUT_UTOK: u128 = 8000;
/// What the scripted upstream reports for every call.
const PROMPT_TOKENS: u64 = 7;
const COMPLETION_TOKENS: u64 = 3;
const CALLS: usize = 5;

/// The rate card the Console's live engine runs (kit `vm/live-engine.sh`): the model priced per
/// token, every open class explicit 0, no flat fee.
fn rate_card() -> String {
    format!(
        "rate_card:\n  {MODEL}: {{ input_utok: {INPUT_UTOK}, output_utok: {OUTPUT_UTOK}, units: {{ \
         search_units: 0, classifications: 0, web_fetch_requests: 0, unitemized_tokens: 0, \
         images: 0, audio_ms: 0, guardrail_automated_reasoning_policies: 0, \
         guardrail_automated_reasoning_policy_units: 0, guardrail_content_policy_image_units: 0, \
         guardrail_content_policy_units: 0, guardrail_contextual_grounding_policy_units: 0, \
         guardrail_sensitive_information_policy_free_units: 0, \
         guardrail_sensitive_information_policy_units: 0, guardrail_topic_policy_units: 0, \
         guardrail_word_policy_units: 0 }} }}\nper_request_fee: 0\n"
    )
}

/// A decimal integer written as a JSON number or as a string.
fn exact(value: &Value) -> Option<u128> {
    value
        .as_u64()
        .map(u128::from)
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

#[test]
fn priced_llm_calls_after_admin_rebuilds_are_metered_under_the_model_lane_at_the_exact_price() {
    let upstream = Scripted::start(200, &chat_answer(PROMPT_TOKENS, COMPLETION_TOKENS));
    let node = Deployment::new("usage-priced")
        .provider("mock", "openai", &upstream.url(""))
        .section(&format!("models:\n  {MODEL}:\n    provider: mock\n"))
        .section(
            "llm:\n  insecure_transport: { accept: plaintext, reason: \"loopback scripted upstream\" }\n",
        )
        .section(&rate_card())
        .boot();

    // The operator's admin changes, as the Console makes them before traffic: a key minted, a
    // group created, and a reload of the configuration from disk. Each one that rebuilds the
    // running configuration must keep the model it serves and prices.
    let key = node.mint(&json!({ "name": "usage-priced" }));
    let group = node.operator(
        "POST",
        "/api/v1/admin/groups",
        Some(&json!({ "name": "usage_priced_team", "config": {} })),
    );
    assert!(
        group.status < 300,
        "the operator creates a group: {} {}",
        group.status,
        group.text()
    );
    let reload = node.operator("POST", "/api/v1/admin/config/reload", None);
    assert!(
        reload.status < 300,
        "the operator reloads the configuration: {} {}",
        reload.status,
        reload.text()
    );

    let chat =
        json!({ "model": MODEL, "messages": [{ "role": "user", "content": "ping" }] }).to_string();
    for call in 0..CALLS {
        let reply = post_json(
            node.data,
            "/v1/chat/completions",
            &key.token,
            chat.as_bytes(),
        );
        assert_eq!(
            reply.status,
            200,
            "priced call {call} is served: {}",
            reply.text()
        );
    }
    assert_eq!(
        upstream.posts("chat/completions"),
        CALLS,
        "every priced call reached the provider once"
    );

    let per_call =
        u128::from(PROMPT_TOKENS) * INPUT_UTOK + u128::from(COMPLETION_TOKENS) * OUTPUT_UTOK;
    let want = per_call * CALLS as u128;
    assert_eq!(want, 190_000, "the fixture's own arithmetic");

    // The engine files usage on its flush interval: wait until the key's row carries every call,
    // then compare every figure exactly, once. A refused read (409 unpriced) is never retried
    // past the wait: it is the fault.
    let deadline = Instant::now() + WAIT;
    let usage = loop {
        let reply = node.operator("GET", "/api/v1/admin/usage", None);
        assert_eq!(
            reply.status,
            200,
            "the usage read prices every served call: {}",
            reply.text()
        );
        let usage = reply.json();
        let filed = usage["by_key"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == key.id.as_str()))
            .and_then(|row| exact(&row["requests"]));
        if filed == Some(CALLS as u128) {
            break usage;
        }
        assert!(
            Instant::now() < deadline,
            "the engine never filed {CALLS} requests for the key: {usage}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };

    let key_row = usage["by_key"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["id"] == key.id.as_str()))
        .expect("the key's row");
    assert_eq!(
        exact(&key_row["spend_micros"]),
        Some(want),
        "the key's spend is the rate card's exact price: {usage}"
    );
    let models = usage["by_model"].as_array().expect("by_model rows");
    assert_eq!(
        models.len(),
        1,
        "every call is filed under the one model lane: {usage}"
    );
    let model_row = &models[0];
    assert_eq!(model_row["model"], MODEL, "the lane is the model: {usage}");
    assert_eq!(
        exact(&model_row["requests"]),
        Some(CALLS as u128),
        "{usage}"
    );
    assert_eq!(
        exact(&model_row["spend_micros"]),
        Some(want),
        "the model's spend is the rate card's exact price: {usage}"
    );
    assert_eq!(
        exact(&usage["total"]["spend_micros"]),
        Some(want),
        "{usage}"
    );
}
