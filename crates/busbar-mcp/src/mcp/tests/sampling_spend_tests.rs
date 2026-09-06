// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-UPSTREAM SAMPLING BUDGET, in isolation: a counter that refuses at the cap, resets on
//! the minute, and never lets one server's spend bite another's.

use super::SamplingSpend;

#[test]
fn the_cap_admits_exactly_cap_completions_in_one_window_and_refuses_the_next() {
    let spend = SamplingSpend::new();
    let now = 1_000_000;
    for _ in 0..3 {
        spend
            .try_spend("fs", 3, now)
            .expect("under the cap, the spend is admitted");
    }
    let err = spend
        .try_spend("fs", 3, now)
        .expect_err("the cap is a refusal, not a warning");
    assert!(
        err.contains("tools.fs.sampling.max_requests_per_minute"),
        "the refusal names the exact key an operator would raise: {err}"
    );
}

#[test]
fn the_window_resets_on_the_next_minute() {
    let spend = SamplingSpend::new();
    let now = 1_000_000;
    spend
        .try_spend("fs", 1, now)
        .expect("the first is admitted");
    spend
        .try_spend("fs", 1, now)
        .expect_err("the second in the same minute is refused");
    spend
        .try_spend("fs", 1, now + 60)
        .expect("the budget is per minute, and the next minute is a fresh window");
}

#[test]
fn one_servers_spend_does_not_bite_anothers() {
    let spend = SamplingSpend::new();
    let now = 1_000_000;
    spend.try_spend("fs", 1, now).expect("fs spends its budget");
    spend.try_spend("fs", 1, now).expect_err("fs is exhausted");
    spend
        .try_spend("search", 1, now)
        .expect("the budget is PER UPSTREAM: search still has its own");
}

// ── THE INPUT SIDE, which the output ceiling never bounded ─────────────────────────────────────
//
// `max_tokens` was clamped from the first line this satisfier had, and the PROMPT was bounded by
// nothing: the `messages` array arrives on an UPSTREAM'S ask and is charged to the INBOUND
// CALLER'S budget. A caller's budget bounds what the caller asked for and cannot bound what
// somebody else appended to it, so the bound has to be here.

use super::{
    chat_body, MAX_SAMPLING_MESSAGES, MAX_SAMPLING_PROMPT_BYTES, MAX_STOP_SEQUENCES,
    MAX_STOP_SEQUENCE_BYTES,
};

/// A policy with generous ceilings, so nothing below is refused by the OUTPUT bound by accident.
fn cfg() -> crate::mcp::config::SamplingCfg {
    crate::mcp::config::SamplingCfg {
        model: "declared-pool".to_string(),
        max_tokens: 1_024,
        max_requests_per_minute: 10,
    }
}

fn ask(params: serde_json::Value) -> Result<serde_json::Value, String> {
    chat_body(Some(&params), &cfg())
}

fn text_message(text: &str) -> serde_json::Value {
    serde_json::json!({ "role": "user", "content": { "type": "text", "text": text } })
}

#[test]
fn an_ask_carrying_more_messages_than_the_cap_is_refused_before_any_body_is_built() {
    let many: Vec<serde_json::Value> = (0..MAX_SAMPLING_MESSAGES + 1)
        .map(|_| text_message("hi"))
        .collect();
    let err = ask(serde_json::json!({ "messages": many }))
        .expect_err("an unbounded message count is the caller paying for the upstream's prompt");
    assert!(
        err.contains(&MAX_SAMPLING_MESSAGES.to_string()),
        "the refusal names the bound: {err}"
    );
    // ...and the cap is a cap, not a refusal of every ask.
    let just_enough: Vec<serde_json::Value> = (0..MAX_SAMPLING_MESSAGES)
        .map(|_| text_message("hi"))
        .collect();
    ask(serde_json::json!({ "messages": just_enough }))
        .expect("an ask at the cap is admitted; the bound is on the excess");
}

/// The bound is on the TOTAL, which is what the bill is. One enormous message and a thousand small
/// ones cost the same, so a per-message limit would bound the wrong number.
#[test]
fn an_ask_whose_prompt_exceeds_the_byte_bound_is_refused_however_it_is_split() {
    let one_huge = "x".repeat(MAX_SAMPLING_PROMPT_BYTES + 1);
    let err = ask(serde_json::json!({ "messages": [text_message(&one_huge)] }))
        .expect_err("one oversized message is an oversized prompt");
    assert!(err.contains("prompt exceeds"), "{err}");

    // The same bytes split across messages that are each individually unremarkable.
    let chunk = "y".repeat(MAX_SAMPLING_PROMPT_BYTES / 4);
    let split: Vec<serde_json::Value> = (0..5).map(|_| text_message(&chunk)).collect();
    let err = ask(serde_json::json!({ "messages": split }))
        .expect_err("a prompt split into pieces is the same prompt and the same bill");
    assert!(err.contains("prompt exceeds"), "{err}");

    // The SYSTEM PROMPT counts too — it is prompt tokens like any other, and a bound that skipped
    // it would be a bound with a hole the upstream chooses the size of.
    let err = ask(serde_json::json!({
        "systemPrompt": one_huge,
        "messages": [text_message("hi")],
    }))
    .expect_err("the system prompt is prompt");
    assert!(err.contains("prompt exceeds"), "{err}");
}

/// `temperature` was TYPE-checked and not RANGE-checked, so `-1` and `1e308` went verbatim into a
/// body the caller paid the round trip for.
#[test]
fn a_temperature_outside_the_protocols_range_is_refused_rather_than_forwarded() {
    for bad in [
        serde_json::json!(-0.5),
        serde_json::json!(2.5),
        serde_json::json!(1e308),
        serde_json::json!("hot"),
    ] {
        let outcome = ask(serde_json::json!({
            "messages": [text_message("hi")],
            "temperature": bad.clone(),
        }));
        assert!(
            outcome.is_err(),
            "a temperature outside `0.0..=2.0` must be refused, not forwarded: {bad}"
        );
    }
    // ...and a temperature INSIDE the range still rides through, so the check is a range and not a
    // deletion of the field.
    let body = ask(serde_json::json!({
        "messages": [text_message("hi")],
        "temperature": 0.7,
    }))
    .expect("an ordinary temperature is forwarded");
    assert_eq!(body["temperature"], serde_json::json!(0.7));
}

/// `stopSequences` was copied through as whatever array arrived: any length, any element type, any
/// element size.
#[test]
fn stop_sequences_are_counted_measured_and_typed() {
    let too_many: Vec<serde_json::Value> = (0..MAX_STOP_SEQUENCES + 1)
        .map(|n| serde_json::json!(format!("s{n}")))
        .collect();
    let err = ask(serde_json::json!({
        "messages": [text_message("hi")],
        "stopSequences": too_many,
    }))
    .expect_err("an unbounded stop list is the upstream's free hand on the caller's request");
    assert!(err.contains(&MAX_STOP_SEQUENCES.to_string()), "{err}");

    let too_long = "z".repeat(MAX_STOP_SEQUENCE_BYTES + 1);
    ask(serde_json::json!({
        "messages": [text_message("hi")],
        "stopSequences": [too_long],
    }))
    .expect_err("an oversized stop sequence is refused");

    ask(serde_json::json!({
        "messages": [text_message("hi")],
        "stopSequences": [{ "not": "a string" }],
    }))
    .expect_err("a non-string stop sequence is a body a provider refuses; refuse it here");

    let body = ask(serde_json::json!({
        "messages": [text_message("hi")],
        "stopSequences": ["STOP"],
    }))
    .expect("an ordinary stop list is still forwarded");
    assert_eq!(body["stop"], serde_json::json!(["STOP"]));
}
