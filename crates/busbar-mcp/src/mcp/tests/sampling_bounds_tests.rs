// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INPUT-SIDE BOUNDS (owner ruling Q22c / Q35), in isolation from the governed pipeline: a unit
//! battery on [`super::chat_body`] alone, because the claim under test — an upstream cannot make a
//! sampling ask any larger than the operator configured — is a fact about translation, not about
//! dispatch, and does not need a fake provider or a live host to prove.
//!
//! Each of the four bounds the module header names (message count, prompt bytes, stop sequences,
//! temperature range) gets three cases: one message over the configured ceiling is REFUSED naming
//! the exact `tools.<server>.sampling.<key>` an operator would edit, exactly at the ceiling is
//! ALLOWED, and a config block that never mentions the new keys still enforces the shipped default.

use super::chat_body;
use crate::mcp::config::{
    SamplingCfg, DEFAULT_MAX_SAMPLING_MESSAGES, DEFAULT_MAX_SAMPLING_PROMPT_BYTES,
    DEFAULT_MAX_STOP_SEQUENCES, DEFAULT_MAX_STOP_SEQUENCE_BYTES, DEFAULT_TEMPERATURE_MAX_MILLI,
    DEFAULT_TEMPERATURE_MIN_MILLI,
};

const SERVER: &str = "fs";

/// The policy under test — every field explicit, so a case that means to move ONE bound never
/// accidentally rides on another's default. `temperature_min_milli`/`_max_milli` are thousandths:
/// `200..=1500` is `0.2..=1.5`.
fn cfg() -> SamplingCfg {
    SamplingCfg {
        model: "sampler-model".to_string(),
        max_tokens: 64,
        max_requests_per_minute: 100,
        max_messages: 3,
        max_prompt_bytes: 32,
        max_stop_sequences: 2,
        max_stop_sequence_bytes: 8,
        temperature_min_milli: 200,
        temperature_max_milli: 1500,
    }
}

/// `n` user messages of EMPTY text — free on the OTHER bound (prompt bytes) so a message-count case
/// never trips the prompt-bytes ceiling first, whatever both are configured to in a given test. The
/// message-count check itself runs before any per-message text is read, so the over-cap case never
/// reaches these bytes at all; the at-cap case does, and empty text keeps it at zero regardless.
fn messages(n: usize) -> serde_json::Value {
    let msgs: Vec<serde_json::Value> = (0..n)
        .map(|_| serde_json::json!({ "role": "user", "content": { "type": "text", "text": "" } }))
        .collect();
    serde_json::json!({ "messages": msgs })
}

// ---------------------------------------------------------------------------------------------
// max_messages
// ---------------------------------------------------------------------------------------------

#[test]
fn one_message_over_the_configured_cap_is_refused_naming_the_key() {
    let c = cfg();
    let params = messages(c.max_messages as usize + 1);
    let err = chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_messages"),
        "the refusal names the exact key an operator would edit: {err}"
    );
    assert!(err.contains("4 messages"), "{err}");
}

#[test]
fn exactly_the_configured_cap_of_messages_is_allowed() {
    let c = cfg();
    let params = messages(c.max_messages as usize);
    chat_body(Some(&params), &c, SERVER).expect("exactly the cap is conformant, not a refusal");
}

#[test]
fn the_shipped_default_bounds_message_count_when_the_key_is_omitted() {
    let c = SamplingCfg {
        max_messages: DEFAULT_MAX_SAMPLING_MESSAGES,
        ..cfg()
    };
    let over = messages(DEFAULT_MAX_SAMPLING_MESSAGES as usize + 1);
    let err = chat_body(Some(&over), &c, SERVER).unwrap_err();
    assert!(err.contains("tools.fs.sampling.max_messages"), "{err}");
    let at = messages(DEFAULT_MAX_SAMPLING_MESSAGES as usize);
    chat_body(Some(&at), &c, SERVER).expect("the default ceiling admits exactly the default");
}

// ---------------------------------------------------------------------------------------------
// max_prompt_bytes
// ---------------------------------------------------------------------------------------------

#[test]
fn a_system_prompt_over_the_configured_byte_cap_is_refused_naming_the_key() {
    let c = cfg();
    let params = serde_json::json!({ "systemPrompt": "x".repeat(c.max_prompt_bytes as usize + 1) });
    let err = chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_prompt_bytes"),
        "the refusal names the exact key an operator would edit: {err}"
    );
}

#[test]
fn message_text_that_pushes_the_running_total_over_the_byte_cap_is_refused() {
    let c = cfg();
    let params = serde_json::json!({
        "messages": [
            { "role": "user", "content": { "type": "text", "text": "x".repeat(c.max_prompt_bytes as usize + 1) } },
        ]
    });
    let err = chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(err.contains("tools.fs.sampling.max_prompt_bytes"), "{err}");
}

#[test]
fn exactly_the_configured_byte_cap_is_allowed() {
    let c = cfg();
    let params = serde_json::json!({
        "messages": [
            { "role": "user", "content": { "type": "text", "text": "x".repeat(c.max_prompt_bytes as usize) } },
        ]
    });
    chat_body(Some(&params), &c, SERVER).expect("exactly the cap is conformant, not a refusal");
}

#[test]
fn the_shipped_default_bounds_prompt_bytes_when_the_key_is_omitted() {
    let c = SamplingCfg {
        max_prompt_bytes: DEFAULT_MAX_SAMPLING_PROMPT_BYTES,
        ..cfg()
    };
    let over = serde_json::json!({
        "systemPrompt": "x".repeat(DEFAULT_MAX_SAMPLING_PROMPT_BYTES as usize + 1)
    });
    let err = chat_body(Some(&over), &c, SERVER).unwrap_err();
    assert!(err.contains("tools.fs.sampling.max_prompt_bytes"), "{err}");
    let at = serde_json::json!({
        "systemPrompt": "x".repeat(DEFAULT_MAX_SAMPLING_PROMPT_BYTES as usize)
    });
    chat_body(Some(&at), &c, SERVER).expect("the default ceiling admits exactly the default");
}

// ---------------------------------------------------------------------------------------------
// max_stop_sequences / max_stop_sequence_bytes
// ---------------------------------------------------------------------------------------------

fn params_with_stop(stop: Vec<&str>) -> serde_json::Value {
    serde_json::json!({
        "messages": [{ "role": "user", "content": { "type": "text", "text": "hi" } }],
        "stopSequences": stop,
    })
}

#[test]
fn one_stop_sequence_over_the_configured_count_cap_is_refused_naming_the_key() {
    let c = cfg();
    let params = params_with_stop(vec!["a", "b", "c"]);
    let err = chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_stop_sequences"),
        "the refusal names the exact key an operator would edit: {err}"
    );
}

#[test]
fn exactly_the_configured_stop_sequence_count_cap_is_allowed() {
    let c = cfg();
    let params = params_with_stop(vec!["a", "b"]);
    chat_body(Some(&params), &c, SERVER).expect("exactly the cap is conformant, not a refusal");
}

#[test]
fn the_shipped_default_bounds_stop_sequence_count_when_the_key_is_omitted() {
    let c = SamplingCfg {
        max_stop_sequences: DEFAULT_MAX_STOP_SEQUENCES,
        ..cfg()
    };
    let stop: Vec<String> = (0..DEFAULT_MAX_STOP_SEQUENCES + 1)
        .map(|i| format!("s{i}"))
        .collect();
    let over = serde_json::json!({
        "messages": [{ "role": "user", "content": { "type": "text", "text": "hi" } }],
        "stopSequences": stop,
    });
    let err = chat_body(Some(&over), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_stop_sequences"),
        "{err}"
    );
}

#[test]
fn one_stop_sequence_longer_than_the_configured_byte_cap_is_refused_naming_the_key() {
    let c = cfg();
    let long = "x".repeat(c.max_stop_sequence_bytes as usize + 1);
    let params = params_with_stop(vec![long.as_str()]);
    let err = chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_stop_sequence_bytes"),
        "the refusal names the exact key an operator would edit: {err}"
    );
}

#[test]
fn a_stop_sequence_exactly_at_the_configured_byte_cap_is_allowed() {
    let c = cfg();
    let at = "x".repeat(c.max_stop_sequence_bytes as usize);
    let params = params_with_stop(vec![at.as_str()]);
    chat_body(Some(&params), &c, SERVER).expect("exactly the cap is conformant, not a refusal");
}

#[test]
fn the_shipped_default_bounds_stop_sequence_length_when_the_key_is_omitted() {
    let c = SamplingCfg {
        max_stop_sequence_bytes: DEFAULT_MAX_STOP_SEQUENCE_BYTES,
        max_stop_sequences: DEFAULT_MAX_STOP_SEQUENCES,
        ..cfg()
    };
    let long = "x".repeat(DEFAULT_MAX_STOP_SEQUENCE_BYTES as usize + 1);
    let params = params_with_stop(vec![long.as_str()]);
    let err = chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_stop_sequence_bytes"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------------------------
// temperature_min / temperature_max
// ---------------------------------------------------------------------------------------------

fn params_with_temperature(t: f64) -> serde_json::Value {
    serde_json::json!({
        "messages": [{ "role": "user", "content": { "type": "text", "text": "hi" } }],
        "temperature": t,
    })
}

#[test]
fn a_temperature_below_the_configured_minimum_is_refused_naming_the_key() {
    let c = cfg();
    let params = params_with_temperature(c.temperature_min() - 0.1);
    let err = chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.temperature_min_milli")
            && err.contains("tools.fs.sampling.temperature_max_milli"),
        "the refusal names both keys of the range an operator would edit: {err}"
    );
}

#[test]
fn a_temperature_exactly_at_the_configured_minimum_is_allowed() {
    let c = cfg();
    let params = params_with_temperature(c.temperature_min());
    chat_body(Some(&params), &c, SERVER).expect("exactly the floor is conformant, not a refusal");
}

#[test]
fn a_temperature_above_the_configured_maximum_is_refused_naming_the_key() {
    let c = cfg();
    let params = params_with_temperature(c.temperature_max() + 0.1);
    let err = chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.temperature_min_milli")
            && err.contains("tools.fs.sampling.temperature_max_milli"),
        "the refusal names both keys of the range an operator would edit: {err}"
    );
}

#[test]
fn a_temperature_exactly_at_the_configured_maximum_is_allowed() {
    let c = cfg();
    let params = params_with_temperature(c.temperature_max());
    chat_body(Some(&params), &c, SERVER).expect("exactly the ceiling is conformant, not a refusal");
}

#[test]
fn the_shipped_default_range_is_the_protocols_own_zero_to_two() {
    let c = SamplingCfg {
        temperature_min_milli: DEFAULT_TEMPERATURE_MIN_MILLI,
        temperature_max_milli: DEFAULT_TEMPERATURE_MAX_MILLI,
        ..cfg()
    };
    let over = params_with_temperature(c.temperature_max() + 0.1);
    let err = chat_body(Some(&over), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.temperature_max_milli"),
        "{err}"
    );
    let at_floor = params_with_temperature(c.temperature_min());
    chat_body(Some(&at_floor), &c, SERVER).expect("the default floor is admitted");
    let at_ceiling = params_with_temperature(c.temperature_max());
    chat_body(Some(&at_ceiling), &c, SERVER).expect("the default ceiling is admitted");
}
