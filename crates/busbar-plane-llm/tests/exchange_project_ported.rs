// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook cases the retired engine crate's tests pinned, ported onto the plane's own projection
//! and rewrite: a request-stage rewrite applied in the arrival's own dialect (fail-safe where it
//! cannot be), the role vocabulary a rewrite round-trips, and the size signal agreeing with the
//! content a hook is shown. Each test cites the legacy test it ports.

use busbar_plane_llm::exchange::arrive::{arrive, Arrived};
use busbar_plane_llm::exchange::project::{apply_rewrite, project};
use serde_json::{json, Value};

fn arrived(target: &str, body: &Value) -> Arrived {
    let h: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let bytes = serde_json::to_vec(body).expect("serializes");
    arrive("POST", target, h, &bytes, &()).unwrap_or_else(|d| panic!("{target}: refused {d:?}"))
}

fn rewrite(messages: Value, tools: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"messages": messages, "tools": tools})).expect("serializes")
}

/// The rewritten arrival, as both its parsed form and its bytes read back.
fn applied(a: &mut Arrived, rw: &[u8]) -> Option<Value> {
    let bytes = apply_rewrite(a, rw)?;
    assert_eq!(bytes, a.body, "the arrival carries the rewritten bytes");
    let v: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(Some(&v), a.parsed.as_ref());
    Some(v)
}

/// A chat body's `messages` are replaced and the rewrite's tools appended to the caller's, every
/// other member untouched; a body with no `messages` array, or an empty rewrite, is left as it was.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/usage_tap_tests.rs::apply_rewrite_to_body_swaps_messages_and_is_fail_safe`.
#[test]
fn a_rewrite_swaps_the_messages_and_is_fail_safe() {
    let mut a = arrived(
        "/v1/chat/completions",
        &json!({"model": "m",
            "messages": [{"role": "user", "content": "a very long original prompt"}],
            "tools": [{"name": "existing"}]}),
    );
    let rw = rewrite(
        json!([{"role": "user", "content": "compressed"}]),
        json!([{"name": "rewriter_retrieve"}]),
    );
    let v = applied(&mut a, &rw).expect("applied");
    assert_eq!(
        v["messages"],
        json!([{"role": "user", "content": "compressed"}])
    );
    assert_eq!(v["tools"].as_array().map(Vec::len), Some(2), "{v}");
    assert_eq!(v["model"], "m");

    let mut g = arrived(
        "/v1/chat/completions",
        &json!({"model": "m", "contents": [{"parts": []}]}),
    );
    let before = (g.body.clone(), g.parsed.clone());
    assert!(apply_rewrite(&mut g, &rw).is_none(), "no messages array");
    assert_eq!((g.body, g.parsed), before, "left as it was");

    let mut e = arrived(
        "/v1/chat/completions",
        &json!({"model": "m", "messages": [{"role": "user", "content": "x"}]}),
    );
    let before = (e.body.clone(), e.parsed.clone());
    assert!(apply_rewrite(&mut e, &rewrite(json!([]), json!([]))).is_none());
    assert_eq!(
        (e.body, e.parsed),
        before,
        "an empty rewrite changes nothing"
    );
}

/// The rewrite is framed in each dialect's own container: bedrock content blocks, gemini contents
/// and parts with the assistant role spelled `model`, the responses input list; a rewrite message
/// whose content is not text aborts a re-framing dialect untouched.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/usage_tap_tests.rs::apply_rewrite_renders_per_dialect`.
#[test]
fn a_rewrite_is_framed_in_each_dialects_own_container() {
    let rw = rewrite(
        json!([{"role": "user", "content": "compressed"},
               {"role": "assistant", "content": "prior"}]),
        json!([]),
    );
    let mut b = arrived(
        "/model/m/converse",
        &json!({"messages": [{"role": "user", "content": [{"text": "orig"}]}]}),
    );
    let v = applied(&mut b, &rw).expect("bedrock");
    assert_eq!(v["messages"][0]["content"][0]["text"], "compressed", "{v}");
    assert_eq!(v["messages"][1]["content"][0]["text"], "prior", "{v}");

    let mut g = arrived(
        "/v1beta/models/m:generateContent",
        &json!({"contents": [{"role": "user", "parts": [{"text": "orig"}]}]}),
    );
    let v = applied(&mut g, &rw).expect("gemini");
    assert_eq!(v["contents"][0]["parts"][0]["text"], "compressed", "{v}");
    assert_eq!(v["contents"][1]["role"], "model", "{v}");

    let mut r = arrived("/v1/responses", &json!({"model": "m", "input": "orig"}));
    let v = applied(&mut r, &rw).expect("responses");
    assert_eq!(v["input"][0]["content"], "compressed", "{v}");

    let blocky = rewrite(
        json!([{"role": "user", "content": [{"type": "text"}]}]),
        json!([]),
    );
    let mut b2 = arrived(
        "/model/m/converse",
        &json!({"messages": [{"role": "user", "content": [{"text": "orig"}]}]}),
    );
    let before = (b2.body.clone(), b2.parsed.clone());
    assert!(apply_rewrite(&mut b2, &blocky).is_none());
    assert_eq!(
        (b2.body, b2.parsed),
        before,
        "a non-text rewrite leaves bedrock untouched"
    );
}

/// A gemini `model` turn is shown to a hook as the canonical `assistant`, and a rewrite echoing
/// either `model` or `assistant` is written back as `model`, never as `user`.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/usage_tap_tests.rs::gemini_rewrite_role_round_trips_model_and_assistant`.
#[test]
fn a_gemini_assistant_turn_round_trips_through_a_rewrite() {
    let a = arrived(
        "/v1beta/models/m:generateContent",
        &json!({"contents": [
            {"role": "user", "parts": [{"text": "hi"}]},
            {"role": "model", "parts": [{"text": "hello"}]}
        ]}),
    );
    let view = project(&a).expect("readable");
    assert_eq!(view.turns[1].0, "assistant", "{:?}", view.turns);

    let mut g = arrived(
        "/v1beta/models/m:generateContent",
        &json!({"contents": [{"role": "user", "parts": [{"text": "orig"}]}]}),
    );
    let v = applied(
        &mut g,
        &rewrite(
            json!([{"role": "user", "content": "u"}, {"role": "model", "content": "m"}]),
            json!([]),
        ),
    )
    .expect("applied");
    assert_eq!(v["contents"][1]["role"], "model", "{v}");

    let mut g2 = arrived(
        "/v1beta/models/m:generateContent",
        &json!({"contents": [{"role": "user", "parts": [{"text": "orig"}]}]}),
    );
    let v = applied(
        &mut g2,
        &rewrite(json!([{"role": "assistant", "content": "a"}]), json!([])),
    )
    .expect("applied");
    assert_eq!(v["contents"][0]["role"], "model", "{v}");
}

/// A tool result and the call's arguments are shown to a hook, and the size signal equals the
/// characters the hook is shown, for string and block-array tool content alike.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/hook_opt_in_projection_tests.rs::size_signal_and_projection_agree_on_tool_role_content`.
#[test]
fn the_size_signal_and_the_projection_agree_on_tool_content() {
    let a = arrived(
        "/v1/chat/completions",
        &json!({"model": "m", "messages": [
            {"role": "user", "content": "run it"},
            {"role": "assistant", "content": null,
             "tool_calls": [{"id": "c1", "type": "function",
                             "function": {"name": "f", "arguments": "{\"q\":\"x\"}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "TOOL RESULT PAYLOAD"}
        ]}),
    );
    let view = project(&a).expect("readable");
    assert_eq!(view.turns.len(), 3, "no turn is dropped");
    assert_eq!(
        view.turns[2],
        ("tool".to_string(), "TOOL RESULT PAYLOAD".to_string())
    );
    assert!(view.turns[1].1.contains("\"q\""), "{:?}", view.turns[1]);
    let shown: usize = view.turns.iter().map(|(_, t)| t.chars().count()).sum();
    assert_eq!(
        shown, view.text_chars,
        "the size signal is what the hook is shown"
    );

    let a = arrived(
        "/v1/chat/completions",
        &json!({"model": "m", "messages": [{"role": "tool", "tool_call_id": "c1",
            "content": [{"type": "text", "text": "TOOL RESULT PAYLOAD"}]}]}),
    );
    let view = project(&a).expect("readable");
    assert_eq!(view.turns[0].1, "TOOL RESULT PAYLOAD");
    assert_eq!(view.text_chars, 19);
}
