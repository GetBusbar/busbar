// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FID-GEMINI CELLS: four request members a translated request now carries to a Gemini far end,
//! each through the plane's own attempt and reply, as the door serves them (the shadow-oracle
//! register's FID-GEMINI entry, items 8-11; coordinator rulings 2026-10-19, Q128 plane-llm
//! p12-LOW).
//!
//! The members are Q57-covered (docs/design/1.6.0-QUESTIONS.md:92): a target dialect that can carry
//! a field carries it. Each changes what Google does, and so may change what Google REPORTS, but
//! never how busbar meters it. "Billing never moves" (BUSBAR-1.6.0.md l.4827) is busbar's billing
//! computation. So every cell proves two things on one served exchange:
//! * the member reaches the far request in Gemini's published spelling;
//! * the far end's reported usage reaches the units the door bills unchanged, by the one rule:
//!   `promptTokenCount` is input, and `candidatesTokenCount` plus the additive `thoughtsTokenCount`
//!   is output (codec/gemini/usage.rs:12-25).
//!
//! RED: a member missing or misspelled on the far request, or the units read off the answer
//! differing from the reported usage by any rule but that one.

use serde_json::{json, Value};

use busbar_plane_llm::exchange::arrive::{arrive, Arrived};
use busbar_plane_llm::exchange::attempt::{build, stream_intent};
use busbar_plane_llm::exchange::handler_of;
use busbar_plane_llm::exchange::reply::{At, Reply, ReplyCtx, Units};
use busbar_plane_llm::exchange::shaping::Shaping;

/// The codec host these cells hand the plane: the OS CSPRNG and the system clock in whole seconds.
struct TestHost;

impl busbar_contract::codec::CodecHost for TestHost {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        getrandom::fill(out).is_ok()
    }

    fn wall_clock_now(&self) -> Option<u64> {
        Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
    }
}

const HOST: &dyn busbar_contract::codec::CodecHost = &TestHost;

/// The one Gemini far end: model `gemini-2.5-flash` (a model that accepts a reasoning-off ask).
const MEMBER: &str = "gemini-2.5-flash";

/// The far end's whole answer, reporting 11 prompt, 7 candidates and 3 thoughts tokens.
const ANSWER: &[u8] = br#"{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":7,"thoughtsTokenCount":3,"totalTokenCount":21},"modelVersion":"gemini-2.5-flash"}"#;

fn shaping() -> Shaping {
    Shaping::from_settings(&json!({
        "providers": { "goo": { "protocol": "gemini", "base_url": "https://gemini.example" } },
        "models": { MEMBER: { "provider": "goo" } },
        "pools": { "p": { "members": [MEMBER] } }
    }))
    .expect("reads")
}

/// One served exchange: the caller's request at `target` arrives, the attempt writes the far
/// request for the Gemini member, and the far end's [`ANSWER`] is fed back. Answers the far
/// request's body and the units the door bills off the answer.
fn exchange(target: &str, body: &Value) -> (Value, Units) {
    let shaping = shaping();
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let bytes = serde_json::to_vec(body).expect("JSON");
    let arrived: Arrived =
        arrive("POST", target, head, &bytes).expect("the caller's request arrives");
    let far = build(HOST, &arrived, head, &shaping, "p", MEMBER).expect("the attempt is written");
    let far_body: Value = serde_json::from_slice(&far.body).expect("the far request is JSON");
    let lane = shaping.lane(MEMBER).expect("the member's lane");
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane,
        intent: handler_of(&arrived)
            .map(|h| stream_intent(h, arrived.parsed.as_ref()))
            .unwrap_or_default(),
        passthrough: false,
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
    };
    let mut reply = Reply::new(HOST, &ctx, 200, head);
    let at = At {
        now_s: 1_752_000_000,
        elapsed_ms: Some(1),
    };
    let piece = reply.feed(HOST, &ctx, ANSWER, true, at);
    assert!(piece.done, "a whole answer ends on its last piece");
    assert_eq!(piece.head.map(|h| h.status), Some(200), "delivered");
    (far_body, piece.units)
}

/// The reported usage, by the one rule: 11 in, 7 + 3 out, nothing cached.
fn assert_metered_unchanged(units: &Units, cell: &str) {
    assert_eq!(
        (
            units.tokens_in,
            units.tokens_out,
            units.cache_read,
            units.cache_write
        ),
        (11, 10, 0, 0),
        "{cell}: the reported usage reaches the billed units by the one rule"
    );
}

/// llm.fidelity|gemini|thinking-off: an Anthropic caller's `thinking:{type:"disabled"}` reaches a
/// 2.5-flash far end as `thinkingConfig.thinkingBudget: 0` (IR-09).
#[test]
fn thinking_off_reaches_gemini_and_the_reported_usage_is_metered_unchanged() {
    let (far, units) = exchange(
        "/v1/messages",
        &json!({"model": "p", "max_tokens": 64, "thinking": {"type": "disabled"},
            "messages": [{"role": "user", "content": "hi"}]}),
    );
    assert_eq!(
        far["generationConfig"]["thinkingConfig"],
        json!({"thinkingBudget": 0}),
        "{far}"
    );
    assert_metered_unchanged(&units, "thinking-off");
}

/// llm.fidelity|gemini|tool-subset: an OpenAI caller's "may call one of these" subset reaches
/// Gemini by declaring only the listed function (IR-10).
#[test]
fn a_tool_subset_reaches_gemini_and_the_reported_usage_is_metered_unchanged() {
    let tool = |name: &str| json!({"type": "function", "function": {"name": name, "parameters": {"type": "object"}}});
    let (far, units) = exchange(
        "/v1/chat/completions",
        &json!({"model": "p",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [tool("a"), tool("b"), tool("c")],
            "tool_choice": {"type": "allowed_tools", "allowed_tools": {"mode": "auto",
                "tools": [{"type": "function", "function": {"name": "b"}}]}}}),
    );
    let names: Vec<&str> = far["tools"][0]["functionDeclarations"]
        .as_array()
        .expect("function declarations")
        .iter()
        .filter_map(|d| d["name"].as_str())
        .collect();
    assert_eq!(names, vec!["b"], "{far}");
    assert_metered_unchanged(&units, "tool-subset");
}

/// llm.fidelity|gemini|tool-result-content: a Bedrock caller's JSON tool result reaches Gemini as
/// the `functionResponse.response` object (GEM-02), where 1.5.5 dropped it.
#[test]
fn a_json_tool_result_reaches_gemini_and_the_reported_usage_is_metered_unchanged() {
    let (far, units) = exchange(
        "/model/p/converse",
        &json!({"messages": [
            {"role": "user", "content": [{"text": "q"}]},
            {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t1", "name": "f", "input": {}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": "t1", "content": [{"json": {"x": 1}}]}}]}
        ]}),
    );
    let response = far["contents"]
        .as_array()
        .expect("contents")
        .iter()
        .flat_map(|c| c["parts"].as_array().cloned().unwrap_or_default())
        .find_map(|p| p.get("functionResponse").cloned())
        .expect("functionResponse");
    assert_eq!(response["response"], json!({"x": 1}), "{far}");
    assert_metered_unchanged(&units, "tool-result-content");
}

/// llm.fidelity|gemini|response-modalities: an OpenAI caller's `modalities` reach Gemini as
/// `generationConfig.responseModalities` (IR-19). Every modality it can name is reported inside
/// `candidatesTokenCount` and metered as output.
#[test]
fn response_modalities_reach_gemini_and_the_reported_usage_is_metered_unchanged() {
    let (far, units) = exchange(
        "/v1/chat/completions",
        &json!({"model": "p", "modalities": ["text", "audio"],
            "messages": [{"role": "user", "content": "hi"}]}),
    );
    assert_eq!(
        far["generationConfig"]["responseModalities"],
        json!(["TEXT", "AUDIO"]),
        "{far}"
    );
    assert_metered_unchanged(&units, "response-modalities");
}
