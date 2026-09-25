// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping round 3 (IR-INTEGRATE, Q57): the Anthropic writer's share of items 10 and 12.
use super::super::proto_codec::protocol_for;
use serde_json::{json, Value};

fn sse_payloads(out: &str) -> Vec<Value> {
    out.split("\n\n")
        .flat_map(|frame| frame.lines())
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str(d).ok())
        .collect()
}

// ───────────────────────────── item 10: served service tier ─────────────────────────────

/// Item 10: a Chat backend's `service_tier` `flex` / `scale` rides the IR attribution slot; an
/// Anthropic client never receives it (its SDK types the member standard | priority | batch).
/// `default` is OpenAI's standard tier. Buffered.
#[test]
fn item10_unknown_served_tier_never_reaches_an_anthropic_client_buffered() {
    for (openai_tier, want) in [
        ("flex", "standard"),
        ("scale", "standard"),
        ("default", "standard"),
        ("priority", "priority"),
    ] {
        let chat = json!({
            "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-4o",
            "service_tier": openai_tier,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "hi"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}
        });
        let mut ir = protocol_for("openai")
            .unwrap()
            .reader()
            .read_response(&chat)
            .expect("read");
        crate::chat_handle::chat_prepare_for_ingress(&mut ir, "anthropic", 0);
        let out = protocol_for("anthropic")
            .unwrap()
            .writer()
            .write_response(&ir);
        assert_eq!(out["usage"]["service_tier"], want, "{openai_tier}: {out}");
    }
}

/// Item 10, stream: the `message_delta` usage omits an unknown tier word.
#[test]
fn item10_unknown_served_tier_never_reaches_an_anthropic_client_stream() {
    for openai_tier in ["flex", "scale"] {
        let mut t =
            crate::proto_stream::StreamTranslate::new("anthropic", "openai").expect("translator");
        let chunks = [
            json!({"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-4o",
                   "service_tier": openai_tier,
                   "choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":null}]}),
            json!({"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-4o",
                   "service_tier": openai_tier,
                   "choices":[{"index":0,"delta":{},"finish_reason":"stop"}],
                   "usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}),
        ];
        let mut out = String::new();
        for c in chunks {
            out.push_str(&String::from_utf8(t.feed(format!("data: {c}\n\n").as_bytes())).unwrap());
        }
        out.push_str(&String::from_utf8(t.feed(b"data: [DONE]\n\n")).unwrap());
        out.push_str(&String::from_utf8(t.finish()).unwrap());
        for p in sse_payloads(&out) {
            for tier in [
                p.pointer("/usage/service_tier"),
                p.pointer("/message/usage/service_tier"),
            ]
            .into_iter()
            .flatten()
            {
                assert!(
                    ["standard", "priority", "batch"].contains(&tier.as_str().unwrap_or("")),
                    "{openai_tier}: an Anthropic client got tier {tier}: {out}"
                );
            }
        }
    }
}

// ─────────────────────── item 12: thinking that cannot be switched off ───────────────────────

fn off_ask() -> crate::ir::IrRequest {
    let mut ir = protocol_for("openai")
        .unwrap()
        .reader()
        .read_request(
            &json!({"model": "m", "max_tokens": 4096, "reasoning_effort": "none",
            "messages": [{"role": "user", "content": "hi"}]}),
        )
        .expect("read");
    assert_eq!(ir.reasoning, Some(crate::ir::IrReasoningAsk::Off));
    ir.extra.clear();
    ir
}

/// Item 12: on a lane declaring `thinking_always_on` (Fable 5.x, Opus 5.5) an Off ask OMITS
/// `thinking` — `{type:"disabled"}` 400s there. The default lane keeps today's bytes.
#[test]
fn item12_off_omits_thinking_on_an_always_on_lane() {
    let w = protocol_for("anthropic").unwrap();
    let always_on = super::super::proto_codec::LaneCaps {
        anthropic_adaptive_thinking: true,
        native_structured_output: true,
        thinking_always_on: true,
        ..Default::default()
    };
    let out = w
        .writer()
        .write_request_for_lane(&off_ask(), "claude-fable-5", &always_on);
    assert!(out.get("thinking").is_none(), "{out}");
    let out = w
        .writer()
        .write_request_for_lane(&off_ask(), "claude-opus-4-5", &Default::default());
    assert_eq!(out["thinking"], json!({"type": "disabled"}), "{out}");
}
