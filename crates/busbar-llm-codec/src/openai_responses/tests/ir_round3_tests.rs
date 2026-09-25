// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping: the Responses custom-tool, reasoning-`none` and summary-reasoning cases.
use crate::proto_codec::{protocol_for, LaneCaps};
use serde_json::json;

fn anthropic_off() -> crate::ir::IrRequest {
    let mut ir = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_request(
            &json!({"model": "m", "max_tokens": 64, "thinking": {"type": "disabled"},
            "messages": [{"role": "user", "content": "hi"}]}),
        )
        .expect("read");
    assert_eq!(ir.reasoning, Some(crate::ir::IrReasoningAsk::Off));
    ir.extra.clear();
    ir
}

/// Item 12: a lane declaring `reasoning_none` gets `reasoning.effort: "none"` for an Off ask; the
/// default lane keeps today's bytes (omitted).
#[test]
fn item12_off_is_reasoning_effort_none_on_a_declaring_lane() {
    let w = protocol_for("responses").unwrap();
    let none_lane = LaneCaps {
        reasoning_none: true,
        ..Default::default()
    };
    let out = w
        .writer()
        .write_request_for_lane(&anthropic_off(), "gpt-5.1", &none_lane);
    assert_eq!(out["reasoning"], json!({"effort": "none"}), "{out}");
    let out = w
        .writer()
        .write_request_for_lane(&anthropic_off(), "gpt-4o", &Default::default());
    assert!(out.get("reasoning").is_none(), "{out}");
}

// ─────────────────────── item 16: a summary streams back into summary[] ───────────────────────

fn sse_payloads(out: &str) -> Vec<serde_json::Value> {
    out.split("\n\n")
        .flat_map(|frame| frame.lines())
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str(d).ok())
        .collect()
}

/// Item 16 (IR-17 stream): a Gemini thought (a SUMMARY) streamed to a Responses client streams as
/// `reasoning_summary_text` and the finalized reasoning item carries it in `summary[]` — the
/// buffered item's shape — not as full `reasoning_text` content.
#[test]
fn item16_gemini_thought_streams_into_the_responses_summary() {
    let mut t = crate::proto_stream::StreamTranslate::new("responses", "gemini")
        .expect("responses ingress translator");
    let chunks = [
        json!({"candidates": [{"content": {"role": "model",
            "parts": [{"text": "weighing it", "thought": true}]}}]}),
        json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "42"}]},
            "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1, "totalTokenCount": 4}}),
    ];
    let mut out = String::new();
    for c in chunks {
        out.push_str(&String::from_utf8(t.feed(format!("data: {c}\r\n\r\n").as_bytes())).unwrap());
    }
    out.push_str(&String::from_utf8(t.finish()).unwrap());
    let payloads = sse_payloads(&out);
    assert!(
        payloads
            .iter()
            .any(|p| p["type"] == "response.reasoning_summary_text.delta"
                && p["delta"] == "weighing it"),
        "{out}"
    );
    assert!(
        !payloads
            .iter()
            .any(|p| p["type"] == "response.reasoning_text.delta"),
        "{out}"
    );
    let item = payloads
        .iter()
        .find(|p| p["type"] == "response.output_item.done" && p["item"]["type"] == "reasoning")
        .map(|p| p["item"].clone())
        .unwrap_or_else(|| panic!("reasoning output_item.done: {out}"));
    assert_eq!(
        item["summary"],
        json!([{"type": "summary_text", "text": "weighing it"}]),
        "{item}"
    );
    assert!(item.get("content").is_none(), "{item}");
}

/// Item 16, buffered answer synthesized as a stream: the same summary placement.
#[test]
fn item16_synthesized_stream_keeps_a_summary_in_summary() {
    let gemini = json!({"candidates": [{"content": {"role": "model", "parts": [
            {"text": "weighing it", "thought": true}, {"text": "42"}]},
        "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1, "totalTokenCount": 4}});
    let mut ir = protocol_for("gemini")
        .unwrap()
        .reader()
        .read_response(&gemini)
        .expect("read");
    crate::chat_handle::chat_prepare_for_ingress(&mut ir, "responses", 0);
    let out = String::from_utf8(
        crate::proto_stream::StreamTranslate::synthesize_from_response("responses", &ir)
            .expect("synthesized"),
    )
    .unwrap();
    let item = sse_payloads(&out)
        .into_iter()
        .find(|p| p["type"] == "response.output_item.done" && p["item"]["type"] == "reasoning")
        .map(|p| p["item"].clone())
        .unwrap_or_else(|| panic!("reasoning output_item.done: {out}"));
    assert_eq!(
        item["summary"],
        json!([{"type": "summary_text", "text": "weighing it"}]),
        "{item}"
    );
}
