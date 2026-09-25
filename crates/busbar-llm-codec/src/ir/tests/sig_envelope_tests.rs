// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR-18 provenance survives the CLIENT round trip (architect ruling, IR-INTEGRATE round 3 item 15).
//!
//! The probe is the whole trip: an Anthropic backend answers a Responses client with signed
//! thinking; the client sends the reasoning item back on its next turn; the Anthropic egress must
//! carry the ORIGINAL signature byte-identical — buffered and stream.

use super::sig_envelope::{self, ENVELOPE_PREFIX};
use super::IrSignatureOrigin;
use crate::proto_codec::protocol_for;

/// A realistic Anthropic signature: base64 with `+`, `/` and `=` in it.
const CLAUDE_SIG: &str = "EqQBCkYIBxgCKkBv+9Zk/3mQ==";

fn prep(ingress: &'static str) -> busbar_substrate_values::ir::egress_prep::EgressPrep<'static> {
    busbar_substrate_values::ir::egress_prep::EgressPrep {
        thought_signature_fill: false,
        ingress_protocol: ingress,
        egress_requires_max_tokens: true,
        lane_default_max_tokens: None,
        global_default_max_tokens: 4096,
        reasoning_allowed: true,
        reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
        prompt_caching_allowed: true,
        cache_control_cap: None,
        lane_caps: Default::default(),
    }
}

/// Client request (in `ingress` dialect) → cross-protocol seam → `egress` writer.
fn egress_request(
    ingress: &'static str,
    egress: &str,
    body: &serde_json::Value,
) -> serde_json::Value {
    let mut req = protocol_for(ingress)
        .expect("ingress")
        .reader()
        .read_request(body)
        .expect("read_request");
    crate::chat_handle::chat_prepare_for_egress(&mut req, &prep(ingress));
    protocol_for(egress)
        .expect("egress")
        .writer()
        .write_request(&req)
}

fn anthropic_signed_answer() -> serde_json::Value {
    serde_json::json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-4-7",
        "content": [
            {"type": "thinking", "thinking": "let me think", "signature": CLAUDE_SIG},
            {"type": "text", "text": "the answer"}
        ],
        "stop_reason": "end_turn", "stop_sequence": null,
        "usage": {"input_tokens": 3, "output_tokens": 5}
    })
}

/// The Responses client's next turn: it replays the reasoning item it was given, verbatim.
fn responses_follow_up(reasoning_item: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "model": "claude-opus-4-7",
        "max_output_tokens": 2048,
        "input": [
            {"role": "user", "content": "q1"},
            reasoning_item,
            {"type": "message", "role": "assistant",
             "content": [{"type": "output_text", "text": "the answer"}]},
            {"role": "user", "content": "q2"}
        ]
    })
}

fn anthropic_thinking_signatures(out: &serde_json::Value) -> Vec<String> {
    out["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["content"].as_array())
        .flatten()
        .filter(|b| b["type"] == "thinking")
        .filter_map(|b| b["signature"].as_str().map(String::from))
        .collect()
}

fn sse_payloads(out: &str) -> Vec<serde_json::Value> {
    out.split("\n\n")
        .flat_map(|frame| frame.lines())
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str(d).ok())
        .collect()
}

#[test]
fn ir18_envelope_round_trips_bytes_and_origin() {
    for origin in [
        IrSignatureOrigin::Anthropic,
        IrSignatureOrigin::Gemini,
        IrSignatureOrigin::OpenAi,
        IrSignatureOrigin::BedrockOther,
    ] {
        for sig in ["", "a", "ab", "abc", "abcd", CLAUDE_SIG, "ünï\u{1F600}:x:y"] {
            let wrapped = sig_envelope::wrap(origin, sig);
            assert!(wrapped.starts_with(ENVELOPE_PREFIX), "{wrapped}");
            assert_eq!(
                sig_envelope::unwrap(&wrapped),
                Some((origin, sig.to_string()))
            );
            // Idempotent: wrapping an envelope again never nests it.
            assert_eq!(sig_envelope::wrap(origin, &wrapped), wrapped);
        }
    }
    // A genuine vendor blob (no prefix, or a malformed envelope) is the carrier's own.
    assert_eq!(
        sig_envelope::read_carried(CLAUDE_SIG.into(), Some(IrSignatureOrigin::OpenAi)),
        (CLAUDE_SIG.to_string(), Some(IrSignatureOrigin::OpenAi))
    );
    assert_eq!(sig_envelope::unwrap("bbsig1:nobody:YQ"), None);
    assert_eq!(sig_envelope::unwrap("bbsig1:openai:*"), None);
}

/// Buffered: Anthropic answer → Responses client → client replays it → Anthropic egress.
#[test]
fn ir18_claude_signature_survives_a_responses_client_round_trip_buffered() {
    let mut ir = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response(&anthropic_signed_answer())
        .expect("read_response");
    crate::chat_handle::chat_prepare_for_ingress(&mut ir, "responses", 0);
    let to_client = protocol_for("responses")
        .unwrap()
        .writer()
        .write_response(&ir);
    let item = to_client["output"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["type"] == "reasoning")
        .cloned()
        .expect("reasoning item");
    let carried = item["encrypted_content"]
        .as_str()
        .expect("encrypted_content");
    assert!(
        carried.starts_with(ENVELOPE_PREFIX),
        "a Claude signature in a Responses carrier is enveloped: {carried}"
    );

    let out = egress_request("responses", "anthropic", &responses_follow_up(&item));
    assert_eq!(
        anthropic_thinking_signatures(&out),
        vec![CLAUDE_SIG.to_string()],
        "Anthropic egress carries the original signature byte-identical: {out}"
    );
}

/// Stream: the same trip, with the Anthropic answer streamed through the translator.
#[test]
fn ir18_claude_signature_survives_a_responses_client_round_trip_stream() {
    let mut t = crate::proto_stream::StreamTranslate::new("responses", "anthropic")
        .expect("responses ingress translator");
    let sig_delta = serde_json::json!({"type": "content_block_delta", "index": 0,
        "delta": {"type": "signature_delta", "signature": CLAUDE_SIG}});
    let frames = [
        r#"{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-7","content":[],"usage":{"input_tokens":3,"output_tokens":0}}}"#.to_string(),
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}"#.to_string(),
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"let me think"}}"#.to_string(),
        sig_delta.to_string(),
        r#"{"type":"content_block_stop","index":0}"#.to_string(),
        r#"{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}"#.to_string(),
        r#"{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"the answer"}}"#.to_string(),
        r#"{"type":"content_block_stop","index":1}"#.to_string(),
        r#"{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":5}}"#.to_string(),
        r#"{"type":"message_stop"}"#.to_string(),
    ];
    let mut out = String::new();
    for data in frames {
        let v: serde_json::Value = serde_json::from_str(&data).unwrap();
        let frame = format!("event: {}\ndata: {data}\n\n", v["type"].as_str().unwrap());
        out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
    }
    out.push_str(&String::from_utf8(t.finish()).unwrap());

    let item = sse_payloads(&out)
        .into_iter()
        .filter(|p| p["type"] == "response.output_item.done")
        .map(|p| p["item"].clone())
        .find(|i| i["type"] == "reasoning")
        .unwrap_or_else(|| panic!("reasoning output_item.done; got {out}"));
    let carried = item["encrypted_content"]
        .as_str()
        .expect("encrypted_content");
    assert!(
        carried.starts_with(ENVELOPE_PREFIX),
        "a Claude signature in a Responses stream carrier is enveloped: {carried}"
    );

    let out = egress_request("responses", "anthropic", &responses_follow_up(&item));
    assert_eq!(
        anthropic_thinking_signatures(&out),
        vec![CLAUDE_SIG.to_string()],
        "Anthropic egress carries the original signature byte-identical: {out}"
    );
}

/// The reverse trip: an OpenAI `encrypted_content` given to an Anthropic client comes back to a
/// Responses backend as the original blob (it used to be read back as an Anthropic signature and
/// dropped as foreign on Responses egress).
#[test]
fn ir18_openai_blob_survives_an_anthropic_client_round_trip() {
    let responses_answer = serde_json::json!({
        "id": "resp_1", "object": "response", "created_at": 1, "status": "completed",
        "model": "o4-mini",
        "output": [
            {"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "hm"}],
             "encrypted_content": "gAAAAB-openai-blob=="},
            {"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
             "content": [{"type": "output_text", "text": "ok", "annotations": []}]}
        ],
        "usage": {"input_tokens": 3, "output_tokens": 5, "total_tokens": 8}
    });
    let mut ir = protocol_for("responses")
        .unwrap()
        .reader()
        .read_response(&responses_answer)
        .expect("read_response");
    crate::chat_handle::chat_prepare_for_ingress(&mut ir, "anthropic", 0);
    let to_client = protocol_for("anthropic")
        .unwrap()
        .writer()
        .write_response(&ir);
    let thinking = to_client["content"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["type"] == "thinking")
        .cloned()
        .expect("thinking block");
    assert!(
        thinking["signature"]
            .as_str()
            .unwrap()
            .starts_with(ENVELOPE_PREFIX),
        "{thinking}"
    );
    let follow_up = serde_json::json!({
        "model": "o4-mini", "max_tokens": 256,
        "messages": [
            {"role": "user", "content": "q1"},
            {"role": "assistant", "content": [thinking, {"type": "text", "text": "ok"}]},
            {"role": "user", "content": "q2"}
        ]
    });
    let out = egress_request("anthropic", "responses", &follow_up);
    let blobs: Vec<&str> = out["input"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["type"] == "reasoning")
        .filter_map(|i| i["encrypted_content"].as_str())
        .collect();
    assert_eq!(blobs, vec!["gAAAAB-openai-blob=="], "{out}");
}

// ───────────────────────── item 19: the same trip through a Gemini client ─────────────────────────

/// The Gemini client's next turn: it replays the thought part it was given (text + signature).
fn gemini_follow_up(thought_signature: &str) -> serde_json::Value {
    serde_json::json!({
        "contents": [
            {"role": "user", "parts": [{"text": "q1"}]},
            {"role": "model", "parts": [
                {"text": "let me think", "thought": true, "thoughtSignature": thought_signature},
                {"text": "the answer"}
            ]},
            {"role": "user", "parts": [{"text": "q2"}]}
        ],
        "generationConfig": {"maxOutputTokens": 2048}
    })
}

fn gemini_thought_signatures(parts_holder: &[serde_json::Value]) -> Vec<String> {
    parts_holder
        .iter()
        .filter_map(|c| c.pointer("/candidates/0/content/parts"))
        .filter_map(|p| p.as_array())
        .flatten()
        .filter_map(|p| p["thoughtSignature"].as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Buffered: Anthropic answer → Gemini client → client replays it → Anthropic egress.
#[test]
fn ir19_claude_signature_survives_a_gemini_client_round_trip_buffered() {
    let mut ir = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response(&anthropic_signed_answer())
        .expect("read_response");
    crate::chat_handle::chat_prepare_for_ingress(&mut ir, "gemini", 0);
    let to_client = protocol_for("gemini").unwrap().writer().write_response(&ir);
    let sigs = gemini_thought_signatures(std::slice::from_ref(&to_client));
    assert_eq!(sigs.len(), 1, "{to_client}");
    assert!(sigs[0].starts_with(ENVELOPE_PREFIX), "{to_client}");

    let out = egress_request("gemini", "anthropic", &gemini_follow_up(&sigs[0]));
    assert_eq!(
        anthropic_thinking_signatures(&out),
        vec![CLAUDE_SIG.to_string()],
        "Anthropic egress carries the original signature byte-identical: {out}"
    );
}

/// Stream: the same trip, the Anthropic answer streamed to the Gemini client.
#[test]
fn ir19_claude_signature_survives_a_gemini_client_round_trip_stream() {
    let mut t = crate::proto_stream::StreamTranslate::new("gemini", "anthropic")
        .expect("gemini ingress translator");
    let frames = [
        r#"{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-7","content":[],"usage":{"input_tokens":3,"output_tokens":0}}}"#.to_string(),
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}"#.to_string(),
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"let me think"}}"#.to_string(),
        serde_json::json!({"type": "content_block_delta", "index": 0,
            "delta": {"type": "signature_delta", "signature": CLAUDE_SIG}}).to_string(),
        r#"{"type":"content_block_stop","index":0}"#.to_string(),
        r#"{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":5}}"#.to_string(),
        r#"{"type":"message_stop"}"#.to_string(),
    ];
    let mut out = String::new();
    for data in frames {
        let v: serde_json::Value = serde_json::from_str(&data).unwrap();
        let frame = format!("event: {}\ndata: {data}\n\n", v["type"].as_str().unwrap());
        out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
    }
    out.push_str(&String::from_utf8(t.finish()).unwrap());
    let sigs = gemini_thought_signatures(&sse_payloads(&out));
    assert_eq!(sigs.len(), 1, "{out}");
    assert!(sigs[0].starts_with(ENVELOPE_PREFIX), "{out}");

    let out = egress_request("gemini", "anthropic", &gemini_follow_up(&sigs[0]));
    assert_eq!(
        anthropic_thinking_signatures(&out),
        vec![CLAUDE_SIG.to_string()],
        "Anthropic egress carries the original signature byte-identical: {out}"
    );
}
