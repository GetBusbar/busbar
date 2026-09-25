// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping: the Gemini streamed generated media and block-relative streamed citations.
use crate::ir::{IrDelta, IrStreamEvent, StreamDecodeState};
use crate::proto_codec::protocol_for;
use serde_json::json;

/// Item 18 (GEM-16): a streamed citation on a LATER text block (text -> functionCall -> text) is
/// relative to that block's text, not to the whole streamed answer.
#[test]
fn item18_citation_on_a_later_text_block_is_block_relative() {
    let reader = protocol_for("gemini").unwrap();
    let mut state = StreamDecodeState::default();
    let chunks = [
        json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "Hello "}]}}]}),
        json!({"candidates": [{"content": {"role": "model",
            "parts": [{"functionCall": {"name": "f", "args": {}}}]}}]}),
        json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "Paris is big"}]}}]}),
        json!({"candidates": [{"content": {"role": "model", "parts": []},
            "citationMetadata": {"citationSources": [
                {"startIndex": 6, "endIndex": 11, "uri": "https://atlas.example"}]},
            "finishReason": "STOP"}]}),
    ];
    let mut events = Vec::new();
    for c in chunks {
        events.extend(reader.reader().read_response_events("", &c, &mut state));
    }
    let (index, cits) = events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockDelta {
                index,
                delta: IrDelta::CitationsDelta(c),
            } => Some((*index, c.clone())),
            _ => None,
        })
        .expect("citations delta");
    let second_text = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockDelta {
                index,
                delta: IrDelta::TextDelta(t),
            } if t == "Paris is big" => Some(*index),
            _ => None,
        })
        .next()
        .expect("second text block");
    assert_eq!(index, second_text, "{events:?}");
    assert_eq!((cits[0].start_index, cits[0].end_index), (Some(0), Some(5)));
}

fn sse_payloads(out: &str) -> Vec<serde_json::Value> {
    out.split("\n\n")
        .flat_map(|frame| frame.lines())
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str(d).ok())
        .collect()
}

fn bedrock_image_answer() -> crate::ir::IrResponse {
    let converse = json!({
        "output": {"message": {"role": "assistant", "content": [
            {"text": "here it is"},
            {"image": {"format": "png", "source": {"bytes": "iVBORw0KGgo="}}}
        ]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 3, "outputTokens": 5, "totalTokens": 8}
    });
    protocol_for("bedrock")
        .unwrap()
        .reader()
        .read_response(&converse)
        .expect("read")
}

/// Item 17 (IR-21): a generated image in a buffered Bedrock answer reaches a Gemini STREAM client
/// as an `inlineData` part (it used to be skipped by the buffered-to-stream synthesis), and an
/// Anthropic stream client — which has no assistant image block — still gets a balanced stream with
/// contiguous block indices.
#[test]
fn item17_generated_image_streams_to_a_gemini_client() {
    let mut ir = bedrock_image_answer();
    crate::chat_handle::chat_prepare_for_ingress(&mut ir, "gemini", 0);
    let out = String::from_utf8(
        crate::proto_stream::StreamTranslate::synthesize_from_response("gemini", &ir)
            .expect("synthesized"),
    )
    .unwrap();
    let inline = sse_payloads(&out)
        .into_iter()
        .filter_map(|p| p.pointer("/candidates/0/content/parts").cloned())
        .flat_map(|p| p.as_array().cloned().unwrap_or_default())
        .find_map(|p| p.get("inlineData").cloned());
    assert_eq!(
        inline,
        Some(json!({"mimeType": "image/png", "data": "iVBORw0KGgo="})),
        "{out}"
    );

    let mut ir = bedrock_image_answer();
    crate::chat_handle::chat_prepare_for_ingress(&mut ir, "anthropic", 0);
    let out = String::from_utf8(
        crate::proto_stream::StreamTranslate::synthesize_from_response("anthropic", &ir)
            .expect("synthesized"),
    )
    .unwrap();
    let payloads = sse_payloads(&out);
    let starts: Vec<i64> = payloads
        .iter()
        .filter(|p| p["type"] == "content_block_start")
        .filter_map(|p| p["index"].as_i64())
        .collect();
    let stops: Vec<i64> = payloads
        .iter()
        .filter(|p| p["type"] == "content_block_stop")
        .filter_map(|p| p["index"].as_i64())
        .collect();
    assert_eq!(starts, vec![0], "{out}");
    assert_eq!(stops, vec![0], "{out}");
}
