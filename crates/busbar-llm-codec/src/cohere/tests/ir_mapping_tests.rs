// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping (owner directive Q57): every field a Cohere v2 body carries that the IR and the other
//! dialect can carry must map, in both directions, buffered and streamed. One section per defect id
//! of the 1.6.0 IR mapping audit (`COH-nn`). The tests drive the production step list end to end —
//! reader → `chat_prepare_for_egress`/`_ingress` → writer, and `StreamTranslate` for streams — on
//! real wire bodies.

use serde_json::{json, Value};

/// A backend stream (`egress` dialect) translated for a client speaking `ingress`.
fn translate_stream(egress: &str, ingress: &str, raw: &str) -> String {
    let mut st = crate::proto_stream::StreamTranslate::new(ingress, egress).expect("translator");
    let mut out = st.feed(raw.as_bytes());
    out.extend(st.finish());
    String::from_utf8_lossy(&out).into_owned()
}

/// The JSON `data:` payloads of an SSE body, in order.
fn sse_data(body: &str) -> Vec<Value> {
    body.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str(d.trim()).ok())
        .collect()
}

/// One Cohere v2 SSE frame.
fn frame(v: Value) -> String {
    let ty = v["type"].as_str().unwrap_or("").to_string();
    format!("event: {ty}\ndata: {v}\n\n")
}

/// A Cohere reasoning-model stream: a `thinking` content block, then the answer's text block with a
/// citation, then `message-end` (the audit's t05 probe body).
fn reasoning_stream() -> String {
    [
        json!({"type":"message-start","id":"c-1","delta":{"message":{"role":"assistant"}}}),
        json!({"type":"content-start","index":0,"delta":{"message":{"content":{"type":"thinking","thinking":""}}}}),
        json!({"type":"content-delta","index":0,"delta":{"message":{"content":{"thinking":"hmm"}}}}),
        json!({"type":"content-end","index":0}),
        json!({"type":"content-start","index":1,"delta":{"message":{"content":{"type":"text","text":""}}}}),
        json!({"type":"content-delta","index":1,"delta":{"message":{"content":{"text":"hello"}}},
               "logprobs":{"token_ids":[1],"text":"hello","logprobs":[-0.1]}}),
        json!({"type":"citation-start","index":0,"delta":{"message":{"citations":{"start":0,"end":5,"text":"hello",
               "sources":[{"type":"document","id":"d1","document":{"title":"t"}}],"type":"TEXT_CONTENT"}}}}),
        json!({"type":"citation-end","index":0}),
        json!({"type":"content-end","index":1}),
        json!({"type":"message-end","delta":{"finish_reason":"MAX_TOKENS","usage":{
               "billed_units":{"input_tokens":10,"output_tokens":5},
               "tokens":{"input_tokens":12,"output_tokens":5},"cached_tokens":4}}}),
    ]
    .into_iter()
    .map(frame)
    .collect()
}

/// Every IR event the Cohere reader decodes from a raw SSE body.
fn read_events(raw: &str) -> Vec<crate::ir::IrStreamEvent> {
    let reader = super::CohereReader;
    let mut state = crate::ir::StreamDecodeState::default();
    let mut out = Vec::new();
    for v in sse_data(raw) {
        out.extend(crate::proto_codec::ProtocolReader::read_response_events(
            &reader, "", &v, &mut state,
        ));
    }
    out
}

// ── COH-01 / COH-02: a reasoning-model stream keeps its answer, and its thinking ──────────────────

/// COH-01: the thinking block's `content-end` used to latch the ONE text slot closed, so the answer
/// that followed was dropped frame by frame and a foreign client received no answer text at all.
#[test]
fn coh01_reasoning_stream_delivers_the_answer_to_every_foreign_client() {
    for ingress in ["anthropic", "openai", "responses", "gemini", "bedrock"] {
        let out = translate_stream("cohere", ingress, &reasoning_stream());
        assert!(
            out.contains("hello"),
            "COH-01: the answer text must reach a {ingress} client: {out}"
        );
    }
}

/// COH-01 at the reader: the thinking block and the text block are two blocks with two IR indices,
/// each opened and closed exactly once, and the citation lands on the TEXT block.
#[test]
fn coh01_thinking_and_text_are_separate_balanced_blocks() {
    use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent as E};
    let evs = read_events(&reasoning_stream());
    let starts: Vec<(usize, IrBlockMeta)> = evs
        .iter()
        .filter_map(|e| match e {
            E::BlockStart { index, block } => Some((*index, block.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        starts,
        vec![(0, IrBlockMeta::Thinking), (1, IrBlockMeta::Text)],
        "{evs:?}"
    );
    let stops: Vec<usize> = evs
        .iter()
        .filter_map(|e| match e {
            E::BlockStop { index } => Some(*index),
            _ => None,
        })
        .collect();
    assert_eq!(stops, vec![0, 1], "{evs:?}");
    assert!(
        evs.iter().any(|e| matches!(e, E::BlockDelta { index: 1, delta: IrDelta::TextDelta(t) } if t == "hello")),
        "{evs:?}"
    );
    assert!(
        evs.iter().any(|e| matches!(e, E::BlockDelta { index: 1, delta: IrDelta::CitationsDelta(c) } if !c.is_empty())),
        "the citation rides the text block: {evs:?}"
    );
}

/// COH-02: the streamed `content-delta {thinking}` is the reasoning text; it used to be dropped.
#[test]
fn coh02_streamed_thinking_delta_reaches_the_client() {
    use crate::ir::{IrDelta, IrStreamEvent as E};
    let evs = read_events(&reasoning_stream());
    assert!(
        evs.iter().any(|e| matches!(e, E::BlockDelta { index: 0, delta: IrDelta::ThinkingDelta(t) } if t == "hmm")),
        "COH-02: {evs:?}"
    );
    let out = translate_stream("cohere", "anthropic", &reasoning_stream());
    let thinking = sse_data(&out)
        .into_iter()
        .any(|v| v["delta"]["type"] == "thinking_delta" && v["delta"]["thinking"] == "hmm");
    assert!(
        thinking,
        "COH-02: the thinking reaches an Anthropic client: {out}"
    );
}

/// A reasoning turn that goes straight from thinking to tool calls keeps the blocks apart too.
#[test]
fn coh01_thinking_then_tool_call_is_balanced() {
    use crate::ir::{IrBlockMeta, IrStreamEvent as E};
    let raw: String = [
        json!({"type":"message-start","id":"c-2","delta":{"message":{"role":"assistant"}}}),
        json!({"type":"content-start","index":0,"delta":{"message":{"content":{"type":"thinking","thinking":""}}}}),
        json!({"type":"content-delta","index":0,"delta":{"message":{"content":{"thinking":"call f"}}}}),
        json!({"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"t1","type":"function","function":{"name":"f","arguments":""}}}}}),
        json!({"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{}"}}}}}),
        json!({"type":"tool-call-end","index":0}),
        json!({"type":"message-end","delta":{"finish_reason":"TOOL_CALL","usage":{"tokens":{"input_tokens":1,"output_tokens":1}}}}),
    ]
    .into_iter()
    .map(frame)
    .collect();
    let evs = read_events(&raw);
    let seq: Vec<String> = evs
        .iter()
        .filter_map(|e| match e {
            E::BlockStart {
                index,
                block: IrBlockMeta::Thinking,
            } => Some(format!("start-thinking-{index}")),
            E::BlockStart {
                index,
                block: IrBlockMeta::ToolUse { .. },
            } => Some(format!("start-tool-{index}")),
            E::BlockStop { index } => Some(format!("stop-{index}")),
            _ => None,
        })
        .collect();
    assert_eq!(
        seq,
        vec!["start-thinking-0", "stop-0", "start-tool-1", "stop-1"],
        "{evs:?}"
    );
}

/// A buffered backend response (`egress` dialect) translated for a client speaking `ingress`.
fn translate_response(egress: &str, ingress: &'static str, body: &Value) -> Value {
    let egress_p = crate::proto_codec::protocol_for(egress).expect("egress");
    let ingress_p = crate::proto_codec::protocol_for(ingress).expect("ingress");
    let mut resp = egress_p
        .reader()
        .read_response(body)
        .expect("read_response");
    crate::chat_handle::chat_prepare_for_ingress(&mut resp, ingress, 1_752_000_000);
    ingress_p.writer().write_response(&resp)
}

// ── COH-10: the prompt-token count a Cohere client is told (MONEY) ────────────────────────────────

/// COH-10, buffered, OpenAI backend: 10 prompt tokens, 4 of them cached. Cohere's
/// `tokens.input_tokens` is the whole prompt and `cached_tokens` the hit; the writer used to emit
/// the IR's UNCACHED share (6) and no `cached_tokens` at all.
#[test]
fn coh10_openai_cached_prompt_reaches_a_cohere_client_whole() {
    let body = json!({
        "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15,
                  "prompt_tokens_details": {"cached_tokens": 4}}
    });
    let out = translate_response("openai", "cohere", &body);
    assert_eq!(out["usage"]["tokens"]["input_tokens"], json!(10), "{out}");
    assert_eq!(out["usage"]["tokens"]["output_tokens"], json!(5), "{out}");
    assert_eq!(out["usage"]["cached_tokens"], json!(4), "{out}");
}

/// COH-10, buffered, Anthropic backend: 10 uncached + 4 cache-read + 3 cache-written = a 17-token
/// prompt. Cohere has no cache-write tier, so the written share is ordinary prompt input here.
#[test]
fn coh10_anthropic_cache_tiers_sum_into_the_cohere_prompt() {
    let body = json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude",
        "content": [{"type": "text", "text": "hello"}],
        "stop_reason": "end_turn", "stop_sequence": null,
        "usage": {"input_tokens": 10, "output_tokens": 5,
                  "cache_creation_input_tokens": 3, "cache_read_input_tokens": 4}
    });
    let out = translate_response("anthropic", "cohere", &body);
    assert_eq!(out["usage"]["tokens"]["input_tokens"], json!(17), "{out}");
    assert_eq!(out["usage"]["cached_tokens"], json!(4), "{out}");
    // An uncached response gains no fabricated `cached_tokens`.
    let plain = json!({
        "id": "msg_2", "type": "message", "role": "assistant", "model": "claude",
        "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
        "stop_sequence": null, "usage": {"input_tokens": 7, "output_tokens": 2}
    });
    let out = translate_response("anthropic", "cohere", &plain);
    assert_eq!(out["usage"]["tokens"]["input_tokens"], json!(7), "{out}");
    assert!(out["usage"].get("cached_tokens").is_none(), "{out}");
}

/// COH-10 round trip: what the Cohere writer emits, the Cohere reader reads back to the same
/// uncached + cache-read split (the writer is the reader's inverse).
#[test]
fn coh10_cohere_usage_is_the_inverse_of_the_cohere_reader() {
    let body = json!({
        "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15,
                  "prompt_tokens_details": {"cached_tokens": 4}}
    });
    let out = translate_response("openai", "cohere", &body);
    let back = crate::proto_codec::protocol_for("cohere")
        .expect("cohere")
        .reader()
        .read_response(&out)
        .expect("read back");
    assert_eq!(back.usage.input_tokens, 6, "{back:?}");
    assert_eq!(back.usage.cache_read_input_tokens, Some(4), "{back:?}");
}

/// COH-10, streamed, Anthropic backend: the prompt counts ride `message_start`; the Cohere
/// `message-end` must carry the whole 17-token prompt and the 4-token cache hit.
#[test]
fn coh10_streamed_message_end_carries_the_whole_prompt_and_the_cache_hit() {
    let raw = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":1,\"cache_read_input_tokens\":4,\"cache_creation_input_tokens\":3}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":5}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );
    let out = translate_stream("anthropic", "cohere", raw);
    let end = sse_data(&out)
        .into_iter()
        .find(|v| v["type"] == "message-end")
        .unwrap_or_else(|| panic!("no message-end: {out}"));
    assert_eq!(
        end["delta"]["usage"]["tokens"]["input_tokens"],
        json!(17),
        "{out}"
    );
    assert_eq!(
        end["delta"]["usage"]["tokens"]["output_tokens"],
        json!(5),
        "{out}"
    );
    assert_eq!(end["delta"]["usage"]["cached_tokens"], json!(4), "{out}");
}
