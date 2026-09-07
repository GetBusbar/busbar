// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE READING FOR A TOKEN COUNT, IN EVERY DIALECT.
//!
//! `usage_tail::token_count` is this crate's own rule for reading a billable count off the wire:
//! "a provider whose spec types these as `number` rather than `integer` (Cohere does; an
//! OpenAI-compatible backend may follow it) reports `11.0`, which `as_u64` answers `None` for —
//! silently ledgering a real billed count as zero."
//!
//! The rule was applied to the Cohere and Gemini readers and to some of the OpenAI ones, and left
//! unapplied at the rest of the Anthropic and OpenAI-Chat usage sites — the buffered response, the
//! streamed `message_start`/`message_delta`/`include_usage` terminal, the truncated-tail recovery,
//! and every cache/attribution sub-bucket. busbar fronts ANTHROPIC-COMPATIBLE and
//! OPENAI-COMPATIBLE backends (self-hosted gateways, inference servers, other proxies), not only
//! the two first-party APIs, and JSON has one number type: `1200` and `1200.0` are the same value
//! and either is a legal serialization of an `integer`-typed field. A backend answering `1200.0`
//! billed ZERO — no error, no warn, a perfectly reconciling invoice for nothing.
//!
//! These tests drive a double-serialized count through every remaining usage site and assert the
//! count that was reported is the count that is billed.

use serde_json::json;

/// Every Anthropic usage site: the buffered response, `message_start`, `message_delta`, and the
/// truncated-tail recovery — totals, cache tiers and attribution sub-buckets alike.
#[test]
fn anthropic_bills_a_double_typed_count_at_every_usage_site() {
    use crate::proto_codec::ProtocolReader as _;
    let reader = crate::anthropic::AnthropicReader;
    let usage = json!({
        "input_tokens": 1200.0,
        "output_tokens": 340.0,
        "cache_creation_input_tokens": 50.0,
        "cache_read_input_tokens": 20.0,
        "cache_creation": {
            "ephemeral_5m_input_tokens": 30.0,
            "ephemeral_1h_input_tokens": 20.0
        },
        "server_tool_use": { "web_search_requests": 3.0 },
        "output_tokens_details": { "thinking_tokens": 7.0 }
    });

    // 1. The buffered response.
    let body = json!({
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "usage": usage.clone()
    });
    let ir = reader.read_response(&body).expect("reads");
    assert_eq!(ir.usage.input_tokens, 1200, "buffered input");
    assert_eq!(ir.usage.output_tokens, 340, "buffered output");
    assert_eq!(ir.usage.cache_creation_input_tokens, Some(50));
    assert_eq!(ir.usage.cache_read_input_tokens, Some(20));
    assert_eq!(ir.usage.detail.cache_creation_5m_input_tokens, Some(30));
    assert_eq!(ir.usage.detail.cache_creation_1h_input_tokens, Some(20));
    assert_eq!(ir.usage.detail.web_search_requests, Some(3));
    assert_eq!(ir.usage.detail.reasoning_tokens, Some(7));

    // 2. The streamed `message_start` — the frame that carries Anthropic's INPUT tokens.
    let mut state = crate::ir::StreamDecodeState::default();
    let started = reader.read_response_events(
        "message_start",
        &json!({ "message": { "role": "assistant", "usage": usage.clone() } }),
        &mut state,
    );
    let start_usage = started
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageStart { usage, .. } => usage.as_ref(),
            _ => None,
        })
        .expect("message_start carries usage");
    assert_eq!(start_usage.input_tokens, 1200, "streamed start input");
    assert_eq!(start_usage.cache_creation_input_tokens, Some(50));
    assert_eq!(start_usage.cache_read_input_tokens, Some(20));
    assert_eq!(start_usage.detail.cache_creation_5m_input_tokens, Some(30));

    // 3. The streamed `message_delta` — the frame that carries the OUTPUT tokens.
    let mut state = crate::ir::StreamDecodeState::default();
    let delta = reader.read_response_events(
        "message_delta",
        &json!({ "delta": { "stop_reason": "end_turn" }, "usage": usage.clone() }),
        &mut state,
    );
    let delta_usage = delta
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("message_delta carries usage");
    assert_eq!(delta_usage.output_tokens, 340, "streamed delta output");
    assert_eq!(delta_usage.input_tokens, 1200);
    assert_eq!(delta_usage.detail.reasoning_tokens, Some(7));

    // 4. The truncated-tail recovery — the billing read for a body too big to buffer whole.
    let tail = format!(r#","usage":{}}}"#, serde_json::to_string(&usage).unwrap());
    let recovered = reader
        .recover_truncated_usage(tail.as_bytes())
        .expect("recovers");
    assert_eq!(recovered.input, 1200, "truncated-tail input");
    assert_eq!(recovered.output, 340, "truncated-tail output");
    assert_eq!(recovered.cache_creation, Some(50));
    assert_eq!(recovered.cache_read, Some(20));
}

/// Every OpenAI-Chat usage site: the buffered response and the `include_usage` terminal chunk —
/// totals, both cache slices and every attribution sub-bucket.
#[test]
fn openai_chat_bills_a_double_typed_count_at_every_usage_site() {
    use crate::proto_codec::ProtocolReader as _;
    let reader = crate::openai_chat::OpenAiReader;
    let usage = json!({
        "prompt_tokens": 1200.0,
        "completion_tokens": 340.0,
        "prompt_tokens_details": {
            "cached_tokens": 200.0,
            "cache_write_tokens": 100.0,
            "audio_tokens": 11.0
        },
        "completion_tokens_details": {
            "reasoning_tokens": 7.0,
            "audio_tokens": 5.0,
            "accepted_prediction_tokens": 3.0,
            "rejected_prediction_tokens": 2.0
        }
    });

    // 1. The buffered response. `prompt_tokens` is a TOTAL including both cache slices, so the
    //    uncached input is 1200 - 200 - 100 = 900.
    let body = json!({
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                     "finish_reason": "stop"}],
        "usage": usage.clone()
    });
    let ir = reader.read_response(&body).expect("reads");
    assert_eq!(ir.usage.input_tokens, 900, "buffered uncached input");
    assert_eq!(ir.usage.output_tokens, 340, "buffered output");
    assert_eq!(ir.usage.cache_read_input_tokens, Some(200));
    assert_eq!(ir.usage.cache_creation_input_tokens, Some(100));
    assert_eq!(ir.usage.detail.reasoning_tokens, Some(7));
    assert_eq!(ir.usage.detail.input_audio_tokens, Some(11));
    assert_eq!(ir.usage.detail.output_audio_tokens, Some(5));
    assert_eq!(ir.usage.detail.accepted_prediction_tokens, Some(3));
    assert_eq!(ir.usage.detail.rejected_prediction_tokens, Some(2));
    assert_eq!(
        ir.usage.billable_tokens(),
        1540,
        "every reported token is billed: 900 uncached + 200 read + 100 write + 340 out"
    );

    // 2. The `include_usage` terminal chunk — the streaming twin of the same object.
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader.read_response_events(
        "",
        &json!({ "choices": [], "usage": usage.clone() }),
        &mut state,
    );
    let streamed = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("the trailing usage chunk carries usage");
    assert_eq!(streamed.input_tokens, 900, "streamed uncached input");
    assert_eq!(streamed.output_tokens, 340, "streamed output");
    assert_eq!(streamed.cache_read_input_tokens, Some(200));
    assert_eq!(streamed.cache_creation_input_tokens, Some(100));
    assert_eq!(streamed.detail.reasoning_tokens, Some(7));
    assert_eq!(streamed.detail.input_audio_tokens, Some(11));
    assert_eq!(streamed.detail.output_audio_tokens, Some(5));
    assert_eq!(streamed.detail.accepted_prediction_tokens, Some(3));
    assert_eq!(streamed.detail.rejected_prediction_tokens, Some(2));
}

/// Every OpenAI-Responses usage site: the buffered response, the stream terminal, and the
/// truncated-tail recovery.
#[test]
fn responses_bills_a_double_typed_count_at_every_usage_site() {
    use crate::proto_codec::ProtocolReader as _;
    let reader = crate::openai_responses::ResponsesReader;
    let usage = json!({
        "input_tokens": 1200.0,
        "input_tokens_details": { "cached_tokens": 200.0, "cache_write_tokens": 100.0 },
        "output_tokens": 340.0,
        "output_tokens_details": { "reasoning_tokens": 7.0 },
        "total_tokens": 1540.0
    });

    // 1. Buffered. `input_tokens` is a TOTAL including both cache slices: 1200 - 200 - 100 = 900.
    let ir = reader
        .read_response(&json!({
            "status": "completed",
            "output": [{"type": "message", "role": "assistant",
                        "content": [{"type": "output_text", "text": "hi"}]}],
            "usage": usage.clone()
        }))
        .expect("reads");
    assert_eq!(ir.usage.input_tokens, 900, "buffered uncached input");
    assert_eq!(ir.usage.output_tokens, 340, "buffered output");
    assert_eq!(ir.usage.cache_read_input_tokens, Some(200));
    assert_eq!(ir.usage.cache_creation_input_tokens, Some(100));
    assert_eq!(ir.usage.detail.reasoning_tokens, Some(7));

    // 2. The stream terminal.
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader.read_response_events(
        "response.completed",
        &json!({ "response": { "status": "completed", "output": [], "usage": usage.clone() } }),
        &mut state,
    );
    let streamed = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("the terminal carries usage");
    assert_eq!(streamed.input_tokens, 900, "streamed uncached input");
    assert_eq!(streamed.output_tokens, 340, "streamed output");
    assert_eq!(streamed.cache_read_input_tokens, Some(200));
    assert_eq!(streamed.cache_creation_input_tokens, Some(100));

    // 3. The truncated-tail recovery.
    let tail = format!(r#","usage":{}}}"#, serde_json::to_string(&usage).unwrap());
    let recovered = reader
        .recover_truncated_usage(tail.as_bytes())
        .expect("recovers");
    assert_eq!(recovered.input, 900, "truncated-tail uncached input");
    assert_eq!(recovered.output, 340, "truncated-tail output");
    assert_eq!(recovered.cache_read, Some(200));
    assert_eq!(recovered.cache_creation, Some(100));
}

/// Every Bedrock Converse usage site: the buffered response, the streamed `metadata` frame, and
/// the truncated-tail recovery.
#[test]
fn bedrock_bills_a_double_typed_count_at_every_usage_site() {
    use crate::proto_codec::ProtocolReader as _;
    let reader = crate::bedrock::BedrockReader;
    let usage = json!({
        "inputTokens": 1200.0,
        "outputTokens": 340.0,
        "cacheWriteInputTokens": 100.0,
        "cacheReadInputTokens": 200.0,
        "totalTokens": 1840.0
    });

    // 1. Buffered. Bedrock's cache counts are ADDITIVE to `inputTokens`, not slices of it.
    let ir = reader
        .read_response(&json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "stopReason": "end_turn",
            "usage": usage.clone()
        }))
        .expect("reads");
    assert_eq!(ir.usage.input_tokens, 1200, "buffered input");
    assert_eq!(ir.usage.output_tokens, 340, "buffered output");
    assert_eq!(ir.usage.cache_creation_input_tokens, Some(100));
    assert_eq!(ir.usage.cache_read_input_tokens, Some(200));

    // 2. The streamed `metadata` frame — the one that carries a Bedrock stream's whole usage.
    let mut state = crate::ir::StreamDecodeState::default();
    let events = reader.read_response_events(
        "metadata",
        // This reader dispatches off the frame body's own `type`.
        &json!({ "type": "metadata", "usage": usage.clone() }),
        &mut state,
    );
    let streamed = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("the metadata frame carries usage");
    assert_eq!(streamed.input_tokens, 1200, "streamed input");
    assert_eq!(streamed.output_tokens, 340, "streamed output");
    assert_eq!(streamed.cache_creation_input_tokens, Some(100));
    assert_eq!(streamed.cache_read_input_tokens, Some(200));

    // 3. The truncated-tail recovery.
    let tail = format!(r#","usage":{}}}"#, serde_json::to_string(&usage).unwrap());
    let recovered = reader
        .recover_truncated_usage(tail.as_bytes())
        .expect("recovers");
    assert_eq!(recovered.input, 1200, "truncated-tail input");
    assert_eq!(recovered.output, 340, "truncated-tail output");
    assert_eq!(recovered.cache_creation, Some(100));
    assert_eq!(recovered.cache_read, Some(200));
}

/// An integer-typed count still reads exactly as it always did — the tolerant reader is a
/// SUPERSET, not a replacement.
#[test]
fn an_integer_count_is_unchanged_in_both_dialects() {
    use crate::proto_codec::ProtocolReader as _;
    let anthropic = crate::anthropic::AnthropicReader
        .read_response(&json!({
            "role": "assistant",
            "content": [],
            "usage": {"input_tokens": 11, "output_tokens": 3, "cache_read_input_tokens": 2}
        }))
        .expect("reads");
    assert_eq!(anthropic.usage.input_tokens, 11);
    assert_eq!(anthropic.usage.output_tokens, 3);
    assert_eq!(anthropic.usage.cache_read_input_tokens, Some(2));

    let openai = crate::openai_chat::OpenAiReader
        .read_response(&json!({
            "choices": [{"index": 0, "message": {"role": "assistant", "content": ""},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3}
        }))
        .expect("reads");
    assert_eq!(openai.usage.input_tokens, 11);
    assert_eq!(openai.usage.output_tokens, 3);
}
