// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A CACHE HIT PRICES AT THE CACHE-READ TIER.
//!
//! The pinned Cohere OpenAPI document types `ApiMeta.cached_tokens` — a `number`, sibling of
//! `tokens` and `billed_units` — as
//!
//!   "The number of prompt tokens that hit the inference cache."
//!
//! Those are PROMPT tokens, counted inside `tokens.input_tokens`, that the model did not have to
//! process. Every other dialect's equivalent (OpenAI `prompt_tokens_details.cached_tokens`,
//! Responses `input_tokens_details.cached_tokens`, Anthropic `cache_read_input_tokens`, Bedrock
//! `cacheReadInputTokens`) is read into the IR's `cache_read_input_tokens`, which is what prices
//! them at the cache-READ tier instead of the full input rate.
//!
//! This reader hardcoded `cache_read_input_tokens: None` at all three of its usage sites — buffered,
//! streamed terminal, and truncated-tail recovery — so a Cohere cache hit was billed at the full
//! input rate, and the writer never emitted the member back on a Cohere -> Cohere hop.
//!
//! The TOTAL is unchanged in every case: the IR keeps `input_tokens` UNCACHED and the cache fields
//! ADDITIVE, so uncached + cache_read reconstructs exactly the `tokens.input_tokens` the upstream
//! reported. Only the TIER the cached share prices at moves.

use super::*;

fn usage_with_cache() -> serde_json::Value {
    serde_json::json!({
        "tokens": { "input_tokens": 1000, "output_tokens": 200 },
        "cached_tokens": 400
    })
}

/// The buffered response.
#[test]
fn a_buffered_cache_hit_is_read_at_the_cache_read_tier() {
    let ir = CohereReader
        .read_response(&serde_json::json!({
            "id": "c-1",
            "finish_reason": "COMPLETE",
            "message": { "role": "assistant", "content": [{"type": "text", "text": "hi"}] },
            "usage": usage_with_cache()
        }))
        .expect("reads");
    assert_eq!(
        ir.usage.cache_read_input_tokens,
        Some(400),
        "the cached prompt tokens must reach the cache-read tier"
    );
    assert_eq!(
        ir.usage.input_tokens, 600,
        "the input total is the UNCACHED share, per the IR's additive-cache convention"
    );
    assert_eq!(
        ir.usage.billable_tokens(),
        1200,
        "1000 prompt + 200 output — the same total as before, priced across two tiers"
    );
}

/// The streamed `message-end` terminal, which carries the identical `usage` object.
#[test]
fn a_streamed_cache_hit_is_read_at_the_cache_read_tier() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events = CohereReader.read_response_events(
        "",
        &serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "COMPLETE", "usage": usage_with_cache() }
        }),
        &mut state,
    );
    let usage = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("the terminal carries usage");
    assert_eq!(usage.cache_read_input_tokens, Some(400));
    assert_eq!(usage.input_tokens, 600);
    assert_eq!(usage.billable_tokens(), 1200);
}

/// The truncated-tail billing recovery — the same body, too large to buffer whole, must not bill a
/// different amount.
#[test]
fn a_truncated_body_reads_the_cache_hit_like_an_untruncated_one() {
    let tail = format!(
        r#","usage":{}}}"#,
        serde_json::to_string(&usage_with_cache()).unwrap()
    );
    let recovered = CohereReader
        .recover_truncated_usage(tail.as_bytes())
        .expect("recovers");
    assert_eq!(recovered.cache_read, Some(400));
    assert_eq!(recovered.input, 600);
}

/// And it survives the WRITE leg: a Cohere -> Cohere hop re-emits the member, with
/// `tokens.input_tokens` restored to the full prompt total the upstream reported.
#[test]
fn the_write_leg_re_emits_the_cache_hit_and_the_full_prompt_total() {
    let ir = CohereReader
        .read_response(&serde_json::json!({
            "id": "c-1",
            "finish_reason": "COMPLETE",
            "message": { "role": "assistant", "content": [{"type": "text", "text": "hi"}] },
            "usage": usage_with_cache()
        }))
        .expect("reads");
    let writer = CohereWriter;
    let out = writer.write_response(&ir);
    assert_eq!(
        out["usage"]["cached_tokens"],
        serde_json::json!(400),
        "the cache hit must survive the hop"
    );
    assert_eq!(
        out["usage"]["tokens"]["input_tokens"],
        serde_json::json!(1000),
        "the wire's prompt total is the FULL one, cached share included, as Cohere reports it"
    );

    // ... and on the stream leg too.
    let writer = CohereWriter;
    let (_evt, frame) = writer
        .write_response_event(&crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: ir.usage.clone(),
        })
        .expect("the terminal frame is written");
    assert_eq!(
        frame["delta"]["usage"]["cached_tokens"],
        serde_json::json!(400)
    );
    assert_eq!(
        frame["delta"]["usage"]["tokens"]["input_tokens"],
        serde_json::json!(1000)
    );
}

/// A response with no cache hit is byte-for-byte what it was: no `cached_tokens` member is
/// invented, and the prompt total is untouched.
#[test]
fn a_response_with_no_cache_hit_is_unchanged() {
    let ir = CohereReader
        .read_response(&serde_json::json!({
            "id": "c-1",
            "finish_reason": "COMPLETE",
            "message": { "role": "assistant", "content": [{"type": "text", "text": "hi"}] },
            "usage": { "tokens": { "input_tokens": 1000, "output_tokens": 200 } }
        }))
        .expect("reads");
    assert_eq!(ir.usage.cache_read_input_tokens, None);
    assert_eq!(ir.usage.input_tokens, 1000);
    let writer = CohereWriter;
    let out = writer.write_response(&ir);
    assert!(
        out["usage"].get("cached_tokens").is_none(),
        "no cache hit was reported, so none is invented: {out}"
    );
    assert_eq!(
        out["usage"]["tokens"]["input_tokens"],
        serde_json::json!(1000)
    );
}
