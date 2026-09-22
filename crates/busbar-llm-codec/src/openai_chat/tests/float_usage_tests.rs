// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FLOAT-ENCODED USAGE COUNTS, PROVEN THROUGH `read_count_u64`.
//!
//! `serde_json::Value::as_u64()` returns `None` for ANY float-backed number, `27.0` included. The
//! OpenAI Chat Completions dialect's usage reads used to go through that bare idiom with
//! `.unwrap_or(0)`, so a provider (or an OpenAI-compatible proxy) that spells a count as a float had
//! a real count recorded as a billed ZERO. These tests pin realistic float-encoded wire payloads
//! through every usage read site: the truncated-stream recovery path (`recover_truncated_usage`),
//! the `stream_options: {include_usage: true}` streaming trailer, the buffered `read_response`, and
//! the reasoning/audio/predicted-output sub-buckets on both the streaming and buffered paths.

use super::*;
use crate::ir::StreamDecodeState;

/// THE TRUNCATED-STREAM RECOVERY PATH. `recover_truncated_usage` parses the trailing `usage` object
/// independently of the main streaming/buffered decode, so it needed its own proof.
#[test]
fn recover_truncated_usage_reads_float_encoded_counts() {
    let reader = OpenAiReader;
    let tail = br#"..."}}],"usage":{"prompt_tokens":1000.0,"completion_tokens":50.0,"prompt_tokens_details":{"cached_tokens":200.0}}}"#;
    let usage = reader
        .recover_truncated_usage(tail)
        .expect("usage tail must be recoverable");
    assert_eq!(
        usage.input, 800,
        "prompt_tokens(1000.0) - cached_tokens(200.0), both float-spelled"
    );
    assert_eq!(usage.output, 50, "completion_tokens(50.0), float-spelled");
    assert_eq!(usage.cache_read, Some(200));
}

/// THE STREAMING PATH: a `stream_options: {include_usage: true}` trailing usage-only chunk
/// (`choices: []`, a real top-level `usage` object) with EVERY field float-spelled, including the
/// reasoning/audio/predicted-output sub-buckets. A fix that only covers the buffered response would
/// leave a streamed request reporting these as zero while `stream: false` reported them correctly.
#[test]
fn streaming_trailing_usage_chunk_reads_float_encoded_counts() {
    let reader = OpenAiReader;
    let mut state = StreamDecodeState::default();
    let chunk = serde_json::json!({
        "id": "chatcmpl-float9",
        "object": OBJ_CHUNK,
        "created": 1u64,
        "model": "gpt-4o",
        "choices": [],
        "usage": {
            "prompt_tokens": 1000.0,
            "completion_tokens": 50.0,
            "prompt_tokens_details": {"cached_tokens": 200.0, "audio_tokens": 3.0},
            "completion_tokens_details": {
                "reasoning_tokens": 400.0,
                "audio_tokens": 7.0,
                "accepted_prediction_tokens": 11.0,
                "rejected_prediction_tokens": 2.0
            }
        }
    });
    let events = reader.read_response_events("", &chunk, &mut state);
    let usage = events
        .into_iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("the trailing usage-only chunk must emit a MessageDelta carrying usage");
    assert_eq!(
        usage.input_tokens, 800,
        "prompt_tokens(1000.0) - cached_tokens(200.0), streamed trailer, both float-spelled"
    );
    assert_eq!(usage.output_tokens, 50, "completion_tokens(50.0), streamed trailer");
    assert_eq!(usage.cache_read_input_tokens, Some(200));
    assert_eq!(usage.detail.reasoning_tokens, Some(400));
    assert_eq!(usage.detail.input_audio_tokens, Some(3));
    assert_eq!(usage.detail.output_audio_tokens, Some(7));
    assert_eq!(usage.detail.accepted_prediction_tokens, Some(11));
    assert_eq!(usage.detail.rejected_prediction_tokens, Some(2));
}

/// THE BUFFERED PATH. The identical float-spelled usage object on a non-streamed `chat.completion`
/// response must read exactly the same as the streaming trailer above.
#[test]
fn buffered_read_response_reads_float_encoded_counts() {
    let body = serde_json::json!({
        "id": "chatcmpl-float10",
        "object": "chat.completion",
        "created": 1u64,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": FINISH_STOP
        }],
        "usage": {
            "prompt_tokens": 1000.0,
            "completion_tokens": 50.0,
            "prompt_tokens_details": {"cached_tokens": 200.0, "audio_tokens": 3.0},
            "completion_tokens_details": {
                "reasoning_tokens": 400.0,
                "audio_tokens": 7.0,
                "accepted_prediction_tokens": 11.0,
                "rejected_prediction_tokens": 2.0
            }
        }
    });
    let ir = OpenAiReader.read_response(&body).expect("read_response");
    assert_eq!(
        ir.usage.input_tokens, 800,
        "prompt_tokens(1000.0) - cached_tokens(200.0), buffered, both float-spelled"
    );
    assert_eq!(ir.usage.output_tokens, 50, "completion_tokens(50.0), buffered");
    assert_eq!(ir.usage.cache_read_input_tokens, Some(200));
    assert_eq!(ir.usage.detail.reasoning_tokens, Some(400));
    assert_eq!(ir.usage.detail.input_audio_tokens, Some(3));
    assert_eq!(ir.usage.detail.output_audio_tokens, Some(7));
    assert_eq!(ir.usage.detail.accepted_prediction_tokens, Some(11));
    assert_eq!(ir.usage.detail.rejected_prediction_tokens, Some(2));
}

// ── AN UNREADABLE COUNT REFUSES, IT DOES NOT BILL ZERO (#81/#42) ────────────────────────────────
//
// The float-spelled count above is the case busbar CAN read. This is the case it cannot: a usage
// field that is there and is not a number busbar understands. The old readers defaulted it to zero,
// which wrote "no work happened" into the ledger for work that did — and money is a view over
// `ledger x ratecard`, so every figure derived from that row was faithfully wrong and nothing
// downstream could tell. These pin the live reader paths, which is where the ledger row comes from.

/// THE BUFFERED IMAGE READER REFUSES AN UNREADABLE BILLED COUNT.
#[test]
fn an_unreadable_image_count_refuses_instead_of_billing_zero() {
    // `"27"` is a string, not a number: present, and not a count.
    let wire = br#"{"data":[{"b64_json":"aGk="}],"usage":{"input_tokens":"27","output_tokens":5}}"#;
    let err = crate::openai_chat::handler::read_image_response(wire)
        .expect_err("a present, unreadable billed count is a refusal, never a zero");
    let text = format!("{err:?}");
    assert!(text.contains("input_tokens"), "the refusal names the field: {text}");

    // And the same body with a READABLE count still reads, float-spelled included — the refusal is
    // about unreadability, not about strictness for its own sake.
    let ok = br#"{"data":[{"b64_json":"aGk="}],"usage":{"input_tokens":27.0,"output_tokens":5}}"#;
    let resp = crate::openai_chat::handler::read_image_response(ok).expect("a float-spelled count reads");
    match resp.billing() {
        Some(busbar_substrate_values::billing::Billing::Tokens(t)) => {
            assert_eq!(t.input, 27);
            assert_eq!(t.output, 5);
        }
        other => panic!("expected token billing, got {other:?}"),
    }
}

/// THE BUFFERED EMBEDDINGS READER REFUSES AN UNREADABLE BILLED COUNT.
#[test]
fn an_unreadable_embeddings_count_refuses_instead_of_billing_zero() {
    let wire = br#"{"model":"m","data":[],"usage":{"prompt_tokens":{"n":27}}}"#;
    let err = crate::openai_chat::handler::read_embeddings_response(wire)
        .expect_err("a present, unreadable billed count is a refusal, never a zero");
    assert!(
        format!("{err:?}").contains("prompt_tokens"),
        "the refusal names the field: {err:?}"
    );
}

/// AN ABSENT COUNT IS STILL ZERO, AND A RESPONSE WITH NO USAGE OBJECT STILL READS.
///
/// The guard on the guard: if the refusal had been written as "anything I cannot turn into a
/// number", every well-formed response that simply omits a count would start failing. Absence is a
/// fact and it is worth zero — that is v1.5.5's behaviour and it does not move.
#[test]
fn an_absent_count_still_reads_as_zero_and_no_usage_object_still_reads() {
    let wire = br#"{"data":[{"b64_json":"aGk="}],"usage":{"input_tokens":27}}"#;
    let resp = crate::openai_chat::handler::read_image_response(wire).expect("absent output_tokens reads");
    match resp.billing() {
        Some(busbar_substrate_values::billing::Billing::Tokens(t)) => {
            assert_eq!(t.input, 27);
            assert_eq!(t.output, 0, "an absent count is zero, exactly as before");
        }
        other => panic!("expected token billing, got {other:?}"),
    }
    // No `usage` object at all: unchanged, bills via the per-image cost basis.
    let wire = br#"{"data":[{"b64_json":"aGk="}]}"#;
    crate::openai_chat::handler::read_image_response(wire).expect("a usage-less image response reads");
}
