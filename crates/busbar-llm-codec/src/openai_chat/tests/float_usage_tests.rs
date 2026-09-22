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
