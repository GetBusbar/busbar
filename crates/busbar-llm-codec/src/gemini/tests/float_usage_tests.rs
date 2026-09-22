// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FLOAT-ENCODED USAGE COUNTS, PROVEN THROUGH `read_count_u64`.
//!
//! `serde_json::Value::as_u64()` returns `None` for ANY float-backed number, `27.0` included. The
//! Gemini dialect's usage reads used to go through that bare idiom with `.unwrap_or(0)`, so a
//! provider that spells a count as a float (e.g. `"thoughtsTokenCount": 372.0`) had a real count of
//! 372 recorded as a billed ZERO. These tests pin realistic float-encoded wire payloads through every
//! Gemini usage read site: the truncated-stream recovery path (`recover_truncated_usage`), the
//! buffered path (`read_response`), the streaming path (`read_response_events`), and — because
//! `gemini_usage` sums four terms into one billed total — the case where only ONE of those terms
//! arrives float-spelled while its siblings are plain integers.

use super::*;
use crate::ir::StreamDecodeState;

/// THE TRUNCATED-STREAM RECOVERY PATH. `recover_truncated_usage` parses the trailing `usageMetadata`
/// object independently of `gemini_usage`, so it needed its own proof: every one of its five fields
/// (prompt, candidates, thoughts, tool-use, cached) spelled as a float must still be read as the real
/// count, not silently dropped to zero by `.as_u64()`.
#[test]
fn recover_truncated_usage_reads_float_encoded_counts() {
    let reader = GeminiReader;
    let tail = br#"..."},"finishReason":"MAX_TOKENS"}],"usageMetadata":{"promptTokenCount":1000.0,"candidatesTokenCount":50.0,"thoughtsTokenCount":4000.0,"toolUsePromptTokenCount":32.0,"cachedContentTokenCount":200.0,"totalTokenCount":5282.0}}"#;
    let usage = reader
        .recover_truncated_usage(tail)
        .expect("usageMetadata tail must be recoverable");
    assert_eq!(
        usage.input, 832,
        "promptTokenCount(1000.0) - cachedContentTokenCount(200.0) + toolUsePromptTokenCount(32.0), \
         every term float-spelled"
    );
    assert_eq!(
        usage.output, 4050,
        "candidatesTokenCount(50.0) + thoughtsTokenCount(4000.0), both float-spelled"
    );
    assert_eq!(
        usage.cache_read,
        Some(200),
        "cachedContentTokenCount(200.0) must read as 200, not None/0"
    );
}

/// THE BUFFERED PATH. A native, non-streamed `generateContent` response with every usage field
/// float-spelled must bill and attribute exactly as the integer-spelled twin would.
#[test]
fn buffered_read_response_reads_float_encoded_counts() {
    let body = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "hi"}]},
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 18.0,
            "candidatesTokenCount": 89.0,
            "thoughtsTokenCount": 83.0,
            "toolUsePromptTokenCount": 32.0,
            "cachedContentTokenCount": 5.0,
            "totalTokenCount": 227.0
        }
    });
    let ir = GeminiReader.read_response(&body).expect("read_response");
    assert_eq!(
        ir.usage.input_tokens, 45,
        "18.0 - 5.0(cached) + 32.0(tool-use), every additive term float-spelled"
    );
    assert_eq!(
        ir.usage.output_tokens, 172,
        "89.0(candidates) + 83.0(thoughts), both float-spelled"
    );
    assert_eq!(ir.usage.cache_read_input_tokens, Some(5));
    assert_eq!(
        ir.usage.detail.reasoning_tokens,
        Some(83),
        "the reasoning sub-bucket must also survive a float-spelled thoughtsTokenCount"
    );
    assert_eq!(
        ir.usage.detail.tool_use_prompt_tokens,
        Some(32),
        "the tool-use attribution sub-bucket must also survive a float-spelled term"
    );
}

/// THE STREAMING PATH. The identical float-spelled `usageMetadata` on the terminal `finishReason`
/// chunk of a stream must produce the same billed `MessageDelta` usage as the buffered path — a fix
/// that only covers `read_response` and leaves `read_response_events` on the broken idiom is not a
/// fix, because Gemini's stream terminal carries the exact same JSON shape.
#[test]
fn streaming_terminal_reads_float_encoded_counts() {
    let reader = GeminiReader;
    let mut state = StreamDecodeState::default();
    let chunk = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "hi"}]},
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 18.0,
            "candidatesTokenCount": 89.0,
            "thoughtsTokenCount": 83.0,
            "toolUsePromptTokenCount": 32.0,
            "cachedContentTokenCount": 5.0,
            "totalTokenCount": 227.0
        }
    });
    let events = reader.read_response_events("", &chunk, &mut state);
    let usage = events
        .into_iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("a finishReason chunk must emit a MessageDelta carrying usage");
    assert_eq!(
        usage.input_tokens, 45,
        "18.0 - 5.0(cached) + 32.0(tool-use), streamed terminal, every term float-spelled"
    );
    assert_eq!(
        usage.output_tokens, 172,
        "89.0(candidates) + 83.0(thoughts), streamed terminal, both float-spelled"
    );
    assert_eq!(usage.cache_read_input_tokens, Some(5));
}

/// THE ADDITIVE SUM, WITH EXACTLY ONE TERM FLOAT-SPELLED. `gemini_usage` sums four terms into the
/// billed total, and `gemini_usage_identity_note` cross-checks that sum against Google's own stated
/// `totalTokenCount`. A single float-spelled term reading as zero would still produce a PLAUSIBLE —
/// merely short — total, which is harder to notice than an all-zero bill. Here only
/// `thoughtsTokenCount` is float-spelled; `promptTokenCount`/`candidatesTokenCount`/
/// `toolUsePromptTokenCount` are plain integers, so a regression in exactly one term of the sum is
/// what this test is sensitive to.
#[test]
fn additive_sum_is_correct_when_exactly_one_term_is_float_spelled() {
    let usage_metadata = serde_json::json!({
        "usageMetadata": {
            "promptTokenCount": 18,
            "candidatesTokenCount": 89,
            "thoughtsTokenCount": 83.0,
            "toolUsePromptTokenCount": 32,
            "totalTokenCount": 222
        }
    });
    let u = gemini_usage(&usage_metadata);
    assert_eq!(
        u.output_tokens, 172,
        "89(candidates, int) + 83.0(thoughts, FLOAT) must equal 172, not 89"
    );
    assert_eq!(
        u.input_tokens, 50,
        "18(prompt, int) + 32(tool-use, int) must equal 50"
    );
    assert_eq!(
        u.billable_tokens(),
        222,
        "the sum of all four terms must reach Google's own stated total even though one term of \
         the sum was float-spelled"
    );
    assert_eq!(
        u.detail.usage_identity_note, None,
        "a correctly-read float term must reconcile against totalTokenCount and raise no \
         discrepancy — a stale float read would make this look like an UNMODELLED counter (a \
         false positive) rather than the parse bug it actually is"
    );
}
