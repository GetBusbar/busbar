// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MONEY BUG regression: `serde_json::Value::as_u64()` returns `None` for ANY float-backed
//! number — `27.0` included. Every Bedrock Converse usage/billing count now reads through the
//! shared [`crate::usage_count::read_count_u64`] seam instead of a bare `.as_u64()`, so a provider
//! that spells a count as a float (a real, observed wire shape) is no longer silently billed as
//! zero.
//!
//! Each test here drives a REALISTIC float-encoded wire payload (not a hand-built integer) through
//! the real read path and asserts the count survives as the exact integer. Every one of these
//! failed with the count reading `0` before the fix (see the RED transcript in the task report);
//! this file is what proves it stays fixed.
use super::*;

/// stream:`metadata.usage` — the ConverseStream terminal usage frame. Float-encoded
/// `inputTokens`/`outputTokens` AND the additive `cacheWriteInputTokens`/`cacheReadInputTokens`
/// buckets must all survive as the exact integer, not 0.
#[test]
fn stream_metadata_float_token_counts_survive_as_integers() {
    let reader = BedrockReader;
    let mut state = crate::ir::StreamDecodeState::default();

    // Buffer the stopReason first, matching the real frame order (messageStop then metadata).
    reader.read_response_events(
        "",
        &serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        &mut state,
    );

    let ev = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": "metadata",
            "usage": {
                "inputTokens": 5.0, "outputTokens": 27.0,
                "cacheWriteInputTokens": 8.0, "cacheReadInputTokens": 6.0
            }
        }),
        &mut state,
    );
    let Some(crate::ir::IrStreamEvent::MessageDelta { usage, .. }) = ev.first() else {
        panic!("expected a MessageDelta carrying usage; got {ev:?}");
    };
    assert_eq!(
        usage.input_tokens, 5,
        "float-encoded inputTokens must survive as the exact integer, not 0"
    );
    assert_eq!(
        usage.output_tokens, 27,
        "float-encoded outputTokens must survive as the exact integer, not 0"
    );
    assert_eq!(
        usage.cache_creation_input_tokens,
        Some(8),
        "float-encoded cacheWriteInputTokens must survive as the exact integer, not 0"
    );
    assert_eq!(
        usage.cache_read_input_tokens,
        Some(6),
        "float-encoded cacheReadInputTokens must survive as the exact integer, not 0"
    );
}

/// Buffered `read_response().usage` — `inputTokens`/`outputTokens`/`cacheWriteInputTokens`/
/// `cacheReadInputTokens`, all float-encoded, must survive as the exact integer.
#[test]
fn buffered_response_float_usage_counts_survive_as_integers() {
    let reader = BedrockReader;
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {
            "inputTokens": 10.0, "outputTokens": 27.0,
            "cacheReadInputTokens": 3.0, "cacheWriteInputTokens": 7.0
        }
    });
    let resp = reader.read_response(&body).expect("read");
    assert_eq!(
        resp.usage.input_tokens, 10,
        "float-encoded inputTokens must survive as the exact integer, not 0"
    );
    assert_eq!(
        resp.usage.output_tokens, 27,
        "float-encoded outputTokens must survive as the exact integer, not 0"
    );
    assert_eq!(
        resp.usage.cache_read_input_tokens,
        Some(3),
        "float-encoded cacheReadInputTokens must survive as the exact integer, not 0"
    );
    assert_eq!(
        resp.usage.cache_creation_input_tokens,
        Some(7),
        "float-encoded cacheWriteInputTokens must survive as the exact integer, not 0"
    );
}

/// MONEY BUG regression (truncated-tail recovery path): a HEAD-truncated non-stream billing buffer
/// still carries a well-formed, self-contained trailing `usage` object that `recover_truncated_usage`
/// isolates and parses on its own. Float-encoded counts must survive here too — this is the
/// LAST-RESORT billing recovery path, so a silent zero here is exactly as costly as one on the
/// primary read path.
#[test]
fn recover_truncated_usage_float_token_counts_survive_as_integers() {
    let reader = BedrockReader;
    let tail = br#"... mangled head cut through here"}],"usage":{"inputTokens":27.0,"outputTokens":9.0,"cacheWriteInputTokens":4.0,"cacheReadInputTokens":3.0}}"#;
    let usage = reader
        .recover_truncated_usage(tail)
        .expect("usage tail must be recoverable");
    assert_eq!(
        usage.input, 27,
        "float-encoded inputTokens must survive as the exact integer, not 0"
    );
    assert_eq!(
        usage.output, 9,
        "float-encoded outputTokens must survive as the exact integer, not 0"
    );
    assert_eq!(
        usage.cache_creation,
        Some(4),
        "float-encoded cacheWriteInputTokens must survive as the exact integer, not 0"
    );
    assert_eq!(
        usage.cache_read,
        Some(3),
        "float-encoded cacheReadInputTokens must survive as the exact integer, not 0"
    );
}
