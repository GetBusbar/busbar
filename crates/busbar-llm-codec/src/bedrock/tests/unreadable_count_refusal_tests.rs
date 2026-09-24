//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT REFUSES; IT IS NEVER LEDGERED AS ZERO (#42).
//!
//! The Bedrock reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
//! so a stringified `"1500"` from a compatible self-hosted backend reached the ledger as ZERO tokens
//! for work that happened. Each test drives the real read path: the buffered response REFUSES, the
//! streaming terminal frame ends the stream in an ERROR (a failed stream is not token-billed, and the
//! refusal is visible rather than a silent zero), and the truncated-tail recovery yields NO usage so
//! the caller falls back to its conservative floor estimate instead of $0. An ABSENT count keeps its
//! meaning — zero — and still reads.
use super::*;

#[test]
fn buffered_response_refuses_a_stringified_count() {
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": "1500", "outputTokens": 9}
    });
    BedrockReader
        .read_response(&body)
        .expect_err("a present, unreadable inputTokens is a refusal, never a zero");
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {"outputTokens": 9}
    });
    let ir = BedrockReader
        .read_response(&body)
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

#[test]
fn streaming_metadata_refuses_a_stringified_count() {
    let mut state = crate::ir::StreamDecodeState::default();
    BedrockReader.read_response_events(
        "",
        &serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        &mut state,
    );
    let ev = BedrockReader.read_response_events(
        "",
        &serde_json::json!({"type": "metadata", "usage": {"inputTokens": 5, "outputTokens": "27"}}),
        &mut state,
    );
    assert!(
        matches!(ev.as_slice(), [IrStreamEvent::Error(_)]),
        "metadata with an unreadable count must end the stream in an error, not a zero; got {ev:?}"
    );
}

#[test]
fn truncated_recovery_yields_no_usage_for_a_stringified_count() {
    let tail = br#"...cut"}],"usage":{"inputTokens":"1500","outputTokens":9}}"#;
    assert_eq!(BedrockReader.recover_truncated_usage(tail), None);
    let tail = br#"...cut"}],"usage":{"outputTokens":9}}"#;
    let u = BedrockReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}

// ── CACHE COUNTS (item 133 remainder) ────────────────────────────────────────────────────────────
//
// `read_cache_usage` read `cacheReadInputTokens`/`cacheWriteInputTokens` as
// `.and_then(read_count_u64)` — an unreadable spelling became `None`, "no caching this turn" — and
// `read_cache_details` SKIPPED a 5m/1h entry whose `inputTokens` would not read, so its tier reported
// fewer tokens than were written. Both now refuse on every path.

fn converse(usage: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": usage
    })
}

#[test]
fn buffered_response_refuses_an_unreadable_cache_count() {
    for usage in [
        serde_json::json!({"inputTokens": 5, "outputTokens": 9, "cacheReadInputTokens": "40"}),
        serde_json::json!({"inputTokens": 5, "outputTokens": 9, "cacheWriteInputTokens": "40"}),
        serde_json::json!({"inputTokens": 5, "outputTokens": 9, "cacheWriteInputTokens": 40,
                           "cacheDetails": [{"ttl": "5m", "inputTokens": "40"}]}),
    ] {
        BedrockReader
            .read_response(&converse(usage.clone()))
            .expect_err(&format!(
                "{usage} carries an unreadable cache count: refusal, not `none`"
            ));
    }
}

#[test]
fn buffered_response_cache_counts_absent_null_readable_and_unknown_ttl_still_read() {
    let ir = BedrockReader
        .read_response(&converse(serde_json::json!({
            "inputTokens": 5, "outputTokens": 9,
            "cacheReadInputTokens": null, "cacheWriteInputTokens": 60,
            "cacheDetails": [
                {"ttl": "1h", "inputTokens": 20},
                {"ttl": "5m", "inputTokens": 40},
                {"ttl": "5m"},
                {"ttl": "9d", "inputTokens": "not a tier this build prices"}
            ]
        })))
        .expect("absent, null, readable and unknown-TTL entries all read");
    assert_eq!(ir.usage.cache_read_input_tokens, None);
    assert_eq!(ir.usage.cache_creation_input_tokens, Some(60));
    assert_eq!(ir.usage.detail.cache_creation_5m_input_tokens, Some(40));
    assert_eq!(ir.usage.detail.cache_creation_1h_input_tokens, Some(20));
}

#[test]
fn streaming_metadata_refuses_an_unreadable_cache_count() {
    for usage in [
        serde_json::json!({"inputTokens": 5, "outputTokens": 9, "cacheReadInputTokens": "40"}),
        serde_json::json!({"inputTokens": 5, "outputTokens": 9,
                           "cacheDetails": [{"ttl": "1h", "inputTokens": "40"}]}),
    ] {
        let mut state = crate::ir::StreamDecodeState::default();
        BedrockReader.read_response_events(
            "",
            &serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
            &mut state,
        );
        let ev = BedrockReader.read_response_events(
            "",
            &serde_json::json!({"type": "metadata", "usage": usage}),
            &mut state,
        );
        assert!(
            matches!(ev.as_slice(), [IrStreamEvent::Error(_)]),
            "metadata with an unreadable cache count must end the stream in an error; got {ev:?}"
        );
    }
}

#[test]
fn truncated_recovery_yields_no_usage_for_an_unreadable_cache_tier() {
    let tail = br#"...cut"}],"usage":{"inputTokens":5,"outputTokens":9,"cacheDetails":[{"ttl":"5m","inputTokens":"40"}]}}"#;
    assert_eq!(BedrockReader.recover_truncated_usage(tail), None);
}
