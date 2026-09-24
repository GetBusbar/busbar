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
