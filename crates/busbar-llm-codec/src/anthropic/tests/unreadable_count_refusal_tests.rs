//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT REFUSES; IT IS NEVER LEDGERED AS ZERO (#42).
//!
//! The Anthropic reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
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
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": "1500", "output_tokens": 9}
    });
    AnthropicReader
        .read_response(&body)
        .expect_err("a present, unreadable input_tokens is a refusal, never a zero");
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let body = serde_json::json!({
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": {"output_tokens": 9}
    });
    let ir = AnthropicReader
        .read_response(&body)
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

#[test]
fn streaming_usage_frames_refuse_a_stringified_count() {
    let start = serde_json::json!({
        "type": "message_start",
        "message": {"id": "m", "role": "assistant", "usage": {"input_tokens": "1500", "output_tokens": 1}}
    });
    assert!(
        matches!(
            AnthropicReader.read_response_event("message_start", &start),
            Some(IrStreamEvent::Error(_))
        ),
        "message_start with an unreadable count must end the stream in an error"
    );
    let delta = serde_json::json!({
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn"},
        "usage": {"output_tokens": "9"}
    });
    assert!(
        matches!(
            AnthropicReader.read_response_event("message_delta", &delta),
            Some(IrStreamEvent::Error(_))
        ),
        "message_delta with an unreadable count must end the stream in an error"
    );
}

#[test]
fn truncated_recovery_yields_no_usage_for_a_stringified_count() {
    let tail = br#"...cut"}],"usage":{"input_tokens":"1500","output_tokens":9}}"#;
    assert_eq!(AnthropicReader.recover_truncated_usage(tail), None);
    let tail = br#"...cut"}],"usage":{"output_tokens":9}}"#;
    let u = AnthropicReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}
