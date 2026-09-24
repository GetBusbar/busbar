//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT REFUSES; IT IS NEVER LEDGERED AS ZERO (#42).
//!
//! The Gemini reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
//! so a stringified `"1500"` from a compatible self-hosted backend reached the ledger as ZERO tokens
//! for work that happened. Each test drives the real read path: the buffered response REFUSES, the
//! streaming terminal frame ends the stream in an ERROR (a failed stream is not token-billed, and the
//! refusal is visible rather than a silent zero), and the truncated-tail recovery yields NO usage so
//! the caller falls back to its conservative floor estimate instead of $0. An ABSENT count keeps its
//! meaning — zero — and still reads.
use super::*;

fn body(usage: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
        "usageMetadata": usage
    })
}

#[test]
fn buffered_response_refuses_a_stringified_count() {
    GeminiReader
        .read_response(&body(
            serde_json::json!({"promptTokenCount": "1500", "candidatesTokenCount": 9}),
        ))
        .expect_err("a present, unreadable promptTokenCount is a refusal, never a zero");
    GeminiReader
        .read_response(&body(
            serde_json::json!({"promptTokenCount": 10, "thoughtsTokenCount": "400"}),
        ))
        .expect_err("thinking tokens are billed output; unreadable, they refuse too");
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let ir = GeminiReader
        .read_response(&body(serde_json::json!({"candidatesTokenCount": 9})))
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

#[test]
fn streaming_terminal_refuses_a_stringified_count() {
    let mut state = crate::ir::StreamDecodeState::default();
    let ev = GeminiReader.read_response_events(
        "",
        &body(serde_json::json!({"promptTokenCount": 18, "candidatesTokenCount": "89"})),
        &mut state,
    );
    assert!(
        matches!(ev.last(), Some(IrStreamEvent::Error(_))),
        "a terminal chunk with an unreadable count must end the stream in an error; got {ev:?}"
    );
    assert!(
        !ev.iter()
            .any(|e| matches!(e, IrStreamEvent::MessageDelta { .. })),
        "no usage-bearing MessageDelta may carry a zeroed count; got {ev:?}"
    );
}

#[test]
fn truncated_recovery_yields_no_usage_for_a_stringified_count() {
    let tail =
        br#"...cut"}],"usageMetadata":{"promptTokenCount":"1500","candidatesTokenCount":9}}"#;
    assert_eq!(GeminiReader.recover_truncated_usage(tail), None);
    let tail = br#"...cut"}],"usageMetadata":{"candidatesTokenCount":9}}"#;
    let u = GeminiReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}
