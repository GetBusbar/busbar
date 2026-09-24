//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT REFUSES; IT IS NEVER LEDGERED AS ZERO (#42).
//!
//! The Cohere reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
//! so a stringified `"1500"` from a compatible self-hosted backend reached the ledger as ZERO tokens
//! for work that happened. Each test drives the real read path: the buffered response REFUSES, the
//! streaming terminal frame ends the stream in an ERROR (a failed stream is not token-billed, and the
//! refusal is visible rather than a silent zero), and the truncated-tail recovery yields NO usage so
//! the caller falls back to its conservative floor estimate instead of $0. An ABSENT count keeps its
//! meaning — zero — and still reads.
use super::*;

fn body(usage: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": "c1",
        "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
        "finish_reason": "COMPLETE",
        "usage": usage
    })
}

#[test]
fn buffered_response_refuses_a_stringified_count() {
    CohereReader
        .read_response(&body(
            serde_json::json!({"tokens": {"input_tokens": "1500", "output_tokens": 9}}),
        ))
        .expect_err("a present, unreadable tokens.input_tokens is a refusal, never a zero");
    CohereReader
        .read_response(&body(
            serde_json::json!({"billed_units": {"input_tokens": "1500"}}),
        ))
        .expect_err("billed_units.input_tokens WINS the bill; unreadable, it refuses too");
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let ir = CohereReader
        .read_response(&body(serde_json::json!({"tokens": {"output_tokens": 9}})))
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

#[test]
fn streaming_message_end_refuses_a_stringified_count() {
    let mut state = crate::ir::StreamDecodeState::default();
    let ev = CohereReader.read_response_events(
        "",
        &serde_json::json!({
            "type": "message-end",
            "delta": {"finish_reason": "COMPLETE", "usage": {"tokens": {"input_tokens": 10, "output_tokens": "5"}}}
        }),
        &mut state,
    );
    assert!(
        matches!(ev.as_slice(), [IrStreamEvent::Error(_)]),
        "message-end with an unreadable count must end the stream in an error, not a zero; got {ev:?}"
    );
}

#[test]
fn truncated_recovery_yields_no_usage_for_a_stringified_count() {
    let tail = br#"...cut"}],"usage":{"tokens":{"input_tokens":"1500","output_tokens":9}}}"#;
    assert_eq!(CohereReader.recover_truncated_usage(tail), None);
    let tail = br#"...cut"}],"usage":{"tokens":{"output_tokens":9}}}"#;
    let u = CohereReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}
