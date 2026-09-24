//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT REFUSES; IT IS NEVER LEDGERED AS ZERO (#42).
//!
//! The OpenAI Chat reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
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
        "id": "c", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": "1500", "completion_tokens": 9}
    });
    OpenAiReader
        .read_response(&body)
        .expect_err("a present, unreadable prompt_tokens is a refusal, never a zero");
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let body = serde_json::json!({
        "id": "c", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "usage": {"completion_tokens": 9}
    });
    let ir = OpenAiReader
        .read_response(&body)
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

#[test]
fn streaming_usage_chunk_refuses_a_stringified_count() {
    let mut state = crate::ir::StreamDecodeState::default();
    let chunk = serde_json::json!({
        "id": "c", "object": "chat.completion.chunk", "model": "gpt-4o",
        "choices": [],
        "usage": {"prompt_tokens": 10, "completion_tokens": "9"}
    });
    let ev = OpenAiReader.read_response_events("", &chunk, &mut state);
    assert!(
        matches!(ev.last(), Some(IrStreamEvent::Error(_))),
        "a usage chunk with an unreadable count must end the stream in an error; got {ev:?}"
    );
    assert!(
        !ev.iter()
            .any(|e| matches!(e, IrStreamEvent::MessageDelta { .. })),
        "no usage-bearing MessageDelta may carry a zeroed count; got {ev:?}"
    );
}

#[test]
fn truncated_recovery_yields_no_usage_for_a_stringified_count() {
    let tail = br#"...cut"}}],"usage":{"prompt_tokens":"1500","completion_tokens":9}}"#;
    assert_eq!(OpenAiReader.recover_truncated_usage(tail), None);
    let tail = br#"...cut"}}],"usage":{"completion_tokens":9}}"#;
    let u = OpenAiReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}
