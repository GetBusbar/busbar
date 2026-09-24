//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT REFUSES; IT IS NEVER LEDGERED AS ZERO (#42).
//!
//! The OpenAI Responses reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
//! so a stringified `"1500"` from a compatible self-hosted backend reached the ledger as ZERO tokens
//! for work that happened. Each test drives the real read path: the buffered response REFUSES, the
//! streaming terminal frame ends the stream in an ERROR (a failed stream is not token-billed, and the
//! refusal is visible rather than a silent zero), and the truncated-tail recovery yields NO usage so
//! the caller falls back to its conservative floor estimate instead of $0. An ABSENT count keeps its
//! meaning — zero — and still reads.
use super::*;

fn response(usage: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": "resp_1",
        "object": OBJ_RESPONSE,
        "created_at": 1_700_000_000_u64,
        "status": STATUS_COMPLETED,
        "model": "gpt-4o",
        "output": [{
            "type": ITEM_TYPE_MESSAGE,
            "role": "assistant",
            "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
        }],
        "usage": usage
    })
}

#[test]
fn buffered_response_refuses_a_stringified_count() {
    ResponsesReader
        .read_response(&response(
            serde_json::json!({"input_tokens": "1500", "output_tokens": 9}),
        ))
        .expect_err("a present, unreadable input_tokens is a refusal, never a zero");
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let ir = ResponsesReader
        .read_response(&response(serde_json::json!({"output_tokens": 9})))
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

#[test]
fn streaming_terminal_refuses_a_stringified_count() {
    let mut state = crate::ir::StreamDecodeState::default();
    let completed = serde_json::json!({
        "response": {"status": STATUS_COMPLETED, "usage": {"input_tokens": 10, "output_tokens": "9"}}
    });
    let ev = ResponsesReader.read_response_events(EVT_RESPONSE_COMPLETED, &completed, &mut state);
    assert!(
        matches!(ev.last(), Some(IrStreamEvent::Error(_))),
        "response.completed with an unreadable count must end the stream in an error; got {ev:?}"
    );
    assert!(
        !ev.iter()
            .any(|e| matches!(e, IrStreamEvent::MessageDelta { .. })),
        "no usage-bearing MessageDelta may carry a zeroed count; got {ev:?}"
    );
}

#[test]
fn truncated_recovery_yields_no_usage_for_a_stringified_count() {
    let tail = br#"...cut"}]}],"usage":{"input_tokens":"1500","output_tokens":9}}"#;
    assert_eq!(ResponsesReader.recover_truncated_usage(tail), None);
    let tail = br#"...cut"}]}],"usage":{"output_tokens":9}}"#;
    let u = ResponsesReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}

// ── CACHE COUNTS (item 133 remainder) ────────────────────────────────────────────────────────────
//
// `read_cached_tokens` / `read_cache_write_tokens` read `input_tokens_details.*` as
// `.and_then(read_count_u64)`, so an unreadable spelling became `None` — "no cache" — and a reported
// cache read or write left the bill. Both now refuse on every path.

#[test]
fn buffered_response_refuses_an_unreadable_cache_count() {
    for details in [
        serde_json::json!({"cached_tokens": "40"}),
        serde_json::json!({"cache_write_tokens": "40"}),
    ] {
        ResponsesReader
            .read_response(&response(serde_json::json!({
                "input_tokens": 100, "output_tokens": 9, "input_tokens_details": details
            })))
            .expect_err("a present, unreadable cache count is a refusal, never `no cache`");
    }
}

#[test]
fn buffered_response_cache_counts_absent_null_and_readable_still_read() {
    let ir = ResponsesReader
        .read_response(&response(serde_json::json!({
            "input_tokens": 100, "output_tokens": 9,
            "input_tokens_details": {"cached_tokens": null}
        })))
        .expect("a null cache count is absence");
    assert_eq!(ir.usage.cache_read_input_tokens, None);
    assert_eq!(ir.usage.cache_creation_input_tokens, None);
    let ir = ResponsesReader
        .read_response(&response(serde_json::json!({
            "input_tokens": 100, "output_tokens": 9,
            "input_tokens_details": {"cached_tokens": 30, "cache_write_tokens": 20}
        })))
        .expect("readable cache counts read");
    assert_eq!(ir.usage.cache_read_input_tokens, Some(30));
    assert_eq!(ir.usage.cache_creation_input_tokens, Some(20));
    assert_eq!(ir.usage.input_tokens, 50);
}

#[test]
fn streaming_terminal_refuses_an_unreadable_cache_count() {
    for details in [
        serde_json::json!({"cached_tokens": "40"}),
        serde_json::json!({"cache_write_tokens": "40"}),
    ] {
        let mut state = crate::ir::StreamDecodeState::default();
        let completed = serde_json::json!({
            "response": {"status": STATUS_COMPLETED, "usage": {
                "input_tokens": 100, "output_tokens": 9, "input_tokens_details": details
            }}
        });
        let ev =
            ResponsesReader.read_response_events(EVT_RESPONSE_COMPLETED, &completed, &mut state);
        assert!(
            matches!(ev.last(), Some(IrStreamEvent::Error(_))),
            "response.completed with an unreadable cache count must end in an error; got {ev:?}"
        );
    }
}

#[test]
fn truncated_recovery_yields_no_usage_for_an_unreadable_cache_write_count() {
    let tail = br#"...cut"}]}],"usage":{"input_tokens":100,"output_tokens":9,"input_tokens_details":{"cache_write_tokens":"40"}}}"#;
    assert_eq!(ResponsesReader.recover_truncated_usage(tail), None);
}
