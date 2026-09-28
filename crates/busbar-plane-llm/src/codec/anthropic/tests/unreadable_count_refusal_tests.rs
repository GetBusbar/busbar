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

// ── CACHE TIER / METERED DETAIL COUNTS (item 133 remainder) ─────────────────────────────────────
//
// `read_cache_tier_detail` read the 5m/1h cache-creation tiers and `web_search_requests` as
// `.and_then(read_count_u64)`, so an unreadable spelling became `None` — "not reported" — on the
// buffered response and on both streaming usage frames. They now refuse, as the totals do.

fn message(usage: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": usage
    })
}

fn unreadable_detail_usages() -> [serde_json::Value; 3] {
    [
        serde_json::json!({"input_tokens": 5, "output_tokens": 9, "cache_creation_input_tokens": 40,
                           "cache_creation": {"ephemeral_5m_input_tokens": "40", "ephemeral_1h_input_tokens": 0}}),
        serde_json::json!({"input_tokens": 5, "output_tokens": 9, "cache_creation_input_tokens": 40,
                           "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": "40"}}),
        serde_json::json!({"input_tokens": 5, "output_tokens": 9,
                           "server_tool_use": {"web_search_requests": "2"}}),
    ]
}

#[test]
fn buffered_response_refuses_an_unreadable_cache_tier_or_metered_count() {
    for usage in unreadable_detail_usages() {
        AnthropicReader
            .read_response(&message(usage.clone()))
            .expect_err(&format!(
                "{usage}: an unreadable priced detail count is a refusal"
            ));
    }
}

#[test]
fn buffered_response_tier_counts_absent_null_and_readable_still_read() {
    let ir = AnthropicReader
        .read_response(&message(serde_json::json!({
            "input_tokens": 5, "output_tokens": 9, "cache_creation_input_tokens": 40,
            "cache_creation": {"ephemeral_5m_input_tokens": 40, "ephemeral_1h_input_tokens": null},
            "server_tool_use": {"web_search_requests": 2}
        })))
        .expect("absent, null and readable detail counts read");
    assert_eq!(ir.usage.detail.cache_creation_5m_input_tokens, Some(40));
    assert_eq!(ir.usage.detail.cache_creation_1h_input_tokens, None);
    assert_eq!(ir.usage.detail.web_search_requests, Some(2));
}

#[test]
fn streaming_usage_frames_refuse_an_unreadable_cache_tier_or_metered_count() {
    for usage in unreadable_detail_usages() {
        let start = serde_json::json!({
            "type": "message_start",
            "message": {"id": "m", "role": "assistant", "usage": usage.clone()}
        });
        assert!(
            matches!(
                AnthropicReader.read_response_event("message_start", &start),
                Some(IrStreamEvent::Error(_))
            ),
            "message_start with {usage} must end the stream in an error"
        );
        let delta = serde_json::json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn"},
            "usage": usage.clone()
        });
        assert!(
            matches!(
                AnthropicReader.read_response_event("message_delta", &delta),
                Some(IrStreamEvent::Error(_))
            ),
            "message_delta with {usage} must end the stream in an error"
        );
    }
}
