//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT IS REFUSED ON ITS OWN; IT IS NEVER LEDGERED AS
//! ZERO (#42), AND IT REFUSES NOTHING ELSE (ARCHITECT ruling 2026-10-15).
//!
//! The Anthropic reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
//! so a stringified `"1500"` from a compatible self-hosted backend reached the ledger as ZERO tokens
//! for work that happened. Each usage field is now judged on its own: the unreadable one is REFUSED
//! (warned loudly, it bills nothing, nothing stands in for it) and the readable ones bill as stated,
//! on the buffered read, both streamed usage frames and the truncated-tail recovery alike. An
//! ABSENT count keeps its meaning — zero — and still reads.
use super::*;

#[test]
fn buffered_response_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let body = serde_json::json!({
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": "1500", "output_tokens": 9}
    });
    let ir = AnthropicReader
        .read_response(crate::codec::test_host::HOST, &body)
        .expect("an unreadable count refuses itself, never the answer");
    assert_eq!((ir.usage.input_tokens, ir.usage.output_tokens), (0, 9));
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
        .read_response(crate::codec::test_host::HOST, &body)
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

/// The (input, output) a streamed frame's event carries, `None` for an error or a frame with none.
fn streamed_tokens(event: &str, data: &serde_json::Value) -> Option<(u64, u64)> {
    match AnthropicReader.read_response_event(crate::codec::test_host::HOST, event, data) {
        Some(IrStreamEvent::MessageStart { usage: Some(u), .. }) => {
            Some((u.input_tokens, u.output_tokens))
        }
        Some(IrStreamEvent::MessageDelta { usage, .. }) => {
            Some((usage.input_tokens, usage.output_tokens))
        }
        _ => None,
    }
}

#[test]
fn streaming_usage_frames_refuse_a_stringified_count_and_bill_the_readable_ones() {
    let start = serde_json::json!({
        "type": "message_start",
        "message": {"id": "m", "role": "assistant", "usage": {"input_tokens": "1500", "output_tokens": 1}}
    });
    assert_eq!(
        streamed_tokens("message_start", &start),
        Some((0, 1)),
        "message_start: the refused input_tokens bills nothing, output_tokens as stated"
    );
    let delta = serde_json::json!({
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn"},
        "usage": {"output_tokens": "9"}
    });
    assert_eq!(
        streamed_tokens("message_delta", &delta),
        Some((0, 0)),
        "message_delta: the refused output_tokens bills nothing, and never ends the stream"
    );
}

#[test]
fn truncated_recovery_refuses_a_stringified_count_and_recovers_the_readable_ones() {
    let tail = br#"...cut"}],"usage":{"input_tokens":"1500","output_tokens":9}}"#;
    let u = AnthropicReader
        .recover_truncated_usage(tail)
        .expect("the readable counts recover");
    assert_eq!((u.input, u.output), (0, 9));
    let tail = br#"...cut"}],"usage":{"output_tokens":9}}"#;
    let u = AnthropicReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}

// ── CACHE TIER / METERED DETAIL COUNTS (item 133 remainder) ─────────────────────────────────────
//
// `read_cache_tier_detail` read the 5m/1h cache-creation tiers and `web_search_requests` as
// `.and_then(read_count_u64)`, so an unreadable spelling became `None` silently. Each is now
// REFUSED on its own, loudly, as the totals are: it bills nothing and the readable counts beside it
// bill (ARCHITECT ruling 2026-10-15).

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
fn buffered_response_refuses_an_unreadable_cache_tier_or_metered_count_on_its_own() {
    for usage in unreadable_detail_usages() {
        let ir = AnthropicReader
            .read_response(crate::codec::test_host::HOST, &message(usage.clone()))
            .unwrap_or_else(|e| {
                panic!("{usage}: a refused detail count refuses only itself: {e:?}")
            });
        assert_eq!(
            (ir.usage.input_tokens, ir.usage.output_tokens),
            (5, 9),
            "{usage}: the readable totals bill as stated"
        );
        let d = &ir.usage.detail;
        assert!(
            d.cache_creation_5m_input_tokens != Some(40)
                && d.cache_creation_1h_input_tokens != Some(40)
                && d.web_search_requests.is_none(),
            "{usage}: the refused count bills nothing: {d:?}"
        );
    }
}

#[test]
fn buffered_response_tier_counts_absent_null_and_readable_still_read() {
    let ir = AnthropicReader
        .read_response(crate::codec::test_host::HOST, &message(serde_json::json!({
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
fn streaming_usage_frames_refuse_an_unreadable_cache_tier_or_metered_count_on_its_own() {
    for usage in unreadable_detail_usages() {
        let start = serde_json::json!({
            "type": "message_start",
            "message": {"id": "m", "role": "assistant", "usage": usage.clone()}
        });
        assert_eq!(
            streamed_tokens("message_start", &start),
            Some((5, 9)),
            "message_start with {usage}: the readable totals bill, the stream does not end"
        );
        let delta = serde_json::json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn"},
            "usage": usage.clone()
        });
        assert_eq!(
            streamed_tokens("message_delta", &delta),
            Some((5, 9)),
            "message_delta with {usage}: the readable totals bill, the stream does not end"
        );
    }
}
