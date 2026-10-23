//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT IS REFUSED ON ITS OWN; IT IS NEVER LEDGERED AS
//! ZERO (#42), AND IT REFUSES NOTHING ELSE (ARCHITECT ruling 2026-10-15).
//!
//! The Bedrock reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
//! so a stringified `"1500"` from a compatible self-hosted backend reached the ledger as ZERO tokens
//! for work that happened. Each usage field is now judged on its own: the unreadable one is REFUSED
//! (warned loudly, it bills nothing, nothing stands in for it, and no stated-total gap prices it
//! back in) and the readable ones bill as stated, on the buffered read, the streamed metadata and
//! the truncated-tail recovery alike. An ABSENT count keeps its meaning — zero — and still reads.
use super::*;

#[test]
fn buffered_response_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": "1500", "outputTokens": 9, "totalTokens": 1509}
    });
    let ir = BedrockReader
        .read_response(crate::codec::test_host::HOST, &body)
        .expect("an unreadable count refuses itself, never the answer");
    assert_eq!((ir.usage.input_tokens, ir.usage.output_tokens), (0, 9));
    assert_eq!(
        ir.usage.detail.usage_identity_note, None,
        "no stated-total gap prices the refused count back in"
    );
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {"outputTokens": 9}
    });
    let ir = BedrockReader
        .read_response(crate::codec::test_host::HOST, &body)
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

/// The (input, output) the streamed metadata frame's events carry, after a `messageStop`.
fn metadata_tokens(usage: serde_json::Value) -> Vec<IrStreamEvent> {
    let mut state = crate::codec::ir::StreamDecodeState::default();
    BedrockReader.read_response_events(
        crate::codec::test_host::HOST,
        "",
        &serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        &mut state,
    );
    BedrockReader.read_response_events(
        crate::codec::test_host::HOST,
        "",
        &serde_json::json!({"type": "metadata", "usage": usage}),
        &mut state,
    )
}

fn delta_tokens(ev: &[IrStreamEvent]) -> Option<(u64, u64)> {
    ev.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { usage, .. } => {
            Some((usage.input_tokens, usage.output_tokens))
        }
        _ => None,
    })
}

#[test]
fn streaming_metadata_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let ev = metadata_tokens(serde_json::json!({"inputTokens": 5, "outputTokens": "27"}));
    assert!(
        !ev.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
        "an unreadable count refuses itself, never the stream; got {ev:?}"
    );
    assert_eq!(delta_tokens(&ev), Some((5, 0)), "{ev:?}");
}

#[test]
fn truncated_recovery_refuses_a_stringified_count_and_recovers_the_readable_ones() {
    let tail = br#"...cut"}],"usage":{"inputTokens":"1500","outputTokens":9}}"#;
    let u = BedrockReader
        .recover_truncated_usage(tail)
        .expect("the readable counts recover");
    assert_eq!((u.input, u.output), (0, 9));
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
// `read_cache_details` SKIPPED a 5m/1h entry whose `inputTokens` would not read, silently. Each is
// now REFUSED on its own, loudly, on every path: it bills nothing and the readable counts beside it
// bill (ARCHITECT ruling 2026-10-15).

fn converse(usage: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": usage
    })
}

#[test]
fn buffered_response_refuses_an_unreadable_cache_count_on_its_own() {
    for usage in [
        serde_json::json!({"inputTokens": 5, "outputTokens": 9, "cacheReadInputTokens": "40"}),
        serde_json::json!({"inputTokens": 5, "outputTokens": 9, "cacheWriteInputTokens": "40"}),
        serde_json::json!({"inputTokens": 5, "outputTokens": 9, "cacheWriteInputTokens": 40,
                           "cacheDetails": [{"ttl": "5m", "inputTokens": "40"}]}),
    ] {
        let ir = BedrockReader
            .read_response(crate::codec::test_host::HOST, &converse(usage.clone()))
            .unwrap_or_else(|e| {
                panic!("{usage}: a refused cache count refuses only itself: {e:?}")
            });
        assert_eq!(
            (ir.usage.input_tokens, ir.usage.output_tokens),
            (5, 9),
            "{usage}: the readable totals bill as stated"
        );
        assert_eq!(ir.usage.cache_read_input_tokens, None, "{usage}");
        assert_eq!(
            ir.usage.detail.cache_creation_5m_input_tokens, None,
            "{usage}"
        );
    }
}

#[test]
fn buffered_response_cache_counts_absent_null_readable_and_unknown_ttl_still_read() {
    let ir = BedrockReader
        .read_response(
            crate::codec::test_host::HOST,
            &converse(serde_json::json!({
                "inputTokens": 5, "outputTokens": 9,
                "cacheReadInputTokens": null, "cacheWriteInputTokens": 60,
                "cacheDetails": [
                    {"ttl": "1h", "inputTokens": 20},
                    {"ttl": "5m", "inputTokens": 40},
                    {"ttl": "5m"},
                    {"ttl": "9d", "inputTokens": "not a tier this build prices"}
                ]
            })),
        )
        .expect("absent, null, readable and unknown-TTL entries all read");
    assert_eq!(ir.usage.cache_read_input_tokens, None);
    assert_eq!(ir.usage.cache_creation_input_tokens, Some(60));
    assert_eq!(ir.usage.detail.cache_creation_5m_input_tokens, Some(40));
    assert_eq!(ir.usage.detail.cache_creation_1h_input_tokens, Some(20));
}

#[test]
fn streaming_metadata_refuses_an_unreadable_cache_count_on_its_own() {
    for usage in [
        serde_json::json!({"inputTokens": 5, "outputTokens": 9, "cacheReadInputTokens": "40"}),
        serde_json::json!({"inputTokens": 5, "outputTokens": 9,
                           "cacheDetails": [{"ttl": "1h", "inputTokens": "40"}]}),
    ] {
        let ev = metadata_tokens(usage.clone());
        assert!(
            !ev.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
            "{usage}: an unreadable cache count refuses itself, never the stream; got {ev:?}"
        );
        assert_eq!(delta_tokens(&ev), Some((5, 9)), "{usage}: {ev:?}");
    }
}

#[test]
fn truncated_recovery_refuses_an_unreadable_cache_tier_on_its_own() {
    let tail = br#"...cut"}],"usage":{"inputTokens":5,"outputTokens":9,"cacheDetails":[{"ttl":"5m","inputTokens":"40"}]}}"#;
    let u = BedrockReader
        .recover_truncated_usage(tail)
        .expect("the readable counts recover");
    assert_eq!((u.input, u.output), (5, 9));
}

// ── EMBEDDINGS AND RERANK (LLM3#6, LLM2#12) ──────────────────────────────────────────────────────
//
// The Titan embeddings and the rerank answers judge their billed count the same way the Converse
// table does: an unreadable one is refused ON ITS OWN, it bills nothing, and the answer is served.
// Refusing the whole answer turned a delivered answer into a 500 with no usage, where v1.5.5's
// `.and_then(Value::as_u64)` served it and billed no usage (v1.5.5 `handlers/bedrock.rs:243-249`).

#[test]
fn embeddings_response_refuses_an_unreadable_billed_input_on_its_own() {
    use crate::codec::bedrock::handler::read_embeddings_response;
    let wire = |n: &str| format!(r#"{{"embedding":[0.1],"inputTextTokenCount":{n}}}"#);
    let served = read_embeddings_response(wire(r#""1500""#).as_bytes())
        .expect("an unreadable count refuses itself, never the answer");
    assert_eq!(
        served.usage, None,
        "inputTextTokenCount:\"1500\" bills nothing: v1.5.5's figure for the body"
    );
    assert_eq!(served.embeddings.len(), 1, "the vector is served");
    assert_eq!(
        read_embeddings_response(wire("1500").as_bytes())
            .expect("readable")
            .usage
            .map(|u| u.input),
        Some(1500)
    );
    assert!(read_embeddings_response(wire("null").as_bytes())
        .expect("null is absence")
        .usage
        .is_none());
}

#[test]
fn rerank_response_refuses_unreadable_search_units_on_its_own() {
    use crate::codec::bedrock::handler::read_rerank_response;
    let wire = |su: &str| {
        format!(
            r#"{{"id":"r1","results":[{{"index":0,"relevance_score":0.5}}],"meta":{{"billed_units":{{"search_units":{su}}}}}}}"#
        )
    };
    let served = read_rerank_response(wire(r#""3""#).as_bytes())
        .expect("an unreadable count refuses itself, never the ranking");
    assert_eq!(
        served.search_units, None,
        "it bills the flat marker, as 1.5.5 did"
    );
    assert_eq!(served.results.len(), 1, "the ranking is served");
    assert_eq!(
        read_rerank_response(wire("3").as_bytes())
            .expect("readable")
            .search_units,
        Some(3)
    );
}
