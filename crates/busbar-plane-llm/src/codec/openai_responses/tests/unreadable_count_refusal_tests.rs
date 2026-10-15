//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT IS REFUSED ON ITS OWN; IT IS NEVER LEDGERED AS
//! ZERO (#42), AND IT REFUSES NOTHING ELSE (ARCHITECT ruling 2026-10-15).
//!
//! The OpenAI Responses reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
//! so a stringified `"1500"` from a compatible self-hosted backend reached the ledger as ZERO tokens
//! for work that happened. Each usage field is now judged on its own: the unreadable one is REFUSED
//! (warned loudly, it bills nothing, nothing stands in for it, and no stated-total gap prices it
//! back in) and the readable ones bill as stated, on the buffered read, the streamed terminal and
//! the truncated-tail recovery alike. An ABSENT count keeps its meaning — zero — and still reads.
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
fn buffered_response_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let ir = ResponsesReader
        .read_response(
            crate::codec::test_host::HOST,
            &response(serde_json::json!({"input_tokens": "1500", "output_tokens": 9, "total_tokens": 1509})),
        )
        .expect("an unreadable count refuses itself, never the answer");
    assert_eq!((ir.usage.input_tokens, ir.usage.output_tokens), (0, 9));
    assert_eq!(
        ir.usage.detail.usage_identity_note, None,
        "no stated-total gap prices the refused count back in"
    );
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let ir = ResponsesReader
        .read_response(
            crate::codec::test_host::HOST,
            &response(serde_json::json!({"output_tokens": 9})),
        )
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

/// The (input, output) a `response.completed` terminal's events carry, and the events.
fn completed_tokens(usage: serde_json::Value) -> (Option<(u64, u64)>, Vec<IrStreamEvent>) {
    let mut state = crate::codec::ir::StreamDecodeState::default();
    let completed = serde_json::json!({
        "response": {"status": STATUS_COMPLETED, "usage": usage}
    });
    let ev = ResponsesReader.read_response_events(
        crate::codec::test_host::HOST,
        EVT_RESPONSE_COMPLETED,
        &completed,
        &mut state,
    );
    let tokens = ev.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { usage, .. } => {
            Some((usage.input_tokens, usage.output_tokens))
        }
        _ => None,
    });
    (tokens, ev)
}

#[test]
fn streaming_terminal_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let (tokens, ev) =
        completed_tokens(serde_json::json!({"input_tokens": 10, "output_tokens": "9"}));
    assert!(
        !ev.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
        "an unreadable count refuses itself, never the stream; got {ev:?}"
    );
    assert_eq!(tokens, Some((10, 0)), "{ev:?}");
}

#[test]
fn truncated_recovery_refuses_a_stringified_count_and_recovers_the_readable_ones() {
    let tail = br#"...cut"}]}],"usage":{"input_tokens":"1500","output_tokens":9}}"#;
    let u = ResponsesReader
        .recover_truncated_usage(tail)
        .expect("the readable counts recover");
    assert_eq!((u.input, u.output), (0, 9));
    let tail = br#"...cut"}]}],"usage":{"output_tokens":9}}"#;
    let u = ResponsesReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}

// ── CACHE COUNTS (item 133 remainder) ────────────────────────────────────────────────────────────
//
// `read_cached_tokens` read `input_tokens_details.cached_tokens` as `.and_then(read_count_u64)`,
// so an unreadable spelling became `None` silently. It is now REFUSED on its own, loudly, on every
// path: it bills nothing (no cache read, and no slice taken out of the stated `input_tokens`) and
// the readable counts bill as stated (ARCHITECT ruling 2026-10-15). `input_tokens_details.cache_write_tokens` is not a ledgered count:
// it is a slice of `input_tokens` billed at the input tier, as 1.5.5 billed it (v1.5.5
// `crates/busbar/src/proto/openai_responses/reader.rs:1022`, `:1341`), so no spelling of it moves
// the bill or refuses the answer.

#[test]
fn buffered_response_refuses_an_unreadable_cache_count_on_its_own() {
    let ir = ResponsesReader
        .read_response(
            crate::codec::test_host::HOST,
            &response(serde_json::json!({
                "input_tokens": 100, "output_tokens": 9,
                "input_tokens_details": {"cached_tokens": "40"}
            })),
        )
        .expect("a refused cache count refuses only itself");
    assert_eq!(ir.usage.cache_read_input_tokens, None);
    assert_eq!((ir.usage.input_tokens, ir.usage.output_tokens), (100, 9));
}

#[test]
fn buffered_response_cache_counts_absent_null_and_readable_still_read() {
    let ir = ResponsesReader
        .read_response(
            crate::codec::test_host::HOST,
            &response(serde_json::json!({
                "input_tokens": 100, "output_tokens": 9,
                "input_tokens_details": {"cached_tokens": null}
            })),
        )
        .expect("a null cache count is absence");
    assert_eq!(ir.usage.cache_read_input_tokens, None);
    assert_eq!(ir.usage.cache_creation_input_tokens, None);
    let ir = ResponsesReader
        .read_response(
            crate::codec::test_host::HOST,
            &response(serde_json::json!({
                "input_tokens": 100, "output_tokens": 9,
                "input_tokens_details": {"cached_tokens": 30, "cache_write_tokens": 20}
            })),
        )
        .expect("readable cache counts read");
    assert_eq!(ir.usage.cache_read_input_tokens, Some(30));
    // 1.5.5: the 20 cache-write tokens stay in the input (100 - 30 cached = 70), no cache write.
    assert_eq!(ir.usage.cache_creation_input_tokens, None);
    assert_eq!(ir.usage.input_tokens, 70);
}

#[test]
fn streaming_terminal_refuses_an_unreadable_cache_count_on_its_own() {
    let (tokens, ev) = completed_tokens(serde_json::json!({
        "input_tokens": 100, "output_tokens": 9, "input_tokens_details": {"cached_tokens": "40"}
    }));
    assert!(
        !ev.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
        "a refused cache count refuses only itself; got {ev:?}"
    );
    assert_eq!(tokens, Some((100, 9)), "{ev:?}");
}

/// The cache-write slice bills inside the input on every path and in every spelling, as in 1.5.5:
/// the buffered answer, the stream terminal and the truncated recovery each ledger input 100,
/// output 9 and no cache write. RED while the reader split the slice out to the cache-write tier
/// (input 60, cache write 40) or refused its stringified spelling.
#[test]
fn cache_write_tokens_bill_inside_the_input_on_every_path() {
    for spelling in [serde_json::json!(40), serde_json::json!("40")] {
        let usage = serde_json::json!({
            "input_tokens": 100, "output_tokens": 9,
            "input_tokens_details": {"cache_write_tokens": spelling}
        });
        let ir = ResponsesReader
            .read_response(crate::codec::test_host::HOST, &response(usage.clone()))
            .expect("the cache-write slice never refuses the answer");
        let t = ir.usage.to_token_usage();
        assert_eq!((t.input, t.output, t.cache_creation), (100, 9, None));
        let mut state = crate::codec::ir::StreamDecodeState::default();
        let completed = serde_json::json!({
            "response": {"status": STATUS_COMPLETED, "usage": usage}
        });
        let ev = ResponsesReader.read_response_events(
            crate::codec::test_host::HOST,
            EVT_RESPONSE_COMPLETED,
            &completed,
            &mut state,
        );
        let streamed = ev
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::MessageDelta { usage, .. } => Some(usage.to_token_usage()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("the terminal carries its usage: {ev:?}"));
        assert_eq!(
            (streamed.input, streamed.output, streamed.cache_creation),
            (100, 9, None)
        );
        let tail = format!(r#"...cut"}}]}}],"usage":{usage}}}"#);
        let recovered = ResponsesReader
            .recover_truncated_usage(tail.as_bytes())
            .expect("the usage recovers");
        assert_eq!(
            (recovered.input, recovered.output, recovered.cache_creation),
            (100, 9, None)
        );
    }
}
