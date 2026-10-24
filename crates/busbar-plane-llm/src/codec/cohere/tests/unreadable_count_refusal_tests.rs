//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT IS REFUSED ON ITS OWN; IT IS NEVER LEDGERED AS
//! ZERO (#42), AND IT REFUSES NOTHING ELSE (ARCHITECT ruling 2026-10-15).
//!
//! The Cohere reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
//! so a stringified `"1500"` from a compatible self-hosted backend reached the ledger as ZERO tokens
//! for work that happened. Each usage field is now judged on its own: the unreadable one is REFUSED
//! (warned loudly, it bills nothing, nothing stands in for it) and the readable ones bill as stated,
//! on the buffered read, the streamed `message-end` and the truncated-tail recovery alike. An ABSENT
//! count keeps its meaning — zero — and still reads.
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
fn buffered_response_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let ir = CohereReader
        .read_response(
            crate::codec::test_host::HOST,
            &body(serde_json::json!({"tokens": {"input_tokens": "1500", "output_tokens": 9}})),
        )
        .expect("an unreadable count refuses itself, never the answer");
    let t = ir.usage.to_token_usage();
    assert_eq!((t.input, t.output), (0, 9));
    let ir = CohereReader
        .read_response(
            crate::codec::test_host::HOST,
            &body(serde_json::json!({"billed_units": {"input_tokens": "1500"}})),
        )
        .expect("an unreadable billed count refuses itself, never the answer");
    let t = ir.usage.to_token_usage();
    assert_eq!(
        (t.input, t.output),
        (0, 0),
        "the refused billed input bills nothing"
    );
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let ir = CohereReader
        .read_response(
            crate::codec::test_host::HOST,
            &body(serde_json::json!({"tokens": {"output_tokens": 9}})),
        )
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

/// The (input, output) a streamed `message-end` with `usage` carries, and its events.
fn message_end(usage: serde_json::Value) -> (Option<(u64, u64)>, Vec<IrStreamEvent>) {
    let mut state = crate::codec::ir::StreamDecodeState::default();
    let ev = CohereReader.read_response_events(
        crate::codec::test_host::HOST,
        "",
        &serde_json::json!({
            "type": "message-end",
            "delta": {"finish_reason": "COMPLETE", "usage": usage}
        }),
        &mut state,
    );
    let tokens = ev.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { usage, .. } => {
            let t = usage.to_token_usage();
            Some((t.input, t.output))
        }
        _ => None,
    });
    (tokens, ev)
}

#[test]
fn streaming_message_end_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let (tokens, ev) =
        message_end(serde_json::json!({"tokens": {"input_tokens": 10, "output_tokens": "5"}}));
    assert!(
        !ev.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
        "an unreadable count refuses itself, never the stream; got {ev:?}"
    );
    assert_eq!(tokens, Some((10, 0)), "{ev:?}");
}

#[test]
fn truncated_recovery_refuses_a_stringified_count_and_recovers_the_readable_ones() {
    let tail = br#"...cut"}],"usage":{"tokens":{"input_tokens":"1500","output_tokens":9}}}"#;
    let u = CohereReader
        .recover_truncated_usage(tail)
        .expect("the readable counts recover");
    assert_eq!((u.input, u.output), (0, 9));
    let tail = br#"...cut"}],"usage":{"tokens":{"output_tokens":9}}}"#;
    let u = CohereReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}

// ── ITEM 133 REMAINDER: `billed_units.search_units` / `billed_units.classifications` ─────────────
//
// These two rode the lenient `.and_then(read_count_u64)` after the rest of the bucket was fixed, so
// a present-but-unreadable spelling became `None` — indistinguishable from "not reported" — and the
// unit silently vanished. Absent or `null` keeps meaning `None`; a readable count is the count; an
// unreadable one is REFUSED on its own, loudly, on every path: it bills nothing and the readable
// counts beside it bill (ARCHITECT ruling 2026-10-15).

const BILLED_UNIT_FIELDS: [&str; 2] = ["search_units", "classifications"];

fn billed_units(field: &str, value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "tokens": {"input_tokens": 10, "output_tokens": 5},
        "billed_units": {field: value}
    })
}

#[test]
fn buffered_response_refuses_an_unreadable_billed_unit_on_its_own() {
    for field in BILLED_UNIT_FIELDS {
        let ir = CohereReader
            .read_response(
                crate::codec::test_host::HOST,
                &body(billed_units(field, serde_json::json!("3"))),
            )
            .unwrap_or_else(|e| panic!("billed_units.{field}: refuses only itself: {e:?}"));
        assert_eq!(ir.usage.detail.search_units, None, "{field}");
        assert_eq!(ir.usage.detail.billed_classifications, None, "{field}");
        let t = ir.usage.to_token_usage();
        assert_eq!(
            (t.input, t.output),
            (10, 5),
            "{field}: the tokens bill as stated"
        );
    }
}

#[test]
fn buffered_response_reads_a_readable_absent_or_null_billed_unit() {
    let ir = CohereReader
        .read_response(
            crate::codec::test_host::HOST,
            &body(serde_json::json!({
                "tokens": {"input_tokens": 10, "output_tokens": 5},
                "billed_units": {"search_units": 3.0, "classifications": 2}
            })),
        )
        .expect("readable billed units read");
    assert_eq!(ir.usage.detail.search_units, Some(3));
    assert_eq!(ir.usage.detail.billed_classifications, Some(2));
    for field in BILLED_UNIT_FIELDS {
        let ir = CohereReader
            .read_response(
                crate::codec::test_host::HOST,
                &body(billed_units(field, serde_json::Value::Null)),
            )
            .expect("a null billed unit is absence, not a refusal");
        assert_eq!(ir.usage.detail.search_units, None);
        assert_eq!(ir.usage.detail.billed_classifications, None);
    }
}

#[test]
fn streaming_message_end_refuses_an_unreadable_billed_unit_on_its_own() {
    for field in BILLED_UNIT_FIELDS {
        let (tokens, ev) = message_end(billed_units(field, serde_json::json!("3")));
        assert!(
            !ev.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
            "billed_units.{field}: refuses only itself, never the stream; got {ev:?}"
        );
        assert_eq!(tokens, Some((10, 5)), "{field}: {ev:?}");
    }
}

#[test]
fn truncated_recovery_refuses_an_unreadable_billed_unit_on_its_own() {
    for field in BILLED_UNIT_FIELDS {
        let tail = format!(
            r#"...cut"}}],"usage":{{"tokens":{{"input_tokens":10,"output_tokens":5}},"billed_units":{{"{field}":"3"}}}}}}"#
        );
        let u = CohereReader
            .recover_truncated_usage(tail.as_bytes())
            .unwrap_or_else(|| panic!("billed_units.{field}: the readable counts recover"));
        assert_eq!((u.input, u.output), (10, 5), "{field}");
    }
    let tail = br#"...cut"}],"usage":{"tokens":{"input_tokens":10,"output_tokens":5},"billed_units":{"search_units":null}}}"#;
    let u = CohereReader
        .recover_truncated_usage(tail)
        .expect("a null billed unit still recovers");
    assert_eq!((u.input, u.output), (10, 5));
}

#[test]
fn rerank_response_refuses_unreadable_search_units_rather_than_billing_flat() {
    use crate::codec::cohere::handler::read_rerank_response;
    let wire = |su: &str| {
        format!(r#"{{"id":"r1","results":[],"meta":{{"billed_units":{{"search_units":{su}}}}}}}"#)
    };
    assert!(
        read_rerank_response(wire(r#""3""#).as_bytes()).is_err(),
        "search_units:\"3\" is present and unreadable: a refusal, never the flat marker"
    );
    assert_eq!(
        read_rerank_response(wire("3").as_bytes())
            .expect("readable")
            .search_units,
        Some(3)
    );
    assert_eq!(
        read_rerank_response(wire("null").as_bytes())
            .expect("null is absence")
            .search_units,
        None
    );
}

#[test]
fn embeddings_response_refuses_an_unreadable_billed_input() {
    use crate::codec::cohere::handler::read_embeddings_response;
    let wire = |n: &str| {
        format!(
            r#"{{"id":"e1","embeddings":{{"float":[[0.1]]}},"meta":{{"billed_units":{{"input_tokens":{n}}}}}}}"#
        )
    };
    assert!(
        read_embeddings_response(wire(r#""1500""#).as_bytes()).is_err(),
        "billed input_tokens:\"1500\" is a refusal, never \"no usage reported\""
    );
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
