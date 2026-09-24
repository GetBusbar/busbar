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

// ── ITEM 133 REMAINDER: `billed_units.search_units` / `billed_units.classifications` ─────────────
//
// These two rode the lenient `.and_then(read_count_u64)` after the rest of the bucket was fixed, so
// a present-but-unreadable spelling became `None` — indistinguishable from "not reported" — and the
// unit silently vanished. Absent or `null` keeps meaning `None`; a readable count is the count; an
// unreadable one REFUSES on every path.

const BILLED_UNIT_FIELDS: [&str; 2] = ["search_units", "classifications"];

fn billed_units(field: &str, value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "tokens": {"input_tokens": 10, "output_tokens": 5},
        "billed_units": {field: value}
    })
}

#[test]
fn buffered_response_refuses_an_unreadable_billed_unit() {
    for field in BILLED_UNIT_FIELDS {
        CohereReader
            .read_response(&body(billed_units(field, serde_json::json!("3"))))
            .expect_err(&format!(
                "a present, unreadable billed_units.{field} is a refusal, never a dropped unit"
            ));
    }
}

#[test]
fn buffered_response_reads_a_readable_absent_or_null_billed_unit() {
    let ir = CohereReader
        .read_response(&body(serde_json::json!({
            "tokens": {"input_tokens": 10, "output_tokens": 5},
            "billed_units": {"search_units": 3.0, "classifications": 2}
        })))
        .expect("readable billed units read");
    assert_eq!(ir.usage.detail.search_units, Some(3));
    assert_eq!(ir.usage.detail.billed_classifications, Some(2));
    for field in BILLED_UNIT_FIELDS {
        let ir = CohereReader
            .read_response(&body(billed_units(field, serde_json::Value::Null)))
            .expect("a null billed unit is absence, not a refusal");
        assert_eq!(ir.usage.detail.search_units, None);
        assert_eq!(ir.usage.detail.billed_classifications, None);
    }
}

#[test]
fn streaming_message_end_refuses_an_unreadable_billed_unit() {
    for field in BILLED_UNIT_FIELDS {
        let mut state = crate::ir::StreamDecodeState::default();
        let ev = CohereReader.read_response_events(
            "",
            &serde_json::json!({
                "type": "message-end",
                "delta": {"finish_reason": "COMPLETE", "usage": billed_units(field, serde_json::json!("3"))}
            }),
            &mut state,
        );
        assert!(
            matches!(ev.as_slice(), [IrStreamEvent::Error(_)]),
            "message-end with an unreadable billed_units.{field} must end the stream in an error, \
             not drop the unit; got {ev:?}"
        );
    }
}

#[test]
fn truncated_recovery_yields_no_usage_for_an_unreadable_billed_unit() {
    for field in BILLED_UNIT_FIELDS {
        let tail = format!(
            r#"...cut"}}],"usage":{{"tokens":{{"input_tokens":10,"output_tokens":5}},"billed_units":{{"{field}":"3"}}}}}}"#
        );
        assert_eq!(
            CohereReader.recover_truncated_usage(tail.as_bytes()),
            None,
            "an unreadable billed_units.{field} yields no recovered usage (the caller bills its floor)"
        );
    }
    let tail = br#"...cut"}],"usage":{"tokens":{"input_tokens":10,"output_tokens":5},"billed_units":{"search_units":null}}}"#;
    let u = CohereReader
        .recover_truncated_usage(tail)
        .expect("a null billed unit still recovers");
    assert_eq!((u.input, u.output), (10, 5));
}

#[test]
fn rerank_response_refuses_unreadable_search_units_rather_than_billing_flat() {
    use crate::cohere::handler::read_rerank_response;
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
    use crate::cohere::handler::read_embeddings_response;
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
