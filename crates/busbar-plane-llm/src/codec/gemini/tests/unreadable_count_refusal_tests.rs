//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT IS REFUSED ON ITS OWN; IT IS NEVER LEDGERED AS
//! ZERO (#42), AND IT REFUSES NOTHING ELSE (ARCHITECT ruling 2026-10-15).
//!
//! The Gemini reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
//! so a stringified `"1500"` from a compatible self-hosted backend reached the ledger as ZERO tokens
//! for work that happened. Each usage field is now judged on its own: the unreadable one is REFUSED
//! (warned loudly, it bills nothing, nothing stands in for it) and the readable ones bill as stated,
//! on the buffered read, the streamed terminal chunk and the truncated-tail recovery alike. An
//! ABSENT count keeps its meaning — zero — and still reads.
use super::*;

fn body(usage: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
        "usageMetadata": usage
    })
}

#[test]
fn buffered_response_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let ir = GeminiReader
        .read_response(
            crate::codec::test_host::HOST,
            &body(serde_json::json!({"promptTokenCount": "1500", "candidatesTokenCount": 9})),
        )
        .expect("an unreadable count refuses itself, never the answer");
    assert_eq!((ir.usage.input_tokens, ir.usage.output_tokens), (0, 9));
    let ir = GeminiReader
        .read_response(
            crate::codec::test_host::HOST,
            &body(serde_json::json!({"promptTokenCount": 10, "thoughtsTokenCount": "400"})),
        )
        .expect("an unreadable thinking count refuses itself, never the answer");
    assert_eq!(
        (ir.usage.input_tokens, ir.usage.output_tokens),
        (10, 0),
        "the refused thinking tokens add nothing to the output"
    );
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let ir = GeminiReader
        .read_response(
            crate::codec::test_host::HOST,
            &body(serde_json::json!({"candidatesTokenCount": 9})),
        )
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

#[test]
fn streaming_terminal_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let mut state = crate::codec::ir::StreamDecodeState::default();
    let ev = GeminiReader.read_response_events(
        crate::codec::test_host::HOST,
        "",
        &body(serde_json::json!({"promptTokenCount": 18, "candidatesTokenCount": "89"})),
        &mut state,
    );
    assert!(
        !ev.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
        "an unreadable count refuses itself, never the stream; got {ev:?}"
    );
    let streamed = ev
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta { usage, .. } => {
                Some((usage.input_tokens, usage.output_tokens))
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("the terminal chunk carries its readable usage: {ev:?}"));
    assert_eq!(streamed, (18, 0));
}

#[test]
fn truncated_recovery_refuses_a_stringified_count_and_recovers_the_readable_ones() {
    let tail =
        br#"...cut"}],"usageMetadata":{"promptTokenCount":"1500","candidatesTokenCount":9}}"#;
    let u = GeminiReader
        .recover_truncated_usage(tail)
        .expect("the readable counts recover");
    assert_eq!((u.input, u.output), (0, 9));
    let tail = br#"...cut"}],"usageMetadata":{"candidatesTokenCount":9}}"#;
    let u = GeminiReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}

// ── EMBEDDINGS (item 133 remainder) ──────────────────────────────────────────────────────────────
//
// `read_embeddings_response` read `usageMetadata.promptTokenCount` as
// `.and_then(read_count_u64).map(|n| TokenUsage{input:n,..})` — a lenient read whose `None` flowed
// straight through the `.map`, so a stringified `"1500"` was billed as NO usage at all (0 input)
// rather than refusing. Now read through `billed_count_opt`.

#[test]
fn embeddings_response_refuses_an_unreadable_billed_input() {
    use crate::codec::gemini::handler::read_embeddings_response;
    let wire = |n: &str| {
        format!(r#"{{"embedding":{{"values":[0.1]}},"usageMetadata":{{"promptTokenCount":{n}}}}}"#)
    };
    assert!(
        read_embeddings_response(wire(r#""1500""#).as_bytes()).is_err(),
        "promptTokenCount:\"1500\" is present and unreadable: a refusal, never \"no usage reported\""
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
