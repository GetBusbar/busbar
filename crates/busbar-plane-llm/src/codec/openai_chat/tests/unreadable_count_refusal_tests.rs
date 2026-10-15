//! ITEM 133 — A PRESENT-BUT-UNREADABLE BILLED COUNT IS REFUSED ON ITS OWN; IT IS NEVER LEDGERED AS
//! ZERO (#42), AND IT REFUSES NOTHING ELSE (ARCHITECT ruling 2026-10-15).
//!
//! The OpenAI Chat reader used to read every billed count as `.and_then(read_count_u64).unwrap_or(0)`,
//! so a stringified `"1500"` from a compatible self-hosted backend reached the ledger as ZERO tokens
//! for work that happened. Each usage field is now judged on its own: the unreadable one is REFUSED
//! (warned loudly, it bills nothing, nothing stands in for it) and the readable ones bill as stated,
//! on the buffered read, the streamed usage chunk and the truncated-tail recovery alike.
//! `{"prompt_tokens":"1500","completion_tokens":9}` bills (0, 9), v1.5.5's figure for that body. An
//! ABSENT count keeps its meaning — zero — and still reads.
use super::*;

#[test]
fn buffered_response_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let body = serde_json::json!({
        "id": "c", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": "1500", "completion_tokens": 9}
    });
    let ir = OpenAiReader
        .read_response(crate::codec::test_host::HOST, &body)
        .expect("an unreadable count refuses itself, never the answer");
    assert_eq!(
        (ir.usage.input_tokens, ir.usage.output_tokens),
        (0, 9),
        "the refused prompt_tokens bills nothing; completion_tokens bills as stated"
    );
}

#[test]
fn buffered_response_with_an_absent_count_still_reads_as_zero() {
    let body = serde_json::json!({
        "id": "c", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "usage": {"completion_tokens": 9}
    });
    let ir = OpenAiReader
        .read_response(crate::codec::test_host::HOST, &body)
        .expect("an absent count is zero");
    assert_eq!(ir.usage.input_tokens, 0);
    assert_eq!(ir.usage.output_tokens, 9);
}

#[test]
fn streaming_usage_chunk_refuses_a_stringified_count_and_bills_the_readable_ones() {
    let mut state = crate::codec::ir::StreamDecodeState::default();
    let chunk = serde_json::json!({
        "id": "c", "object": "chat.completion.chunk", "model": "gpt-4o",
        "choices": [],
        "usage": {"prompt_tokens": 10, "completion_tokens": "9"}
    });
    let ev =
        OpenAiReader.read_response_events(crate::codec::test_host::HOST, "", &chunk, &mut state);
    assert!(
        !ev.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
        "an unreadable count refuses itself, never the stream; got {ev:?}"
    );
    let streamed = ev
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta { usage, .. } => Some(usage.to_token_usage()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the usage chunk carries its readable usage: {ev:?}"));
    assert_eq!(
        (streamed.input, streamed.output),
        (10, 0),
        "prompt_tokens bills as stated; the refused completion_tokens bills nothing"
    );
}

#[test]
fn truncated_recovery_refuses_a_stringified_count_and_recovers_the_readable_ones() {
    let tail = br#"...cut"}}],"usage":{"prompt_tokens":"1500","completion_tokens":9}}"#;
    let u = OpenAiReader
        .recover_truncated_usage(tail)
        .expect("the readable counts recover");
    assert_eq!((u.input, u.output), (0, 9));
    let tail = br#"...cut"}}],"usage":{"completion_tokens":9}}"#;
    let u = OpenAiReader
        .recover_truncated_usage(tail)
        .expect("an absent count still recovers");
    assert_eq!((u.input, u.output), (0, 9));
}

// ── THE CACHE-WRITE SLICE ────────────────────────────────────────────────────────────────────────
//
// `prompt_tokens_details.cache_write_tokens` is not a ledgered count: it is a slice of
// `prompt_tokens` billed at the input tier, exactly as 1.5.5 billed it (v1.5.5
// `crates/busbar/src/proto/openai_chat/reader.rs:966` buffered and `:693` stream,
// `cache_creation_input_tokens: None`). So no spelling of it moves the bill or refuses the answer.

fn chat_body(usage: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": "c", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "usage": usage
    })
}

/// The cache-write slice bills inside the input on every path and in every spelling, as in 1.5.5:
/// the buffered answer, the `include_usage` chunk and the truncated recovery each ledger input 100,
/// output 9 and no cache write. RED while the reader split the slice out to the cache-write tier
/// (input 60, cache write 40) or refused its stringified spelling.
#[test]
fn cache_write_tokens_bill_inside_the_input_on_every_path() {
    for spelling in [
        serde_json::json!(40),
        serde_json::json!("40"),
        serde_json::Value::Null,
    ] {
        let usage = serde_json::json!({
            "prompt_tokens": 100, "completion_tokens": 9,
            "prompt_tokens_details": {"cache_write_tokens": spelling}
        });
        let ir = OpenAiReader
            .read_response(crate::codec::test_host::HOST, &chat_body(usage.clone()))
            .expect("the cache-write slice never refuses the answer");
        let t = ir.usage.to_token_usage();
        assert_eq!((t.input, t.output, t.cache_creation), (100, 9, None));

        let mut state = crate::codec::ir::StreamDecodeState::default();
        let chunk = serde_json::json!({
            "id": "c", "object": "chat.completion.chunk", "model": "gpt-4o",
            "choices": [],
            "usage": usage
        });
        let ev = OpenAiReader.read_response_events(
            crate::codec::test_host::HOST,
            "",
            &chunk,
            &mut state,
        );
        let streamed = ev
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::MessageDelta { usage, .. } => Some(usage.to_token_usage()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("the usage chunk carries its usage: {ev:?}"));
        assert_eq!(
            (streamed.input, streamed.output, streamed.cache_creation),
            (100, 9, None)
        );

        let tail = format!(r#"...cut"}}}}],"usage":{usage}}}"#);
        let recovered = OpenAiReader
            .recover_truncated_usage(tail.as_bytes())
            .expect("the usage recovers");
        assert_eq!(
            (recovered.input, recovered.output, recovered.cache_creation),
            (100, 9, None)
        );
    }
}
