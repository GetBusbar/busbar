// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COHERE USAGE CENSUS (MONEY-AUDIT A-F1; owner 2026-10-02: every billed count lands in an
//! existing meter class by the provider's own semantics; the plane reports units, never a price).
//!
//! The census is the pinned wire lock (`testing/llm-conformance/wire/cohere.wire.json`, read through
//! `codec::usage_census`). Cohere's spec types every count as a JSON `number`, so a census that read
//! only `integer` members found none; this one reads both. Every count the lock declares under the
//! response `usage` and the `message-end` frame's `delta.usage` has a class below, and reporting 7
//! more of it moves the ledgered units by exactly that class on the buffered read, the
//! truncated-body recovery and the stream tap, through both ledger projections.

use super::*;
use crate::codec::usage_census::{bump, class_of, ledgered, lock_counts, moved, Ledgered};

/// Which turn a count is measured on. Cohere invoices `billed_units`, whose token counts WIN the
/// reserved input/output classes over the raw `tokens` (`IrUsage::to_token_usage`), so a raw count
/// is measured on a turn that reports no billed tokens, where it is what the ledger holds.
#[derive(Clone, Copy)]
enum Turn {
    /// Raw `tokens`, the cache hit and every `billed_units` count.
    Billed,
    /// Raw `tokens` and the cache hit only.
    Raw,
}

/// What each Cohere `usage` count IS, as the move one more of it makes on the ledgered units
/// (input, output, cache read, cache write, `search_units`), and the turn it is measured on. The
/// billed token counts are the reserved input/output classes; the cache hit is a cache read out of
/// the input; `search_units` is the open class `search_units`. `classifications` is a RESIDUAL: no
/// meter class the LLM plane declares carries it, so the reader WARNs it and it moves nothing.
const COHERE_COUNT_CLASSES: &[(&str, (Turn, Ledgered))] = &[
    ("tokens.input_tokens", (Turn::Raw, [1, 0, 0, 0, 0])),
    ("tokens.output_tokens", (Turn::Raw, [0, 1, 0, 0, 0])),
    ("cached_tokens", (Turn::Billed, [-1, 0, 1, 0, 0])),
    ("billed_units.input_tokens", (Turn::Billed, [1, 0, 0, 0, 0])),
    (
        "billed_units.output_tokens",
        (Turn::Billed, [0, 1, 0, 0, 0]),
    ),
    ("billed_units.search_units", (Turn::Billed, [0, 0, 0, 0, 1])),
    (
        "billed_units.classifications",
        (Turn::Billed, [0, 0, 0, 0, 0]),
    ),
];

fn base_usage(turn: Turn) -> serde_json::Value {
    match turn {
        Turn::Billed => serde_json::json!({
            "tokens": {"input_tokens": 1000, "output_tokens": 100},
            "cached_tokens": 50,
            "billed_units": {"input_tokens": 1000, "output_tokens": 100,
                             "search_units": 2, "classifications": 1}
        }),
        Turn::Raw => serde_json::json!({
            "tokens": {"input_tokens": 1000, "output_tokens": 100},
            "cached_tokens": 50
        }),
    }
}

/// The buffered read and the truncated-body recovery of one response carrying `usage`.
fn buffered_and_truncated(usage: &serde_json::Value) -> [Ledgered; 2] {
    let body = serde_json::json!({
        "id": "c1",
        "finish_reason": "COMPLETE",
        "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
        "usage": usage
    });
    let buffered = CohereReader
        .read_response(&body)
        .expect("read")
        .usage
        .to_token_usage();
    let recovered = CohereReader
        .recover_truncated_usage(body.to_string().as_bytes())
        .expect("the trailing usage is recoverable");
    [ledgered(&buffered), ledgered(&recovered)]
}

/// The stream tap of a same-dialect stream whose `message-end` carries `usage`.
fn streamed(usage: &serde_json::Value) -> Ledgered {
    let mut t = crate::codec::proto_stream::StreamTranslate::new_same_proto("cohere")
        .expect("same-proto translator");
    let end = serde_json::json!({
        "type": "message-end",
        "delta": {"finish_reason": "COMPLETE", "usage": usage}
    });
    let _ = t.feed(b"data: {\"type\":\"message-start\",\"id\":\"m\"}\n\n");
    let _ = t.feed(
        b"data: {\"type\":\"content-delta\",\"index\":0,\"delta\":{\"message\":{\"content\":{\"text\":\"hi\"}}}}\n\n",
    );
    let _ = t.feed(format!("data: {end}\n\n").as_bytes());
    let _ = t.finish();
    ledgered(&t.usage().expect("the tap captured usage").to_token_usage())
}

/// EVERY COUNT COHERE REPORTS IS LEDGERED IN ITS OWN CLASS, ON EVERY READ PATH. RED when the reader
/// drops a count (a chat's billed search units ledgered nowhere), mis-classes one, or the lock gains
/// a count nobody classed.
#[test]
fn every_usage_count_in_the_wire_lock_is_ledgered_in_its_class() {
    let response = lock_counts("cohere", "response", "usage.");
    assert_eq!(
        response.len(),
        COHERE_COUNT_CLASSES.len(),
        "the lock's usage counts {response:?} each need exactly one class"
    );
    for field in &response {
        let (turn, class) = class_of(COHERE_COUNT_CLASSES, field, "usage");
        let before = buffered_and_truncated(&base_usage(turn));
        let mut usage = base_usage(turn);
        bump(&mut usage, field, 7);
        let after = buffered_and_truncated(&usage);
        for (path, (a, b)) in ["buffered", "truncated"]
            .iter()
            .zip(after.iter().zip(before.iter()))
        {
            assert_eq!(
                moved(*a, *b),
                class.map(|c| 7 * c),
                "{path}: 7 more `usage.{field}` must move (input, output, cache read, cache write, \
                 search_units) by its class"
            );
        }
    }

    let stream = lock_counts("cohere", "stream", "type=message-end.delta.usage.");
    assert_eq!(
        stream.len(),
        COHERE_COUNT_CLASSES.len(),
        "the stream lock's usage counts {stream:?} each need exactly one class"
    );
    for field in &stream {
        let (turn, class) = class_of(COHERE_COUNT_CLASSES, field, "message-end.delta.usage");
        let before = streamed(&base_usage(turn));
        let mut usage = base_usage(turn);
        bump(&mut usage, field, 7);
        assert_eq!(
            moved(streamed(&usage), before),
            class.map(|c| 7 * c),
            "stream: 7 more `message-end.delta.usage.{field}` must move (input, output, cache read, \
             cache write, search_units) by its class"
        );
    }
}

/// A chat's billed search units reach the ledger as `search_units` on every read path; a residual
/// `classifications` count is ledgered under no class at all.
#[test]
fn chat_search_units_ledger_and_classifications_ledger_nowhere() {
    let usage = base_usage(Turn::Billed);
    let [buffered, truncated] = buffered_and_truncated(&usage);
    assert_eq!(buffered[4], 2, "buffered: 2 search units ledgered");
    assert_eq!(truncated[4], 2, "truncated: 2 search units ledgered");
    assert_eq!(streamed(&usage)[4], 2, "stream: 2 search units ledgered");
    let u = CohereReader
        .read_response(&serde_json::json!({
            "id": "c1", "finish_reason": "COMPLETE",
            "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
            "usage": usage
        }))
        .expect("read")
        .usage
        .to_token_usage();
    let classes: Vec<String> = crate::codec::wire_shim::tier_usage(&u)
        .usage_units
        .into_keys()
        .collect();
    assert!(
        !classes.iter().any(|c| c.contains("classif")),
        "classifications is a residual, never a ledger class: {classes:?}"
    );
}
