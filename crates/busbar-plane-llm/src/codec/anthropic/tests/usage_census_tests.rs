// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ANTHROPIC USAGE CENSUS (MONEY-AUDIT A-F1; owner 2026-10-02: every billed count lands in an
//! existing meter class by the provider's own semantics; the plane reports units, never a price).
//!
//! The census is the pinned wire lock (`testing/llm-conformance/wire/anthropic.wire.json`, read
//! through `codec::usage_census`): every integer count it declares under the response `usage` object and under the `message_delta` stream
//! frame's `usage` has a class below, and reporting 7 more of it moves the ledgered units by exactly
//! that class on the buffered read, the truncated-body recovery and the stream tap, as both ledger
//! projections read them (the governance ledger's `tier_usage` and the plane's `Units`).

use super::super::proto_codec::ProtocolReader;
use super::AnthropicReader;
use crate::codec::usage_census::{
    at, bump, class_of, ledgered, lock_counts, moved, slot, Ledgered, CR, CW, IN, NONE, OUT,
};

/// What each Anthropic `usage` count IS, as the move one more of it makes on the ledgered units.
/// The four totals are the reserved token classes. A web search is one billed search, the open
/// class `search_units`. The 5m/1h tiers are slices of `cache_creation_input_tokens` and the
/// thinking count a slice of `output_tokens`, so neither moves a unit of its own (the per-TTL rate
/// split is escalated, A-F1). A web fetch is the open class `web_fetch_requests` (owner LEDGER-100:
/// every reported unit is a ledger line; the operator's card prices it).
const ANTHROPIC_COUNT_CLASSES: &[(&str, Ledgered)] = &[
    ("input_tokens", at(IN, 1)),
    ("output_tokens", at(OUT, 1)),
    ("cache_read_input_tokens", at(CR, 1)),
    ("cache_creation_input_tokens", at(CW, 1)),
    ("cache_creation.ephemeral_5m_input_tokens", NONE),
    ("cache_creation.ephemeral_1h_input_tokens", NONE),
    ("output_tokens_details.thinking_tokens", NONE),
    (
        "server_tool_use.web_fetch_requests",
        at(slot("web_fetch_requests"), 1),
    ),
    (
        "server_tool_use.web_search_requests",
        at(slot("search_units"), 1),
    ),
];

/// A turn that reports every count, so each is measured against a realistic neighbourhood.
fn base_usage() -> serde_json::Value {
    serde_json::json!({
        "input_tokens": 1000,
        "output_tokens": 100,
        "cache_read_input_tokens": 50,
        "cache_creation_input_tokens": 40,
        "cache_creation": {"ephemeral_5m_input_tokens": 30, "ephemeral_1h_input_tokens": 10},
        "output_tokens_details": {"thinking_tokens": 20},
        "server_tool_use": {"web_search_requests": 2, "web_fetch_requests": 1}
    })
}

/// The buffered read and the truncated-body recovery of one response carrying `usage`.
fn buffered_and_truncated(usage: &serde_json::Value) -> [Ledgered; 2] {
    let body = serde_json::json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn", "stop_sequence": null,
        "usage": usage
    });
    let buffered = AnthropicReader
        .read_response(&body)
        .expect("read")
        .usage
        .to_token_usage();
    let recovered = AnthropicReader
        .recover_truncated_usage(body.to_string().as_bytes())
        .expect("the trailing usage is recoverable");
    [ledgered(&buffered), ledgered(&recovered)]
}

/// The stream tap of a same-dialect stream whose `message_delta` carries `usage`.
fn streamed(usage: &serde_json::Value) -> Ledgered {
    let mut t = crate::codec::proto_stream::StreamTranslate::new_same_proto("anthropic")
        .expect("same-proto translator");
    let start = serde_json::json!({
        "type": "message_start",
        "message": {"id": "m", "type": "message", "role": "assistant", "model": "claude-x",
                    "content": [], "usage": {"input_tokens": 1000, "output_tokens": 1}}
    });
    let delta = serde_json::json!({
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn", "stop_sequence": null},
        "usage": usage
    });
    let _ = t.feed(format!("event: message_start\ndata: {start}\n\n").as_bytes());
    let _ = t.feed(format!("event: message_delta\ndata: {delta}\n\n").as_bytes());
    let _ = t.feed(b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
    let _ = t.finish();
    ledgered(&t.usage().expect("the tap captured usage").to_token_usage())
}

/// EVERY COUNT ANTHROPIC REPORTS IS LEDGERED IN ITS OWN CLASS, ON EVERY READ PATH. RED when the
/// reader drops a count (a web search ledgered nowhere), mis-classes one, or the lock gains a count
/// nobody classed.
#[test]
fn every_usage_count_in_the_wire_lock_is_ledgered_in_its_class() {
    let response = lock_counts("anthropic", "response", "usage.");
    assert_eq!(
        response.len(),
        ANTHROPIC_COUNT_CLASSES.len(),
        "the lock's usage counts {response:?} each need exactly one class"
    );
    let before = buffered_and_truncated(&base_usage());
    for field in &response {
        let class = class_of(ANTHROPIC_COUNT_CLASSES, field, "usage");
        let mut usage = base_usage();
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
                 every open class) by its class"
            );
        }
    }

    let stream = lock_counts("anthropic", "stream", "type=message_delta.usage.");
    assert!(
        stream
            .iter()
            .any(|f| f == "server_tool_use.web_search_requests"),
        "the stream lock names the web-search count: {stream:?}"
    );
    let before = streamed(&base_usage());
    for field in &stream {
        let class = class_of(ANTHROPIC_COUNT_CLASSES, field, "message_delta.usage");
        let mut usage = base_usage();
        bump(&mut usage, field, 7);
        assert_eq!(
            moved(streamed(&usage), before),
            class.map(|c| 7 * c),
            "stream: 7 more `message_delta.usage.{field}` must move (input, output, cache read, \
             cache write, every open class) by its class"
        );
    }
}

/// A turn's web searches reach the ledger as `search_units` on every read path, and a turn that ran
/// none puts NO `search_units` row on it: a zero is no hit on the class, so a card silent about
/// `search_units` on that lane is never refused for a turn that searched nothing.
#[test]
fn web_searches_ledger_as_search_units_and_none_is_no_row() {
    let usage = base_usage();
    let [buffered, truncated] = buffered_and_truncated(&usage);
    assert_eq!(buffered[4], 2, "buffered: 2 web searches ledgered");
    assert_eq!(truncated[4], 2, "truncated: 2 web searches ledgered");
    assert_eq!(streamed(&usage)[4], 2, "stream: 2 web searches ledgered");

    let none = serde_json::json!({
        "input_tokens": 10, "output_tokens": 5,
        "server_tool_use": {"web_search_requests": 0, "web_fetch_requests": 0}
    });
    let body = serde_json::json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x",
        "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
        "usage": none
    });
    let u = AnthropicReader
        .read_response(&body)
        .expect("read")
        .usage
        .to_token_usage();
    assert!(
        !crate::codec::wire_shim::tier_usage(&u)
            .usage_units
            .contains_key(crate::codec::ir::rerank::SEARCH_UNITS_CLASS),
        "a zero search count is no search_units row"
    );
}

/// A turn's web fetches reach the ledger as exactly one `web_fetch_requests` line on every read
/// path (buffered, truncated, stream), beside its searches and its tokens, and move no other class
/// (owner LEDGER-100). RED before this lane: the reader did not read the count at all.
#[test]
fn web_fetches_ledger_as_web_fetch_requests_on_every_path() {
    let usage = base_usage();
    let fetch = slot("web_fetch_requests");
    let [buffered, truncated] = buffered_and_truncated(&usage);
    let streamed = streamed(&usage);
    for (path, l) in [
        ("buffered", buffered),
        ("truncated", truncated),
        ("stream", streamed),
    ] {
        assert_eq!(l[fetch], 1, "{path}: 1 web fetch ledgered");
        let lines = l[4..].iter().filter(|n| **n != 0).count();
        assert_eq!(
            lines, 2,
            "{path}: searches and fetches, one line each: {l:?}"
        );
    }
}
