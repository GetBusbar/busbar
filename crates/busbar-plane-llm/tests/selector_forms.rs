// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every selector form this plane answers, answered BOTH ways.
//!
//! The claim walk is public so the crate's own conformance tests can reach every arm, and the
//! existing walk covers the forms the ladder declares plus the connection-shaped forms that are
//! always `false`. What it does not cover is the two forms the ladder happens not to use today —
//! an exact path and an exact header value — and an arm nothing exercises is an arm that can be
//! inverted without a single test noticing. A future rung spelled with either form would then
//! match every request except the one it names.
//!
//! Each form is asserted on a value that matches AND on a value that does not, because a matcher
//! stuck at `true` and a matcher stuck at `false` are both matchers that are not matching.

use busbar_contract::grammar::{PathSeg, Selector};
use busbar_plane_llm::claims::matches_selector;

fn no_headers(_: &str) -> Option<&'static str> {
    None
}

/// A header lookup over one fixed pair.
fn header_of<'h>(want: &'static str, value: &'h str) -> impl Fn(&str) -> Option<&'h str> {
    move |name: &str| (name == want).then_some(value)
}

/// An EXACT path matches that path and nothing else — not a prefix of it, not a path with it as a
/// prefix, and not a path that differs in one byte.
#[test]
fn the_exact_path_form_matches_only_that_path() {
    let s = Selector::ExactPath("/v1/chat/completions");
    assert!(matches_selector(&s, "/v1/chat/completions", &no_headers));
    assert!(!matches_selector(&s, "/v1/chat/completion", &no_headers));
    assert!(!matches_selector(
        &s,
        "/v1/chat/completions/extra",
        &no_headers
    ));
    assert!(!matches_selector(&s, "/v1/chat", &no_headers));
    assert!(!matches_selector(&s, "", &no_headers));
}

/// An EXACT header matches the named header carrying exactly that value.
///
/// A different value on the right header, the right value on a different header, and an absent
/// header are all non-matches: an inverted comparison here would claim every request whose header
/// says anything BUT the declared value, which is every other vendor's traffic.
#[test]
fn the_exact_header_form_matches_only_that_name_and_value() {
    let s = Selector::HeaderExact("x-vendor", "acme");
    assert!(matches_selector(
        &s,
        "/anything",
        &header_of("x-vendor", "acme")
    ));
    assert!(!matches_selector(
        &s,
        "/anything",
        &header_of("x-vendor", "other")
    ));
    assert!(!matches_selector(
        &s,
        "/anything",
        &header_of("x-other", "acme")
    ));
    assert!(!matches_selector(&s, "/anything", &no_headers));
}

/// A header PRESENT form asks only whether the header arrived, whatever it carries — including
/// empty.
#[test]
fn the_header_present_form_asks_only_whether_it_arrived() {
    let s = Selector::HeaderPresent("anthropic-version");
    assert!(matches_selector(
        &s,
        "/anything",
        &header_of("anthropic-version", "2023-06-01")
    ));
    assert!(matches_selector(
        &s,
        "/anything",
        &header_of("anthropic-version", "")
    ));
    assert!(!matches_selector(
        &s,
        "/anything",
        &header_of("anthropic-beta", "x")
    ));
    assert!(!matches_selector(&s, "/anything", &no_headers));
}

/// A header PREFIX form matches a value that starts with the prefix, and not one that merely
/// contains it.
#[test]
fn the_header_prefix_form_matches_only_at_the_start() {
    let s = Selector::HeaderPrefix("authorization", "AWS4-HMAC-SHA256");
    assert!(matches_selector(
        &s,
        "/anything",
        &header_of("authorization", "AWS4-HMAC-SHA256 Credential=x")
    ));
    assert!(matches_selector(
        &s,
        "/anything",
        &header_of("authorization", "AWS4-HMAC-SHA256")
    ));
    assert!(!matches_selector(
        &s,
        "/anything",
        &header_of("authorization", "Bearer AWS4-HMAC-SHA256")
    ));
    assert!(!matches_selector(
        &s,
        "/anything",
        &header_of("authorization", "AWS4-HMAC")
    ));
    assert!(!matches_selector(&s, "/anything", &no_headers));
}

/// A path SUFFIX form matches at the end and nowhere else.
#[test]
fn the_path_suffix_form_matches_only_at_the_end() {
    let s = Selector::PathSuffix("/v1/embeddings");
    assert!(matches_selector(&s, "/v1/embeddings", &no_headers));
    assert!(matches_selector(&s, "/openai/v1/embeddings", &no_headers));
    assert!(!matches_selector(&s, "/v1/embeddings/batch", &no_headers));
    assert!(!matches_selector(&s, "/v1/embedding", &no_headers));
}

/// A path CONTAINS form matches anywhere in the target, and not at all when the needle is absent.
#[test]
fn the_path_contains_form_matches_anywhere_in_the_target() {
    let s = Selector::PathContains("/converse");
    assert!(matches_selector(&s, "/model/claude/converse", &no_headers));
    assert!(matches_selector(
        &s,
        "/model/claude/converse-stream",
        &no_headers
    ));
    assert!(!matches_selector(&s, "/model/claude/invoke", &no_headers));
}

/// A one-level prefix form reaches exactly one segment past the prefix, and no deeper.
#[test]
fn the_one_level_prefix_form_reaches_exactly_one_segment() {
    let s = Selector::PrefixOneLevel("/v1/admin");
    assert!(matches_selector(&s, "/v1/admin/keys", &no_headers));
    assert!(!matches_selector(&s, "/v1/admin/keys/abc", &no_headers));
    assert!(!matches_selector(&s, "/v2/admin/keys", &no_headers));
}

/// A pattern form takes one segment per variable and swallows the rest at a tail.
#[test]
fn the_pattern_form_counts_segments_and_swallows_a_tail() {
    const MODELS: &[PathSeg] = &[
        PathSeg::Lit("v1beta"),
        PathSeg::Lit("models"),
        PathSeg::Var,
        PathSeg::Tail,
    ];
    let s = Selector::PathPattern(MODELS);
    assert!(matches_selector(&s, "/v1beta/models/gemini", &no_headers));
    assert!(matches_selector(
        &s,
        "/v1beta/models/gemini/anything/else",
        &no_headers
    ));
    assert!(!matches_selector(&s, "/v1beta/models", &no_headers));
    assert!(!matches_selector(&s, "/v1/models/gemini", &no_headers));
}
