// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which claim a request matches, checked over EVERY selector form the vocabulary carries -- the
//! forms this plane declares, and the forms it is handed no facts to answer.

use busbar_contract::grammar::{PathSeg, Selector};
use busbar_plane_llm::claims::{dialect_for, matches_selector};

fn no_headers(_: &str) -> Option<&'static str> {
    None
}

/// The pattern form is answered by the contract's own matcher, not by a copy of it. The copy is
/// gone; this is the case that proves the shared one is really what runs -- a variable takes one
/// segment and a path with a segment too few or too many matches neither.
#[test]
fn the_pattern_form_is_the_contracts_own_answer() {
    const P: &[PathSeg] = &[PathSeg::Lit("model"), PathSeg::Var, PathSeg::Lit("invoke")];
    let s = Selector::PathPattern(P);
    assert!(matches_selector(&s, "/model/a.claude/invoke", &no_headers));
    assert!(!matches_selector(&s, "/model/a.claude", &no_headers));
    assert!(!matches_selector(
        &s,
        "/model/a.claude/invoke/extra",
        &no_headers
    ));
    assert_eq!(
        dialect_for("/model/a.claude/invoke", &no_headers),
        Some("bedrock")
    );
}

/// A form about the CONNECTION is not answered from a path and a header lookup, because neither
/// carries it. `false` here is a stated answer, not a wildcard's shrug -- and the compiler now
/// requires a stated answer for every form the vocabulary grows.
#[test]
fn a_form_this_plane_is_handed_no_facts_for_never_matches() {
    for s in [
        Selector::Sni("api.openai.com"),
        Selector::ClientCertSubject("CN=anyone"),
        Selector::StreamName("chat"),
        Selector::Alpn("h2"),
        Selector::Port(443),
    ] {
        assert!(
            !matches_selector(&s, "/v1/chat/completions", &no_headers),
            "{s:?} was answered from facts this plane does not have"
        );
    }
}

/// The forms the ladder actually declares answer exactly as they did before every form was
/// written out: this is the ladder, walked, and the dialect each rung names.
#[test]
fn the_declared_ladder_answers_unchanged() {
    assert_eq!(
        dialect_for("/v1/chat/completions", &no_headers),
        Some("openai")
    );
    assert_eq!(dialect_for("/v2/chat", &no_headers), Some("cohere"));
    assert_eq!(dialect_for("/v1/responses", &no_headers), Some("responses"));
    assert_eq!(
        dialect_for("/v1beta/models/gemini:generateContent", &no_headers),
        Some("gemini")
    );
    assert_eq!(
        dialect_for("/anything", &|n: &str| (n == "x-api-key").then_some("k")),
        Some("anthropic")
    );
    assert_eq!(dialect_for("/nothing/here", &no_headers), None);
}
