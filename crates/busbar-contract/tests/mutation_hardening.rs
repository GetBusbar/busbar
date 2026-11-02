// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mutation-hardening tests for `busbar-grammar`.

use busbar_contract::spans::{resolve_pointer, Resolved, Span};

fn found<'b>(body: &'b [u8], pointer: &str) -> &'b [u8] {
    match resolve_pointer(body, pointer) {
        Resolved::Found(span) => span.of(body),
        other => panic!("{pointer} did not resolve against {body:?}: {other:?}"),
    }
}

#[test]
fn span_len_and_is_empty_are_pinned_to_independent_values() {
    assert_eq!(Span::new(0, 0).len(), 0);
    assert_eq!(Span::new(2, 5).len(), 3);
    assert_eq!(Span::new(5, 2).len(), 0, "an inverted span covers no bytes");
    assert_eq!(Span::new(0, 1_000_000).len(), 1_000_000);

    assert!(Span::new(0, 0).is_empty());
    assert!(Span::new(5, 5).is_empty());
    assert!(!Span::new(0, 1).is_empty());
    assert!(
        Span::new(5, 2).is_empty(),
        "an inverted span has len() == 0, so it counts as empty too"
    );
}

/// A byte that is neither a container opener, a string quote, a literal's first letter, nor a
#[test]
fn a_lone_garbage_byte_is_malformed_not_an_empty_number() {
    assert_eq!(resolve_pointer(b"x", ""), Resolved::Malformed);
    assert_eq!(resolve_pointer(b"@", ""), Resolved::Malformed);
    assert_eq!(resolve_pointer(br#"{"a":@}"#, "/a"), Resolved::Malformed);
}

/// `skip_container` must skip a STRING it encounters while walking PAST a container it is not
#[test]
fn skip_container_steps_over_a_string_holding_bracket_characters() {
    let body = br#"{"decoy":["}{[]"],"lane":"gold"}"#;
    assert_eq!(found(body, "/lane"), br#""gold""#);

    let body = br#"{"decoy":{"x":"}{[]"},"lane":"gold"}"#;
    assert_eq!(found(body, "/lane"), br#""gold""#);
}

/// Every one of the nine escape letters `next_json_char` recognizes decodes to its own distinct
#[test]
fn every_recognized_escape_letter_decodes_to_its_own_character() {
    assert_eq!(
        found(b"{\"a\\\\b\":1}", "/a\\b"),
        b"1",
        "\\\\ must decode to \\"
    );
    assert_eq!(
        found(b"{\"a\\/b\":1}", "/a~1b"),
        b"1",
        "\\/ must decode to /"
    );
    assert_eq!(
        found(b"{\"a\\bb\":1}", "/a\u{8}b"),
        b"1",
        "\\b must decode to U+0008"
    );
    assert_eq!(
        found(b"{\"a\\fb\":1}", "/a\u{c}b"),
        b"1",
        "\\f must decode to U+000C"
    );
    assert_eq!(
        found(b"{\"a\\nb\":1}", "/a\nb"),
        b"1",
        "\\n must decode to U+000A"
    );
    assert_eq!(
        found(b"{\"a\\rb\":1}", "/a\rb"),
        b"1",
        "\\r must decode to U+000D"
    );
    assert_eq!(
        found(b"{\"a\\tb\":1}", "/a\tb"),
        b"1",
        "\\t must decode to U+0009"
    );
}

/// A surrogate pair's second escape must have BOTH the backslash and the `u` in the right place —
#[test]
fn a_surrogate_pairs_second_escape_needs_both_the_backslash_and_the_u() {
    assert_eq!(
        resolve_pointer(b"{\"\\uD800\\xDC00\":1}", "/x"),
        Resolved::Missing,
        "a second escape spelled \\x instead of \\u is not a low surrogate"
    );
}

/// The position after decoding a full surrogate-pair character must land exactly on the byte that
#[test]
fn a_character_after_a_surrogate_pair_decodes_from_the_right_position() {
    let body = "{\"\\uD83D\\uDE00Z\": 1}".as_bytes();
    assert_eq!(found(body, "/\u{1F600}Z"), b"1");
}

/// A 3-byte-lead UTF-8 character (U+0800..U+FFFF), embedded literally (unescaped) in a key, must
#[test]
fn a_three_byte_utf8_character_decodes_in_a_key() {
    let body = "{\"a\u{20ac}b\": 1}".as_bytes();
    assert_eq!(found(body, "/a\u{20ac}b"), b"1");
}

/// `literal` must compare every byte of the candidate word, not merely its length — a same-length
#[test]
fn a_same_length_impostor_literal_is_malformed() {
    assert_eq!(resolve_pointer(b"toue", ""), Resolved::Malformed);
    assert_eq!(resolve_pointer(b"nunl", ""), Resolved::Malformed);
    assert_eq!(resolve_pointer(b"folse", ""), Resolved::Malformed);
}
