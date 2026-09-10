// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Direct cases for the `busbar-grammar` behaviours nothing else pins.
//!
//! Each one below is a behaviour that `tests/adversarial.rs` and `tests/json_scanner.rs` leave
//! unobserved — they reach it only through another call that would move with it, so it could be
//! rewritten with every one of those tests still green: [`Span::len`]/
//! [`Span::is_empty`] pinned only through each other, the number/garbage-byte match guard in
//! `skip_value`, the quote-skipping arm inside `skip_container` (only ever exercised through a
//! STRING VALUE's own direct scan, never through a decoy CONTAINER a search has to skip past),
//! six of the nine escape-letter arms in the key-comparison decoder, the surrogate-pair
//! second-escape check's `||`, the position advance after a decoded surrogate pair, a 3-byte
//! UTF-8 lead byte, and the exact-match guard in `literal`.
//!
//! A few other survivors from that run (the `MAX_JSON_DEPTH` comparisons in `descend`/`member`/
//! `element`/`skip_value`, and the `depth + 1` arithmetic feeding them) are NOT re-tested here:
//! they are redundant with `skip_container`'s own independent, stack-size-bounded ceiling
//! (`depth + level + 1 > MAX_JSON_DEPTH`), which is mathematically invariant under the recursion
//! (the sum is conserved as `depth` grows and the remaining structural depth `level` shrinks by
//! the same amount at each pointer step) — so for any input a JSON Pointer's own semantics can
//! construct, `skip_container`'s check refuses at exactly the same total nesting `skip_container`
//! would refuse at regardless of whether the other sites' own bookkeeping is intact. See the
//! finding notes for the full argument; these are reported as equivalent/defense-in-depth rather
//! than given forced tests.

use busbar_grammar::{resolve_pointer, Resolved, Span};

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
/// number's first byte, must be refused — not silently treated as "a number of zero digits".
/// `skip_value`'s number-guard (`*c == b'-' || c.is_ascii_digit()`) exists precisely to keep this
/// byte out of `scan_number`, which would otherwise report `Ok` at the SAME position with nothing
/// consumed.
#[test]
fn a_lone_garbage_byte_is_malformed_not_an_empty_number() {
    assert_eq!(resolve_pointer(b"x", ""), Resolved::Malformed);
    assert_eq!(resolve_pointer(b"@", ""), Resolved::Malformed);
    assert_eq!(resolve_pointer(br#"{"a":@}"#, "/a"), Resolved::Malformed);
}

/// `skip_container` must skip a STRING it encounters while walking PAST a container it is not
/// interested in — not just when the string itself is the top-level value being scanned (that
/// path goes through `scan_string` directly and never touches `skip_container`'s own quote arm).
/// Here the interesting key is AFTER a decoy ARRAY whose one element is a string carrying every
/// bracket character; finding it requires `skip_container` to jump over that string whole.
#[test]
fn skip_container_steps_over_a_string_holding_bracket_characters() {
    let body = br#"{"decoy":["}{[]"],"lane":"gold"}"#;
    assert_eq!(found(body, "/lane"), br#""gold""#);
    // And nested one level deeper, so the decoy's own container is itself skipped from within an
    // object value rather than an array value.
    let body = br#"{"decoy":{"x":"}{[]"},"lane":"gold"}"#;
    assert_eq!(found(body, "/lane"), br#""gold""#);
}

/// Every one of the nine escape letters `next_json_char` recognizes decodes to its own distinct
/// character — not to "whatever the adjacent arm produces" (a deleted-arm mutant falls through to
/// the SAME `Decoded::Malformed` catch-all every other deleted arm falls through to, so a
/// per-escape assertion is the only thing that tells them apart from one another).
#[test]
fn every_recognized_escape_letter_decodes_to_its_own_character() {
    // Quote and reverse-solidus are exercised already by existing tests; the rest are not.
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
/// `||` in that guard is not `&&`: a second escape with the backslash but the wrong letter, or the
/// letter but no backslash, is just as malformed as having neither.
#[test]
fn a_surrogate_pairs_second_escape_needs_both_the_backslash_and_the_u() {
    // Backslash present, but the letter after it is not `u`.
    assert_eq!(
        resolve_pointer(b"{\"\\uD800\\xDC00\":1}", "/x"),
        Resolved::Missing,
        "a second escape spelled \\x instead of \\u is not a low surrogate"
    );
}

/// The position after decoding a full surrogate-pair character must land exactly on the byte that
/// follows it — advancing by the wrong amount would read every character after an astral escape
/// from the wrong offset for the rest of the key.
#[test]
fn a_character_after_a_surrogate_pair_decodes_from_the_right_position() {
    let body = "{\"\\uD83D\\uDE00Z\": 1}".as_bytes();
    assert_eq!(found(body, "/\u{1F600}Z"), b"1");
}

/// A 3-byte-lead UTF-8 character (U+0800..U+FFFF), embedded literally (unescaped) in a key, must
/// decode like any other multi-byte character — not be treated as an unreadable lead byte.
#[test]
fn a_three_byte_utf8_character_decodes_in_a_key() {
    let body = "{\"a\u{20ac}b\": 1}".as_bytes(); // U+20AC EURO SIGN, 3 UTF-8 bytes
    assert_eq!(found(body, "/a\u{20ac}b"), b"1");
}

/// `literal` must compare every byte of the candidate word, not merely its length — a same-length
/// impostor (`toue` where `true` was expected) is not the literal it resembles.
#[test]
fn a_same_length_impostor_literal_is_malformed() {
    assert_eq!(resolve_pointer(b"toue", ""), Resolved::Malformed);
    assert_eq!(resolve_pointer(b"nunl", ""), Resolved::Malformed);
    assert_eq!(resolve_pointer(b"folse", ""), Resolved::Malformed);
}
