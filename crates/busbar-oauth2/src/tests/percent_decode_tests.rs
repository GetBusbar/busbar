// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-oauth2/src/routes.rs` — the `percent_decode_tests` battery.

use super::percent_decode;

// A trailing `%` (or a `%` too close to the end to carry two more bytes) used to be sliced as
// `&s[i+1..i+3]` on the `&str`, which panics when the missing bytes would have landed inside a
// multibyte UTF-8 character rather than simply running past the end of an all-ASCII string.
// Anyone who could get a query string in front of this decoder could crash the process.
#[test]
fn a_percent_sign_that_cannot_carry_two_more_bytes_does_not_panic() {
    assert_eq!(percent_decode("%"), "%");
    assert_eq!(percent_decode("a%"), "a%");
    assert_eq!(percent_decode("a%2"), "a%2");
}

// The historical panic path: a `%` sitting immediately before a multibyte UTF-8 character. The
// old code computed byte indices `i+1..i+3` from ASCII-counting logic and handed them straight
// to `&str` slicing, which panics unless both endpoints fall on a char boundary. `é` is a
// 2-byte character, so `i+3` from a preceding `%` lands inside it.
#[test]
fn a_percent_sign_immediately_before_a_multibyte_character_does_not_panic() {
    // `€` is 3 UTF-8 bytes, so the old `i+1..i+3` slice split its 2nd and 3rd bytes.
    assert_eq!(percent_decode("%€"), "%€");
    // A hex-looking ASCII byte followed by a 2-byte character shifts the split into the
    // character's interior instead.
    assert_eq!(percent_decode("%aé"), "%aé");
    // The exact case named in the defect report: a `%` immediately followed by an emoji, a
    // 4-byte character.
    assert_eq!(percent_decode("%\u{1F600}"), "%\u{1F600}");
}

#[test]
fn a_well_formed_percent_escape_still_decodes() {
    assert_eq!(percent_decode("%2B"), "+");
    assert_eq!(percent_decode("a%20b"), "a b");
    assert_eq!(percent_decode("%e2%82%ac"), "€");
}
