// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::percent_decode;

#[test]
fn a_percent_sign_that_cannot_carry_two_more_bytes_does_not_panic() {
    assert_eq!(percent_decode("%"), "%");
    assert_eq!(percent_decode("a%"), "a%");
    assert_eq!(percent_decode("a%2"), "a%2");
}

#[test]
fn a_percent_sign_immediately_before_a_multibyte_character_does_not_panic() {
    assert_eq!(percent_decode("%€"), "%€");

    assert_eq!(percent_decode("%aé"), "%aé");

    assert_eq!(percent_decode("%\u{1F600}"), "%\u{1F600}");
}

#[test]
fn a_well_formed_percent_escape_still_decodes() {
    assert_eq!(percent_decode("%2B"), "+");
    assert_eq!(percent_decode("a%20b"), "a b");
    assert_eq!(percent_decode("%e2%82%ac"), "€");
}
