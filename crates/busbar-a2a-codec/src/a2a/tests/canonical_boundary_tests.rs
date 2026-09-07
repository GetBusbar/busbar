// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EDGES OF RFC 8785's ESCAPE RULE, which the vector suite beside this one steps over.
//!
//! `canonical_tests.rs` grades the canonicalizer against the RFC's own vectors, and those vectors
//! are about VALUES — the shapes a document takes. This file is about a BOUNDARY: the single
//! comparison `(c as u32) < 0x20` that decides, for every character in every string in every Agent
//! Card, whether it is escaped or emitted literally.
//!
//! Mutation testing found that comparison unguarded. Relaxing it to `<=` — one character's worth of
//! difference, U+0020, the SPACE — left the whole suite green. That is not a cosmetic difference:
//! the canonical form is the JWS payload a signed Agent Card's signature is verified against, and
//! the preimage of the pinned card fingerprint. A canonicalizer that writes `"\u0020"` where every
//! other implementation writes `" "` verifies no signature any other implementation produced and
//! raises a permanent false drift alarm on every card containing a space — which is every card with
//! a human-readable `description`.
//!
//! The existing vector reaches U+0001 and U+001F on the escaped side and U+007F on the literal
//! side. It never touches U+0020 itself, and U+0020 is the boundary. So the cells here walk the
//! three characters either side of the line and assert the line is exactly where the RFC puts it.

use super::*;
use serde_json::json;

fn c(v: &Value) -> String {
    canonicalize(v).expect("canonicalizable")
}

/// RFC 8785 section 3.2.2.2: `\u` escaping applies BELOW U+0020 and stops there. U+001F is the last
/// escaped code point and U+0020 — the space — is the first literal one.
///
/// Both sides of the line in one cell, because either alone is satisfiable by a comparison that is
/// off by one in the other direction.
#[test]
fn the_escape_boundary_sits_below_the_space_and_not_at_it() {
    // The last code point that IS escaped.
    assert_eq!(
        c(&json!("\u{1f}")),
        r#""\u001f""#,
        "U+001F is below U+0020 and RFC 8785 escapes it"
    );
    // The first code point that is NOT — a space is a space, not `\u0020`.
    assert_eq!(
        c(&json!("\u{20}")),
        "\" \"",
        "U+0020 (SPACE) must be emitted literally; escaping it changes the JWS payload every \
         signed Agent Card is verified against"
    );
    // And the one above it, so the rule reads as a floor rather than as a hole at exactly 0x20.
    assert_eq!(c(&json!("\u{21}")), "\"!\"");
}

/// A space in a REALISTIC card field, not as a lone character. This is the cell that says what the
/// boundary costs: an ordinary human-readable description is the common case, and a canonicalizer
/// that escapes its spaces produces a byte string no second implementation reproduces.
#[test]
fn an_ordinary_sentence_canonicalizes_with_its_spaces_intact() {
    let out = c(&json!({"description": "A helpful agent."}));
    assert_eq!(out, r#"{"description":"A helpful agent."}"#);
    assert!(
        !out.contains("\\u0020"),
        "a space was escaped: `{out}` — the fingerprint of this card is now busbar's alone"
    );
}

/// U+0000 is the OTHER end of the escaped range, and the vector suite starts at U+0001. A
/// comparison that became `> 0` rather than `< 0x20` would still escape U+0001..U+001F and emit a
/// RAW NUL byte, which is legal in a Rust `str` and is not legal JSON at all.
#[test]
fn the_null_character_is_escaped_rather_than_emitted_raw() {
    let out = c(&json!("\u{0}"));
    assert_eq!(out, r#""\u0000""#);
    assert!(
        !out.contains('\u{0}'),
        "a raw NUL reached the canonical form, which is not JSON any parser accepts"
    );
}

/// Every control character in the range is escaped, and each one's escape is the FOUR-DIGIT
/// lower-case hex form RFC 8785 section 3.2.2.2 specifies — not three digits, not upper case, and
/// not the shorter `\x` form some serializers emit. The seven characters with a dedicated
/// two-character escape are excluded because for those the RFC says the SHORTEST escape wins.
#[test]
fn every_remaining_control_character_takes_the_four_digit_lower_case_escape() {
    let shortest_form_has_its_own_escape = ['\u{8}', '\u{9}', '\u{a}', '\u{c}', '\u{d}'];
    let mut checked = 0;
    for cp in 0x00u32..0x20 {
        let ch = char::from_u32(cp).expect("control code point");
        if shortest_form_has_its_own_escape.contains(&ch) {
            continue;
        }
        let out = c(&json!(ch.to_string()));
        assert_eq!(
            out,
            format!("\"\\u{cp:04x}\""),
            "U+{cp:04X} did not take the four-digit lower-case escape"
        );
        checked += 1;
    }
    // The floor that stops this loop from passing by checking nothing: 32 control code points less
    // the 5 with a dedicated escape.
    assert_eq!(
        checked, 27,
        "the loop skipped code points it should have checked"
    );
}

/// The five characters RFC 8785 gives a dedicated two-character escape keep it, rather than
/// falling through to the `\u` form. `\b \t \n \f \r` are shorter, and section 3.2.2.2 says the
/// shortest escape wins — so a canonicalizer that wrote `\u0009` for a tab would be legal JSON with
/// a different fingerprint.
#[test]
fn the_five_short_escapes_are_preferred_over_the_unicode_form() {
    for (ch, expected) in [
        ('\u{8}', r#""\b""#),
        ('\u{9}', r#""\t""#),
        ('\u{a}', r#""\n""#),
        ('\u{c}', r#""\f""#),
        ('\u{d}', r#""\r""#),
    ] {
        let out = c(&json!(ch.to_string()));
        assert_eq!(out, expected, "U+{:04X} lost its short escape", ch as u32);
        assert!(
            !out.contains("\\u"),
            "U+{:04X} took the long form when a shorter one exists",
            ch as u32
        );
    }
}

/// A KEY is written through the same string writer as a value, so the boundary must hold on both.
/// Object names are the half the signature's member ordering is taken over, so an escape that
/// appears only in names is an escape that changes the sort AND the bytes.
#[test]
fn the_escape_boundary_holds_for_object_names_as_well_as_values() {
    assert_eq!(c(&json!({"a b": 1})), r#"{"a b":1}"#);
    assert_eq!(c(&json!({"a\u{1f}b": 1})), r#"{"a\u001fb":1}"#);
}

/// `CanonicalError`'s `Display` is what an operator reads when a fingerprint cannot be taken, and
/// mutation replaced the whole implementation with `Ok(())` — an EMPTY message — without a test
/// noticing. A refusal that renders to nothing is a refusal nobody can act on: the log line says a
/// card could not be canonicalized and then does not say why.
#[test]
fn the_canonical_refusal_renders_a_message_that_names_the_cause() {
    let rendered = CanonicalError::NonFiniteNumber.to_string();
    assert!(
        !rendered.is_empty(),
        "the refusal rendered to nothing at all"
    );
    assert!(
        rendered.contains("finite") || rendered.contains("NaN") || rendered.contains("infinit"),
        "`{rendered}` does not name the non-finite number that caused it"
    );
}
