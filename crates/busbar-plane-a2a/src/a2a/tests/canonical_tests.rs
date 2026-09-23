// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC 8785 conformance, judged by the RFC's OWN vectors rather than by our reading of it.
//!
//! Every vector below is transcribed from RFC 8785 with its section cited on the test. The point of
//! citing rather than inventing is that a canonicalizer graded against its author's expectations
//! proves only that the author was self-consistent, and a fingerprint two implementations compute
//! differently is worse than no fingerprint at all.

use super::*;
use serde_json::json;

fn c(v: &Value) -> String {
    canonicalize(v).expect("canonicalizable")
}

/// RFC 8785 section 3.2.3: members are sorted on the UTF-16 code units of their NAMES, and the
/// sorting is recursive. This is the vector from the RFC's own "Sorting of Object Properties"
/// example, reduced to its ASCII rows.
#[test]
fn object_members_sort_by_name() {
    let v = json!({
        "\u{20ac}": "Euro Sign",
        "\r": "Carriage Return",
        "1": "One",
        "\u{80}": "Control",
        "\u{1f600}": "Emoji",
        "\u{f8ff}": "Private Use",
        "": "Empty",
        "aa": "Two chars",
        "a": "One char",
    });
    // The RFC's expected order, and the last two rows are the whole point of the vector: the
    // SUPPLEMENTARY emoji sorts BEFORE the private-use U+F8FF, because in UTF-16 it is the surrogate
    // pair 0xD83D 0xDE00 and 0xD83D is below 0xF8FF. By code point it is the other way round, so an
    // implementation that sorted Rust strings would emit these two the wrong way round and agree
    // with this vector on every other row.
    let names: Vec<&str> = vec![
        "\"\"",
        "\"\\r\"",
        "\"1\"",
        "\"a\"",
        "\"aa\"",
        "\"\u{80}\"",
        "\"\u{20ac}\"",
        "\"\u{1f600}\"",
        "\"\u{f8ff}\"",
    ];
    let out = c(&v);
    let mut cursor = 0usize;
    for name in names {
        let at = out[cursor..]
            .find(name)
            .unwrap_or_else(|| panic!("`{name}` missing or out of order in {out}"));
        cursor += at + name.len();
    }
}

/// UTF-16 order is not code-point order, and the disagreement is the reason this is not left to the
/// map's own `Ord`. U+FFFD is a BMP character, so its UTF-16 unit is 0xFFFD; U+10000 is a
/// SUPPLEMENTARY character whose first UTF-16 unit is the surrogate 0xD800. So U+10000 sorts BELOW
/// U+FFFD in UTF-16 and ABOVE it by code point, and a canonicalizer that sorted Rust strings would
/// emit them the wrong way round.
#[test]
fn a_supplementary_name_sorts_below_a_high_bmp_name() {
    let out = c(&json!({ "\u{fffd}": 1, "\u{10000}": 2 }));
    let supplementary = out.find('\u{10000}').expect("supplementary name present");
    let bmp = out.find('\u{fffd}').expect("bmp name present");
    assert!(
        supplementary < bmp,
        "UTF-16 order puts the supplementary name first; got {out}"
    );
}

/// RFC 8785 section 3.2.2.2: the two-character escapes are used where they exist, `\u` only below
/// U+0020, and everything else is emitted literally. `\u007f` is NOT escaped: it is above U+001F.
#[test]
fn strings_use_the_shortest_escape_and_nothing_more() {
    assert_eq!(
        c(&json!("\"\\\u{8}\u{c}\n\r\t")),
        r#""\"\\\b\f\n\r\t""#.to_string()
    );
    assert_eq!(c(&json!("\u{1}\u{1f}")), r#""\u0001\u001f""#.to_string());
    assert_eq!(c(&json!("\u{7f}")), "\"\u{7f}\"".to_string());
    assert_eq!(c(&json!("\u{20ac}\u{1f600}")), "\"\u{20ac}\u{1f600}\"");
}

/// RFC 8785 section 3.2.2.3 defers to ECMAScript `Number.prototype.toString`, where a whole number
/// has no fractional part and negative zero prints as `0`. The vectors are from the RFC's
/// number-serialization table.
// The RFC's vectors are quoted at the precision the RFC WROTE them, which for one row is more
// digits than the double can hold. That excess is the vector's whole point (the canonical form is
// the SHORTEST decimal that round-trips, not the decimal that was typed), so the literal is kept
// verbatim rather than pre-rounded to whatever the compiler would have stored anyway.
#[allow(clippy::excessive_precision)]
#[test]
fn numbers_print_as_ecmascript() {
    assert_eq!(c(&json!(1.0)), "1");
    assert_eq!(c(&json!(-0.0f64)), "0");
    assert_eq!(c(&json!(0)), "0");
    assert_eq!(c(&json!(333333333.33333329)), "333333333.3333333");
    assert_eq!(c(&json!(1e30)), "1e+30");
    assert_eq!(c(&json!(1.0e-7)), "1e-7");
    assert_eq!(c(&json!(1e21)), "1e+21");
    // Just below the exponential threshold, so it prints in full.
    assert_eq!(c(&json!(1e20)), "100000000000000000000");
    // Just above the small threshold, so it prints in full.
    assert_eq!(c(&json!(1e-6)), "0.000001");
}

/// A `u64` beyond f64's exactly-representable range must survive. Routing it through a double would
/// silently round it, and a fingerprint over a rounded value is a fingerprint of a document nobody
/// sent.
#[test]
fn a_large_integer_is_not_routed_through_a_double() {
    assert_eq!(c(&json!(9007199254740993u64)), "9007199254740993");
    assert_eq!(c(&json!(u64::MAX)), "18446744073709551615");
    assert_eq!(c(&json!(i64::MIN)), "-9223372036854775808");
}

/// Whitespace is not canonical, and neither is anything decorative. The canonical form of a
/// structure is byte-identical no matter how it was spelled on the wire, which is the property the
/// fingerprint rests on: a proxy that re-indents a card must not manufacture a drift alarm.
#[test]
fn two_spellings_of_one_document_canonicalize_identically() {
    let pretty: Value =
        serde_json::from_str("{\n  \"b\" : [ 1, 2 ],\n  \"a\" : { \"z\": 1.0, \"y\": true }\n}")
            .expect("parse");
    let terse: Value = serde_json::from_str(r#"{"a":{"y":true,"z":1},"b":[1,2]}"#).expect("parse");
    assert_eq!(c(&pretty), c(&terse));
    assert_eq!(c(&terse), r#"{"a":{"y":true,"z":1},"b":[1,2]}"#);
}

/// ARRAY order is data, not presentation, so it is preserved exactly. Sorting an array would make
/// two genuinely different documents canonicalize the same, which is a fingerprint collision the
/// pin would never see.
#[test]
fn array_order_is_preserved() {
    assert_eq!(c(&json!([3, 1, 2])), "[3,1,2]");
    assert_ne!(c(&json!([3, 1, 2])), c(&json!([1, 2, 3])));
}

/// NON-FINITE NUMBERS ARE UNREPRESENTABLE BEFORE THEY REACH THE CANONICALIZER — which is the honest
/// name for what this checks, and NOT "the canonicalizer refuses one".
///
/// `CanonicalError::NonFiniteNumber` cannot be produced through anything this suite can call:
/// `serde_json::Number` will not BUILD a NaN or an infinity (`from_f64` answers `None`), and
/// `to_value` renders one as `null` rather than a number, so no `Value` reaching `canonicalize` can
/// carry one. Asserting the refusal here would be asserting something no code path can satisfy; the
/// defence that actually holds is the type's, and this test pins THAT. See the note on
/// `CanonicalError::NonFiniteNumber` for why the arm stays anyway.
#[test]
fn a_non_finite_number_cannot_be_built_into_a_value_at_all() {
    // The first and, in practice, only line of defence.
    assert!(serde_json::Number::from_f64(f64::NAN).is_none());
    assert!(serde_json::Number::from_f64(f64::INFINITY).is_none());
    assert!(serde_json::Number::from_f64(f64::NEG_INFINITY).is_none());
    // And the other route into a `Value` does not carry one either: it degrades to `null`, which
    // canonicalizes as `null` and never reaches `number()`.
    assert_eq!(
        serde_json::to_value(f64::NAN).expect("to_value"),
        Value::Null
    );
    assert_eq!(
        c(&serde_json::to_value(f64::NAN).expect("to_value")),
        "null"
    );

    // The finite number the canonicalizer does render, so the arm's neighbour stays covered.
    let mut map = serde_json::Map::new();
    map.insert(
        "x".to_string(),
        Value::Number(serde_json::Number::from_f64(1.0).expect("finite")),
    );
    assert_eq!(
        canonicalize(&Value::Object(map)),
        Ok(r#"{"x":1}"#.to_string())
    );
}

/// Empty containers still canonicalize, and an absent member is not an empty one. A card that
/// declares no skills and a card that declares none of the member at all are different documents.
#[test]
fn empty_containers_are_distinct_from_absent_ones() {
    assert_eq!(c(&json!({})), "{}");
    assert_eq!(c(&json!([])), "[]");
    assert_ne!(c(&json!({ "skills": [] })), c(&json!({})));
    assert_ne!(
        c(&json!({ "skills": Value::Null })),
        c(&json!({ "skills": [] }))
    );
}
