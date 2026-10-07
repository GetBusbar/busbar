// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JSON CANONICALIZATION SCHEME, RFC 8785, over `serde_json::Value`.
//!
//! WHY THIS EXISTS RATHER THAN `serde_json::to_string`. Two things on the A2A plane hash a document
//! that arrived over the network, and both of them are security decisions:
//!
//! 1. A signed Agent Card's JWS payload is the card serialized per RFC 8785 with the `signatures`
//!    member removed. Verifying a signature against anything else verifies a different document.
//! 2. The pinned card FINGERPRINT is a hash of the whole received card. If two byte-different but
//!    semantically identical serializations hash differently, every proxy that re-serializes a card
//!    manufactures a drift alarm; if two semantically different cards can be made to hash the same,
//!    the pin is worthless.
//!
//! `serde_json::to_string` gives neither guarantee: it preserves neither a canonical key order for
//! every input path nor RFC 8785's number formatting. So the canonicalizer is written out, and the
//! tests below are the RFC's own vectors rather than our idea of what they should say.
//!
//! DELIBERATELY OVER `Value`, NOT OVER OUR OWN STRUCTS. Hashing a busbar-owned projection of a card
//! would mean any field busbar does not model could change without registering as drift, which is
//! precisely the silent rug-pull the pin exists to catch. The canonical form is taken over the
//! document AS RECEIVED.

use serde_json::Value;

/// A document that cannot be canonicalized. Every arm is a case where producing SOME string would be
/// worse than refusing: a fingerprint nobody can reproduce is a permanent false drift alarm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalError {
    /// RFC 8785 section 3.2.2.3: NaN and the infinities have no canonical form. JSON cannot even
    /// carry them, so their presence means the document was built in memory, not parsed.
    ///
    /// NOT REACHABLE THROUGH ANY WIRE PATH TODAY, and the tests say so rather than pretending
    /// otherwise: `serde_json::Number` refuses to build a non-finite value at all (`from_f64`
    /// answers `None`) and `to_value` degrades one to `null`, so no `Value` handed to
    /// [`canonicalize`] can carry one while the default (non-`arbitrary_precision`) serde_json is
    /// what parses cards. The arm stays because it is a DEFENCE against a `Value` some future
    /// in-memory path builds, not a case a card can arrive in — and a canonicalizer that emitted
    /// `null` or `0` for such a number would mint a fingerprint no second implementation could
    /// reproduce, which is a permanent false drift alarm on Agent Card signature verification.
    NonFiniteNumber,
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalError::NonFiniteNumber => {
                write!(f, "cannot canonicalize: a number is NaN or infinite")
            }
        }
    }
}

/// The RFC 8785 canonical serialization of `value`.
pub fn canonicalize(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&number(n)?),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 section 3.2.3: members are sorted on the UTF-16 code units of their names.
            // `serde_json`'s default map is already sorted, but by Rust's `str` ordering, which is
            // UTF-8 CODE POINT order. The two disagree above the BMP: a supplementary character
            // sorts BELOW U+E000..U+FFFF in UTF-16 and ABOVE it in code-point order. Relying on the
            // map's own order would therefore be correct for every card anyone has yet written and
            // wrong for the first one with an emoji in an extension key.
            let mut names: Vec<&String> = map.keys().collect();
            names.sort_by_key(|n| utf16_units(n));
            out.push('{');
            for (i, name) in names.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write_value(&map[name.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn utf16_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// RFC 8785 section 3.2.2.2: the SHORTEST escape wins, `\u` only below U+0020, and every other
/// character is emitted literally as UTF-8. A serializer that escaped non-ASCII would still be legal
/// JSON and would still hash differently, which is the whole hazard.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// RFC 8785 section 3.2.2.3: EVERY number is an IEEE-754 double, printed as ECMAScript
/// `Number.prototype.toString`. That includes a number that arrived as an integer: `9007199254740993`
/// is the double `9007199254740992` and canonicalizes as that, because the signer's canonicalizer
/// (any conforming JCS implementation) parsed it into a double before printing. Printing the integer
/// exactly would verify a correctly signed card against a different document.
fn number(n: &serde_json::Number) -> Result<String, CanonicalError> {
    // `as f64` on an integer rounds to nearest, ties to even, which is what an ECMAScript parse does.
    let f = if let Some(i) = n.as_i64() {
        i as f64
    } else if let Some(u) = n.as_u64() {
        u as f64
    } else {
        n.as_f64().ok_or(CanonicalError::NonFiniteNumber)?
    };
    if !f.is_finite() {
        return Err(CanonicalError::NonFiniteNumber);
    }
    Ok(ecmascript_number(f))
}

/// ECMAScript `Number::toString` for a finite double (ECMA-262 Number::toString steps 5-12).
///
/// The shortest round-tripping digit string comes from Rust's own float formatter; the LAYOUT is
/// written out here so it follows the ECMAScript rules exactly rather than Rust's presentation.
/// One more difference is in the digits themselves: when the double lies exactly halfway between two
/// k-digit decimals that both round-trip, ECMAScript takes the one with the EVEN last digit and Rust
/// takes the upper one. RFC 8785 Appendix B carries such a value (1424953923781206.25 is
/// `1424953923781206.2`), so [`shortest_digits`] settles the tie the ECMAScript way.
fn ecmascript_number(f: f64) -> String {
    if f == 0.0 {
        // ECMAScript prints negative zero as "0".
        return "0".to_string();
    }
    let (digits, point) = shortest_digits(f.abs());
    let k = digits.len() as i32;
    // The value is 0.<digits> x 10^n.
    let n = point + 1;
    let mut out = String::new();
    if f < 0.0 {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.push_str(&"0".repeat((n - k) as usize));
    } else if 0 < n && n <= 21 {
        out.push_str(&digits[..n as usize]);
        out.push('.');
        out.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat((-n) as usize));
        out.push_str(&digits);
    } else {
        let e = n - 1;
        out.push_str(&digits[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if e < 0 { '-' } else { '+' });
        out.push_str(&e.abs().to_string());
    }
    out
}

/// The shortest decimal digit string that round-trips to `abs` (a finite positive double) and the
/// decimal exponent of its first digit, with an exact halfway tie settled to the even last digit.
fn shortest_digits(abs: f64) -> (String, i32) {
    let (digits, exp) = split_scientific(&format!("{abs:e}"));
    // The exact expansion of a double has at most 767 significant digits, so 800 is exact.
    let (exact, exact_exp) = split_scientific(&format!("{abs:.800e}"));
    let exact = exact.trim_end_matches('0');
    let k = digits.len();
    let halfway = exact_exp == exp && exact.len() == k + 1 && exact.ends_with('5');
    if !halfway {
        return (digits, exp);
    }
    let lower = exact[..k].to_string();
    let mut upper = lower.clone().into_bytes();
    // `lower` does not end in 9 here: a 9 would carry and the carried form would be shorter.
    if let Some(last) = upper.last_mut() {
        if *last == b'9' {
            return (digits, exp);
        }
        *last += 1;
    }
    let upper = String::from_utf8(upper).unwrap_or_default();
    let round_trips = |d: &str| format!("{d}e{}", exp - (k as i32 - 1)).parse::<f64>() == Ok(abs);
    if !(round_trips(&lower) && round_trips(&upper)) {
        return (digits, exp);
    }
    let even = |d: &str| d.as_bytes().last().is_some_and(|b| (b - b'0') % 2 == 0);
    if even(&lower) {
        (lower, exp)
    } else {
        (upper, exp)
    }
}

/// `d.ddde-N` (Rust `{:e}`) to its digits with the point removed and its decimal exponent.
fn split_scientific(s: &str) -> (String, i32) {
    let (mantissa, exp) = s.split_once('e').unwrap_or((s, "0"));
    (mantissa.replace('.', ""), exp.parse().unwrap_or(0))
}

#[cfg(test)]
#[path = "tests/canonical_tests.rs"]
mod canonical_tests;
