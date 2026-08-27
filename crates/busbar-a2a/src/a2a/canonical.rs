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
pub(crate) enum CanonicalError {
    /// RFC 8785 section 3.2.2.3: NaN and the infinities have no canonical form. JSON cannot even
    /// carry them, so their presence means the document was built in memory, not parsed.
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
pub(crate) fn canonicalize(value: &Value) -> Result<String, CanonicalError> {
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

/// RFC 8785 section 3.2.2.3: numbers print as ECMAScript `Number.prototype.toString`, so `1.0` is
/// `1` and the exponent form carries an explicit sign. Integers that arrived as integers are printed
/// from their integer representation, which keeps a `u64` beyond f64's exact range exact.
fn number(n: &serde_json::Number) -> Result<String, CanonicalError> {
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }
    let f = n.as_f64().ok_or(CanonicalError::NonFiniteNumber)?;
    if !f.is_finite() {
        return Err(CanonicalError::NonFiniteNumber);
    }
    Ok(ecmascript_number(f))
}

/// ECMAScript `Number::toString` for a finite double.
///
/// Rust's own `{}` is already the shortest round-tripping decimal, which is the hard half and the
/// half the two languages agree on. They disagree on PRESENTATION, in exactly three places, and each
/// one is a real card field away from mattering: a whole number prints with a trailing `.0`, the
/// exponent threshold differs, and the exponent has no `+`.
fn ecmascript_number(f: f64) -> String {
    if f == 0.0 {
        // ECMAScript prints negative zero as "0".
        return "0".to_string();
    }
    let abs = f.abs();
    // ECMAScript switches to exponential notation at 1e21 and above, and below 1e-6.
    if (1e-6..1e21).contains(&abs) {
        let plain = format!("{f}");
        return plain.strip_suffix(".0").unwrap_or(&plain).to_string();
    }
    let exp = format!("{f:e}");
    // Rust writes `1e21` and `1e-7`; ECMAScript writes `1e+21` and `1e-7`.
    match exp.split_once('e') {
        Some((mantissa, e)) if !e.starts_with('-') => format!("{mantissa}e+{e}"),
        _ => exp,
    }
}

#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/canonical_tests.rs"]
mod canonical_tests;
