// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TAIL-USAGE ISOLATION — the dialect-neutral byte-scan behind each reader's
//! `recover_truncated_usage`.
//!
//! A same-protocol non-stream billing buffer whose HEAD was dropped to keep it bounded at
//! `max_translated_body_bytes()` is no longer a well-formed top-level JSON document (its opening
//! structure — or a string it cut through — is gone), so the normal `Op::extract_usage`
//! full-document parse reliably fails on it. But the `usage` object itself sits at (or near) the
//! TAIL of every supported dialect's response and is a small, SELF-CONTAINED balanced `{...}` value,
//! so it can be isolated and parsed on its own even though the surrounding document cannot be. This
//! module owns that isolation; each dialect reader maps the resulting `Value`'s fields onto the
//! neutral `TokenUsage` itself.

/// Find the LAST occurrence of `needle` in `hay` (there can be more than one `"usage"` substring —
/// e.g. inside delivered assistant content — so anchoring on the last one biases toward the real
/// trailing usage object, which is where every dialect places it).
fn find_last(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

/// From just past a `"usage"`/`"usageMetadata"` key, skip the `:` and whitespace, then
/// bracket-match the following `{...}` object (string- and escape-aware, so a `}` inside a quoted
/// string value does not close the object early). Returns the byte span INCLUDING both braces.
fn balanced_object_after(buf: &[u8], mut i: usize) -> Option<&[u8]> {
    while i < buf.len() && (buf[i] as char).is_whitespace() {
        i += 1;
    }
    if buf.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    while i < buf.len() && (buf[i] as char).is_whitespace() {
        i += 1;
    }
    if buf.get(i) != Some(&b'{') {
        return None;
    }
    let start = i;
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut escape = false;
    while i < buf.len() {
        let c = buf[i];
        if in_str {
            if escape {
                escape = false;
            } else if c == b'\\' {
                escape = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&buf[start..=i]);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Isolate the self-contained trailing usage object from a HEAD-truncated response `tail`: find the
/// LAST `key` (`"usage"` for most dialects, `"usageMetadata"` for gemini), bracket-match the
/// balanced `{...}` value after it, and parse just that span into a `Value`. Returns `None` when the
/// key is absent or its object doesn't fit in the retained tail (never observed — a usage object is a
/// handful of integer fields). The caller maps this dialect's fields off the returned value.
pub fn isolate_tail_usage_object(tail: &[u8], key: &[u8]) -> Option<serde_json::Value> {
    let key_pos = find_last(tail, key)?;
    let obj = balanced_object_after(tail, key_pos + key.len())?;
    busbar_substrate_values::json::parse(obj).ok()
}

/// Read a TOKEN COUNT off a wire value that the provider's spec types as a JSON *number*, not an
/// integer. Cohere's published OpenAPI types every count in `Usage` — `tokens.input_tokens`,
/// `tokens.output_tokens`, the whole `billed_units` bucket and `cached_tokens` — as `type: number`,
/// so `11.0` is a SPEC-VALID way for Cohere to report eleven tokens. `serde_json`'s `as_u64` returns
/// `None` for `11.0` (it is an `f64` in the parsed tree, not an integer), and a reader that reaches
/// for `as_u64` then falls through to `unwrap_or(0)` ledgers a real, billed token count as ZERO with
/// no error anywhere. Nothing about the body is malformed; only the JSON number form differs, so
/// this is a silent, total loss of the count for that request.
///
/// An integer parses exactly as before. A finite non-negative float is accepted; a non-integral
/// value is rounded UP, because a partially-consumed billing unit is still a whole unit charged and
/// this must never bill LESS than the provider reported. Negative, non-finite and out-of-range
/// values stay `None` (there is no such token count) rather than saturating into a fabricated one.
#[must_use]
pub fn token_count(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let f = v.as_f64()?;
    if !f.is_finite() || f < 0.0 {
        return None;
    }
    let ceil = f.ceil();
    // `u64::MAX` is not exactly representable as an `f64`; compare against the next power of two so
    // the cast below can never be undefined-adjacent or wrap.
    if ceil >= 18_446_744_073_709_551_616.0 {
        return None;
    }
    Some(ceil as u64)
}

#[cfg(test)]
mod token_count_tests {
    use super::token_count;
    use serde_json::json;

    /// A whole-valued double must stay EXACT — `11.0` is eleven tokens, never twelve. `f.ceil()` on
    /// an already-integral float is a no-op, but this pins that byte-for-byte rather than trusting
    /// the implementation.
    #[test]
    fn integral_double_is_exact_not_rounded_up() {
        assert_eq!(token_count(&json!(11.0)), Some(11));
        assert_eq!(token_count(&json!(0.0)), Some(0));
        assert_eq!(token_count(&json!(1_000_000.0)), Some(1_000_000));
    }

    /// A genuine `u64` (no decimal point in the wire bytes) parses exactly as it always did, via
    /// the `as_u64` fast path — this function must not regress the integer case while adding double
    /// tolerance.
    #[test]
    fn plain_integer_is_unaffected() {
        assert_eq!(token_count(&json!(11)), Some(11));
        assert_eq!(token_count(&json!(0)), Some(0));
    }

    /// A fractional value rounds UP: a partially-consumed billing unit is still a whole unit
    /// charged, and this must never bill LESS than the provider reported.
    #[test]
    fn fractional_double_rounds_up() {
        assert_eq!(token_count(&json!(11.1)), Some(12));
        assert_eq!(token_count(&json!(11.9)), Some(12));
        assert_eq!(token_count(&json!(0.001)), Some(1));
    }

    /// A negative count is not a real token count under any provider's billing model — reject
    /// rather than clamp to 0, so a caller's `unwrap_or(0)` and this function's `None` are
    /// distinguishable in principle even though both currently ledger nothing.
    #[test]
    fn negative_is_rejected() {
        assert_eq!(token_count(&json!(-1.0)), None);
        assert_eq!(token_count(&json!(-0.5)), None);
    }

    /// NaN and +/-infinity are not finite counts; must never silently bill as 0 or saturate to a
    /// fabricated maximum.
    #[test]
    fn non_finite_is_rejected() {
        assert_eq!(token_count(&json!(f64::NAN)), None);
        assert_eq!(token_count(&json!(f64::INFINITY)), None);
        assert_eq!(token_count(&json!(f64::NEG_INFINITY)), None);
    }

    /// A value at or beyond `u64::MAX`'s representable range must not silently saturate to
    /// `u64::MAX` (the `as` cast's default behavior) and pose as a real, enormous token count.
    #[test]
    fn overflow_is_rejected_not_saturated() {
        assert_eq!(token_count(&json!(1.0e30)), None);
        assert_eq!(token_count(&json!(18_446_744_073_709_551_616.0_f64)), None);
    }

    /// A non-numeric value (string, bool, null, object) is not a token count at all.
    #[test]
    fn non_numeric_is_rejected() {
        assert_eq!(token_count(&json!("11")), None);
        assert_eq!(token_count(&json!(null)), None);
        assert_eq!(token_count(&json!(true)), None);
    }
}
