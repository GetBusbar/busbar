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
/// `None` for `11.0` (it is an `f64` in the parsed tree, not an integer), and every reader that
/// reached for `as_u64` then fell through to its `unwrap_or(0)` — ledgering a real, billed token
/// count as ZERO with no error anywhere. Nothing about the body is malformed; only the JSON number
/// form differs, so this is a silent, total loss of the count for that request.
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
