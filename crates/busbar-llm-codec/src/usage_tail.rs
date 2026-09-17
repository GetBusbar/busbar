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
    // `is_ascii_whitespace` (NOT `(buf[i] as char).is_whitespace()`): the `as char` cast reinterprets
    // a raw byte as a Unicode scalar, so Latin-1/C1 bytes 0x85 (NEL) and 0xA0 (NBSP) would count as
    // whitespace — but only ASCII whitespace is legal JSON inter-token whitespace.
    while i < buf.len() && buf[i].is_ascii_whitespace() {
        i += 1;
    }
    if buf.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    while i < buf.len() && buf[i].is_ascii_whitespace() {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// L7: the C1/Latin-1 bytes 0x85 (NEL) and 0xA0 (NBSP) are NOT JSON whitespace and must not be
    /// skipped. The pre-fix `(buf[i] as char).is_whitespace()` cast treated them as whitespace, so
    /// the scan stepped over them and matched the `:`/`{` beyond — wrongly recovering an object.
    #[test]
    fn c1_latin1_bytes_are_not_json_whitespace() {
        // `[0x85, ':', '{', '}']` scanned from 0: only ASCII whitespace may precede the `:`, so a
        // leading 0x85/0xA0 means the very first byte is not `:` and no object is recovered.
        assert_eq!(balanced_object_after(&[0x85, b':', b'{', b'}'], 0), None);
        assert_eq!(balanced_object_after(&[0xA0, b':', b'{', b'}'], 0), None);
    }

    /// Byte-neutral control: ASCII whitespace around the `:` is still skipped and the object is
    /// recovered exactly as before.
    #[test]
    fn ascii_whitespace_still_skipped() {
        assert_eq!(
            balanced_object_after(b" : {\"a\":1}", 0),
            Some(&b"{\"a\":1}"[..])
        );
    }
}
