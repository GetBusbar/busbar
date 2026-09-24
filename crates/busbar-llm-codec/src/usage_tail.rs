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

/// The longest string value [`first_string_value_after`] reads. A stop-reason token is a short enum
/// member (`ERROR`, `MALFORMED_FUNCTION_CALL`); a value that runs past this is not one, and reading
/// it would be work proportional to the body rather than to the field.
const MAX_TOKEN_BYTES: usize = 64;

/// The string value of the FIRST `key` (quotes included, e.g. `b"\"finish_reason\""`) in `buf`,
/// without parsing the document: locate the key, skip `:` and whitespace, and read the quoted value
/// that follows, bounded at [`MAX_TOKEN_BYTES`]. `None` when the key is absent, its value is not a
/// plain string, or the value is longer than a token.
///
/// The one scan the key location costs is the only body-size-proportional work; everything after it
/// is bounded. A key spelled inside a delivered string value cannot match: there its closing quote
/// is escaped (`\"`), and the needle requires a bare `"` right after the key's last letter.
pub fn first_string_value_after<'b>(buf: &'b [u8], key: &[u8]) -> Option<&'b str> {
    if key.is_empty() || buf.len() < key.len() {
        return None;
    }
    let key_pos = (0..=buf.len() - key.len()).find(|&i| &buf[i..i + key.len()] == key)?;
    let mut i = key_pos + key.len();
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
    if buf.get(i) != Some(&b'"') {
        return None;
    }
    let start = i + 1;
    let end = buf
        .get(start..buf.len().min(start + MAX_TOKEN_BYTES + 1))?
        .iter()
        .position(|&c| c == b'"' || c == b'\\')
        .map(|n| start + n)?;
    if buf[end] != b'"' {
        // An escape inside the value: not a plain enum token.
        return None;
    }
    std::str::from_utf8(&buf[start..end]).ok()
}
