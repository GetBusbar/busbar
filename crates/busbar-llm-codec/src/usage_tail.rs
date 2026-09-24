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

/// The longest stop-reason KEY (quotes included) [`StopKeyScanner`] can look for. Every dialect's
/// key is a short field name; the bound is what lets the scanner carry its state inline.
pub const MAX_STOP_KEY_BYTES: usize = 32;

/// Where [`StopKeyScanner`] is in the `"key" : "token"` grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanState {
    /// Looking for the first occurrence of the key.
    Seeking,
    /// Just past the key: whitespace, then `:`.
    BeforeColon,
    /// Just past the `:`: whitespace, then the opening `"`.
    BeforeQuote,
    /// Inside the value, collecting the token.
    InToken,
    /// The token is complete.
    Found,
    /// The first key was not followed by a plain token: no answer, and none will come.
    Gone,
}

/// [`first_string_value_after`], INCREMENTALLY: fed a body chunk by chunk as it passes through a
/// relay, it answers exactly what `first_string_value_after` would answer over the whole body,
/// without keeping a copy of it.
///
/// The state it carries across a chunk boundary is bounded and inline (no heap): at most the last
/// `key.len() - 1` bytes while seeking (a key split across two chunks), then at most
/// [`MAX_TOKEN_BYTES`] of the token. Per chunk the work is the key search over that chunk, then
/// bounded work after the key.
#[derive(Clone, Debug)]
pub struct StopKeyScanner {
    key: &'static [u8],
    state: ScanState,
    carry: [u8; MAX_STOP_KEY_BYTES],
    carry_len: usize,
    token: [u8; MAX_TOKEN_BYTES],
    token_len: usize,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

impl StopKeyScanner {
    /// A scanner for `key` (quotes included). `None` for an empty key or one longer than
    /// [`MAX_STOP_KEY_BYTES`].
    pub fn new(key: &'static [u8]) -> Option<Self> {
        (!key.is_empty() && key.len() <= MAX_STOP_KEY_BYTES).then_some(Self {
            key,
            state: ScanState::Seeking,
            carry: [0; MAX_STOP_KEY_BYTES],
            carry_len: 0,
            token: [0; MAX_TOKEN_BYTES],
            token_len: 0,
        })
    }

    /// Feed the next chunk of the body.
    pub fn feed(&mut self, chunk: &[u8]) {
        let mut rest = chunk;
        if self.state == ScanState::Seeking {
            let k = self.key.len();
            let mut found = false;
            // A key that STARTS in the carried tail of the previous chunks and ends in this one.
            // Only a match starting inside the carry counts here: one starting in `chunk` is found
            // by the search below, and a carry match is always the earlier of the two.
            if self.carry_len > 0 {
                let take = chunk.len().min(k - 1);
                let mut joint = [0u8; 2 * MAX_STOP_KEY_BYTES];
                joint[..self.carry_len].copy_from_slice(&self.carry[..self.carry_len]);
                joint[self.carry_len..self.carry_len + take].copy_from_slice(&chunk[..take]);
                if let Some(p) = find(&joint[..self.carry_len + take], self.key) {
                    if p < self.carry_len {
                        rest = &chunk[p + k - self.carry_len..];
                        found = true;
                    }
                }
            }
            if !found {
                if let Some(p) = find(chunk, self.key) {
                    rest = &chunk[p + k..];
                    found = true;
                }
            }
            if !found {
                // Keep the last `k - 1` bytes of everything seen, for a key split at the boundary.
                let keep = k - 1;
                if chunk.len() >= keep {
                    self.carry[..keep].copy_from_slice(&chunk[chunk.len() - keep..]);
                    self.carry_len = keep;
                } else {
                    let total = self.carry_len + chunk.len();
                    let drop = total.saturating_sub(keep);
                    self.carry.copy_within(drop..self.carry_len, 0);
                    let kept = self.carry_len - drop;
                    self.carry[kept..kept + chunk.len()].copy_from_slice(chunk);
                    self.carry_len = kept + chunk.len();
                }
                return;
            }
            self.carry_len = 0;
            self.state = ScanState::BeforeColon;
        }
        for &c in rest {
            self.state = match self.state {
                ScanState::BeforeColon if c.is_ascii_whitespace() => ScanState::BeforeColon,
                ScanState::BeforeColon if c == b':' => ScanState::BeforeQuote,
                ScanState::BeforeQuote if c.is_ascii_whitespace() => ScanState::BeforeQuote,
                ScanState::BeforeQuote if c == b'"' => ScanState::InToken,
                ScanState::InToken if c == b'"' => ScanState::Found,
                ScanState::InToken if c == b'\\' || self.token_len == MAX_TOKEN_BYTES => {
                    ScanState::Gone
                }
                ScanState::InToken => {
                    self.token[self.token_len] = c;
                    self.token_len += 1;
                    ScanState::InToken
                }
                ScanState::Found | ScanState::Gone => break,
                ScanState::Seeking | ScanState::BeforeColon | ScanState::BeforeQuote => {
                    ScanState::Gone
                }
            };
        }
    }

    /// The token, once the body has supplied all of it; `None` otherwise.
    pub fn token(&self) -> Option<&str> {
        (self.state == ScanState::Found)
            .then(|| std::str::from_utf8(&self.token[..self.token_len]).ok())
            .flatten()
    }
}
