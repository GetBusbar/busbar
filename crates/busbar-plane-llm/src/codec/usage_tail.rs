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
    crate::codec::json::parse(obj).ok()
}

/// The longest string value [`StopKeyScanner`] reads. A stop-reason token is a short enum member
/// (`ERROR`, `MALFORMED_FUNCTION_CALL`); a value that runs past this is not one, and reading it
/// would be work proportional to the body rather than to the field.
const MAX_TOKEN_BYTES: usize = 64;

/// The longest stop-reason KEY (quotes included) [`StopKeyScanner`] can look for. Every dialect's
/// key is a short field name; the bound is what lets the scanner carry its state inline.
pub const MAX_STOP_KEY_BYTES: usize = 32;

/// The deepest container nesting [`StopKeyScanner`] tracks the container kinds of. A dialect's stop
/// field sits a few levels deep; a body nested past this is still scanned, and its deeper
/// containers are never the stop field's.
const MAX_TRACKED_DEPTH: u16 = 64;

/// A dialect's non-stream stop-reason field, located STRUCTURALLY: the member `key` (quotes
/// included, e.g. `b"\"finish_reason\""`) of an object at container nesting `depth`, counting every
/// `{` and `[` from the document root (`1` is a top-level member; a Gemini candidate's member,
/// `{"candidates":[{…}]}`, is `3`). Only that member is the field: the same name spelled deeper —
/// inside a tool call's `args` object, say — is content, never the stop reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopKey {
    pub key: &'static [u8],
    pub depth: u16,
}

/// Where [`StopKeyScanner`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanState {
    /// Walking the document for the first member named `key` at `depth`.
    Seeking,
    /// Just past the `:`: whitespace, then the opening `"`.
    BeforeQuote,
    /// Inside the value, collecting the token.
    InToken,
    /// The token is complete.
    Found,
    /// The first such member's value is not a plain token: no answer, and none will come.
    Gone,
}

/// The string value of the FIRST member [`StopKey`] names, read INCREMENTALLY: fed a body chunk by
/// chunk as it passes through a relay, it walks the JSON lexically (strings, escapes, container
/// nesting) without parsing or keeping a copy of the body. The state it carries is bounded and
/// inline (no heap): the nesting depth, a bit per tracked container, the match position in the key
/// and at most [`MAX_TOKEN_BYTES`] of the token. A member of the same name at another depth — a
/// tool's `args` object that happens to hold `"finishReason":"MALFORMED_FUNCTION_CALL"` — or the
/// name spelled inside a string value never matches.
#[derive(Clone, Debug)]
pub struct StopKeyScanner {
    /// The key's name, quotes stripped.
    name: &'static [u8],
    depth: u16,
    state: ScanState,
    /// The current container nesting.
    level: u16,
    /// Bit `n` set: the container at nesting `n + 1` is an object.
    objects: u64,
    in_string: bool,
    escaped: bool,
    /// The string being walked is a candidate member name at the key's depth.
    candidate: bool,
    /// How many bytes of `name` the candidate has matched.
    matched: usize,
    /// A candidate that matched `name` whole has just closed: the next non-whitespace byte decides
    /// whether it was a member name (`:`) or a value.
    closed_match: bool,
    lexeme: [u8; MAX_TOKEN_BYTES],
    lexeme_len: usize,
}

impl StopKeyScanner {
    /// A scanner for `key`. `None` for an empty or unquoted key, one longer than
    /// [`MAX_STOP_KEY_BYTES`], or a depth of `0`.
    pub fn new(key: StopKey) -> Option<Self> {
        let k = key.key;
        let well_formed = k.len() > 2
            && k.len() <= MAX_STOP_KEY_BYTES
            && k[0] == b'"'
            && k[k.len() - 1] == b'"'
            && key.depth > 0;
        well_formed.then_some(Self {
            name: &k[1..k.len() - 1],
            depth: key.depth,
            state: ScanState::Seeking,
            level: 0,
            objects: 0,
            in_string: false,
            escaped: false,
            candidate: false,
            matched: 0,
            closed_match: false,
            lexeme: [0; MAX_TOKEN_BYTES],
            lexeme_len: 0,
        })
    }

    /// Whether the innermost open container is an object.
    fn in_object(&self) -> bool {
        self.level > 0
            && self.level <= MAX_TRACKED_DEPTH
            && self.objects & (1u64 << (self.level - 1)) != 0
    }

    /// Feed the next chunk of the body.
    pub fn feed(&mut self, chunk: &[u8]) {
        for &c in chunk {
            match self.state {
                ScanState::Found | ScanState::Gone => return,
                ScanState::Seeking => self.seek(c),
                ScanState::BeforeQuote if c.is_ascii_whitespace() => {}
                ScanState::BeforeQuote if c == b'"' => self.state = ScanState::InToken,
                ScanState::BeforeQuote => self.state = ScanState::Gone,
                ScanState::InToken if c == b'"' => self.state = ScanState::Found,
                ScanState::InToken if c == b'\\' || self.lexeme_len == MAX_TOKEN_BYTES => {
                    self.state = ScanState::Gone;
                }
                ScanState::InToken => {
                    self.lexeme[self.lexeme_len] = c;
                    self.lexeme_len += 1;
                }
            }
        }
    }

    /// One byte of the document walk while seeking.
    fn seek(&mut self, c: u8) {
        if self.in_string {
            if self.escaped {
                self.escaped = false;
                self.candidate = false;
            } else if c == b'\\' {
                self.escaped = true;
                self.candidate = false;
            } else if c == b'"' {
                self.in_string = false;
                self.closed_match = self.candidate && self.matched == self.name.len();
                self.candidate = false;
            } else if self.candidate {
                if self.name.get(self.matched) == Some(&c) {
                    self.matched += 1;
                } else {
                    self.candidate = false;
                }
            }
            return;
        }
        if self.closed_match {
            if c.is_ascii_whitespace() {
                return;
            }
            self.closed_match = false;
            if c == b':' {
                // The member this scanner looks for: its value decides the answer.
                self.state = ScanState::BeforeQuote;
                return;
            }
        }
        match c {
            b'"' => {
                self.in_string = true;
                self.candidate = self.level == self.depth && self.in_object();
                self.matched = 0;
            }
            b'{' | b'[' => {
                self.level = self.level.saturating_add(1);
                if self.level <= MAX_TRACKED_DEPTH {
                    let bit = 1u64 << (self.level - 1);
                    if c == b'{' {
                        self.objects |= bit;
                    } else {
                        self.objects &= !bit;
                    }
                }
            }
            b'}' | b']' => self.level = self.level.saturating_sub(1),
            _ => {}
        }
    }

    /// The token, once the body has supplied all of it; `None` otherwise.
    pub fn token(&self) -> Option<&str> {
        (self.state == ScanState::Found)
            .then(|| std::str::from_utf8(&self.lexeme[..self.lexeme_len]).ok())
            .flatten()
    }
}
