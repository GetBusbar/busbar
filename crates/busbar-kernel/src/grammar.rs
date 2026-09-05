// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed grammars: where a claim can match, where a credential can be found, and the one
//! serialization the kernel understands.
//!
//! Everything a plugin varies is a key into a registry. Everything STRUCTURAL is closed, and this
//! file is where the closed structures live. There are three of them:
//!
//! - **Selectors** — the forms a claim may match on. A plane says "these bytes are mine" only in
//!   one of these shapes, which is what makes "can two claims both match?" a question with an
//!   answer rather than an opinion.
//! - **Locations** — the forms a credential or an idempotency key may be found at. Each form also
//!   says how it is masked, so hiding a credential is decided by the grammar and not per plane.
//! - **The JSON span scanner** — the kernel reads exactly one serialization, and it reads it
//!   without allocating and without copying: a pointer is resolved to a SPAN of the caller's own
//!   bytes, by walking them once.
//!
//! The scanner is the hot one. It never builds a tree, never unescapes into a buffer it owns, and
//! never looks at a byte twice. Skipping a value it does not care about is a byte loop; matching a
//! key decodes escapes on both sides a character at a time through the stack. Its budget is under a
//! microsecond per kibibyte scanned, and a body whose one interesting key is serialised LAST is the
//! case that has to meet it, because that is the case where the whole body is scanned.

/// A half-open range of bytes in someone else's buffer.
///
/// The scanner's whole answer, and the reason it never allocates: it says WHERE, never WHAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    /// First byte.
    pub start: usize,
    /// One past the last byte.
    pub end: usize,
}

impl Span {
    /// A span from `start` to `end`.
    pub fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }

    /// How many bytes it covers.
    pub fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether it covers none.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// The bytes themselves, from the buffer the span was found in.
    pub fn of(self, buf: &[u8]) -> &[u8] {
        &buf[self.start.min(buf.len())..self.end.min(buf.len())]
    }
}

/// The claim grammar and the credential grammar, as the contract crate declares them.
///
/// Both are plugin-visible: a plane writes its claims and an auth scheme names where its credential
/// lives, so the kernel evaluates values that arrived from outside it. It does not get a second
/// spelling of them. The contract owns the shapes, the overlap decision, the form-to-family map and
/// the masking rule; what stays here is the one thing the loop alone needs — how specific one
/// selector is against another, which is the within-a-plane precedence order, not part of what a
/// selector IS.
pub use busbar_contract::{
    ArrivalLocation, Location, MaskKind, PathSeg as Segment, Selector, SelectorForm, SignedOver,
};

/// The three axes the boot-time overlap check groups selector forms onto.
///
/// Deliberately coarser than the contract's per-form family: the overlap decision only needs to
/// know whether two selectors read the same axis at all, and every handshake-derived form is one
/// axis for that purpose. It is the kernel's own grouping, which is why it lives here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorFamily {
    /// The request path.
    Path,
    /// A named header.
    Header,
    /// The transport handshake: server name, protocol, certificate subject, stream name, port.
    Transport,
}

/// Which axis a selector reads.
#[must_use]
pub fn family(selector: &Selector) -> SelectorFamily {
    match selector {
        Selector::ExactPath(_)
        | Selector::PrefixOneLevel(_)
        | Selector::PathPattern(_)
        | Selector::PathSuffix(_)
        | Selector::PathContains(_) => SelectorFamily::Path,
        Selector::HeaderExact(..) | Selector::HeaderPresent(_) | Selector::HeaderPrefix(..) => {
            SelectorFamily::Header
        }
        Selector::Sni(_)
        | Selector::ClientCertSubject(_)
        | Selector::StreamName(_)
        | Selector::Alpn(_)
        | Selector::Port(_) => SelectorFamily::Transport,
    }
}

/// How specific a selector is, for the within-one-plane precedence order: a literal beats a
/// variable, longer beats shorter, a whole path beats a fragment of one.
#[must_use]
pub fn specificity(selector: &Selector) -> u32 {
    match selector {
        Selector::ExactPath(p) => 10_000 + p.len() as u32,
        Selector::PathPattern(segments) => {
            let literals = segments
                .iter()
                .filter(|s| matches!(s, Segment::Lit(_)))
                .count() as u32;
            let open = segments
                .iter()
                .filter(|s| matches!(s, Segment::Tail))
                .count() as u32;
            5_000 + literals * 100 + segments.len() as u32 - open * 50
        }
        Selector::PrefixOneLevel(p) => 4_000 + p.len() as u32,
        Selector::HeaderExact(n, v) => 3_000 + (n.len() + v.len()) as u32,
        Selector::HeaderPrefix(n, v) => 2_000 + (n.len() + v.len()) as u32,
        Selector::HeaderPresent(n) => 1_500 + n.len() as u32,
        Selector::PathSuffix(s) | Selector::PathContains(s) => 1_000 + s.len() as u32,
        Selector::Sni(s) | Selector::ClientCertSubject(s) | Selector::StreamName(s) => {
            800 + s.len() as u32
        }
        Selector::Alpn(a) => 600 + a.len() as u32,
        Selector::Port(_) => 500,
    }
}

/// How far into a body the kernel has to read before a unit can open.
///
/// The unit opens when the deepest declared pointer has resolved or the declared length ends. No
/// pointer is ever evaluated over a truncated prefix, which is the whole reason this is a value
/// the pump can compare rather than a rule someone remembers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeepestPointer {
    /// Nothing needs the body.
    None,
    /// A byte offset the scanner reached.
    Offset(usize),
    /// The end of the body, whatever that turns out to be.
    EndOfBody,
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The JSON span scanner
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// How deep the scanner will descend before it calls the document malformed.
///
/// A bound rather than a stack overflow: a hostile body that is ten thousand open brackets is a
/// refusal, not a crash.
pub const MAX_JSON_DEPTH: usize = 64;

/// What resolving a pointer found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// The value is here.
    Found(Span),
    /// The bytes ran out mid-value: the answer may still arrive in a later chunk.
    NeedMore,
    /// The document is well-formed as far as it was read, and the pointer is not in it.
    Missing,
    /// The bytes are not JSON.
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanErr {
    NeedMore,
    Malformed,
}

/// Resolve a JSON pointer over a scanned prefix, without allocating and without copying.
///
/// The pointer is the usual slash-separated one: an empty pointer names the whole document, `~1`
/// means a slash inside a key and `~0` means a tilde. An array step is a decimal index.
///
/// The answer is a span into `input`. Running out of bytes is [`Resolved::NeedMore`] and not an
/// error, because the scanner is also run incrementally as body chunks arrive.
pub fn resolve_pointer(input: &[u8], pointer: &str) -> Resolved {
    let start = skip_ws(input, 0);
    if start >= input.len() {
        return Resolved::NeedMore;
    }
    if pointer.is_empty() {
        return match skip_value(input, start, 0) {
            Ok(end) => Resolved::Found(Span::new(start, end)),
            Err(ScanErr::NeedMore) => Resolved::NeedMore,
            Err(ScanErr::Malformed) => Resolved::Malformed,
        };
    }
    if !pointer.starts_with('/') {
        return Resolved::Malformed;
    }
    match descend(input, start, &pointer[1..], 0) {
        Ok(Some(span)) => Resolved::Found(span),
        Ok(None) => Resolved::Missing,
        Err(ScanErr::NeedMore) => Resolved::NeedMore,
        Err(ScanErr::Malformed) => Resolved::Malformed,
    }
}

/// Walk one pointer step at `at`, then the rest.
fn descend(b: &[u8], at: usize, tokens: &str, depth: usize) -> Result<Option<Span>, ScanErr> {
    if depth > MAX_JSON_DEPTH {
        return Err(ScanErr::Malformed);
    }
    let (token, rest) = match tokens.find('/') {
        Some(cut) => (&tokens[..cut], Some(&tokens[cut + 1..])),
        None => (tokens, None),
    };
    let i = skip_ws(b, at);
    let found = match b.get(i) {
        None => return Err(ScanErr::NeedMore),
        Some(b'{') => member(b, i, token, depth)?,
        Some(b'[') => element(b, i, token, depth)?,
        Some(_) => None,
    };
    match (found, rest) {
        (None, _) => Ok(None),
        (Some(span), None) => Ok(Some(span)),
        (Some(span), Some(rest)) => descend(b, span.start, rest, depth + 1),
    }
}

/// Find `key` in the object that starts at `at`.
fn member(b: &[u8], at: usize, key: &str, depth: usize) -> Result<Option<Span>, ScanErr> {
    let mut i = skip_ws(b, at + 1);
    if b.get(i) == Some(&b'}') {
        return Ok(None);
    }
    loop {
        if b.get(i) != Some(&b'"') {
            return Err(if i >= b.len() {
                ScanErr::NeedMore
            } else {
                ScanErr::Malformed
            });
        }
        let key_end = scan_string(b, i)?;
        let matched = key_eq(&b[i + 1..key_end - 1], key);
        i = skip_ws(b, key_end);
        if b.get(i) != Some(&b':') {
            return Err(if i >= b.len() {
                ScanErr::NeedMore
            } else {
                ScanErr::Malformed
            });
        }
        let value_start = skip_ws(b, i + 1);
        if value_start >= b.len() {
            return Err(ScanErr::NeedMore);
        }
        let value_end = skip_value(b, value_start, depth + 1)?;
        if matched {
            return Ok(Some(Span::new(value_start, value_end)));
        }
        i = skip_ws(b, value_end);
        match b.get(i) {
            Some(b',') => i = skip_ws(b, i + 1),
            Some(b'}') => return Ok(None),
            None => return Err(ScanErr::NeedMore),
            Some(_) => return Err(ScanErr::Malformed),
        }
    }
}

/// Find element `index` in the array that starts at `at`.
fn element(b: &[u8], at: usize, index: &str, depth: usize) -> Result<Option<Span>, ScanErr> {
    let wanted: usize = match index.parse() {
        Ok(n) => n,
        Err(_) => return Ok(None),
    };
    let mut i = skip_ws(b, at + 1);
    if b.get(i) == Some(&b']') {
        return Ok(None);
    }
    let mut seen = 0usize;
    loop {
        if i >= b.len() {
            return Err(ScanErr::NeedMore);
        }
        let end = skip_value(b, i, depth + 1)?;
        if seen == wanted {
            return Ok(Some(Span::new(i, end)));
        }
        seen += 1;
        i = skip_ws(b, end);
        match b.get(i) {
            Some(b',') => i = skip_ws(b, i + 1),
            Some(b']') => return Ok(None),
            None => return Err(ScanErr::NeedMore),
            Some(_) => return Err(ScanErr::Malformed),
        }
    }
}

/// Move past whitespace.
fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while let Some(c) = b.get(i) {
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            _ => break,
        }
    }
    i
}

/// The index one past the value that starts at `i`. The byte loop the budget is measured on.
fn skip_value(b: &[u8], i: usize, depth: usize) -> Result<usize, ScanErr> {
    if depth > MAX_JSON_DEPTH {
        return Err(ScanErr::Malformed);
    }
    match b.get(i) {
        None => Err(ScanErr::NeedMore),
        Some(b'"') => scan_string(b, i),
        Some(b'{') | Some(b'[') => skip_container(b, i, depth),
        Some(b't') => literal(b, i, b"true"),
        Some(b'f') => literal(b, i, b"false"),
        Some(b'n') => literal(b, i, b"null"),
        Some(c) if *c == b'-' || c.is_ascii_digit() => scan_number(b, i),
        Some(_) => Err(ScanErr::Malformed),
    }
}

/// Skip a whole object or array, counting brackets and stepping over strings so a brace inside a
/// string never confuses the count.
fn skip_container(b: &[u8], start: usize, depth: usize) -> Result<usize, ScanErr> {
    let mut level = 0usize;
    let mut i = start;
    while let Some(c) = b.get(i) {
        match c {
            b'{' | b'[' => {
                level += 1;
                if depth + level > MAX_JSON_DEPTH {
                    return Err(ScanErr::Malformed);
                }
                i += 1;
            }
            b'}' | b']' => {
                level -= 1;
                i += 1;
                if level == 0 {
                    return Ok(i);
                }
            }
            b'"' => i = scan_string(b, i)?,
            _ => i += 1,
        }
    }
    Err(ScanErr::NeedMore)
}

/// The index one past the string that starts at the quote at `i`.
fn scan_string(b: &[u8], i: usize) -> Result<usize, ScanErr> {
    if b.get(i) != Some(&b'"') {
        return Err(ScanErr::Malformed);
    }
    let mut j = i + 1;
    while let Some(c) = b.get(j) {
        match c {
            b'\\' => j += 2,
            b'"' => return Ok(j + 1),
            _ => j += 1,
        }
    }
    Err(ScanErr::NeedMore)
}

/// The index one past the number that starts at `i`.
fn scan_number(b: &[u8], i: usize) -> Result<usize, ScanErr> {
    let mut j = i;
    while let Some(c) = b.get(j) {
        match c {
            b'-' | b'+' | b'.' | b'e' | b'E' => j += 1,
            c if c.is_ascii_digit() => j += 1,
            _ => return Ok(j),
        }
    }
    // A number that runs to the end of the buffer may have more digits in the next chunk.
    Err(ScanErr::NeedMore)
}

/// `true`, `false` or `null`.
fn literal(b: &[u8], i: usize, word: &[u8]) -> Result<usize, ScanErr> {
    let end = i + word.len();
    match b.get(i..end) {
        Some(seen) if seen == word => Ok(end),
        Some(_) => Err(ScanErr::Malformed),
        None => Err(ScanErr::NeedMore),
    }
}

/// Compare a raw JSON key against a pointer token, decoding both sides as it goes.
///
/// Neither side is unescaped into a buffer: each step decodes one character from each and compares
/// them, so a key with an escape in it costs a few instructions and no memory.
fn key_eq(raw: &[u8], token: &str) -> bool {
    let mut r = 0usize;
    let mut t = token.as_bytes();
    loop {
        let left = next_json_char(raw, &mut r);
        let right = next_token_char(&mut t);
        match (left, right) {
            (None, None) => return true,
            (Some(a), Some(c)) if a == c => continue,
            _ => return false,
        }
    }
}

/// One character of a JSON string body, escapes decoded.
fn next_json_char(raw: &[u8], at: &mut usize) -> Option<char> {
    let c = *raw.get(*at)?;
    if c != b'\\' {
        // The key is UTF-8 by definition of the format; a malformed byte compares unequal, which is
        // the safe answer for a lookup. Only the ONE character's own bytes are validated: reading
        // the whole remainder here would make matching a key quadratic in its length, and "never
        // looks at a byte twice" is the scanner's budget, not a figure of speech.
        let width = utf8_width(c)?;
        let ch = std::str::from_utf8(raw.get(*at..*at + width)?)
            .ok()?
            .chars()
            .next()?;
        *at += width;
        return Some(ch);
    }
    let esc = *raw.get(*at + 1)?;
    *at += 2;
    Some(match esc {
        b'"' => '"',
        b'\\' => '\\',
        b'/' => '/',
        b'b' => '\u{8}',
        b'f' => '\u{c}',
        b'n' => '\n',
        b'r' => '\r',
        b't' => '\t',
        b'u' => {
            let first = hex4(raw, *at)?;
            *at += 4;
            let code = if (0xD800..0xDC00).contains(&first) {
                // A surrogate pair: the low half follows as a second escape.
                if raw.get(*at) != Some(&b'\\') || raw.get(*at + 1) != Some(&b'u') {
                    return None;
                }
                let low = hex4(raw, *at + 2)?;
                *at += 6;
                0x10000 + ((first as u32 - 0xD800) << 10) + (low as u32 - 0xDC00)
            } else {
                first as u32
            };
            return char::from_u32(code);
        }
        _ => return None,
    })
}

/// How many bytes the character starting with this byte occupies, or nothing if it is not a
/// leading byte at all.
fn utf8_width(lead: u8) -> Option<usize> {
    match lead {
        0x00..=0x7F => Some(1),
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

/// Four hex digits as a number.
fn hex4(raw: &[u8], at: usize) -> Option<u16> {
    let mut value = 0u16;
    for offset in 0..4 {
        let digit = (*raw.get(at + offset)? as char).to_digit(16)?;
        value = value * 16 + digit as u16;
    }
    Some(value)
}

/// One character of a pointer token, with the pointer's own two escapes decoded.
fn next_token_char(token: &mut &[u8]) -> Option<char> {
    let c = *token.first()?;
    if c == b'~' {
        let next = *token.get(1)?;
        *token = &token[2..];
        return match next {
            b'0' => Some('~'),
            b'1' => Some('/'),
            _ => None,
        };
    }
    let width = utf8_width(c)?;
    let ch = std::str::from_utf8(token.get(..width)?)
        .ok()?
        .chars()
        .next()?;
    *token = &token[width..];
    Some(ch)
}

/// How far the scanner got before it ran out of bytes.
///
/// The pump uses this when a body arrives in chunks: it re-runs the scan over the longer prefix and
/// stops as soon as the deepest declared pointer resolves, so a pointer is never read off a
/// truncated document and a body whose interesting key comes last is still found.
pub fn scan_frontier(input: &[u8]) -> usize {
    let start = skip_ws(input, 0);
    match skip_value(input, start, 0) {
        Ok(end) => end,
        Err(_) => input.len(),
    }
}
