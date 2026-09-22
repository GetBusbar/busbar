// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed JSON span grammar: the one serialization busbar reads, read once.
//!
//! JSON is the single serialization the kernel understands, and it understands it as a CLOSED
//! grammar — not a document model, not a parser with options, but one scanner with one reading.
//! This crate is that reading, on its own, so that there is exactly one of it: the kernel names it,
//! the contract re-exports it as `busbar_contract::spans`, and a plane resolves its declared
//! pointers through it instead of carrying a fourth copy of the same walk.
//!
//! It depends on nothing of busbar's. That is the point: a grammar that named a contract type could
//! not be the thing the contract is written on top of, and a grammar with a dependency has a second
//! place its meaning can change. The only outside name here is the derive that lets a span be sealed
//! into the policy journal and read back, which is what makes a resolved pointer a value the kernel
//! can compare rather than a number someone remembers.
//!
//! It locates values; it does not validate them. Structure is read strictly — brackets have to
//! match, punctuation has to be where punctuation goes — but number and string grammar is not
//! checked against the RFC, so `01.2.3e` and a raw control byte inside a string are located rather
//! than refused. Nothing downstream needs a well-formedness verdict from here: the body busbar
//! forwards is parsed by the provider, whose strictness is the one that counts. Reading a resolved
//! span as "this document is valid JSON" is reading something the scanner never said.
//!
//! The scanner is the hot one. It never builds a tree, never unescapes into a buffer it owns, and
//! never looks at a byte twice. Skipping a value it does not care about is a byte loop; matching a
//! key decodes escapes on both sides a character at a time through the stack. Its budget is under a
//! microsecond per kibibyte scanned, and a body whose one interesting key is serialised LAST is the
//! case that has to meet it, because that is the case where the whole body is scanned.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

/// A half-open range of bytes in someone else's buffer.
///
/// The scanner's whole answer, and the reason it never allocates: it says WHERE, never WHAT.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Span {
    /// First byte.
    pub start: usize,
    /// One past the last byte.
    pub end: usize,
}

impl Span {
    /// A span from `start` to `end`.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }

    /// How many bytes it covers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether it covers none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes themselves, from the buffer the span was found in.
    ///
    /// Total, for every span and every buffer. `Span::new` is public, so a span the scanner never
    /// produced — one read back out of a journal, one a caller did its own arithmetic on — can still
    /// arrive here, and both ends are clamped so that reading one is an empty answer rather than a
    /// panic in the middle of a request. A span whose start is past its end covers no bytes, which
    /// is already what [`Span::len`] says about it.
    #[must_use]
    pub fn of(self, buf: &[u8]) -> &[u8] {
        let end = self.end.min(buf.len());
        &buf[self.start.min(end)..end]
    }
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
    /// The bytes cannot be read as JSON structure.
    ///
    /// A structural reading, not a verdict on the document: the scanner found a byte where no value,
    /// key, separator or matching bracket could go. A [`Resolved::Found`] is the converse — where
    /// the value is — and never a claim that what is in the span is well-formed.
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
///
/// A member spelled twice answers the LAST one. JSON says nothing about repeated names, so what
/// counts is what reads the body after this does: serde_json takes the last, and so do the
/// providers' own parsers. Answering the first would let a body price and permit one model while
/// the upstream serves another — the divergence is the author of the body's to choose, not the
/// operator's — so the walk keeps the latest match rather than returning on the first.
///
/// The object is still walked exactly once, so the budget is the budget it always was; the answer
/// simply is not final until the closing brace, which is also why a truncated object asks for more
/// instead of handing back a match a later duplicate could still replace.
fn member(b: &[u8], at: usize, key: &str, depth: usize) -> Result<Option<Span>, ScanErr> {
    let mut i = skip_ws(b, at + 1);
    if b.get(i) == Some(&b'}') {
        return Ok(None);
    }
    let mut latest: Option<Span> = None;
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
        i = skip_ws(b, value_end);
        if matched {
            latest = Some(Span::new(value_start, value_end));
        }
        // What follows the value has to be this object's own punctuation. Walking on without that
        // look would hand back a span out of a document closed by the wrong bracket.
        match b.get(i) {
            Some(b',') => i = skip_ws(b, i + 1),
            Some(b'}') => return Ok(latest),
            None => return Err(ScanErr::NeedMore),
            Some(_) => return Err(ScanErr::Malformed),
        }
    }
}

/// Find element `index` in the array that starts at `at`.
fn element(b: &[u8], at: usize, index: &str, depth: usize) -> Result<Option<Span>, ScanErr> {
    // The pointer grammar's array index is a single `0` or a digit string with no leading zero.
    // An integer parse is looser than that — it takes a leading `+` and any run of leading zeroes
    // — so the token is checked against the grammar first and a token that is not an index names
    // nothing, exactly as a member name the object does not carry names nothing.
    let token = index.as_bytes();
    let is_index = match token {
        [b'0'] => true,
        [first, ..] => first.is_ascii_digit() && *first != b'0',
        [] => false,
    };
    if !is_index {
        return Ok(None);
    }
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
        let element_start = i;
        i = skip_ws(b, end);
        if seen == wanted {
            // What follows the element has to be this array's own punctuation, and it has to have
            // ARRIVED. A value that self-terminates on the last byte — a closed string, a matched
            // container, a literal — is followed by nothing yet, and what follows it is what says
            // whether this is an array at all: the same bytes continued `}` make the document
            // malformed. The object walk already waits for its closing brace for its own reason, and
            // an answer that a later chunk turns into a refusal is the one thing the incremental
            // scan must not hand back.
            return match b.get(i) {
                Some(b',') | Some(b']') => Ok(Some(Span::new(element_start, end))),
                None => Err(ScanErr::NeedMore),
                Some(_) => Err(ScanErr::Malformed),
            };
        }
        seen += 1;
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

/// Skip a whole object or array, matching brackets and stepping over strings so a brace inside a
/// string never confuses the walk.
///
/// The open brackets are held on a stack bounded by the depth ceiling rather than merely counted: a
/// closer that does not match the opener it would close is malformed, not a level down. Counting
/// alone would answer a span ending at the wrong bracket, which is bytes that are not a value.
fn skip_container(b: &[u8], start: usize, depth: usize) -> Result<usize, ScanErr> {
    let mut stack = [0u8; MAX_JSON_DEPTH];
    let mut level = 0usize;
    let mut i = start;
    while let Some(c) = b.get(i) {
        match c {
            b'{' | b'[' => {
                if depth + level + 1 > MAX_JSON_DEPTH {
                    return Err(ScanErr::Malformed);
                }
                stack[level] = *c;
                level += 1;
                i += 1;
            }
            b'}' | b']' => {
                let opener = match level.checked_sub(1) {
                    Some(below) => stack[below],
                    None => return Err(ScanErr::Malformed),
                };
                let wanted = if *c == b'}' { b'{' } else { b'[' };
                if opener != wanted {
                    return Err(ScanErr::Malformed);
                }
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

/// One step of a decode: a character, the end of the side, or bytes that spell no character.
///
/// The third arm is the whole point. Folding "nothing left to read" together with "what is left
/// cannot be read" makes a key whose decoded prefix is the token compare EQUAL to it once the
/// remainder is a broken escape, which hands whoever wrote the body the choice of which member the
/// kernel reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoded {
    Char(char),
    End,
    Malformed,
}

/// Compare a raw JSON key against a pointer token, decoding both sides as it goes.
///
/// Neither side is unescaped into a buffer: each step decodes one character from each and compares
/// them, so a key with an escape in it costs a few instructions and no memory.
///
/// An undecodable character on either side is a MISMATCH here and not a [`Resolved::Malformed`] for
/// the document, because the two say different things. Malformed is the structural reading — a byte
/// where no value, key, separator or bracket could go — and a broken escape inside a well-delimited
/// string is string grammar, which this crate locates rather than validates, exactly as it locates
/// `01.2.3e` and a raw control byte. So the object is still walked and its other members still
/// resolve; only the key that cannot be read is not the key that was asked for.
fn key_eq(raw: &[u8], token: &str) -> bool {
    let mut r = 0usize;
    let mut t = token.as_bytes();
    loop {
        let left = next_json_char(raw, &mut r);
        let right = next_token_char(&mut t);
        match (left, right) {
            (Decoded::End, Decoded::End) => return true,
            (Decoded::Char(a), Decoded::Char(c)) if a == c => continue,
            _ => return false,
        }
    }
}

/// One character of a JSON string body, escapes decoded.
fn next_json_char(raw: &[u8], at: &mut usize) -> Decoded {
    let Some(&c) = raw.get(*at) else {
        return Decoded::End;
    };
    if c != b'\\' {
        // The key is UTF-8 by definition of the format; a malformed byte is undecodable, which is
        // the safe answer for a lookup. Only the ONE character's own bytes are validated: reading
        // the whole remainder here would make matching a key quadratic in its length, and "never
        // looks at a byte twice" is the scanner's budget, not a figure of speech.
        let Some(width) = utf8_width(c) else {
            return Decoded::Malformed;
        };
        let decoded = raw
            .get(*at..*at + width)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|s| s.chars().next());
        let Some(ch) = decoded else {
            return Decoded::Malformed;
        };
        *at += width;
        return Decoded::Char(ch);
    }
    let Some(&esc) = raw.get(*at + 1) else {
        return Decoded::Malformed;
    };
    *at += 2;
    Decoded::Char(match esc {
        b'"' => '"',
        b'\\' => '\\',
        b'/' => '/',
        b'b' => '\u{8}',
        b'f' => '\u{c}',
        b'n' => '\n',
        b'r' => '\r',
        b't' => '\t',
        b'u' => {
            let Some(first) = hex4(raw, *at) else {
                return Decoded::Malformed;
            };
            *at += 4;
            let code = if (0xD800..0xDC00).contains(&first) {
                // A surrogate pair: the low half follows as a second escape.
                if raw.get(*at) != Some(&b'\\') || raw.get(*at + 1) != Some(&b'u') {
                    return Decoded::Malformed;
                }
                let Some(low) = hex4(raw, *at + 2) else {
                    return Decoded::Malformed;
                };
                // The second escape has to be the low half. Anything else is not a character, the
                // same answer every other malformed escape here gives — and taking it on trust would
                // run the combining arithmetic below off the bottom of its range.
                if !(0xDC00..0xE000).contains(&low) {
                    return Decoded::Malformed;
                }
                *at += 6;
                0x10000 + ((first as u32 - 0xD800) << 10) + (low as u32 - 0xDC00)
            } else {
                first as u32
            };
            // A lone low half lands here, and `char::from_u32` refuses it.
            return match char::from_u32(code) {
                Some(ch) => Decoded::Char(ch),
                None => Decoded::Malformed,
            };
        }
        _ => return Decoded::Malformed,
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
fn next_token_char(token: &mut &[u8]) -> Decoded {
    let Some(&c) = token.first() else {
        return Decoded::End;
    };
    if c == b'~' {
        // The pointer's escape grammar is exactly `~0` and `~1`. A bare tilde at the end of a token,
        // or a tilde followed by anything else, spells no character — so the token is not the key
        // spelled with the part in front of it.
        let Some(&next) = token.get(1) else {
            return Decoded::Malformed;
        };
        *token = &token[2..];
        return match next {
            b'0' => Decoded::Char('~'),
            b'1' => Decoded::Char('/'),
            _ => Decoded::Malformed,
        };
    }
    let Some(width) = utf8_width(c) else {
        return Decoded::Malformed;
    };
    let decoded = token
        .get(..width)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(|s| s.chars().next());
    let Some(ch) = decoded else {
        return Decoded::Malformed;
    };
    *token = &token[width..];
    Decoded::Char(ch)
}

/// One past the last byte of the document that starts the input, or the whole input if there is no
/// such document.
///
/// The answer is an INDEX and never a verdict. A complete value followed by trailing bytes ends
/// where the value ends; bytes that ran out mid-value, and bytes that are not JSON structure at all,
/// both come back as the length of the input — so a caller reading this as "the document is whole"
/// is reading something the scanner never said, and a caller that needs that answer has to ask
/// [`resolve_pointer`] with the empty pointer, which distinguishes the three.
///
/// What it is FOR is a body arriving in chunks: re-run over the longer prefix and stop as soon as
/// the deepest declared pointer resolves, so a pointer is never read off a truncated document and a
/// body whose interesting key comes last is still found. The kernel's pump does that with
/// [`resolve_pointer`] directly and does not call this; it is on the surface for a plane that spools
/// its own body, and the sentence that used to be here said the pump called it, which it does not.
pub fn scan_frontier(input: &[u8]) -> usize {
    let start = skip_ws(input, 0);
    match skip_value(input, start, 0) {
        Ok(end) => end,
        Err(_) => input.len(),
    }
}
