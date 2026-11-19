// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JSON SEAM (DEP-3, ARC-6): sonic-rs behind one facade.
//!
//! The dynamic tree is [`Value`] (`sonic_rs::Value`, re-exported; there is no tree of our own).
//! Every reader here keeps a number's lexeme (sonic's `arbitrary_precision`, `use_rawnumber`), so
//! a number is written back byte for byte and is never rounded through binary64:
//!
//! - [`parse`] / [`parse_str`]: one document into `T`, bounded by [`MAX_JSON_DEPTH`];
//! - [`parse_value`]: the tree, the last of duplicate object keys kept (as serde's maps keep it);
//! - [`parse_typed`]: the tree as a typed field reads it (`u64`, else `i64`, else finite `f64`);
//! - [`from_value`]: a tree into `T`, through its text;
//! - [`to_vec`] / [`to_string`]: sonic's writer, raw numbers verbatim ([`to_vec_pretty`],
//!   [`to_string_pretty`] indented, [`to_writer`] streamed into any `io::Write`);
//! - [`to_value`]: the tree of a serializable value; [`number_text`]: a number's lexeme.
//!
//! A built or edited object keeps its members in key order (the workspace turns on sonic's
//! `sort_keys`), so it is written in the same order whatever order it was built in. That covers
//! [`json!`], [`Map`], [`to_value`] and the trees of [`parse_value`] and [`parse_typed`] (their
//! duplicate-key pass edits every object); a `Value` read by [`parse`] keeps the document's order
//! until it is edited.
//!
//! [`parse_foreign`] is the one door through which a **third-party** type (one whose
//! `Deserialize` we do not own) is filled: it reads numbers in binary64, so such a type sees
//! `u64`/`i64`/`f64` and never sonic's exact-number token map. `SchemaCheck` (feature `schema`)
//! and `Body` (feature `axum`) are built on it and on [`to_vec`]: JSON Schema and axum answers
//! without our source naming another JSON library.
//!
//! [`Error`] never prints the input: sonic appends about 16 bytes of the document to its message,
//! and the facade's text stops before them.
//!

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{Deserialize, DeserializeOwned};
use serde::Serialize;

pub use busbar_count::json_span::MAX_JSON_DEPTH;

pub use sonic_rs::error::Category;
pub use sonic_rs::{
    json, Array, JsonContainerTrait, JsonNumberTrait, JsonType, JsonValueMutTrait, JsonValueTrait,
    LazyValue, Number, Object as Map, OwnedLazyValue, RawNumber, Value, ValueRef,
};

/// A reader over one document, for a caller that drives its own `Visitor` or `DeserializeSeed`
/// (`Deserializer::from_str` / `from_slice`, then `end()` to refuse trailing bytes). Built so, it
/// reads numbers in binary64; `.use_rawnumber()` hands `deserialize_any` the exact-number token
/// instead, as [`parse`] does. It applies no depth guard: check [`exceeds_max_depth`] first when
/// the input is untrusted.
///
/// [`exceeds_max_depth`]: exceeds_max_depth
pub use sonic_rs::Deserializer;

/// The borrowed reader, for text that must not be copied out of its owner's custody (secret
/// JSON, DES-SECURE-JSON-DECODE): [`from_slice_borrowed`] reads one document into `T`, every string
/// and key borrowed from the input or from a caller-owned decode arena at least as long as the
/// input, numbers handed as [`NUMBER_TOKEN`] maps (tell one with [`is_number_token`]) and raw tokens
/// as [`BorrowedRaw`]. A refusal is a [`BorrowedError`]: a fixed reason and a position, never input.
/// It applies no depth guard: check [`exceeds_max_depth`] first.
pub use sonic_rs::{
    from_slice_borrowed, is_number_token, BorrowedError, BorrowedRaw, NUMBER_TOKEN,
};

#[cfg(feature = "axum")]
mod body;
#[cfg(feature = "axum")]
pub use body::Body;

#[cfg(feature = "schema")]
mod schema;
#[cfg(feature = "schema")]
pub use schema::SchemaCheck;

/// A JSON error from the facade. Its text is sonic's, cut after the first
/// ` at line L column C`: sonic appends a fragment of the input there, and an input can hold a
/// secret. The position stays readable through [`Error::line`] and [`Error::column`].
pub struct Error(sonic_rs::Error);

impl Error {
    /// A refusal of the facade's own, in `message`'s words.
    fn refused(message: impl fmt::Display) -> Self {
        Self(<sonic_rs::Error as serde::de::Error>::custom(message))
    }

    /// What kind of refusal this is (syntax, end of input, type, I/O).
    pub fn classify(&self) -> Category {
        self.0.classify()
    }

    /// The 1-based line of the refusal, or 0 when it has no position.
    pub fn line(&self) -> usize {
        self.0.line()
    }

    /// The 1-based column of the refusal, or 0 when it has no position.
    pub fn column(&self) -> usize {
        self.0.column()
    }

    /// The byte offset of the refusal in the input.
    pub fn offset(&self) -> usize {
        self.0.offset()
    }

    /// Whether the input ended before the document did.
    pub fn is_eof(&self) -> bool {
        self.0.is_eof()
    }

    /// The refusal in its own words: the [`Display`](fmt::Display) text without its
    /// ` at line L column C` suffix (and so without any input). The position stays readable
    /// through [`Error::line`] and [`Error::column`].
    pub fn message(&self) -> String {
        let text = self.0.to_string();
        let shown = shown(&text, self.0.line(), self.0.column());
        let marker = format!(" at line {} column {}", self.0.line(), self.0.column());
        shown
            .strip_suffix(marker.as_str())
            .unwrap_or(shown)
            .to_owned()
    }
}

impl From<sonic_rs::Error> for Error {
    fn from(error: sonic_rs::Error) -> Self {
        Self(error)
    }
}

/// sonic's text up to and including the first ` at line L column C`; what follows it is input.
fn shown(text: &str, line: usize, column: usize) -> &str {
    if line == 0 {
        // No position: sonic writes the code text alone, with no fragment.
        return text;
    }
    let marker = format!(" at line {line} column {column}");
    match text.find(&marker) {
        Some(at) => &text[..at + marker.len()],
        None => text.split('\n').next().unwrap_or_default(),
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.0.to_string();
        f.write_str(shown(&text, self.0.line(), self.0.column()))
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Error {}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::refused(message)
    }
}

impl serde::ser::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::refused(message)
    }
}

/// The refusal of a document nested deeper than [`MAX_JSON_DEPTH`], checked before any parser
/// recurses into it.
fn too_deep(bytes: &[u8]) -> Result<(), Error> {
    if exceeds_max_depth(bytes, MAX_JSON_DEPTH) {
        return Err(Error::refused(format_args!(
            "JSON nesting exceeds {MAX_JSON_DEPTH}"
        )));
    }
    Ok(())
}

/// Read one JSON document into `T`, numbers kept as their lexemes (a `T` that holds a [`Value`]
/// or a [`RawNumber`] keeps them exactly).
///
/// # Errors
/// Invalid JSON, trailing bytes, nesting beyond [`MAX_JSON_DEPTH`], or a document `T` refuses.
pub fn parse<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Error> {
    too_deep(bytes)?;
    Ok(sonic_rs::from_slice(bytes)?)
}

/// [`parse`] for text.
///
/// # Errors
/// As [`parse`].
pub fn parse_str<'de, T: Deserialize<'de>>(text: &'de str) -> Result<T, Error> {
    too_deep(text.as_bytes())?;
    Ok(sonic_rs::from_str(text)?)
}

/// Read one JSON document into the tree. Numbers keep their lexemes; of an object's duplicate
/// keys the last is kept, at its own position, as serde's maps keep it (a reader of untrusted JSON
/// never sees the first of two `"id"`s while a map-based reader sees the second).
///
/// # Errors
/// As [`parse`].
pub fn parse_value(bytes: &[u8]) -> Result<Value, Error> {
    let mut value: Value = parse(bytes)?;
    keep_last(&mut value);
    Ok(value)
}

/// Drop every object member that a later member of the same name overrides.
fn keep_last(value: &mut Value) {
    if let Some(items) = value.as_array_mut() {
        items.iter_mut().for_each(keep_last);
        return;
    }
    let Some(members) = value.as_object_mut() else {
        return;
    };
    let mut remaining: BTreeMap<String, usize> = BTreeMap::new();
    for (key, _) in members.iter() {
        *remaining.entry(key.to_owned()).or_default() += 1;
    }
    members.retain(|key, member| {
        let last = remaining.get_mut(key).is_some_and(|left| {
            *left -= 1;
            *left == 0
        });
        if last {
            keep_last(member);
        }
        last
    });
}

/// Read one JSON document into the tree as a typed field reads it: each number is a `u64`, else an
/// `i64`, else a finite `f64` (so `-0` is `-0.0` and `1.0` is a float), the last of duplicate keys
/// kept as in [`parse_value`].
///
/// # Errors
/// As [`parse`], and a number no typed field can hold (beyond `f64`, such as `1e400`), which is
/// refused rather than rounded.
pub fn parse_typed(bytes: &[u8]) -> Result<Value, Error> {
    let mut value = parse_value(bytes)?;
    binary64(&mut value)?;
    Ok(value)
}

/// Replace every exact number in `value` by its typed reading.
fn binary64(value: &mut Value) -> Result<(), Error> {
    if let Some(number) = value.as_raw_number() {
        *value = typed_number(number.as_str())?;
    } else if let Some(items) = value.as_array_mut() {
        items.iter_mut().try_for_each(binary64)?;
    } else if let Some(members) = value.as_object_mut() {
        members
            .iter_mut()
            .try_for_each(|(_, member)| binary64(member))?;
    }
    Ok(())
}

/// A JSON number lexeme as a typed field reads it.
fn typed_number(lexeme: &str) -> Result<Value, Error> {
    if let Ok(unsigned) = lexeme.parse::<u64>() {
        return Ok(Value::from(unsigned));
    }
    // `-0` is no integer to a typed reader: it reads as the float `-0.0`.
    if lexeme != "-0" {
        if let Ok(signed) = lexeme.parse::<i64>() {
            return Ok(Value::from(signed));
        }
    }
    // A finite float only: `Value::try_from` refuses infinity, so `1e400` is never rounded.
    lexeme
        .parse::<f64>()
        .ok()
        .and_then(|float| Value::try_from(float).ok())
        .ok_or_else(|| Error::refused("JSON number out of range"))
}

/// Read a tree into `T`, through its text (numbers keep their lexemes).
///
/// # Errors
/// A tree `T` refuses.
pub fn from_value<T: DeserializeOwned>(value: &Value) -> Result<T, Error> {
    parse(&to_vec(value)?)
}

/// Fill a third-party type from one JSON document, numbers read in binary64.
///
/// The facade's other readers hand `deserialize_any` a number as sonic's exact-number token map,
/// which only our types (and sonic's) understand; a type we do not own would see a map where it
/// wants a number. Through this door it sees `u64`, `i64` or `f64`. The caller names no JSON
/// library: `T` is inferred from the third-party API the document is handed to.
///
/// # Errors
/// Invalid JSON or UTF-8, trailing bytes, nesting beyond [`MAX_JSON_DEPTH`], a document larger than
/// sonic reads (4 GiB), or a document `T` refuses.
pub fn parse_foreign<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if u32::try_from(bytes.len()).is_err() {
        return Err(Error::refused("JSON documents above 4 GiB are not read"));
    }
    too_deep(bytes)?;
    // Every byte is checked here: sonic checks UTF-8 only in the strings it decodes, and a
    // skipped member is not decoded.
    let text = std::str::from_utf8(bytes).map_err(|_| Error::refused("invalid UTF-8 in JSON"))?;
    // No `use_rawnumber`: numbers reach `T` in binary64.
    let mut reader = sonic_rs::Deserializer::from_str(text);
    let value = T::deserialize(&mut reader)?;
    reader.end()?;
    Ok(value)
}

/// Write `value` as JSON (raw numbers verbatim).
///
/// # Errors
/// A value sonic cannot write (a non-finite float, a map key that is not a string).
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    Ok(sonic_rs::to_vec(value)?)
}

/// [`to_vec`] as text.
///
/// # Errors
/// As [`to_vec`].
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    Ok(sonic_rs::to_string(value)?)
}

/// [`to_vec`], indented two spaces per level (serde's pretty layout).
///
/// # Errors
/// As [`to_vec`].
pub fn to_vec_pretty<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    Ok(sonic_rs::to_vec_pretty(value)?)
}

/// [`to_vec_pretty`] as text.
///
/// # Errors
/// As [`to_vec`].
pub fn to_string_pretty<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    Ok(sonic_rs::to_string_pretty(value)?)
}

/// [`to_vec`] into any writer without serializer-owned heap staging of strings.
///
/// The sink is not flushed. It may hold a prefix on failure; discard incomplete owned output or
/// defer external publication until this returns successfully. A bounded sink controls its own
/// output growth, not allocations in the input's `Serialize` implementation: native [`Value`]
/// objects still allocate sorting references under `sort_keys`. Borrowed strings, as used by the
/// JSON-RPC envelope writer, are emitted directly without those tree allocations.
///
/// # Errors
/// As [`to_vec`], and `writer`'s own I/O refusal.
pub fn to_writer<W: std::io::Write, T: Serialize + ?Sized>(
    writer: W,
    value: &T,
) -> Result<(), Error> {
    Ok(sonic_rs::to_writer_io(writer, value)?)
}

/// Build the tree of a serializable value (a number keeps its lexeme when `value` holds one).
///
/// # Errors
/// A value sonic cannot write (a non-finite float, a map key that is not a string).
pub fn to_value<T: Serialize + ?Sized>(value: &T) -> Result<Value, Error> {
    match sonic_rs::to_value(value) {
        Ok(tree) => Ok(tree),
        // sonic's tree serializer holds only i64/u64/f64 numbers, so an i128/u128 outside them
        // (a full-range count) is refused there; the text writer spells it exactly and the parsed
        // tree keeps that lexeme. Any other refusal is refused again by the writer.
        Err(_) => parse_value(&to_vec(value)?),
    }
}

/// A number's text: a read number's lexeme exactly as the document spelled it, a built one as
/// sonic writes it; `None` for a value that is not a number.
pub fn number_text(value: &Value) -> Option<String> {
    if let Some(raw) = value.as_raw_number() {
        return Some(raw.as_str().to_owned());
    }
    value.as_number().map(|number| number.to_string())
}

/// The member a JSON Pointer (RFC 6901) names: `""` is the whole tree, every other pointer starts
/// with `/`; `~1` reads `/` and `~0` reads `~`; an array step is a decimal index without a sign or a
/// leading zero. `None` when a step names nothing.
pub fn pointer<'v>(value: &'v Value, pointer: &str) -> Option<&'v Value> {
    if pointer.is_empty() {
        return Some(value);
    }
    pointer
        .strip_prefix('/')?
        .split('/')
        .map(pointer_token)
        .try_fold(value, |target, token| {
            if target.is_object() {
                target.get(token.as_str())
            } else if target.is_array() {
                pointer_index(&token).and_then(|at| target.get(at))
            } else {
                None
            }
        })
}

/// [`pointer`] for editing the member in place.
pub fn pointer_mut<'v>(value: &'v mut Value, pointer: &str) -> Option<&'v mut Value> {
    if pointer.is_empty() {
        return Some(value);
    }
    pointer
        .strip_prefix('/')?
        .split('/')
        .map(pointer_token)
        .try_fold(value, |target, token| {
            if target.is_object() {
                target.get_mut(token.as_str())
            } else if target.is_array() {
                pointer_index(&token).and_then(move |at| target.get_mut(at))
            } else {
                None
            }
        })
}

/// One pointer step, unescaped (`~1` first, so `~01` reads `~1`).
fn pointer_token(step: &str) -> String {
    step.replace("~1", "/").replace("~0", "~")
}

/// An array step: decimal digits, no sign, no leading zero.
fn pointer_index(token: &str) -> Option<usize> {
    if token.starts_with('+') || (token.starts_with('0') && token.len() != 1) {
        return None;
    }
    token.parse().ok()
}

/// The log line for a body that did not parse: its length, never its bytes.
#[cold]
pub fn parse_err_log(bytes_len: usize) -> String {
    format!("invalid JSON ({bytes_len} bytes)")
}

/// THE JSON NESTING-DEPTH GUARD: does `bytes` nest `{`/`[` deeper than `max`?
#[must_use]
pub fn exceeds_max_depth(bytes: &[u8], max: usize) -> bool {
    // Outside strings every byte is looked at; a string body is skipped to its closing quote by
    // `past_string_body`. An unterminated string or a trailing escape ends the scan as "not too
    // deep", as a byte-at-a-time scan does.
    let mut depth: usize = 0;
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'"' => {
                let Some(end) = past_string_body(bytes, i + 1) else {
                    return false;
                };
                i = end;
                continue;
            }
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    false
}

/// String-body bytes [`past_string_body`] looks at one by one before it searches.
const SHORT_STRING: usize = 16;

/// One past the closing quote of the JSON string whose body starts at `body` (just after its
/// opening quote), or `None` when the input ends first. A backslash skips the byte after it.
/// The first [`SHORT_STRING`] bytes are looked at one by one (most keys and short values end
/// there, where a `memchr2` call costs more than it saves); past them `memchr2` finds the next
/// quote or backslash, so a long string body is not walked a byte at a time.
#[must_use]
pub fn past_string_body(bytes: &[u8], body: usize) -> Option<usize> {
    let mut i = body;
    let short_end = body.saturating_add(SHORT_STRING);
    while i < short_end {
        match bytes.get(i)? {
            b'"' => return Some(i + 1),
            b'\\' => i += 2,
            _ => i += 1,
        }
    }
    loop {
        i += memchr::memchr2(b'"', b'\\', bytes.get(i..)?)?;
        if bytes.get(i) == Some(&b'"') {
            return Some(i + 1);
        }
        i += 2;
    }
}

/// Read the same exact-number, last-key-wins tree with an additional caller depth bound.
/// The facade's global depth ceiling remains in force.
pub fn parse_value_bounded(bytes: &[u8], max_depth: usize) -> Result<Value, Error> {
    if exceeds_max_depth(bytes, max_depth) {
        return Err(Error::refused(format_args!(
            "JSON nesting exceeds {max_depth}"
        )));
    }
    parse_value(bytes)
}
