// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JSON SEAM (DEP-3, ARC-6): sonic-rs behind one facade.
//!
//! The dynamic tree is [`Value`] (`sonic_rs::Value`, re-exported; there is no tree of our own).
//! Every reader here keeps a number's lexeme (sonic's `arbitrary_precision`, `use_rawnumber`), so
//! a number is written back byte for byte and is never rounded through binary64:
//!
//! - [`parse`] / [`parse_str`]: one document into `T`, bounded by [`crate::spans::MAX_JSON_DEPTH`];
//! - [`parse_value`]: the tree, the last of duplicate object keys kept (as serde's maps keep it);
//! - [`parse_typed`]: the tree as a typed field reads it (`u64`, else `i64`, else finite `f64`);
//! - [`from_value`]: a tree into `T`, through its text;
//! - [`to_vec`] / [`to_string`]: sonic's writer, raw numbers verbatim.
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
//! A JSON library that keeps number lexemes hands a foreign serializer a token struct in place of
//! a number, and the YAML writer refuses it (`yaml::TagWriter`). [`to_yaml`] is the conversion:
//! every number becomes a real YAML scalar, or is refused when it cannot be written exactly.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{Deserialize, DeserializeOwned};
use serde::Serialize;

use crate::spans::{exceeds_max_depth, MAX_JSON_DEPTH};

pub use sonic_rs::error::Category;
pub use sonic_rs::{
    json, Array, JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, LazyValue, Number,
    Object as Map, OwnedLazyValue, RawNumber, Value,
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

/// The log line for a body that did not parse: its length, never its bytes.
#[cold]
pub fn parse_err_log(bytes_len: usize) -> String {
    format!("invalid JSON ({bytes_len} bytes)")
}

/// Convert plugin JSON into real YAML scalars. serde_json arbitrary_precision exposes a
/// private map marker through generic serializers, which would corrupt numeric settings.
/// Refuse integers outside YAML's exact range instead of silently rounding their value.
pub fn to_yaml(value: &serde_json::Value) -> Result<crate::yaml::Value, String> {
    use crate::yaml::Value;
    use serde_json::Value as Json;
    Ok(match value {
        Json::Null => Value::Null,
        Json::Bool(value) => Value::Bool(*value),
        Json::String(value) => Value::Text(value.clone()),
        Json::Number(value) => {
            if let Some(value) = value.as_u64() {
                Value::from(value)
            } else if let Some(value) = value.as_i64() {
                Value::from(value)
            } else {
                let text = value.to_string();
                if !text.contains(['.', 'e', 'E']) {
                    return Err("plugin migration integer exceeds the exact YAML range".into());
                }
                let value = value
                    .as_f64()
                    .filter(|value| value.is_finite())
                    .ok_or("plugin migration number is not a finite YAML scalar")?;
                let replay = serde_json::Number::from_f64(value)
                    .ok_or("plugin migration number is not finite")?
                    .to_string();
                if decimal_value(&text) != decimal_value(&replay) {
                    return Err(
                        "plugin migration decimal cannot be represented exactly in YAML".into(),
                    );
                }
                Value::Float(value)
            }
        }
        Json::Array(values) => Value::Array(values.iter().map(to_yaml).collect::<Result<_, _>>()?),
        Json::Object(values) => Value::Map(
            values
                .iter()
                .map(|(key, value)| Ok((Value::Text(key.clone()), to_yaml(value)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

fn decimal_value(text: &str) -> Option<(bool, String, i64)> {
    let (negative, text) = text
        .strip_prefix('-')
        .map_or((false, text), |text| (true, text));
    let (coefficient, exponent) =
        text.split_once(['e', 'E'])
            .map_or(Some((text, 0_i64)), |(coefficient, exponent)| {
                exponent
                    .parse()
                    .ok()
                    .map(|exponent| (coefficient, exponent))
            })?;
    let decimals = coefficient
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let mut digits = coefficient.replace('.', "");
    digits = digits.trim_start_matches('0').to_owned();
    if digits.is_empty() {
        return Some((false, "0".into(), 0));
    }
    let trailing = digits.len() - digits.trim_end_matches('0').len();
    digits.truncate(digits.len() - trailing);
    let exponent = exponent
        .checked_sub(i64::try_from(decimals).ok()?)?
        .checked_add(i64::try_from(trailing).ok()?)?;
    Some((negative, digits, exponent))
}
