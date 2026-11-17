// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed JSON span grammar: the one serialization busbar reads, read once.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

pub use busbar_count::json_span::{resolve_pointer, scan_frontier, Resolved, Span, MAX_JSON_DEPTH};

use serde::{Deserialize, Deserializer};
use serde_json::{value::RawValue, Value};
use std::marker::PhantomData;

/// Parse one document bounded by [`MAX_JSON_DEPTH`], preserving exact numeric lexemes and
/// literal object keys, including serde's private number marker. Duplicate object keys keep
/// their last value. This is for public JSON; decoded strings are ordinary owned strings.
pub fn parse_value(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    if crate::spans::exceeds_max_depth(bytes, MAX_JSON_DEPTH) {
        return Err(<serde_json::Error as serde::de::Error>::custom(format!(
            "JSON nesting exceeds {MAX_JSON_DEPTH}"
        )));
    }
    serde_json::from_slice::<Tokens<Exact>>(bytes).map(|value| value.0)
}

/// Parse one document as serde_json's typed reader reads it: the `Value` a typed field sees.
///
/// Strings, literals and containers are serde_json's own, with literal object keys and the last
/// of duplicate keys kept. Each number token is read by serde_json's typed reader as `u64`, else
/// `i64`, else `f64`, the first reading an integer field accepts, so a token no integer field
/// accepts stays a non-integer number. A `Value` parsed directly is not that reading under
/// `arbitrary_precision`, which every build carries (`-0` reads there as the integer `0`).
///
/// # Errors
/// What serde_json refuses for the document, in its words, and a number its typed reader cannot
/// read (one beyond `f64`).
pub fn parse_typed_value(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    typed_value(bytes, drop)
}

/// [`parse_typed_value`] for a document whose strings are secret: the checked copy it reads
/// first is [`wipe`]d, as the caller wipes the value it is answered.
///
/// # Errors
/// As [`parse_typed_value`].
pub fn parse_typed_value_wiping(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    typed_value(bytes, |mut checked| wipe(&mut checked))
}

/// The typed reading of `bytes`; `discard` takes the checked copy once it is read.
fn typed_value(bytes: &[u8], discard: impl FnOnce(Value)) -> Result<Value, serde_json::Error> {
    // serde_json's own refusal and depth bound first: the token walk recurses per container.
    let checked = serde_json::from_slice::<Value>(bytes)?;
    let typed = serde_json::from_slice::<Tokens<Typed>>(bytes).map(|value| value.0);
    discard(checked);
    typed
}

/// Zero `value`'s owned strings and object keys, leaving it empty of them.
pub fn wipe(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(items) => {
            for (mut key, mut value) in std::mem::take(items) {
                key.zeroize();
                wipe(&mut value);
            }
        }
        _ => {}
    }
}

/// How a document's scalar tokens are read; its containers are walked by [`Tokens`].
trait Scalar {
    fn read(token: &str) -> Result<Value, serde_json::Error>;
}

/// Each scalar as `Value` reads it, numbers kept as their exact lexeme.
struct Exact;

impl Scalar for Exact {
    fn read(token: &str) -> Result<Value, serde_json::Error> {
        serde_json::from_str::<Value>(token)
    }
}

/// Each number as serde_json's typed reader reads it; other scalars as `Value` reads them.
struct Typed;

impl Scalar for Typed {
    fn read(token: &str) -> Result<Value, serde_json::Error> {
        if !matches!(token.as_bytes().first(), Some(b'-' | b'0'..=b'9')) {
            return serde_json::from_str::<Value>(token);
        }
        if let Ok(unsigned) = serde_json::from_str::<u64>(token) {
            return Ok(Value::from(unsigned));
        }
        if let Ok(signed) = serde_json::from_str::<i64>(token) {
            return Ok(Value::from(signed));
        }
        // The typed reader yields only a finite `f64`, which is always a JSON number.
        serde_json::from_str::<f64>(token).map(Value::from)
    }
}

/// One document's tree, its scalar tokens read by `S`.
struct Tokens<S>(Value, PhantomData<S>);

impl<'de, S: Scalar> Deserialize<'de> for Tokens<S> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // RawValue identifies the actual JSON token before any arbitrary-precision transport
        // maps are synthesized. Container members recurse through this same distinction; only
        // scalar tokens reach `S`. Escaped object keys remain ordinary keys.
        let raw = <&RawValue>::deserialize(deserializer)?.get();
        let value = match raw.as_bytes().first() {
            Some(b'{') => {
                let mut de = serde_json::Deserializer::from_str(raw);
                de.deserialize_map(ObjectVisitor::<S>(PhantomData))
            }
            Some(b'[') => serde_json::from_str::<Vec<Tokens<S>>>(raw)
                .map(|items| Value::Array(items.into_iter().map(|item| item.0).collect())),
            _ => S::read(raw),
        };
        value
            .map(|value| Tokens(value, PhantomData))
            .map_err(serde::de::Error::custom)
    }
}

struct ObjectVisitor<S>(PhantomData<S>);

impl<'de, S: Scalar> serde::de::Visitor<'de> for ObjectVisitor<S> {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, Tokens<S>>()? {
            object.insert(key, value.0);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod exact_value_tests {
    use super::*;

    #[test]
    fn exact_values_preserve_literal_marker_keys_numbers_and_duplicate_policy() {
        let value = parse_value(br#"{"$serde_json::private::Number":"123","n":1e+400,"id":18446744073709551617,"x":1,"x":2}"#).unwrap();
        assert_eq!(value["$serde_json::private::Number"], "123");
        assert_eq!(value["n"].to_string(), "1e+400");
        assert_eq!(value["id"].to_string(), "18446744073709551617");
        assert_eq!(value["x"], 2);
        assert!(parse_value(br#"{"x":1} trailing"#).is_err());
        assert!(parse_value(b"[1,]").is_err());
    }

    #[test]
    fn exact_values_bound_recursive_container_depth() {
        let body = |depth| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert!(parse_value(body(MAX_JSON_DEPTH - 1).as_bytes()).is_ok());
        assert!(parse_value(body(MAX_JSON_DEPTH + 1).as_bytes()).is_err());
    }
}

#[cfg(test)]
mod bc2_depth_error_tests {
    use super::*;

    #[test]
    fn over_depth_error_is_not_eof_and_names_depth() {
        let doc = "[".repeat(MAX_JSON_DEPTH + 1) + &"]".repeat(MAX_JSON_DEPTH + 1);
        let err = parse_value(doc.as_bytes()).unwrap_err();
        assert!(!err.is_eof(), "got {err}");
        assert!(err.to_string().contains("nesting"), "got {err}");
    }
}
