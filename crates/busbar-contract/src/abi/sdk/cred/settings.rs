// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Settings parsed so credentials are sealed as they are read and no error quotes a value.

use core::fmt;

use serde::de::value::{MapAccessDeserializer, MapDeserializer, SeqDeserializer};
use serde::de::{self, DeserializeOwned, Expected, IntoDeserializer, Unexpected, Visitor};
use serde::forward_to_deserialize_any;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use super::{Cred, CredUrl, UserinfoUrl};

/// Why settings did not parse: the field path and what was wrong, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsError {
    path: String,
    what: String,
}

impl SettingsError {
    fn new(what: String) -> Self {
        Self {
            path: String::new(),
            what,
        }
    }

    fn at(mut self, path: &str) -> Self {
        if self.path.is_empty() {
            self.path = path.to_owned();
        }
        self
    }

    /// The path of the setting that failed (`""` = the document).
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// `settings: ` and serde's own words, every value in them written `***` ([`SettingsError::path`]
/// names where).
impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "settings: {}", self.what)
    }
}

impl std::error::Error for SettingsError {}

/// serde's `Unexpected` words with the value written `***`.
fn kind(u: &Unexpected<'_>) -> &'static str {
    match u {
        Unexpected::Bool(_) => "boolean `***`",
        Unexpected::Unsigned(_) | Unexpected::Signed(_) => "integer `***`",
        Unexpected::Float(_) => "floating point `***`",
        Unexpected::Char(_) => "character `***`",
        Unexpected::Str(_) => "string \"***\"",
        Unexpected::Bytes(_) => "byte array",
        Unexpected::Unit => "unit value",
        Unexpected::Option => "Option value",
        Unexpected::NewtypeStruct => "newtype struct",
        Unexpected::Seq => "sequence",
        Unexpected::Map => "map",
        Unexpected::Enum => "enum",
        Unexpected::UnitVariant => "unit variant",
        Unexpected::NewtypeVariant => "newtype variant",
        Unexpected::TupleVariant => "tuple variant",
        Unexpected::StructVariant => "struct variant",
        Unexpected::Other(_) => "a value",
    }
}

/// serde's `one of` list.
fn one_of(names: &'static [&'static str]) -> String {
    match names {
        [] => "there are no fields".to_owned(),
        [one] => format!("expected `{one}`"),
        [a, b] => format!("expected `{a}` or `{b}`"),
        many => format!(
            "expected one of {}",
            many.iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

impl de::Error for SettingsError {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self::new("invalid value".into())
    }
    fn invalid_type(unexp: Unexpected<'_>, exp: &dyn Expected) -> Self {
        Self::new(format!("invalid type: {}, expected {exp}", kind(&unexp)))
    }
    fn invalid_value(unexp: Unexpected<'_>, exp: &dyn Expected) -> Self {
        Self::new(format!("invalid value: {}, expected {exp}", kind(&unexp)))
    }
    fn invalid_length(len: usize, exp: &dyn Expected) -> Self {
        Self::new(format!("invalid length {len}, expected {exp}"))
    }
    fn unknown_variant(_: &str, expected: &'static [&'static str]) -> Self {
        Self::new(format!("unknown variant `***`, {}", one_of(expected)))
    }
    fn unknown_field(field: &str, expected: &'static [&'static str]) -> Self {
        Self::new(format!("unknown field `{field}`, {}", one_of(expected)))
    }
    fn missing_field(field: &'static str) -> Self {
        Self::new(format!("missing field `{field}`"))
    }
    fn duplicate_field(field: &'static str) -> Self {
        Self::new(format!("duplicate field `{field}`"))
    }
}

/// Parse a plugin's settings document into `T`. Every [`Cred`] and [`CredUrl`] field is sealed as
/// it is read, every string the parse tree held is wiped, and the error names a path and a type,
/// never a value.
///
/// # Errors
/// The document is not JSON, or does not match `T`.
pub fn settings<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, SettingsError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| {
        SettingsError::new(format!(
            "not a JSON document (line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;
    T::deserialize(Node::new(value, String::new()))
}

fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(m) => {
            let taken = core::mem::take(m);
            for (mut k, mut v) in taken {
                k.zeroize();
                wipe(&mut v);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

struct Node {
    value: Value,
    path: String,
}

impl Node {
    fn new(value: Value, path: String) -> Self {
        Self { value, path }
    }

    fn take(&mut self) -> Value {
        core::mem::take(&mut self.value)
    }

    fn child(&self, key: &str) -> String {
        if self.path.is_empty() {
            key.to_owned()
        } else {
            format!("{}.{key}", self.path)
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        wipe(&mut self.value);
    }
}

struct Key(String);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> IntoDeserializer<'de, SettingsError> for Node {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

impl<'de> IntoDeserializer<'de, SettingsError> for Key {
    type Deserializer = de::value::StringDeserializer<SettingsError>;
    fn into_deserializer(mut self) -> Self::Deserializer {
        core::mem::take(&mut self.0).into_deserializer()
    }
}

impl Node {
    fn entries(&mut self) -> Vec<(Key, Node)> {
        let Value::Object(map) = self.take() else {
            return Vec::new();
        };
        map.into_iter()
            .map(|(k, v)| {
                let p = self.child(&k);
                (Key(k), Node::new(v, p))
            })
            .collect()
    }

    fn items(&mut self) -> Vec<Node> {
        let Value::Array(a) = self.take() else {
            return Vec::new();
        };
        a.into_iter()
            .enumerate()
            .map(|(i, v)| Node::new(v, self.child(&i.to_string())))
            .collect()
    }
}

impl<'de> de::Deserializer<'de> for Node {
    type Error = SettingsError;

    fn deserialize_any<V: Visitor<'de>>(mut self, visitor: V) -> Result<V::Value, Self::Error> {
        let path = self.path.clone();
        let out = match &self.value {
            Value::Null => visitor.visit_unit(),
            Value::Bool(b) => visitor.visit_bool(*b),
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    visitor.visit_u64(u)
                } else if let Some(i) = n.as_i64() {
                    visitor.visit_i64(i)
                } else {
                    visitor.visit_f64(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            Value::String(_) => {
                let Value::String(s) = self.take() else {
                    unreachable!()
                };
                visitor.visit_string(s)
            }
            Value::Array(_) => {
                let items = self.items();
                visitor.visit_seq(SeqDeserializer::new(items.into_iter()))
            }
            Value::Object(_) => {
                let entries = self.entries();
                visitor.visit_map(MapDeserializer::new(entries.into_iter()))
            }
        };
        out.map_err(|e| e.at(&path))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        if self.value.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        mut self,
        _: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        let path = self.path.clone();
        let out = match &self.value {
            Value::String(_) => {
                let Value::String(s) = self.take() else {
                    unreachable!()
                };
                let key = Key(s);
                visitor.visit_enum(key.into_deserializer())
            }
            Value::Object(_) => {
                let entries = self.entries();
                visitor.visit_enum(MapAccessDeserializer::new(MapDeserializer::new(
                    entries.into_iter(),
                )))
            }
            _ => Err(de::Error::invalid_type(
                Unexpected::Other("a non-variant"),
                &"a variant",
            )),
        };
        out.map_err(|e| e.at(&path))
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        drop(self);
        visitor.visit_unit()
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        unit unit_struct seq tuple tuple_struct map struct identifier
    }
}

struct CredVisitor;

impl<'de> Visitor<'de> for CredVisitor {
    type Value = Cred;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }
    fn visit_str<E: de::Error>(self, s: &str) -> Result<Cred, E> {
        Ok(Cred::from_bytes(Zeroizing::new(s.as_bytes().to_vec())))
    }
    fn visit_string<E: de::Error>(self, s: String) -> Result<Cred, E> {
        Ok(Cred::from_bytes(Zeroizing::new(s.into_bytes())))
    }
}

impl<'de> de::Deserialize<'de> for Cred {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_string(CredVisitor)
    }
}

struct CredUrlVisitor;

impl<'de> Visitor<'de> for CredUrlVisitor {
    type Value = CredUrl;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }
    fn visit_str<E: de::Error>(self, s: &str) -> Result<CredUrl, E> {
        CredUrl::split(s).map_err(|why| E::invalid_value(Unexpected::Other("a string"), &why))
    }
    fn visit_string<E: de::Error>(self, s: String) -> Result<CredUrl, E> {
        let s = Zeroizing::new(s);
        self.visit_str(&s)
    }
}

impl<'de> de::Deserialize<'de> for CredUrl {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_string(CredUrlVisitor)
    }
}

struct UserinfoUrlVisitor;

impl<'de> Visitor<'de> for UserinfoUrlVisitor {
    type Value = UserinfoUrl;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }
    fn visit_str<E: de::Error>(self, s: &str) -> Result<UserinfoUrl, E> {
        CredUrl::parse_userinfo(s)
            .map(UserinfoUrl)
            .map_err(|why| E::invalid_value(Unexpected::Other("a string"), &why))
    }
    fn visit_string<E: de::Error>(self, s: String) -> Result<UserinfoUrl, E> {
        let s = Zeroizing::new(s);
        self.visit_str(&s)
    }
}

impl<'de> de::Deserialize<'de> for UserinfoUrl {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_string(UserinfoUrlVisitor)
    }
}
