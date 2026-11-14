// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! YAML for busbar: one parser and emitter, serde-saphyr (YAML 1.2, `forbid(unsafe_code)`), with
//! every option pinned to the meaning busbar 1.5.5 gave a configuration file, and one untyped tree,
//! ciborium's [`Value`], whose mappings keep their key order as a `Vec` of pairs.
//!
//! Every YAML read and write in core and in the plugins goes through this module. Nothing here is
//! a YAML parser, emitter or value type of our own: the parser and emitter are serde-saphyr's, the
//! tree is ciborium's, and the traits below only add serde_yaml-style lookups to that tree.
//!
//! What the pins keep from 1.5.5 (serde_yaml_ng 0.10 on libyaml), each with a test in
//! `tests/yaml_1_5_5_meaning.rs`:
//! - `yes`, `no`, `on`, `off`, `y`, `n` (any case) are strings, never booleans.
//! - Integers with redundant leading zeros (`0644`, `-007`, `+00`) are strings when read untyped.
//! - Numbers with underscores (`1_000`) are strings when read untyped.
//! - `1:30` (sexagesimal) is a string.
//! - `<<` is a literal key; merge keys are not expanded.
//! - A duplicate key is refused, with the line and column of the repeat.
//! - `.inf`, `-.inf` and `.nan` are floats.
//! - Application tags (`!Tag value`) are accepted, as 1.5.5 accepted them. An untyped read gives
//!   the node's value; the admin source bridge (busbar-kernel `document_source`) carries the tag
//!   itself through an edit.

#![forbid(unsafe_code)]

use std::fmt;

use serde::de::DeserializeOwned;
use serde::Serialize;

pub use ciborium::Value;
pub use serde_saphyr::{Deserializer, Location};

/// A YAML mapping: the key/value pairs of a [`Value::Map`], in document order.
pub type Mapping = Vec<(Value, Value)>;

/// Everything a YAML call site needs in scope: the tree, the mapping, and their lookups.
pub mod prelude {
    pub use super::{Index, Mapping, MappingExt, Value, ValueExt};
}

/// The parser options, pinned to 1.5.5's meaning. The one place they are set.
#[must_use]
pub fn options() -> serde_saphyr::Options {
    use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy, NonFiniteFloatPolicy};
    serde_saphyr::options! {
        duplicate_keys: DuplicateKeyPolicy::Error,
        merge_keys: MergeKeyPolicy::AsOrdinary,
        strict_booleans: true,
        legacy_octal_numbers: false,
        leading_zero_numbers_as_strings: true,
        underscored_numbers_as_strings: true,
        ignore_binary_tag_for_string: true,
        reject_unsupported_tags: false,
        non_finite_float_policy: NonFiniteFloatPolicy::PassThrough,
        with_snippet: false,
    }
}

/// A YAML read or write failure: the message, and where in the text it happened when known.
#[derive(Debug)]
pub struct Error {
    message: String,
    /// The document path to the failing node (`a.b[0].c`), as serde_yaml printed it; `None` at
    /// the root.
    path: Option<String>,
    location: Option<Location>,
    /// Whether `Display` appends the position (false when the message already carries one).
    placed_suffix: bool,
}

impl Error {
    /// Where in the YAML text the error happened (1-based line and column), when known.
    #[must_use]
    pub fn location(&self) -> Option<Location> {
        self.location
    }

    fn unplaced(message: impl fmt::Display) -> Self {
        Self {
            message: message.to_string(),
            path: None,
            location: None,
            placed_suffix: false,
        }
    }
}

impl fmt::Display for Error {
    /// serde_yaml's shape: `path: ` when below the root, the message, then ` at line L column C`
    /// when the position is known.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(f, "{path}: ")?;
        }
        f.write_str(&self.message)?;
        match self.location.filter(|_| self.placed_suffix) {
            Some(at) => write!(f, " at line {} column {}", at.line(), at.column()),
            None => Ok(()),
        }
    }
}

impl std::error::Error for Error {}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::unplaced(msg)
    }
}

impl serde::ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::unplaced(msg)
    }
}

impl From<serde_saphyr::Error> for Error {
    /// Keeps the bare message; [`Error`]'s `Display` adds the position as serde_yaml did
    /// (serde-saphyr writes ` at line L, column C`).
    fn from(error: serde_saphyr::Error) -> Self {
        let location = error.location().filter(|l| *l != Location::UNKNOWN);
        let mut message = error.to_string();
        let mut placed_suffix = false;
        if let Some(at) = location {
            let suffix = format!(" at line {}, column {}", at.line(), at.column());
            if let Some(bare) = message.strip_suffix(&suffix) {
                message = bare.to_owned();
                placed_suffix = true;
            }
        }
        Self {
            message,
            path: None,
            location,
            placed_suffix,
        }
    }
}

impl Error {
    fn at_path(mut self, path: serde_path_to_error::Path) -> Self {
        let path = path.to_string();
        if path != "." {
            self.path = Some(path);
        }
        self
    }
}

impl From<serde_saphyr::SerializeError> for Error {
    fn from(error: serde_saphyr::SerializeError) -> Self {
        Self::unplaced(error)
    }
}

/// Read a YAML document into `T`.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    with_deserializer(text, |d| T::deserialize(d))
}

/// Read a UTF-8 YAML document into `T`.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    let text = std::str::from_utf8(bytes).map_err(Error::unplaced)?;
    from_str(text)
}

/// Read a YAML document whose top level must be a mapping, keeping its key order. ([`Mapping`] is
/// a `Vec` of pairs, so `from_str::<Mapping>` would ask for a sequence; read it through here.)
pub fn mapping_from_str(text: &str) -> Result<Mapping, Error> {
    match from_str::<Value>(text)? {
        Value::Map(mapping) => Ok(mapping),
        _ => Err(Error::unplaced("invalid type: expected a mapping")),
    }
}

/// [`mapping_from_str`] over UTF-8 bytes.
pub fn mapping_from_slice(bytes: &[u8]) -> Result<Mapping, Error> {
    match from_slice::<Value>(bytes)? {
        Value::Map(mapping) => Ok(mapping),
        _ => Err(Error::unplaced("invalid type: expected a mapping")),
    }
}

/// The deserializer [`with_deserializer`] hands its reader: serde-saphyr's, tracking the path to
/// the node being read so an error names it, as serde_yaml's did.
pub type Tracked<'t, 'de, 'e> = serde_path_to_error::Deserializer<'t, 't, Deserializer<'de, 'e>>;

/// Run `read` over a YAML deserializer for `text`: for generic `D: Deserializer` readers and
/// `DeserializeSeed`s, where serde_yaml offered `Deserializer::from_str`.
pub fn with_deserializer<'de, R, F>(text: &'de str, read: F) -> Result<R, Error>
where
    F: for<'t, 'e> FnOnce(Tracked<'t, 'de, 'e>) -> Result<R, serde_saphyr::Error>,
{
    let mut track = serde_path_to_error::Track::new();
    let read = serde_saphyr::with_deserializer_from_str_with_options(text, options(), |de| {
        read(serde_path_to_error::Deserializer::new(de, &mut track))
    });
    read.map_err(|e| Error::from(e).at_path(track.path()))
}

/// The first application tag (`!Name`, or a non-core tag URI) anywhere in the document, keys
/// included; `None` when it has none. An untyped [`Value`] read keeps a tagged node's value but
/// not its tag, so a reader that must refuse or carry tags asks here first.
pub fn first_application_tag(text: &str) -> Result<Option<String>, Error> {
    with_deserializer(text, |d| {
        serde::de::DeserializeSeed::deserialize(FindTag, d)
    })
}

/// serde-saphyr's newtype name for its public `serde_saphyr::Tagged<T>` wrapper: a deserializer
/// asked for it hands the visitor the node as the sequence `[value, tag?]`.
const TAGGED: &str = "__yaml_tagged";

struct FindTag;

impl<'de> serde::de::DeserializeSeed<'de> for FindTag {
    type Value = Option<String>;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_newtype_struct(TAGGED, self)
    }
}

impl<'de> serde::de::Visitor<'de> for FindTag {
    type Value = Option<String>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a YAML node")
    }
    fn visit_newtype_struct<D: serde::Deserializer<'de>>(
        self,
        de: D,
    ) -> Result<Self::Value, D::Error> {
        de.deserialize_any(FindTagInside)
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let inside = seq.next_element_seed(FindTagInsideSeed)?.flatten();
        let tag = seq
            .next_element::<String>()?
            .filter(|t| !t.starts_with("tag:yaml.org,2002:"));
        Ok(tag.or(inside))
    }
}

struct FindTagInsideSeed;

impl<'de> serde::de::DeserializeSeed<'de> for FindTagInsideSeed {
    type Value = Option<String>;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_any(FindTagInside)
    }
}

/// The node itself (its own tag already read): scalars carry none further; collections are
/// searched through their keys and values.
struct FindTagInside;

impl<'de> serde::de::Visitor<'de> for FindTagInside {
    type Value = Option<String>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a YAML node")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_i128<E: serde::de::Error>(self, _: i128) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_u128<E: serde::de::Error>(self, _: u128) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_bytes<E: serde::de::Error>(self, _: &[u8]) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_any(FindTagInside)
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut found = None;
        while let Some(tag) = seq.next_element_seed(FindTag)? {
            found = found.or(tag);
        }
        Ok(found)
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut found = None;
        while let Some(tag) = map.next_key_seed(FindTag)? {
            found = found.or(tag);
            found = found.or(map.next_value_seed(FindTag)?);
        }
        Ok(found)
    }
}

/// Write `value` as a YAML document.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    Ok(serde_saphyr::to_string(&value)?)
}

/// Write `value` as a YAML document to `writer`.
pub fn to_writer<W: std::io::Write, T: Serialize + ?Sized>(
    mut writer: W,
    value: &T,
) -> Result<(), Error> {
    Ok(serde_saphyr::to_io_writer(&mut writer, &value)?)
}

/// Read a [`Value`] tree into `T` exactly as if `T` had been read from the text: the tree is
/// written out and read back through the same pinned parser, so integer-into-float fields, `null`,
/// human-readable forms and every pin behave as they do for a direct read. Config-time only.
pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    let text = to_string(&value)?;
    from_str(&text).map_err(|e| Error::unplaced(e.message))
}

/// Write `value` into a [`Value`] tree, as reading back its YAML text would give it.
pub fn to_value<T: Serialize + ?Sized>(value: &T) -> Result<Value, Error> {
    let text = to_string(value)?;
    from_str(&text).map_err(|e| Error::unplaced(e.message))
}

/// A way to index into a [`Value`]: a string key, an integer key or sequence position, or a
/// [`Value`] key. The same set serde_yaml's `Index` accepted.
pub trait Index {
    /// The position of this key among `mapping`'s pairs.
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize>;
    /// The sequence element this index names, if it is a position.
    fn element<'v>(&self, _sequence: &'v [Value]) -> Option<&'v Value> {
        None
    }
    /// The sequence element this index names, mutably.
    fn element_mut<'v>(&self, _sequence: &'v mut [Value]) -> Option<&'v mut Value> {
        None
    }
    /// This index as a mapping key.
    fn key(&self) -> Value;
}

impl Index for str {
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize> {
        mapping
            .iter()
            .position(|(k, _)| matches!(k, Value::Text(t) if t == self))
    }
    fn key(&self) -> Value {
        Value::Text(self.to_owned())
    }
}

impl Index for String {
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize> {
        self.as_str().position(mapping)
    }
    fn key(&self) -> Value {
        Value::Text(self.clone())
    }
}

impl Index for usize {
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize> {
        let wanted = u64::try_from(*self).ok()?;
        mapping
            .iter()
            .position(|(k, _)| k.as_integer().and_then(|i| u64::try_from(i).ok()) == Some(wanted))
    }
    fn element<'v>(&self, sequence: &'v [Value]) -> Option<&'v Value> {
        sequence.get(*self)
    }
    fn element_mut<'v>(&self, sequence: &'v mut [Value]) -> Option<&'v mut Value> {
        sequence.get_mut(*self)
    }
    fn key(&self) -> Value {
        Value::from(*self as u64)
    }
}

impl Index for Value {
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize> {
        mapping.iter().position(|(k, _)| k == self)
    }
    fn element<'v>(&self, sequence: &'v [Value]) -> Option<&'v Value> {
        let at = usize::try_from(self.as_integer()?).ok()?;
        sequence.get(at)
    }
    fn element_mut<'v>(&self, sequence: &'v mut [Value]) -> Option<&'v mut Value> {
        let at = usize::try_from(self.as_integer()?).ok()?;
        sequence.get_mut(at)
    }
    fn key(&self) -> Value {
        self.clone()
    }
}

impl<T: Index + ?Sized> Index for &T {
    fn position(&self, mapping: &[(Value, Value)]) -> Option<usize> {
        (**self).position(mapping)
    }
    fn element<'v>(&self, sequence: &'v [Value]) -> Option<&'v Value> {
        (**self).element(sequence)
    }
    fn element_mut<'v>(&self, sequence: &'v mut [Value]) -> Option<&'v mut Value> {
        (**self).element_mut(sequence)
    }
    fn key(&self) -> Value {
        (**self).key()
    }
}

static NULL: Value = Value::Null;

/// serde_yaml-style reads over a [`Value`].
pub trait ValueExt {
    /// The value at `index` in a mapping or sequence; `None` when absent or not a collection.
    fn get<I: Index>(&self, index: I) -> Option<&Value>;
    /// The value at `index`, mutably.
    fn get_mut<I: Index>(&mut self, index: I) -> Option<&mut Value>;
    /// `value[index]` as serde_yaml read it: the value at `index`, or `Null` when absent.
    fn at<I: Index>(&self, index: I) -> &Value;
    /// `value[index] = ..` as serde_yaml wrote it: a `Null` becomes an empty mapping, and a
    /// missing mapping key is inserted as `Null`.
    ///
    /// # Panics
    /// When the value is neither a mapping nor `Null`, or a sequence position is out of range, as
    /// serde_yaml's `IndexMut` did.
    fn at_mut<I: Index>(&mut self, index: I) -> &mut Value;
    /// The string, if this is a string.
    fn as_str(&self) -> Option<&str>;
    /// The mapping, if this is a mapping.
    fn as_mapping(&self) -> Option<&Mapping>;
    /// The mapping, mutably.
    fn as_mapping_mut(&mut self) -> Option<&mut Mapping>;
    /// The sequence, if this is a sequence.
    fn as_sequence(&self) -> Option<&Vec<Value>>;
    /// The sequence, mutably.
    fn as_sequence_mut(&mut self) -> Option<&mut Vec<Value>>;
    /// The integer as a `u64`, if it is one.
    fn as_u64(&self) -> Option<u64>;
    /// The integer as an `i64`, if it is one.
    fn as_i64(&self) -> Option<i64>;
    /// The number as an `f64` (integers included), if it is one.
    fn as_f64(&self) -> Option<f64>;
    /// Whether this is a mapping.
    fn is_mapping(&self) -> bool;
    /// Whether this is a sequence.
    fn is_sequence(&self) -> bool;
    /// Whether this is a string.
    fn is_string(&self) -> bool;
    /// Whether this is a number (integer or float).
    fn is_number(&self) -> bool;
    /// Whether this is an integer that fits a `u64`.
    fn is_u64(&self) -> bool;
    /// Whether this is an integer that fits an `i64`.
    fn is_i64(&self) -> bool;
    /// Whether this is a float.
    fn is_f64(&self) -> bool;
}

impl ValueExt for Value {
    fn get<I: Index>(&self, index: I) -> Option<&Value> {
        match self {
            Value::Map(m) => index.position(m).map(|at| &m[at].1),
            Value::Array(s) => index.element(s),
            _ => None,
        }
    }

    fn get_mut<I: Index>(&mut self, index: I) -> Option<&mut Value> {
        match self {
            Value::Map(m) => index.position(m).map(|at| &mut m[at].1),
            Value::Array(s) => index.element_mut(s),
            _ => None,
        }
    }

    fn at<I: Index>(&self, index: I) -> &Value {
        self.get(index).unwrap_or(&NULL)
    }

    fn at_mut<I: Index>(&mut self, index: I) -> &mut Value {
        if self.is_null() {
            *self = Value::Map(Mapping::new());
        }
        match self {
            Value::Map(m) => {
                let at = match index.position(m) {
                    Some(at) => at,
                    None => {
                        m.push((index.key(), Value::Null));
                        m.len() - 1
                    }
                };
                &mut m[at].1
            }
            Value::Array(s) => index
                .element_mut(s)
                .expect("YAML sequence index out of range"),
            _ => panic!("cannot index into a YAML scalar"),
        }
    }

    fn as_str(&self) -> Option<&str> {
        self.as_text()
    }

    fn as_mapping(&self) -> Option<&Mapping> {
        self.as_map()
    }

    fn as_mapping_mut(&mut self) -> Option<&mut Mapping> {
        self.as_map_mut()
    }

    fn as_sequence(&self) -> Option<&Vec<Value>> {
        self.as_array()
    }

    fn as_sequence_mut(&mut self) -> Option<&mut Vec<Value>> {
        self.as_array_mut()
    }

    fn as_u64(&self) -> Option<u64> {
        self.as_integer().and_then(|i| u64::try_from(i).ok())
    }

    fn as_i64(&self) -> Option<i64> {
        self.as_integer().and_then(|i| i64::try_from(i).ok())
    }

    #[allow(clippy::cast_precision_loss)]
    fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Integer(i) => Some(i128::from(*i) as f64),
            _ => None,
        }
    }

    fn is_mapping(&self) -> bool {
        self.is_map()
    }

    fn is_sequence(&self) -> bool {
        self.is_array()
    }

    fn is_string(&self) -> bool {
        self.is_text()
    }

    fn is_number(&self) -> bool {
        self.is_integer() || self.is_float()
    }

    fn is_u64(&self) -> bool {
        self.as_u64().is_some()
    }

    fn is_i64(&self) -> bool {
        self.as_i64().is_some()
    }

    fn is_f64(&self) -> bool {
        self.is_float()
    }
}

/// serde_yaml `Mapping`-style key operations over a [`Mapping`] (a `Vec` of pairs, in order).
///
/// The names differ from serde_yaml's where `Vec` already has a method of that name
/// (`get`, `get_mut`, `insert`, `remove`, `retain`).
pub trait MappingExt {
    /// The value under `key`.
    fn get_key<I: Index>(&self, key: I) -> Option<&Value>;
    /// The value under `key`, mutably.
    fn get_key_mut<I: Index>(&mut self, key: I) -> Option<&mut Value>;
    /// Whether `key` is present.
    fn contains_key<I: Index>(&self, key: I) -> bool;
    /// Set `key` to `value`: replaced in place when present (keeping its position), appended
    /// otherwise. Returns the old value.
    fn insert_key(&mut self, key: impl Into<Value>, value: Value) -> Option<Value>;
    /// Remove `key`, as serde_yaml's `Mapping::remove` did: the last pair moves into its place
    /// (`swap_remove`), so migrated documents keep 1.5.5's key order. Returns its value.
    fn remove_key<I: Index>(&mut self, key: I) -> Option<Value>;
    /// Remove `key` and return the pair, as [`MappingExt::remove_key`] does.
    fn remove_entry_key<I: Index>(&mut self, key: I) -> Option<(Value, Value)>;
    /// The value under `key`, inserted from `make` first when absent.
    fn entry_or_insert_with<I: Index>(
        &mut self,
        key: I,
        make: impl FnOnce() -> Value,
    ) -> &mut Value;
    /// The keys, in order.
    fn keys(&self) -> impl Iterator<Item = &Value>;
    /// The values, in order.
    fn values(&self) -> impl Iterator<Item = &Value>;
    /// The values, in order, mutably.
    fn values_mut(&mut self) -> impl Iterator<Item = &mut Value>;
    /// Keep only the pairs `keep` accepts, in order.
    fn retain_pairs(&mut self, keep: impl FnMut(&Value, &mut Value) -> bool);
}

impl MappingExt for Mapping {
    fn get_key<I: Index>(&self, key: I) -> Option<&Value> {
        key.position(self).map(|at| &self[at].1)
    }

    fn get_key_mut<I: Index>(&mut self, key: I) -> Option<&mut Value> {
        key.position(self).map(|at| &mut self[at].1)
    }

    fn contains_key<I: Index>(&self, key: I) -> bool {
        key.position(self).is_some()
    }

    fn insert_key(&mut self, key: impl Into<Value>, value: Value) -> Option<Value> {
        let key = key.into();
        match key.position(self) {
            Some(at) => Some(std::mem::replace(&mut self[at].1, value)),
            None => {
                self.push((key, value));
                None
            }
        }
    }

    fn remove_key<I: Index>(&mut self, key: I) -> Option<Value> {
        self.remove_entry_key(key).map(|(_, v)| v)
    }

    fn remove_entry_key<I: Index>(&mut self, key: I) -> Option<(Value, Value)> {
        key.position(self).map(|at| self.swap_remove(at))
    }

    fn entry_or_insert_with<I: Index>(
        &mut self,
        key: I,
        make: impl FnOnce() -> Value,
    ) -> &mut Value {
        let at = match key.position(self) {
            Some(at) => at,
            None => {
                self.push((key.key(), make()));
                self.len() - 1
            }
        };
        &mut self[at].1
    }

    fn keys(&self) -> impl Iterator<Item = &Value> {
        self.iter().map(|(k, _)| k)
    }

    fn values(&self) -> impl Iterator<Item = &Value> {
        self.iter().map(|(_, v)| v)
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut Value> {
        self.iter_mut().map(|(_, v)| v)
    }

    fn retain_pairs(&mut self, mut keep: impl FnMut(&Value, &mut Value) -> bool) {
        self.retain_mut(|(k, v)| keep(k, v));
    }
}
