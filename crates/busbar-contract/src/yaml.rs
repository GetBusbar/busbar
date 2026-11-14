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
                // serde_yaml printed no position on a struct's missing field (the error is raised
                // after the mapping ends); every other placed error kept its position.
                placed_suffix = !message.starts_with("missing field ");
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

/// Read a [`Value`] tree into `T`, in memory, as serde_yaml's `from_value` did: through
/// [`ValueDeserializer`], with its semantics and its error texts (which carry no position).
pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    T::deserialize(deserializer(value))
}

/// A [`Value`] tree as serde input, read in memory: what serde_yaml offered by making its `Value`
/// itself a `Deserializer`. Pass it wherever a generic `D: Deserializer` reader or a
/// `DeserializeSeed` wants the tree, instead of writing the tree out and parsing it again.
///
/// The rules are serde_yaml 0.9's `Value` deserializer's, rule by rule, on ciborium's variants:
/// - any: an integer is visited as `u64` when non-negative and `i64` otherwise (wider ones as
///   `u128`/`i128`), a float as `f64`, null as unit, a string, a bool, a sequence, a mapping
///   (keys read as values in turn), bytes as bytes;
/// - every number type takes any number, so an integer reads into an `f32`/`f64` field;
/// - null reads as `None`, as unit, as an empty sequence and as an empty mapping;
/// - an enum is a string (a unit variant) or, as written YAML spells it, a single-key mapping
///   (the variant and its content);
/// - a tag (`Value::Tag`) is transparent: its value is read in its place;
/// - human-readable, as YAML is; type errors are serde's `invalid type: ..., expected ...` texts.
#[derive(Debug, Clone)]
pub struct ValueDeserializer {
    value: Value,
}

/// A [`ValueDeserializer`] over `value`.
#[must_use]
pub fn deserializer(value: Value) -> ValueDeserializer {
    ValueDeserializer { value }
}

impl<'de> serde::de::IntoDeserializer<'de, Error> for ValueDeserializer {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

impl<'de> serde::de::IntoDeserializer<'de, Error> for Value {
    type Deserializer = ValueDeserializer;
    fn into_deserializer(self) -> ValueDeserializer {
        deserializer(self)
    }
}

/// The value under any tags: ciborium's `Tag` wraps a value the reader sees through.
fn untag(mut value: Value) -> Value {
    loop {
        match value {
            Value::Tag(_, inner) => value = *inner,
            other => return other,
        }
    }
}

/// How serde names `value` in an `invalid type` error, as serde_yaml named its `Value`'s variants.
fn unexpected(value: &Value) -> serde::de::Unexpected<'_> {
    use serde::de::Unexpected;
    match value {
        Value::Null => Unexpected::Unit,
        Value::Bool(b) => Unexpected::Bool(*b),
        Value::Integer(i) => {
            let i = i128::from(*i);
            match (u64::try_from(i), i64::try_from(i)) {
                (Ok(u), _) => Unexpected::Unsigned(u),
                (_, Ok(s)) => Unexpected::Signed(s),
                _ => Unexpected::Other("integer"),
            }
        }
        Value::Float(f) => Unexpected::Float(*f),
        Value::Text(s) => Unexpected::Str(s),
        Value::Bytes(b) => Unexpected::Bytes(b),
        Value::Array(_) => Unexpected::Seq,
        Value::Map(_) => Unexpected::Map,
        Value::Tag(_, inner) => unexpected(inner),
        _ => Unexpected::Other("YAML value"),
    }
}

#[cold]
fn invalid_type(value: &Value, expected: &dyn serde::de::Expected) -> Error {
    serde::de::Error::invalid_type(unexpected(value), expected)
}

fn visit_integer<'de, V: serde::de::Visitor<'de>>(
    integer: ciborium::value::Integer,
    visitor: V,
) -> Result<V::Value, Error> {
    let i = i128::from(integer);
    if let Ok(u) = u64::try_from(i) {
        visitor.visit_u64(u)
    } else if let Ok(s) = i64::try_from(i) {
        visitor.visit_i64(s)
    } else if let Ok(u) = u128::try_from(i) {
        visitor.visit_u128(u)
    } else {
        visitor.visit_i128(i)
    }
}

fn visit_sequence<'de, V: serde::de::Visitor<'de>>(
    sequence: Vec<Value>,
    visitor: V,
) -> Result<V::Value, Error> {
    let len = sequence.len();
    let mut access = ValueSeq {
        iter: sequence.into_iter(),
    };
    let seq = visitor.visit_seq(&mut access)?;
    if access.iter.len() == 0 {
        Ok(seq)
    } else {
        Err(serde::de::Error::invalid_length(
            len,
            &"fewer elements in sequence",
        ))
    }
}

fn visit_mapping<'de, V: serde::de::Visitor<'de>>(
    mapping: Mapping,
    visitor: V,
) -> Result<V::Value, Error> {
    let len = mapping.len();
    let mut access = ValueMap {
        iter: mapping.into_iter(),
        value: None,
    };
    let map = visitor.visit_map(&mut access)?;
    if access.iter.len() == 0 {
        Ok(map)
    } else {
        Err(serde::de::Error::invalid_length(
            len,
            &"fewer elements in map",
        ))
    }
}

impl ValueDeserializer {
    fn deserialize_number<'de, V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Integer(i) => visit_integer(i, visitor),
            Value::Float(f) => visitor.visit_f64(f),
            other => Err(invalid_type(&other, &visitor)),
        }
    }
}

impl<'de> serde::Deserializer<'de> for ValueDeserializer {
    type Error = Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Null => visitor.visit_unit(),
            Value::Bool(b) => visitor.visit_bool(b),
            Value::Integer(i) => visit_integer(i, visitor),
            Value::Float(f) => visitor.visit_f64(f),
            Value::Text(s) => visitor.visit_string(s),
            Value::Bytes(b) => visitor.visit_byte_buf(b),
            Value::Array(s) => visit_sequence(s, visitor),
            Value::Map(m) => visit_mapping(m, visitor),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_bool<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Bool(b) => visitor.visit_bool(b),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_i8<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_i16<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_i32<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_i64<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_i128<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_u8<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_u16<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_u32<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_u64<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_u128<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_f32<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_f64<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_number(visitor)
    }

    fn deserialize_char<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_str<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Text(s) => visitor.visit_string(s),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_bytes<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_byte_buf(visitor)
    }

    fn deserialize_byte_buf<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Text(s) => visitor.visit_string(s),
            Value::Bytes(b) => visitor.visit_byte_buf(b),
            Value::Array(s) => visit_sequence(s, visitor),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_option<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Null => visitor.visit_none(),
            other => visitor.visit_some(deserializer(other)),
        }
    }

    fn deserialize_unit<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Null => visitor.visit_unit(),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_unit_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Array(s) => visit_sequence(s, visitor),
            Value::Null => visit_sequence(Vec::new(), visitor),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_tuple<V: serde::de::Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match untag(self.value) {
            Value::Map(m) => visit_mapping(m, visitor),
            Value::Null => visit_mapping(Mapping::new(), visitor),
            other => Err(invalid_type(&other, &visitor)),
        }
    }

    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        let (variant, content) = match untag(self.value) {
            variant @ Value::Text(_) => (variant, None),
            Value::Map(mut m) if m.len() == 1 => {
                let (variant, content) = m.swap_remove(0);
                (variant, Some(content))
            }
            other => return Err(invalid_type(&other, &"a Value::Tagged enum")),
        };
        visitor.visit_enum(ValueEnum { variant, content })
    }

    fn deserialize_identifier<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_ignored_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }
}

/// A sequence's elements, each read as a [`ValueDeserializer`].
struct ValueSeq {
    iter: std::vec::IntoIter<Value>,
}

impl<'de> serde::de::SeqAccess<'de> for ValueSeq {
    type Error = Error;

    fn next_element_seed<T: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        match self.iter.next() {
            Some(value) => seed.deserialize(deserializer(value)).map(Some),
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        match self.iter.size_hint() {
            (lower, Some(upper)) if lower == upper => Some(upper),
            _ => None,
        }
    }
}

impl<'de> serde::Deserializer<'de> for ValueSeq {
    type Error = Error;

    /// serde_yaml's tuple-variant content: an empty sequence reads as unit.
    fn deserialize_any<V: serde::de::Visitor<'de>>(
        mut self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        let len = self.iter.len();
        if len == 0 {
            return visitor.visit_unit();
        }
        let ret = visitor.visit_seq(&mut self)?;
        if self.iter.len() == 0 {
            Ok(ret)
        } else {
            Err(serde::de::Error::invalid_length(
                len,
                &"fewer elements in sequence",
            ))
        }
    }

    fn deserialize_ignored_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map struct enum identifier
    }
}

/// A mapping's pairs, keys and values each read as a [`ValueDeserializer`].
struct ValueMap {
    iter: std::vec::IntoIter<(Value, Value)>,
    value: Option<Value>,
}

impl<'de> serde::de::MapAccess<'de> for ValueMap {
    type Error = Error;

    fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.iter.next() {
            Some((key, value)) => {
                self.value = Some(value);
                seed.deserialize(deserializer(key)).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<T: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<T::Value, Error> {
        match self.value.take() {
            Some(value) => seed.deserialize(deserializer(value)),
            None => Err(serde::de::Error::custom("value is missing")),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        match self.iter.size_hint() {
            (lower, Some(upper)) if lower == upper => Some(upper),
            _ => None,
        }
    }
}

impl<'de> serde::Deserializer<'de> for ValueMap {
    type Error = Error;

    /// serde_yaml's struct-variant content.
    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_map(self)
    }

    fn deserialize_ignored_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map struct enum identifier
    }
}

/// An enum read from a [`Value`]: the variant name, and its content when it has one.
struct ValueEnum {
    variant: Value,
    content: Option<Value>,
}

impl<'de> serde::de::EnumAccess<'de> for ValueEnum {
    type Error = Error;
    type Variant = ValueVariant;

    fn variant_seed<V: serde::de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, ValueVariant), Error> {
        let variant = seed.deserialize(deserializer(self.variant))?;
        Ok((
            variant,
            ValueVariant {
                content: self.content,
            },
        ))
    }
}

/// An enum variant's content, read as serde_yaml read a `Value::Tagged`'s value.
struct ValueVariant {
    content: Option<Value>,
}

impl<'de> serde::de::VariantAccess<'de> for ValueVariant {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        match self.content {
            Some(content) => serde::Deserialize::deserialize(deserializer(content)),
            None => Ok(()),
        }
    }

    fn newtype_variant_seed<T: serde::de::DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Error> {
        match self.content {
            Some(content) => seed.deserialize(deserializer(content)),
            None => Err(serde::de::Error::invalid_type(
                serde::de::Unexpected::UnitVariant,
                &"newtype variant",
            )),
        }
    }

    fn tuple_variant<V: serde::de::Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.content.map(untag) {
            Some(Value::Array(s)) => serde::Deserializer::deserialize_any(
                ValueSeq {
                    iter: s.into_iter(),
                },
                visitor,
            ),
            Some(other) => Err(invalid_type(&other, &"tuple variant")),
            None => Err(serde::de::Error::invalid_type(
                serde::de::Unexpected::UnitVariant,
                &"tuple variant",
            )),
        }
    }

    fn struct_variant<V: serde::de::Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.content.map(untag) {
            Some(Value::Map(m)) => serde::Deserializer::deserialize_any(
                ValueMap {
                    iter: m.into_iter(),
                    value: None,
                },
                visitor,
            ),
            Some(other) => Err(invalid_type(&other, &"struct variant")),
            None => Err(serde::de::Error::invalid_type(
                serde::de::Unexpected::UnitVariant,
                &"struct variant",
            )),
        }
    }
}

/// Write `value` into a [`Value`] tree, as reading back its YAML text would give it.
/// Takes the value by value, as serde_yaml's `to_value` did (a reference serializes the same).
pub fn to_value<T: Serialize>(value: T) -> Result<Value, Error> {
    let text = to_string(&value)?;
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
