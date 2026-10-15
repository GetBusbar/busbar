// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROVIDER-KEY DESCRIPTOR (row 155 B1c, ARCHITECT ruling "Option A"): the keys of a
//! `providers:` entry that a PLANE owns, stated by that plane as data in its Statement, so the
//! kernel parses a provider entry without holding one plane key name.
//!
//! A provider entry is read in three FORMS, and each form's keys are in their own frozen order:
//! the catalog definition ([`ProviderKeys::catalog`]), the operator's deployment
//! ([`ProviderKeys::deployment`]) and the whole resolved entry ([`ProviderKeys::entry`]). The
//! kernel's own keys of an entry (its destination, its credential and outbound-auth binding, its
//! health block and its metadata allowance) are never in a descriptor: a descriptor names only what
//! the plane adds.
//!
//! THE NEUTRAL SHAPE VOCABULARY. A key's [`Shape`] is one of seven words and nothing else: `str`,
//! `one-of` (a string that is one of the listed words), `int`, `bool`, `list` (of one shape),
//! `str-map` (string to string) and `table` (a nested struct: its own keys, in order, and whether an
//! unknown key in it is refused). A descriptor naming any other shape word is refused by [`decode`].
//!
//! THE ENCODING. JSON, under the ONE Statement-extensions key [`EXT_PROVIDER_KEYS`]
//! (`abi::mechanism::extensions`):
//!
//! ```text
//! descriptor = { "catalog": table, "deployment": table, "entry": table }
//! table      = { "deny_unknown": bool, "keys": [ key, ... ] }
//! key        = { "name": string, "shape": shape, "required": bool }
//! shape      = "str" | "int" | "bool" | "str-map"
//!            | { "one-of": [ string, ... ] } | { "list": shape } | { "table": table }
//! ```
//!
//! Every object holds exactly its stated members; a key name is stated once per table; a `one-of`
//! lists at least one word, each once.
//!
//! DORMANT: the loader reads the descriptor into `PlaneRegistration::provider_keys` and the kernel's
//! door fold keeps it; nothing parses a provider entry from it yet (unwired seam, wiring owner B1c-2).

use serde_json::{Map, Value};

/// THE STATEMENT-EXTENSIONS KEY a plane states its provider-key descriptor under
/// (`Statement::extensions`, read by `abi::mechanism::extensions::get`).
pub const EXT_PROVIDER_KEYS: &str = "provider_keys";

/// The shape word of [`Shape::Str`].
pub const SHAPE_STR: &str = "str";
/// The shape word of [`Shape::OneOf`].
pub const SHAPE_ONE_OF: &str = "one-of";
/// The shape word of [`Shape::Int`].
pub const SHAPE_INT: &str = "int";
/// The shape word of [`Shape::Bool`].
pub const SHAPE_BOOL: &str = "bool";
/// The shape word of [`Shape::List`].
pub const SHAPE_LIST: &str = "list";
/// The shape word of [`Shape::StrMap`].
pub const SHAPE_STR_MAP: &str = "str-map";
/// The shape word of [`Shape::Table`].
pub const SHAPE_TABLE: &str = "table";

/// The neutral shape words, in the vocabulary's order: the only shapes a descriptor may name.
pub const SHAPE_WORDS: &[&str] = &[
    SHAPE_STR,
    SHAPE_ONE_OF,
    SHAPE_INT,
    SHAPE_BOOL,
    SHAPE_LIST,
    SHAPE_STR_MAP,
    SHAPE_TABLE,
];

/// ONE KEY'S SHAPE, in the neutral vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// A string.
    Str,
    /// A string that is one of these words, in their stated order.
    OneOf(Vec<String>),
    /// An integer.
    Int,
    /// A boolean.
    Bool,
    /// A list, every element of this shape.
    List(Box<Shape>),
    /// A map of string to string.
    StrMap,
    /// A nested struct.
    Table(Table),
}

/// A STRUCT'S KEYS: in their frozen order, and whether a key it does not name is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    /// Whether a key this table does not name is refused (otherwise it is passed over).
    pub deny_unknown: bool,
    /// Its keys, in their frozen order.
    pub keys: Vec<Key>,
}

/// ONE KEY: its name, its shape and whether it must be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// The key as written in config.
    pub name: String,
    /// Its shape.
    pub shape: Shape,
    /// Whether an entry that omits it is refused.
    pub required: bool,
}

/// THE PLANE'S PROVIDER KEYS, per form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderKeys {
    /// The catalog definition's keys.
    pub catalog: Table,
    /// The operator deployment's keys.
    pub deployment: Table,
    /// The whole resolved entry's keys.
    pub entry: Table,
}

/// The descriptor's JSON bytes.
#[must_use]
pub fn encode(keys: &ProviderKeys) -> Vec<u8> {
    let mut doc = Map::new();
    doc.insert("catalog".into(), table_value(&keys.catalog));
    doc.insert("deployment".into(), table_value(&keys.deployment));
    doc.insert("entry".into(), table_value(&keys.entry));
    Value::Object(doc).to_string().into_bytes()
}

/// The descriptor `bytes` state.
///
/// # Errors
///
/// Where the bytes are not a descriptor: not JSON, a member missing or not stated by the encoding, a
/// shape word outside [`SHAPE_WORDS`], a key name stated twice in one table, or an empty or
/// repeated `one-of` word.
pub fn decode(bytes: &[u8]) -> Result<ProviderKeys, String> {
    let doc: Value = serde_json::from_slice(bytes)
        .map_err(|e| format!("the provider keys are not JSON: {e}"))?;
    let doc = members(
        &doc,
        "the provider keys",
        &["catalog", "deployment", "entry"],
    )?;
    Ok(ProviderKeys {
        catalog: table_of(doc[0], "catalog")?,
        deployment: table_of(doc[1], "deployment")?,
        entry: table_of(doc[2], "entry")?,
    })
}

/// The descriptor a Statement's extensions blob states under [`EXT_PROVIDER_KEYS`]; `None` when it
/// states none.
///
/// # Errors
///
/// The stated value is not a descriptor ([`decode`]).
pub fn stated(extensions: &[u8]) -> Result<Option<ProviderKeys>, String> {
    crate::abi::mechanism::extensions::get(extensions, EXT_PROVIDER_KEYS)
        .map(decode)
        .transpose()
}

fn table_value(t: &Table) -> Value {
    let mut out = Map::new();
    out.insert("deny_unknown".into(), Value::Bool(t.deny_unknown));
    out.insert(
        "keys".into(),
        Value::Array(t.keys.iter().map(key_value).collect()),
    );
    Value::Object(out)
}

fn key_value(k: &Key) -> Value {
    let mut out = Map::new();
    out.insert("name".into(), Value::String(k.name.clone()));
    out.insert("shape".into(), shape_value(&k.shape));
    out.insert("required".into(), Value::Bool(k.required));
    Value::Object(out)
}

fn shape_value(s: &Shape) -> Value {
    let one = |word: &str, v: Value| {
        let mut out = Map::new();
        out.insert(word.into(), v);
        Value::Object(out)
    };
    match s {
        Shape::Str => Value::String(SHAPE_STR.into()),
        Shape::OneOf(words) => one(
            SHAPE_ONE_OF,
            Value::Array(words.iter().cloned().map(Value::String).collect()),
        ),
        Shape::Int => Value::String(SHAPE_INT.into()),
        Shape::Bool => Value::String(SHAPE_BOOL.into()),
        Shape::List(of) => one(SHAPE_LIST, shape_value(of)),
        Shape::StrMap => Value::String(SHAPE_STR_MAP.into()),
        Shape::Table(t) => one(SHAPE_TABLE, table_value(t)),
    }
}

/// The members `names` of the object `v`, in that order: every one present, no other.
fn members<'a>(v: &'a Value, at: &str, names: &[&str]) -> Result<Vec<&'a Value>, String> {
    let Value::Object(m) = v else {
        return Err(format!("`{at}` is not an object"));
    };
    if let Some(other) = m.keys().find(|k| !names.contains(&k.as_str())) {
        return Err(format!(
            "`{at}` states `{other}`, which is not one of {names:?}"
        ));
    }
    names
        .iter()
        .map(|n| {
            m.get(*n)
                .ok_or_else(|| format!("`{at}` does not state `{n}`"))
        })
        .collect()
}

fn bool_of(v: &Value, at: &str) -> Result<bool, String> {
    v.as_bool()
        .ok_or_else(|| format!("`{at}` is not a boolean"))
}

fn table_of(v: &Value, at: &str) -> Result<Table, String> {
    let m = members(v, at, &["deny_unknown", "keys"])?;
    let Value::Array(list) = m[1] else {
        return Err(format!("`{at}.keys` is not a list"));
    };
    let mut keys: Vec<Key> = Vec::with_capacity(list.len());
    for (i, k) in list.iter().enumerate() {
        let key = key_of(k, &format!("{at}.keys[{i}]"))?;
        if keys.iter().any(|seen| seen.name == key.name) {
            return Err(format!("`{at}` states the key `{}` twice", key.name));
        }
        keys.push(key);
    }
    Ok(Table {
        deny_unknown: bool_of(m[0], &format!("{at}.deny_unknown"))?,
        keys,
    })
}

fn key_of(v: &Value, at: &str) -> Result<Key, String> {
    let m = members(v, at, &["name", "shape", "required"])?;
    let name = m[0]
        .as_str()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| format!("`{at}.name` is not a non-empty string"))?;
    Ok(Key {
        name: name.to_string(),
        shape: shape_of(m[1], &format!("{at}.shape"))?,
        required: bool_of(m[2], &format!("{at}.required"))?,
    })
}

fn shape_of(v: &Value, at: &str) -> Result<Shape, String> {
    let not_neutral = |word: &str| {
        format!(
            "`{at}` names the shape `{word}`, which is not a neutral shape word (one of {})",
            SHAPE_WORDS.join(", ")
        )
    };
    match v {
        Value::String(word) => match word.as_str() {
            SHAPE_STR => Ok(Shape::Str),
            SHAPE_INT => Ok(Shape::Int),
            SHAPE_BOOL => Ok(Shape::Bool),
            SHAPE_STR_MAP => Ok(Shape::StrMap),
            other => Err(not_neutral(other)),
        },
        Value::Object(m) if m.len() == 1 => {
            let (word, inner) = m.iter().next().ok_or_else(|| not_neutral(""))?;
            match word.as_str() {
                SHAPE_ONE_OF => one_of(inner, at).map(Shape::OneOf),
                SHAPE_LIST => {
                    shape_of(inner, &format!("{at}.{SHAPE_LIST}")).map(|s| Shape::List(Box::new(s)))
                }
                SHAPE_TABLE => table_of(inner, &format!("{at}.{SHAPE_TABLE}")).map(Shape::Table),
                other => Err(not_neutral(other)),
            }
        }
        _ => Err(format!(
            "`{at}` is neither a shape word nor a one-member shape object"
        )),
    }
}

fn one_of(v: &Value, at: &str) -> Result<Vec<String>, String> {
    let Value::Array(list) = v else {
        return Err(format!("`{at}.{}` is not a list", SHAPE_ONE_OF));
    };
    let mut words: Vec<String> = Vec::with_capacity(list.len());
    for w in list {
        let w = w.as_str().filter(|w| !w.is_empty()).ok_or_else(|| {
            format!(
                "`{at}.{}` lists a word that is not a non-empty string",
                SHAPE_ONE_OF
            )
        })?;
        if words.iter().any(|seen| seen == w) {
            return Err(format!("`{at}.{}` lists `{w}` twice", SHAPE_ONE_OF));
        }
        words.push(w.to_string());
    }
    if words.is_empty() {
        return Err(format!("`{at}.{}` lists no word", SHAPE_ONE_OF));
    }
    Ok(words)
}

#[cfg(test)]
#[path = "tests/provider_keys_tests.rs"]
mod tests;
