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
//! THE NEUTRAL SHAPE VOCABULARY. A key's [`Shape`] is one of ten words and nothing else: `str`,
//! `one-of` (a string that is one of the listed words), `int`, `u32`, `u64`, `usize` (an unsigned
//! integer of that width, so a value out of range is refused in the previous release's words),
//! `bool`, `list` (of one shape), `str-map` (string to string) and `table` (a nested struct: its own
//! keys, in order, whether an unknown key in it is refused, and, optionally, the name a wrong-typed
//! value is refused against, e.g. `struct X`). A descriptor naming any other shape word is refused
//! by [`decode`].
//!
//! THE LIST RANK (arch-audit u29 F2, coordinator ruling): a key may state a `rank`. The host lists
//! a form's keys (its own and every plane's) by rank, then unranked in declaration order, when it
//! refuses an unknown key, so the list is the previous release's frozen field order. A rank orders a
//! list and grants nothing.
//!
//! THE OTHER FORMS (same ruling): beside the three provider forms, a plane may state the keys it owns
//! in the `limits` section (`limits`) and in a pool member (`pool_member`). Both are optional.
//!
//! THE ENCODING. JSON, under the ONE Statement-extensions key [`EXT_PROVIDER_KEYS`]
//! (`abi::mechanism::extensions`):
//!
//! ```text
//! descriptor = { "catalog": table, "deployment": table, "entry": table,
//!                ("limits": table,)? ("pool_member": table,)? }
//! table      = { "deny_unknown": bool, "keys": [ key, ... ] (, "expecting": string)? }
//! key        = { "name": string, "shape": shape, "required": bool (, "rank": u16)? }
//! shape      = "str" | "int" | "u32" | "u64" | "usize" | "bool" | "str-map"
//!            | { "one-of": [ string, ... ] } | { "list": shape } | { "table": table }
//!
//! An optional member is written only when stated, so a descriptor stating none of them encodes as
//! it did before they existed.
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
/// The shape word of [`Shape::U32`].
pub const SHAPE_U32: &str = "u32";
/// The shape word of [`Shape::U64`].
pub const SHAPE_U64: &str = "u64";
/// The shape word of [`Shape::Usize`].
pub const SHAPE_USIZE: &str = "usize";
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
    SHAPE_U32,
    SHAPE_U64,
    SHAPE_USIZE,
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
    /// An unsigned 32-bit integer.
    U32,
    /// An unsigned 64-bit integer.
    U64,
    /// An unsigned pointer-width integer.
    Usize,
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
    /// What a value of the wrong type is refused against (`struct X`, the previous release's
    /// words); `None` when the table states none.
    pub expecting: Option<String>,
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
    /// Its list rank ([`EXT_PROVIDER_KEYS`]'s module docs); `None` when it states none.
    pub rank: Option<u16>,
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
    /// The `limits` section's keys this plane owns; `None` when it states none.
    pub limits: Option<Table>,
    /// A pool member's keys this plane owns; `None` when it states none.
    pub pool_member: Option<Table>,
}

/// The descriptor's JSON bytes.
#[must_use]
pub fn encode(keys: &ProviderKeys) -> Vec<u8> {
    let mut doc = Map::new();
    doc.insert("catalog".into(), table_value(&keys.catalog));
    doc.insert("deployment".into(), table_value(&keys.deployment));
    doc.insert("entry".into(), table_value(&keys.entry));
    if let Some(t) = &keys.limits {
        doc.insert("limits".into(), table_value(t));
    }
    if let Some(t) = &keys.pool_member {
        doc.insert("pool_member".into(), table_value(t));
    }
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
        &["limits", "pool_member"],
    )?;
    Ok(ProviderKeys {
        catalog: table_of(
            required(&doc[0], "the provider keys", "catalog")?,
            "catalog",
        )?,
        deployment: table_of(
            required(&doc[1], "the provider keys", "deployment")?,
            "deployment",
        )?,
        entry: table_of(required(&doc[2], "the provider keys", "entry")?, "entry")?,
        limits: doc[3].map(|t| table_of(t, "limits")).transpose()?,
        pool_member: doc[4].map(|t| table_of(t, "pool_member")).transpose()?,
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
    if let Some(expecting) = &t.expecting {
        out.insert("expecting".into(), Value::String(expecting.clone()));
    }
    Value::Object(out)
}

fn key_value(k: &Key) -> Value {
    let mut out = Map::new();
    out.insert("name".into(), Value::String(k.name.clone()));
    out.insert("shape".into(), shape_value(&k.shape));
    out.insert("required".into(), Value::Bool(k.required));
    if let Some(rank) = k.rank {
        out.insert("rank".into(), Value::from(rank));
    }
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
        Shape::U32 => Value::String(SHAPE_U32.into()),
        Shape::U64 => Value::String(SHAPE_U64.into()),
        Shape::Usize => Value::String(SHAPE_USIZE.into()),
        Shape::Bool => Value::String(SHAPE_BOOL.into()),
        Shape::List(of) => one(SHAPE_LIST, shape_value(of)),
        Shape::StrMap => Value::String(SHAPE_STR_MAP.into()),
        Shape::Table(t) => one(SHAPE_TABLE, table_value(t)),
    }
}

/// The members of the object `v`: `names`, every one present, then `optional`, each `None` when
/// absent, in that order; no other member.
fn members<'a>(
    v: &'a Value,
    at: &str,
    names: &[&str],
    optional: &[&str],
) -> Result<Vec<Option<&'a Value>>, String> {
    let Value::Object(m) = v else {
        return Err(format!("`{at}` is not an object"));
    };
    let all: Vec<&str> = names.iter().chain(optional).copied().collect();
    if let Some(other) = m.keys().find(|k| !all.contains(&k.as_str())) {
        return Err(format!(
            "`{at}` states `{other}`, which is not one of {all:?}"
        ));
    }
    for n in names {
        if !m.contains_key(*n) {
            return Err(format!("`{at}` does not state `{n}`"));
        }
    }
    Ok(all.iter().map(|n| m.get(*n)).collect())
}

/// A member [`members`] holds present.
fn required<'a>(v: &Option<&'a Value>, at: &str, name: &str) -> Result<&'a Value, String> {
    v.ok_or_else(|| format!("`{at}` does not state `{name}`"))
}

fn bool_of(v: &Value, at: &str) -> Result<bool, String> {
    v.as_bool()
        .ok_or_else(|| format!("`{at}` is not a boolean"))
}

fn table_of(v: &Value, at: &str) -> Result<Table, String> {
    let m = members(v, at, &["deny_unknown", "keys"], &["expecting"])?;
    let Value::Array(list) = required(&m[1], at, "keys")? else {
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
    let expecting = m[2]
        .map(|e| {
            e.as_str()
                .filter(|e| !e.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("`{at}.expecting` is not a non-empty string"))
        })
        .transpose()?;
    Ok(Table {
        deny_unknown: bool_of(
            required(&m[0], at, "deny_unknown")?,
            &format!("{at}.deny_unknown"),
        )?,
        keys,
        expecting,
    })
}

fn key_of(v: &Value, at: &str) -> Result<Key, String> {
    let m = members(v, at, &["name", "shape", "required"], &["rank"])?;
    let name = required(&m[0], at, "name")?
        .as_str()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| format!("`{at}.name` is not a non-empty string"))?;
    let rank = m[3]
        .map(|r| {
            r.as_u64()
                .and_then(|r| u16::try_from(r).ok())
                .ok_or_else(|| format!("`{at}.rank` is not an integer in 0..=65535"))
        })
        .transpose()?;
    Ok(Key {
        name: name.to_string(),
        shape: shape_of(required(&m[1], at, "shape")?, &format!("{at}.shape"))?,
        required: bool_of(required(&m[2], at, "required")?, &format!("{at}.required"))?,
        rank,
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
            SHAPE_U32 => Ok(Shape::U32),
            SHAPE_U64 => Ok(Shape::U64),
            SHAPE_USIZE => Ok(Shape::Usize),
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
