// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIALECT MAPPING WALKER (TODO 36b, stage 0 of the dialect file): one walker for every
//! dialect's mapped request fields.
//!
//! Each dialect states its wire ↔ IR mapping as data in `crates/busbar-plane-llm/dialects/<d>.toml`;
//! `cargo xtask dialect compile` emits it as the `const` tables of `codec/<d>/map.gen.rs` (the
//! `dialect-map` gate refuses a committed table that differs from a fresh compile). A row is a
//! [`Field`]: wire path, [`Slot`], [`Codec`]. This module is the only code that reads the tables:
//!
//! * [`read`] fills each slot from its wire path, then parks in `extra` every raw top-level member
//!   the slot does not reproduce byte-for-byte, so a same-dialect re-serialize keeps the caller's
//!   exact member (`extra` is written last and is cleared on the cross-protocol seam);
//! * [`write`] emits each carried slot at its wire path, overlaying a nested path onto the
//!   container already in the body;
//! * [`keys`] names the top-level members a table models, for the reader's modelled-key list.
//!
//! A row whose carry is irregular names a [`Hook`] from the one registry below; the walker calls
//! the hook's reader and writer in the row's place.

use serde_json::{Map, Value};

use crate::codec::ir::{IrRequest, IrServiceTier, IrVerbosity};

/// A flat IR request slot a field table can name. Each slot has ONE neutral JSON spelling (the
/// slot's own number / flag / string, a string map, or the IR word); a row's [`Codec`] maps it to
/// the dialect's spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// `IrRequest::metadata`: a string → string map.
    Metadata,
    /// `IrRequest::service_tier`: the [`IrServiceTier`] word.
    ServiceTier,
    /// `IrRequest::store`.
    Store,
    /// `IrRequest::safety_identifier`.
    SafetyIdentifier,
    /// `IrRequest::prompt_cache_key`.
    PromptCacheKey,
    /// `IrRequest::verbosity`: the [`IrVerbosity`] word.
    Verbosity,
    /// `IrRequest::output_modalities` (carried by a hook).
    OutputModalities,
    /// A hosted web search in `IrRequest::hosted_tools` (carried by a hook).
    WebSearch,
}

/// Which way a [`Word`] row maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Read and written.
    Both,
    /// Read only: the wire word reads as the neutral one, which is written otherwise.
    Read,
    /// Written only: the dialect sends this word for the neutral one, but reading the wire word
    /// does not yield it.
    Write,
}

/// One row of a word table: `(wire word, neutral word, direction)`. Reading takes the FIRST
/// readable row whose wire word matches; writing takes the FIRST writable row whose neutral word
/// matches. A neutral word with no row has no form on the wire.
pub type Word = (&'static str, &'static str, Dir);

/// How a row's slot value is spelled on the wire.
#[derive(Clone, Copy)]
pub enum Codec {
    /// The slot's neutral spelling, unchanged.
    Plain,
    /// The slot's neutral word through a word table.
    Words(&'static [Word]),
    /// Named irregular code from the [`Hook`] registry.
    Hook(Hook),
}

/// THE HOOK REGISTRY: every named piece of irregular carry a mapping row may cite (`hook = "<name>"`
/// in the dialect file names the variant in snake case). Each hook is a reader (wire value → IR)
/// and a writer (IR → wire value, `None` to omit the member).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    /// Chat `modalities`: `audio` output is written only beside the caller's own `audio` member.
    ChatModalities,
    /// Chat `web_search_options`: one hosted web search per request, its location nested.
    ChatWebSearch,
}

impl Hook {
    fn read(self, raw: &Value, ir: &mut IrRequest) {
        use crate::codec::openai_chat::slots;
        match self {
            Hook::ChatModalities => slots::read_modalities(raw, ir),
            Hook::ChatWebSearch => slots::read_web_search(raw, ir),
        }
    }

    fn write(self, req: &IrRequest) -> Option<Value> {
        use crate::codec::openai_chat::slots;
        match self {
            Hook::ChatModalities => slots::write_modalities(req),
            Hook::ChatWebSearch => slots::write_web_search(req),
        }
    }
}

/// One mapping row. The path is the member's keys from the body's top level.
#[derive(Clone, Copy)]
pub struct Field {
    pub path: &'static [&'static str],
    pub slot: Slot,
    pub codec: Codec,
}

/// A row with no modifiers.
pub const fn row(path: &'static [&'static str], slot: Slot, codec: Codec) -> Field {
    Field { path, slot, codec }
}

/// A dialect's field table: its row groups, walked in order (a group shared by two dialects is
/// written once and named by both).
pub type Table = &'static [&'static [Field]];

impl Slot {
    /// The slot's neutral JSON value, `None` when the request does not carry it.
    fn get(self, r: &IrRequest) -> Option<Value> {
        match self {
            Slot::Metadata => r.metadata.as_ref().map(|pairs| {
                Value::Object(
                    pairs
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                        .collect(),
                )
            }),
            Slot::ServiceTier => r.service_tier.map(|t| Value::from(t.as_str())),
            Slot::Store => r.store.map(Value::from),
            Slot::SafetyIdentifier => r.safety_identifier.clone().map(Value::from),
            Slot::PromptCacheKey => r.prompt_cache_key.clone().map(Value::from),
            Slot::Verbosity => r.verbosity.map(|v| Value::from(v.as_str())),
            Slot::OutputModalities | Slot::WebSearch => None,
        }
    }

    /// Fill the slot from its neutral JSON value when it is still empty and the value is of the
    /// slot's type (an earlier row wins; a mistyped value fills nothing).
    fn fill(self, r: &mut IrRequest, v: &Value) {
        fn first<T>(slot: &mut Option<T>, v: Option<T>) {
            if slot.is_none() {
                *slot = v;
            }
        }
        let text = || v.as_str().map(String::from);
        match self {
            Slot::Metadata => first(&mut r.metadata, string_map(v)),
            Slot::ServiceTier => first(
                &mut r.service_tier,
                v.as_str().and_then(IrServiceTier::parse),
            ),
            Slot::Store => first(&mut r.store, v.as_bool()),
            Slot::SafetyIdentifier => first(&mut r.safety_identifier, text()),
            Slot::PromptCacheKey => first(&mut r.prompt_cache_key, text()),
            Slot::Verbosity => first(&mut r.verbosity, v.as_str().and_then(IrVerbosity::parse)),
            Slot::OutputModalities | Slot::WebSearch => {}
        }
    }
}

/// An object of string values as `(key, value)` pairs; `None` for any other shape.
fn string_map(v: &Value) -> Option<Vec<(String, String)>> {
    v.as_object()?
        .iter()
        .map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect()
}

/// The neutral word for wire word `wire` (the first readable row), if any.
pub fn word_in(words: &[Word], wire: &str) -> Option<&'static str> {
    words
        .iter()
        .find(|(w, _, dir)| *w == wire && *dir != Dir::Write)
        .map(|(_, neutral, _)| *neutral)
}

/// The neutral word for the wire member `v` (absent, or not a string → `None`).
pub fn read_word(words: &[Word], v: Option<&Value>) -> Option<String> {
    word_in(words, v?.as_str()?).map(String::from)
}

/// The wire word for neutral word `neutral` (the first row), if the dialect has one.
pub fn word_out(words: &[Word], neutral: &str) -> Option<&'static str> {
    words
        .iter()
        .find(|(_, n, dir)| *n == neutral && *dir != Dir::Read)
        .map(|(wire, _, _)| *wire)
}

fn rows(table: Table) -> impl Iterator<Item = &'static Field> {
    table.iter().flat_map(|group| group.iter())
}

fn at<'a>(obj: &'a Map<String, Value>, path: &[&str]) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    rest.iter().try_fold(obj.get(*first)?, |v, k| v.get(*k))
}

fn put(out: &mut Map<String, Value>, path: &[&str], v: Value) {
    match path {
        [] => {}
        [key] => {
            out.insert((*key).to_string(), v);
        }
        [key, rest @ ..] => {
            if let Some(inner) = out
                .entry((*key).to_string())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
            {
                put(inner, rest, v);
            }
        }
    }
}

/// THE READ WALK. Fill every slot `table` names from the wire body `obj`, then park in `extra` each
/// raw top-level member the filled slots do not write back identically (same-dialect fidelity).
pub fn read(table: Table, obj: &Map<String, Value>, ir: &mut IrRequest) {
    for f in rows(table) {
        let Some(raw) = at(obj, f.path) else {
            continue;
        };
        match f.codec {
            Codec::Plain => f.slot.fill(ir, raw),
            Codec::Words(words) => {
                if let Some(neutral) = raw.as_str().and_then(|w| word_in(words, w)) {
                    f.slot.fill(ir, &Value::from(neutral));
                }
            }
            Codec::Hook(hook) => hook.read(raw, ir),
        }
    }
    let mut written = Map::new();
    write(table, ir, &mut written);
    for key in keys(table) {
        if let Some(raw) = obj.get(key) {
            if written.get(key) != Some(raw) {
                ir.extra.insert(key.to_string(), raw.clone());
            }
        }
    }
}

/// THE WRITE WALK. Emit every slot of `table` that `req` carries into `out` at its wire path. A
/// neutral word the row's table has no wire word for is not written.
pub fn write(table: Table, req: &IrRequest, out: &mut Map<String, Value>) {
    for f in rows(table) {
        let value = match f.codec {
            Codec::Plain => f.slot.get(req),
            Codec::Words(words) => f
                .slot
                .get(req)
                .and_then(|v| v.as_str().and_then(|n| word_out(words, n)))
                .map(Value::from),
            Codec::Hook(hook) => hook.write(req),
        };
        if let Some(v) = value {
            put(out, f.path, v);
        }
    }
}

/// The top-level members `table` models: every single-key path. (A nested row's container is the
/// dialect's own structure, which may hold members no row names.)
pub fn keys(table: Table) -> impl Iterator<Item = &'static str> {
    rows(table).filter_map(|f| match f.path {
        [key] => Some(*key),
        _ => None,
    })
}

#[cfg(test)]
#[path = "tests/carry_tests.rs"]
mod tests;
