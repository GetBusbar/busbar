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
    /// `IrRequest::temperature`.
    Temperature,
    /// `IrRequest::top_p`.
    TopP,
    /// `IrRequest::top_k`.
    TopK,
    /// `IrRequest::frequency_penalty`.
    FrequencyPenalty,
    /// `IrRequest::presence_penalty`.
    PresencePenalty,
    /// `IrRequest::seed`.
    Seed,
    /// `IrRequest::n`, the candidate count.
    N,
    /// `IrRequest::stop`: read from a string or an array of strings, written as an array.
    Stop,
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

/// One mapping row: the member's keys from the body's top level, its slot and codec, and the row
/// modifiers the mapping file states.
#[derive(Clone, Copy)]
pub struct Field {
    pub path: &'static [&'static str],
    pub slot: Slot,
    pub codec: Codec,
    /// Same-dialect fidelity: a raw member the slot does not reproduce is parked in `extra`.
    pub park: bool,
    /// Clamp a number into a range before it is written.
    pub clamp: Option<Clamp>,
    /// Truncate a list to `(at most n entries, the dialect's name in the truncation diagnostic)`.
    pub cap: Option<(usize, &'static str)>,
    /// Omit the member, observably, under an egress condition.
    pub drop_if: Option<DropIf>,
}

/// The clamp a row applies on write (`clamp`, `clamp_warn`, `clamp_parameter` in the mapping
/// file). It is the temperature clamp: the warn, emitted only when the clamp changed the value,
/// carries `requested_temperature` / `clamped_temperature` (and `parameter`, when `parameter`).
#[derive(Clone, Copy)]
pub struct Clamp {
    pub min: f64,
    pub max: f64,
    pub warn: &'static str,
    pub parameter: bool,
}

/// An egress condition a row is dropped under (`drop_if` in the mapping file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    /// The writer emitted a thinking ask: the provider refuses a modified sampling knob beside it.
    /// A temperature of exactly 1 is what thinking runs at, so omitting it is not warned.
    Thinking,
}

/// The drop a row takes under [`Cond`] (`drop_if`, `drop_warn`, `drop_warn_value`): its warn, and
/// whether the warn names the dropped value.
#[derive(Clone, Copy)]
pub struct DropIf {
    pub when: Cond,
    pub warn: &'static str,
    pub value: bool,
}

/// A row with no modifiers.
pub const fn row(path: &'static [&'static str], slot: Slot, codec: Codec) -> Field {
    Field {
        path,
        slot,
        codec,
        park: false,
        clamp: None,
        cap: None,
        drop_if: None,
    }
}

impl Field {
    /// `park = true`.
    pub const fn park(mut self) -> Field {
        self.park = true;
        self
    }

    /// `clamp = [min, max]`, `clamp_warn`, `clamp_parameter`.
    pub const fn clamp(mut self, min: f64, max: f64, warn: &'static str, parameter: bool) -> Field {
        self.clamp = Some(Clamp {
            min,
            max,
            warn,
            parameter,
        });
        self
    }

    /// `cap = n` (the dialect's `label` names it in the diagnostic).
    pub const fn cap(mut self, n: usize, label: &'static str) -> Field {
        self.cap = Some((n, label));
        self
    }

    /// `drop_if`, `drop_warn`, `drop_warn_value`.
    pub const fn drop_if(mut self, when: Cond, warn: &'static str, value: bool) -> Field {
        self.drop_if = Some(DropIf { when, warn, value });
        self
    }
}

/// What the egress writer knows that a row's modifiers may test.
#[derive(Debug, Clone, Copy, Default)]
pub struct Egress {
    /// The writer emitted a thinking ask.
    pub thinking: bool,
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
            Slot::Temperature => r.temperature.map(Value::from),
            Slot::TopP => r.top_p.map(Value::from),
            Slot::TopK => r.top_k.map(Value::from),
            Slot::FrequencyPenalty => r.frequency_penalty.map(Value::from),
            Slot::PresencePenalty => r.presence_penalty.map(Value::from),
            Slot::Seed => r.seed.map(Value::from),
            Slot::N => r.n.map(Value::from),
            Slot::Stop => (!r.stop.is_empty()).then(|| Value::from(r.stop.clone())),
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
        let count = || v.as_u64().and_then(|n| u32::try_from(n).ok());
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
            Slot::Temperature => first(&mut r.temperature, v.as_f64()),
            Slot::TopP => first(&mut r.top_p, v.as_f64()),
            Slot::TopK => first(&mut r.top_k, count()),
            Slot::FrequencyPenalty => first(&mut r.frequency_penalty, v.as_f64()),
            Slot::PresencePenalty => first(&mut r.presence_penalty, v.as_f64()),
            Slot::Seed => first(&mut r.seed, v.as_i64()),
            Slot::N => first(&mut r.n, count()),
            Slot::Stop => {
                if r.stop.is_empty() {
                    r.stop = crate::codec::ir::read_stop_sequences(Some(v));
                }
            }
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
    for f in rows(table).filter(|f| f.park) {
        if let Some(v) = value_of(f, ir) {
            put(&mut written, f.path, v);
        }
    }
    for f in rows(table).filter(|f| f.park) {
        if let [key] = f.path {
            if let Some(raw) = obj.get(*key) {
                if written.get(*key) != Some(raw) {
                    ir.extra.insert((*key).to_string(), raw.clone());
                }
            }
        }
    }
}

/// The wire value of `f` for `req` before any modifier.
fn value_of(f: &Field, req: &IrRequest) -> Option<Value> {
    match f.codec {
        Codec::Plain => f.slot.get(req),
        Codec::Words(words) => f
            .slot
            .get(req)
            .and_then(|v| v.as_str().and_then(|n| word_out(words, n)))
            .map(Value::from),
        Codec::Hook(hook) => hook.write(req),
    }
}

/// The warn of a row dropped under its condition. Its fields are the slot's own (a static field
/// name per slot, as the writers always spelled them).
fn warn_drop(d: &DropIf, slot: Slot, req: &IrRequest) {
    match slot {
        // Thinking runs at temperature 1: omitting exactly 1 changes nothing and is not warned.
        Slot::Temperature if req.temperature == Some(1.0) => {}
        Slot::Temperature if d.value => {
            tracing::warn!(temperature = ?req.temperature, "{}", d.warn);
        }
        Slot::TopP if d.value => {
            if let Some(top_p) = req.top_p {
                tracing::warn!(top_p, "{}", d.warn);
            }
        }
        Slot::TopK if d.value => {
            if let Some(top_k) = req.top_k {
                tracing::warn!(top_k, "{}", d.warn);
            }
        }
        _ => tracing::warn!("{}", d.warn),
    }
}

/// Clamp `v` into `[min, max]`: `(the value to write, whether the clamp changed it)`. A non-finite
/// value (unreachable through JSON) is returned unchanged.
pub fn clamp(v: f64, min: f64, max: f64) -> (f64, bool) {
    if !v.is_finite() {
        return (v, false);
    }
    let clamped = v.clamp(min, max);
    (clamped, clamped != v)
}

/// THE WRITE WALK. Emit every slot of `table` that `req` carries into `out` at its wire path,
/// through the row's modifiers: a row whose drop condition holds is omitted with its warn, a clamp
/// is applied (warned when it changed the value), a list is capped. A neutral word the row's table
/// has no wire word for is not written.
pub fn write(table: Table, req: &IrRequest, egress: Egress, out: &mut Map<String, Value>) {
    for f in rows(table) {
        let Some(mut v) = value_of(f, req) else {
            continue;
        };
        if let Some(d) = &f.drop_if {
            if match d.when {
                Cond::Thinking => egress.thinking,
            } {
                warn_drop(d, f.slot, req);
                continue;
            }
        }
        if let (Some(c), Some(n)) = (&f.clamp, v.as_f64()) {
            let (clamped, changed) = clamp(n, c.min, c.max);
            if changed && c.parameter {
                tracing::warn!(
                    requested_temperature = n,
                    clamped_temperature = clamped,
                    parameter = "temperature",
                    "{}",
                    c.warn
                );
            } else if changed {
                tracing::warn!(
                    requested_temperature = n,
                    clamped_temperature = clamped,
                    "{}",
                    c.warn
                );
            }
            v = Value::from(clamped);
        }
        if let (Some((cap, label)), Some(items)) = (f.cap, v.as_array()) {
            let items: Vec<String> = items
                .iter()
                .filter_map(|i| i.as_str().map(String::from))
                .collect();
            v = Value::from(crate::codec::ir::clamp_stop(&items, cap, label));
        }
        put(out, f.path, v);
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
