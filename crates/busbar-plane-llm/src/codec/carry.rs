// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIALECT MAPPING WALKER (TODO 36b, stage 0 of the dialect file): one walker for every
//! dialect's mapped request fields.
//!
//! Each dialect states its wire ↔ IR mapping as data in `crates/busbar-plane-llm/dialects/<d>.toml`;
//! `cargo xtask dialect compile` emits it as the `const` tables of `codec/<d>/map.gen.rs` (the
//! `dialect-map` gate refuses a committed table that differs from a fresh compile). A row is a
//! [`Field`]: wire path, [`Slot`], [`ValueCodec`]. This module is the only code that reads the tables:
//!
//! * [`read_fields`] fills each slot from its wire path, then parks in `extra` every raw top-level member
//!   the slot does not reproduce byte-for-byte, so a same-dialect re-serialize keeps the caller's
//!   exact member (`extra` is written last and is cleared on the cross-protocol seam);
//! * [`write_fields`] emits each carried slot at its wire path, overlaying a nested path onto the
//!   container already in the body;
//! * [`keys`] names the top-level members a table models, for the reader's modelled-key list.
//!
//! A row whose carry is irregular names a [`Hook`] from the one registry below; the walker calls
//! the hook's reader and writer in the row's place.

use serde_json::{Map, Value};

use crate::codec::ir::{IrRequest, IrServiceTier, IrVerbosity};

/// A flat IR request slot a field table can name. Each slot has ONE neutral JSON spelling (the
/// slot's own number / flag / string, a string map, or the IR word); a row's [`ValueCodec`] maps it to
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
    /// An OpenAI custom (free-form grammar) tool in `IrRequest::hosted_tools` (carried by code).
    CustomTool,
    /// A member the dialect's own structural code models (`prim` rows): no slot of its own.
    Structure,
}

/// THE CONTROL ORDER: every request control a dialect may have no form for, in the order a
/// dialect's dropped controls are warned and audited. Each dialect's dropped set is DERIVED from
/// its mapping: a control is dropped when the request carries it and the dialect has no row for it
/// (or its row's word table has no word for the value), unless the dialect's `[controls]` names it
/// silent (a 1.5.5 waiver) or carried by its own code.
pub const CONTROL_ORDER: &[Slot] = &[
    Slot::TopK,
    Slot::Stop,
    Slot::FrequencyPenalty,
    Slot::PresencePenalty,
    Slot::Seed,
    Slot::N,
    Slot::Metadata,
    Slot::ServiceTier,
    Slot::Store,
    Slot::SafetyIdentifier,
    Slot::PromptCacheKey,
    Slot::Verbosity,
    Slot::OutputModalities,
    Slot::CustomTool,
];

/// How a dialect handles a control slot beyond its rows (`[controls]` in the mapping file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handled {
    /// Dropped with neither a warn nor an audit entry: the 1.5.5 behaviour, kept as a named waiver
    /// (`silent = true`, its reason cited in the mapping file).
    Silent,
    /// Carried, warned or reported by the named dialect code (`code = "<name>"`).
    Code(&'static str),
    /// When dropped, warned with this text instead of the dialect's `drop_warn`; `true` names the
    /// dropped value in the warn's fields (`warn = "<text>"`, `value = true|false`).
    Warn(&'static str, bool),
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
pub enum ValueCodec {
    /// The slot's neutral spelling, unchanged.
    Plain,
    /// The slot's neutral word through a word table.
    Words(&'static [Word]),
    /// Named irregular code from the [`Hook`] registry.
    Hook(Hook),
    /// A member the dialect's named structural code reads and writes (`prim = "<name>"`); the walker
    /// only counts it among the modelled keys.
    Prim(&'static str),
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
    pub codec: ValueCodec,
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
pub const fn row(path: &'static [&'static str], slot: Slot, codec: ValueCodec) -> Field {
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
            Slot::CustomTool | Slot::Structure => None,
        }
    }

    /// The slot's name: the IR field's, as warns and the seam's audit name a dropped control.
    pub fn name(self) -> &'static str {
        match self {
            Slot::Metadata => "metadata",
            Slot::ServiceTier => "service_tier",
            Slot::Store => "store",
            Slot::SafetyIdentifier => "safety_identifier",
            Slot::PromptCacheKey => "prompt_cache_key",
            Slot::Verbosity => "verbosity",
            Slot::OutputModalities => "output_modalities",
            Slot::WebSearch => "web_search",
            Slot::Temperature => "temperature",
            Slot::TopP => "top_p",
            Slot::TopK => "top_k",
            Slot::FrequencyPenalty => "frequency_penalty",
            Slot::PresencePenalty => "presence_penalty",
            Slot::Seed => "seed",
            Slot::N => "n",
            Slot::Stop => "stop",
            Slot::CustomTool => "custom_tool",
            Slot::Structure => "structure",
        }
    }

    /// Whether the request carries the control: set, or (stop) non-empty, or (output modalities)
    /// naming anything but text, or (custom tool) holding one.
    pub fn carried(self, r: &IrRequest) -> bool {
        match self {
            Slot::OutputModalities => r
                .output_modalities
                .as_ref()
                .is_some_and(|m| m.iter().any(|m| *m != crate::codec::ir::IrModality::Text)),
            Slot::CustomTool => r
                .hosted_tools
                .iter()
                .any(|t| matches!(t, crate::codec::ir::IrHostedTool::Custom(_))),
            Slot::WebSearch => r
                .hosted_tools
                .iter()
                .any(|t| matches!(t, crate::codec::ir::IrHostedTool::WebSearch(_))),
            Slot::Structure => false,
            other => other.get(r).is_some(),
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
            Slot::CustomTool | Slot::Structure => {}
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
pub fn read_fields(table: Table, obj: &Map<String, Value>, ir: &mut IrRequest) {
    for f in rows(table) {
        let Some(raw) = at(obj, f.path) else {
            continue;
        };
        match f.codec {
            ValueCodec::Plain => f.slot.fill(ir, raw),
            ValueCodec::Words(words) => {
                if let Some(neutral) = raw.as_str().and_then(|w| word_in(words, w)) {
                    f.slot.fill(ir, &Value::from(neutral));
                }
            }
            ValueCodec::Hook(hook) => hook.read(raw, ir),
            ValueCodec::Prim(_) => {}
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
        ValueCodec::Plain => f.slot.get(req),
        ValueCodec::Words(words) => f
            .slot
            .get(req)
            .and_then(|v| v.as_str().and_then(|n| word_out(words, n)))
            .map(Value::from),
        ValueCodec::Hook(hook) => hook.write(req),
        ValueCodec::Prim(_) => None,
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
pub fn write_fields(table: Table, req: &IrRequest, egress: Egress, out: &mut Map<String, Value>) {
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

/// THE DERIVED DROPS: the controls of [`CONTROL_ORDER`] that `req` carries and this dialect cannot
/// write: no row names the slot (a hook row and a `prim` row carry it), or its word-table row has
/// no word for the value — unless `controls` names the slot silent or carried by code. The names
/// are the ones the dialect's `dropped_egress_controls` reports and its warns carry.
pub fn dropped<'a>(
    table: Table,
    controls: &'a [(Slot, Handled)],
    req: &'a IrRequest,
) -> impl Iterator<Item = Slot> + 'a {
    CONTROL_ORDER.iter().copied().filter(move |&slot| {
        if !slot.carried(req) {
            return false;
        }
        match handled(controls, slot) {
            Some(Handled::Silent | Handled::Code(_)) => false,
            _ => match rows(table).find(|f| f.slot == slot) {
                None => true,
                Some(
                    f @ Field {
                        codec: ValueCodec::Words(_),
                        ..
                    },
                ) => value_of(f, req).is_none(),
                Some(_) => false,
            },
        }
    })
}

fn handled(controls: &[(Slot, Handled)], slot: Slot) -> Option<Handled> {
    controls.iter().find(|(s, _)| *s == slot).map(|(_, h)| *h)
}

/// THE ONE DROP WARN: one warn per [`dropped`] control, in the dialect's own words — its
/// `[controls]` text for the slot when it names one, else its `drop_warn`.
pub fn warn_drops(
    table: Table,
    controls: &[(Slot, Handled)],
    drop_warn: Option<&crate::codec::dialect::DropWarn>,
    req: &IrRequest,
) {
    for slot in dropped(table, controls, req) {
        match (handled(controls, slot), drop_warn) {
            (Some(Handled::Warn(text, value)), _) => warn_slot(slot, text, value, req),
            (_, Some(drop_warn)) => crate::codec::dialect::warn_dropped([slot.name()], drop_warn),
            (_, None) => tracing::warn!(
                control = slot.name(),
                "dropping a request control on egress: the dialect has no form for it"
            ),
        }
    }
}

/// A dropped control's own warn. With `value`, the warn names the dropped value under the slot's
/// field (and `parameter`, for a sampling control), as each writer always spelled it.
fn warn_slot(slot: Slot, text: &str, value: bool, req: &IrRequest) {
    match (slot, value) {
        (Slot::FrequencyPenalty, true) => {
            if let Some(frequency_penalty) = req.frequency_penalty {
                tracing::warn!(
                    parameter = "frequency_penalty",
                    frequency_penalty,
                    "{}",
                    text
                );
            }
        }
        (Slot::PresencePenalty, true) => {
            if let Some(presence_penalty) = req.presence_penalty {
                tracing::warn!(parameter = "presence_penalty", presence_penalty, "{}", text);
            }
        }
        (Slot::Seed, true) => {
            if let Some(seed) = req.seed {
                tracing::warn!(parameter = "seed", seed, "{}", text);
            }
        }
        (Slot::N, true) => {
            if let Some(n) = req.n {
                tracing::warn!(parameter = "n", n, "{}", text);
            }
        }
        (Slot::ServiceTier, true) => {
            if let Some(tier) = req.service_tier {
                tracing::warn!(service_tier = tier.as_str(), "{}", text);
            }
        }
        (Slot::Stop, true) => {
            let stop_count = req.stop.len();
            tracing::warn!(
                stop_count,
                "{}",
                text.replace("{count}", &stop_count.to_string())
            );
        }
        _ => tracing::warn!("{}", text),
    }
}

/// Keep in `extra` every top-level member of `obj` that `table` does not model (same-dialect
/// fidelity for what the dialect has no row or structural code for).
pub fn keep_unmodelled(table: Table, obj: &Map<String, Value>, extra: &mut Map<String, Value>) {
    for (key, value) in obj {
        if !models(table, key) {
            extra.insert(key.clone(), value.clone());
        }
    }
}

/// Whether `key` is a top-level member `table` models (the reader keeps every other member in
/// `extra`).
pub fn models(table: Table, key: &str) -> bool {
    keys(table).any(|k| k == key)
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
