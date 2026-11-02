// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The EXPORT PROJECTION GRAMMAR (design `export-projection-grammar.md`) — the per-instance
//! `streams:` / `fields:` surface, its validation, and the CORE-SIDE ENFORCEMENT that makes an
//! over-reading sink impossible rather than merely forbidden.
//!
//! ## The principle
//!
//! The engine holds everything; **each `export:` INSTANCE is a projection of it**. The plugin does
//! not choose what it sees — the OPERATOR does, per instance, in config. Core builds each sink's
//! payload TO ITS PROJECTION, so an ungranted field is never serialized and therefore never crosses
//! the ABI. That is what makes "an exporter may access everything it is given" a safe statement.
//!
//! ## `fields:` OVERRIDES — and that is a SECURITY property, not a style choice
//!
//! This deliberately INVERTS the `hooks:` combine rule (lists are ADDITIVE there, see
//! `config::overlay`). The asymmetry is justified, not an inconsistency:
//!
//! > If `fields:` were additive, a future busbar version that adds a field to a stream's defaults
//! > would SILENTLY WIDEN what every already-configured sink receives.
//!
//! Override means the operator's list is EXHAUSTIVE: a field added in a later release can never leak
//! into a sink someone configured a year ago. **Hooks compose BEHAVIOUR, so additive is right there.
//! Projections bound DISCLOSURE, so override is right here.**
//!
//! ## The three things this module refuses to do quietly
//!
//! One defect class recurs across this release — *reports success while quietly not taking
//! effect*. A config surface that validates and then delivers nothing would be a fresh
//! instance of it, hand-built. So all three of these are LOUD errors at `--validate`/boot:
//!
//! 1. a stream this release has **no producer** for ([`stream_produced`]);
//! 2. a stream the instance's **module cannot carry** (the streams its sink declares);
//! 3. a `fields:` list that omits a **pinned** field, or names a field this release does not
//!    produce.

use busbar_contract::abi::export::{ExportField, ExportStream};
use serde_json::Value;

pub(crate) const PRODUCED_STREAMS: &[ExportStream] = &[
    ExportStream::Metrics,
    ExportStream::Logs,
    ExportStream::Traces,
    ExportStream::Events,
];

pub(crate) fn stream_produced(stream: ExportStream) -> bool {
    PRODUCED_STREAMS.contains(&stream)
}

pub(crate) fn produced_fields(stream: ExportStream) -> &'static [ExportField] {
    use ExportField as F;
    match stream {
        ExportStream::Metrics => &[],

        ExportStream::Logs => &[F::Ts, F::IngressProtocol, F::Pool, F::Outcome, F::LatencyMs],

        ExportStream::Traces => &[],

        ExportStream::Events => &[
            F::Seq,
            F::Ts,
            F::PrevHash,
            F::Kind,
            F::Actor,
            F::Resource,
            F::Outcome,
        ],

        ExportStream::Costs
        | ExportStream::Decisions
        | ExportStream::Identity
        | ExportStream::Prompts
        | ExportStream::Completions => &[],
    }
}

/// One sink's PROJECTION: the streams it subscribes to and the fields it is granted, as two dense
/// bitmasks. `Copy` and pointer-free, so the request-finish path reads it with an `AND`+compare.
///
/// The field mask is a GRANT, not a filter: [`ProjectedRecord`] can only write a field the mask
/// holds, so an ungranted field is never serialized and never reaches a sink.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) struct Projection {
    streams: u16,
    fields: u64,
}

impl Projection {
    fn from_parts(streams: &[ExportStream], fields: &[ExportField]) -> Projection {
        let mut p = Projection::default();
        for s in streams {
            p.streams |= 1u16 << stream_bit(*s);
        }
        for f in fields {
            p.fields |= 1u64 << f.bit();
        }
        p
    }

    #[cfg(test)]
    pub(crate) fn for_test(streams: &[ExportStream], fields: &[ExportField]) -> Projection {
        Projection::from_parts(streams, fields)
    }

    #[inline]
    pub(crate) fn wants_stream(self, stream: ExportStream) -> bool {
        self.streams & (1u16 << stream_bit(stream)) != 0
    }

    #[inline]
    pub(crate) fn grants(self, stream: ExportStream, field: ExportField) -> bool {
        self.wants_stream(stream) && self.fields & (1u64 << field.bit()) != 0
    }

    #[cfg(test)]
    pub(crate) fn is_empty(self) -> bool {
        self.streams == 0
    }

    #[inline]
    pub(crate) fn union(self, other: Projection) -> Projection {
        Projection {
            streams: self.streams | other.streams,
            fields: self.fields | other.fields,
        }
    }

    #[cfg(test)]
    pub(crate) fn granted_fields(self, stream: ExportStream) -> Vec<ExportField> {
        ExportField::ALL
            .iter()
            .copied()
            .filter(|f| self.grants(stream, *f))
            .collect()
    }
}

fn stream_bit(stream: ExportStream) -> u16 {
    ExportStream::ALL
        .iter()
        .position(|s| *s == stream)
        .expect("every stream is in ExportStream::ALL") as u16
}

/// The config generation's UNION-OF-PROJECTIONS — "what does ANYTHING configured on this generation
/// want". Computed ONCE per config apply, read per request.
///
/// THE COMPUTE GATE. This is the SAME mechanism `crate::hooks::requested_signals` already uses for
/// hook signals, at stream+field granularity: the read runs ONLY when declared, never
/// call-then-discard. It supersedes the one-off `export::request_log_configured()` boolean — one
/// mechanism, not two. If no sink's projection includes a stream, core never assembles a payload for
/// it and there is no hot-path cost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProjectionUnion(Projection);

impl ProjectionUnion {
    pub(crate) fn of<'a>(projections: impl IntoIterator<Item = &'a Projection>) -> ProjectionUnion {
        ProjectionUnion(
            projections
                .into_iter()
                .fold(Projection::default(), |acc, p| acc.union(*p)),
        )
    }

    #[inline]
    pub(crate) fn wants_stream(self, stream: ExportStream) -> bool {
        self.0.wants_stream(stream)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}

pub(crate) struct ProjectedRecord {
    projection: Projection,
    stream: ExportStream,

    fields: serde_json::Map<String, Value>,
}

impl ProjectedRecord {
    pub(crate) fn new(projection: Projection, stream: ExportStream) -> ProjectedRecord {
        ProjectedRecord {
            projection,
            stream,
            fields: serde_json::Map::new(),
        }
    }

    pub(crate) fn set(&mut self, field: ExportField, value: impl Into<Value>) -> &mut Self {
        if self.projection.grants(self.stream, field) {
            self.fields
                .insert(field.as_token().to_string(), value.into());
        }
        self
    }

    pub(crate) fn finish(self) -> Value {
        Value::Object(self.fields)
    }
}

pub(crate) fn resolve_projection(
    name: &str,
    module: &str,
    module_carries: Option<&[ExportStream]>,
    stream_tokens: Option<&[String]>,
    fields: Option<&[String]>,
    durable: bool,
    errors: &mut Vec<String>,
) -> Projection {
    let before = errors.len();

    if durable {
        errors.push(format!(
            "export.{name}.durable: `true` is NOT YET IMPLEMENTED in this release — core does not \
             spool this sink's records, so accepting it would promise a completeness guarantee \
             nothing delivers. The key is reserved and the spool arrives in a later release; set \
             `durable: false` (or omit it) meanwhile."
        ));
    }

    let subscribed: Vec<ExportStream> = match stream_tokens {
        None => module_carries.unwrap_or(PRODUCED_STREAMS).to_vec(),
        Some([]) => {
            errors.push(format!(
                "export.{name}.streams: is EMPTY — a sink that subscribes to no stream receives \
                 nothing at all. Omit the key to take the module's own streams ({}), or name the \
                 streams you want.",
                tokens(module_carries.unwrap_or(&[]))
            ));
            Vec::new()
        }
        Some(list) => {
            let mut out = Vec::new();
            for tok in list {
                let Some(stream) = ExportStream::from_token(tok) else {
                    if tok == "audit" {
                        errors.push(format!(
                            "export.{name}.streams: `audit` is NOT a stream — it was a use case, \
                             not a data type. An auditor is a SINK whose projection includes the \
                             right streams (e.g. `streams: [logs, identity, decisions, events, \
                             costs]`), which is strictly more expressive. The streams are: {}.",
                            ExportStream::vocabulary()
                        ));
                    } else {
                        errors.push(format!(
                            "export.{name}.streams: unknown stream `{tok}`; the streams are: {}.",
                            ExportStream::vocabulary()
                        ));
                    }
                    continue;
                };
                if !stream_produced(stream) {
                    errors.push(format!(
                        "export.{name}.streams: `{}` HAS NO PRODUCER in this release — nothing \
                         generates those records yet, so subscribing would deliver nothing while \
                         reporting success. It arrives in a later release. The streams this \
                         release produces are: {}.",
                        stream.as_token(),
                        tokens(PRODUCED_STREAMS)
                    ));
                    continue;
                }
                if let Some(carried) = module_carries {
                    if !carried.contains(&stream) {
                        errors.push(format!(
                            "export.{name}.streams: `module: {module}` cannot carry the `{}` \
                             stream (it carries: {}), so this subscription would deliver nothing. \
                             Point a different module at this stream, or drop it from `streams:`.",
                            stream.as_token(),
                            tokens(carried)
                        ));
                        continue;
                    }
                }
                if out.contains(&stream) {
                    errors.push(format!(
                        "export.{name}.streams: `{}` is listed twice.",
                        stream.as_token()
                    ));
                    continue;
                }
                out.push(stream);
            }
            out
        }
    };

    let granted: Vec<ExportField> = match fields {
        None => subscribed
            .iter()
            .flat_map(|s| match s {
                ExportStream::Traces => s.default_fields(),
                other => produced_fields(*other),
            })
            .copied()
            .collect(),
        Some(list) => resolve_fields_override(name, list, &subscribed, errors),
    };

    if errors.len() != before {
        return Projection::default();
    }
    Projection::from_parts(&subscribed, &granted)
}

fn resolve_fields_override(
    name: &str,
    list: &[String],
    subscribed: &[ExportStream],
    errors: &mut Vec<String>,
) -> Vec<ExportField> {
    if list.is_empty() {
        errors.push(format!(
            "export.{name}.fields: is EMPTY — `fields:` is an EXHAUSTIVE OVERRIDE, so an empty list \
             means a record with no fields at all. Omit the key to take each subscribed stream's \
             default fields."
        ));
        return Vec::new();
    }

    let mut blocked = false;
    for s in subscribed {
        if s.default_fields().is_empty() {
            errors.push(format!(
                "export.{name}.fields: the `{}` stream has no per-record fields to project (its \
                 unit is the documented metric catalog — families, not record fields), so \
                 `fields:` cannot apply to it.",
                s.as_token()
            ));
            blocked = true;
            continue;
        }
        let produced = produced_fields(*s);
        if let Some(missing) = s
            .pinned_fields()
            .iter()
            .find(|p| !produced.contains(p))
            .copied()
        {
            errors.push(format!(
                "export.{name}.fields: the `{}` stream cannot be projected with `fields:` in this \
                 release — its PINNED field `{}` (which `fields:` may never omit, because it is \
                 what makes the records joinable) HAS NO PRODUCER yet and arrives in a later \
                 release. Omit `fields:` to receive the stream's produced default set.",
                s.as_token(),
                missing.as_token()
            ));
            blocked = true;
        }
    }

    let mut granted: Vec<ExportField> = Vec::new();
    for tok in list {
        let Some(field) = ExportField::from_token(tok) else {
            errors.push(format!(
                "export.{name}.fields: unknown field `{tok}`. The fields of the subscribed streams \
                 are: {}.",
                subscribed_field_tokens(subscribed)
            ));
            continue;
        };
        if !subscribed
            .iter()
            .any(|s| s.default_fields().contains(&field))
        {
            errors.push(format!(
                "export.{name}.fields: `{tok}` is not a field of any subscribed stream ({}), so it \
                 would never arrive. The fields of the subscribed streams are: {}.",
                tokens(subscribed),
                subscribed_field_tokens(subscribed)
            ));
            continue;
        }
        if !blocked
            && !subscribed
                .iter()
                .any(|s| produced_fields(*s).contains(&field))
        {
            errors.push(format!(
                "export.{name}.fields: `{tok}` HAS NO PRODUCER in this release — it is a documented \
                 field of a subscribed stream but nothing fills it in yet, so asking for it \
                 explicitly would leave a permanently-absent key. It arrives in a later release."
            ));
            continue;
        }
        if granted.contains(&field) {
            errors.push(format!("export.{name}.fields: `{tok}` is listed twice."));
            continue;
        }
        granted.push(field);
    }

    if !blocked {
        for s in subscribed {
            for pinned in s.pinned_fields() {
                if !granted.contains(pinned) {
                    errors.push(format!(
                        "export.{name}.fields: omits `{}`, which is PINNED on the `{}` stream. \
                         `fields:` bounds what a sink is DISCLOSED, but it must not break the \
                         records' STRUCTURE: {} Add `{}` to `fields:`, or omit `fields:` to take \
                         the stream's defaults.",
                        pinned.as_token(),
                        s.as_token(),
                        pinned_reason(*pinned),
                        pinned.as_token()
                    ));
                }
            }
        }
    }
    granted
}

fn pinned_reason(field: ExportField) -> &'static str {
    match field {
        ExportField::CorrelationId => {
            "one request is split across several streams, and `correlation_id` is the join key that \
             reassembles them — without it the records are unjoinable."
        }
        ExportField::PrevHash => {
            "it is the link in the event hash chain — without it the chain cannot be verified."
        }
        ExportField::Seq => "it is the event's position in the chain.",
        ExportField::Ts => "it is when the event happened, and part of what the chain hashes.",
        ExportField::TraceId | ExportField::SpanId => {
            "it is the span tree's own identity — without it a span cannot be placed in a trace."
        }
        _ => "it is structural to the stream's records.",
    }
}

fn tokens(streams: &[ExportStream]) -> String {
    streams
        .iter()
        .map(|s| s.as_token())
        .collect::<Vec<_>>()
        .join(" | ")
}

fn subscribed_field_tokens(subscribed: &[ExportStream]) -> String {
    ExportField::ALL
        .iter()
        .filter(|f| subscribed.iter().any(|s| s.default_fields().contains(f)))
        .map(|f| f.as_token())
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
#[path = "tests/projection_tests.rs"]
mod tests;
