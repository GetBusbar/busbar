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
//! Projections bound DISCLOSURE, so override is right here.** (Recorded next to the combine rule in
//! `design/audit-decisions-1.5.3.md`.)
//!
//! ## The three things this module refuses to do quietly
//!
//! Every audit round in this release surfaced the same defect class — *reports success while quietly
//! not taking effect*. A config surface that validates and then delivers nothing would be a fresh
//! instance of it, hand-built. So all three of these are LOUD errors at `--validate`/boot:
//!
//! 1. a stream this release has **no producer** for ([`stream_produced`]);
//! 2. a stream the instance's **module cannot carry** ([`module_streams`]);
//! 3. a `fields:` list that omits a **pinned** field, or names a field this release does not
//!    produce.

use busbar_plugin_loader::{ExportField, ExportStream};
use serde_json::Value;

// ───────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS RELEASE ACTUALLY PRODUCES — the HARD RULE's single source of truth.
// ───────────────────────────────────────────────────────────────────────────────────────────────

/// The streams this release has a REAL PRODUCER for — i.e. core builds the records.
///
/// THE HARD RULE: a config naming a stream that is not here LOUD-FAILS at validate, naming the
/// stream and saying it arrives in a later release. It must NEVER validate-and-silently-deliver-
/// nothing. Shipping the surface ahead of the producers is the tempting shortcut and it is a defect,
/// not a shortcut: `streams: [prompts]` would parse, report success, and deliver nothing forever.
///
/// What produces each entry TODAY (open these before changing this list — the rule is only worth
/// what the citations are worth):
/// - `metrics` — the recorder + emit sites in `crate::metrics`, rendered by
///   `crate::export::prometheus`.
/// - `logs` — [`crate::export::build_request_log`], from the request-finish path
///   (`crate::ingress::finish_inner`). PARTIAL: it produces a subset of the stream's documented
///   default fields (see [`produced_fields`]).
/// - `traces` — the OpenTelemetry span pipeline (`crate::observability`), exported by the `otlp`
///   module.
/// - `events` — the hash-chained admin records in `crate::admin::audit` (`busbar_api::AuditRecord`:
///   `seq`/`ts`/`action`/`resource`/`outcome`/`principal`/`prev_hash`/`hash`). PARTIAL: admin
///   mutations only; config applies, plugin loads/refusals, boot and shutdown are a later unit.
///
/// NOT here, and therefore rejected: `costs`, `decisions`, `identity`, `prompts`, `completions`.
/// `decisions` is the one to protect hardest — core ALREADY computes exclusion reasons and hook
/// verdicts and then DISCARDS them, so it is tempting to call it "nearly there". It is not a
/// producer until the records exist.
pub(crate) const PRODUCED_STREAMS: &[ExportStream] = &[
    ExportStream::Metrics,
    ExportStream::Logs,
    ExportStream::Traces,
    ExportStream::Events,
];

/// True when this release has a producer for `stream` (see [`PRODUCED_STREAMS`]).
pub(crate) fn stream_produced(stream: ExportStream) -> bool {
    PRODUCED_STREAMS.contains(&stream)
}

/// The fields of `stream` this release actually FILLS IN, a subset of the stream's frozen
/// documented default set ([`ExportStream::default_fields`]).
///
/// This exists so that `fields:` cannot name a field that would never arrive. The default (no
/// `fields:`) projection is the produced subset, which is why a partial stream can ship at all —
/// but an EXPLICIT request for a field is a promise, and a promise this release cannot keep is a
/// loud error rather than a permanently-absent key in the operator's SIEM.
///
/// `logs` is kept honest by `crate::export::tests::projection_tests` — it asserts this list equals
/// the keys [`crate::export::build_request_log`] actually emits, so the table cannot drift from the
/// producer it describes.
pub(crate) fn produced_fields(stream: ExportStream) -> &'static [ExportField] {
    use ExportField as F;
    match stream {
        // Aggregate: the unit is the documented metric CATALOG (families), not record fields.
        ExportStream::Metrics => &[],
        // `crate::export::build_request_log` — the five fields today's request log carries. The rest
        // of the stream's documented default set (correlation_id, model_requested, model_served,
        // provider, status) is the producer unit that follows this one.
        ExportStream::Logs => &[F::Ts, F::IngressProtocol, F::Pool, F::Outcome, F::LatencyMs],
        // Spans are emitted by the tracing/OTLP layer, NOT built as records by core, so core has no
        // per-field projection to apply to them. An operator asking to project trace FIELDS is
        // asking for something this release cannot do — loudly, not silently.
        ExportStream::Traces => &[],
        // `busbar_api::AuditRecord`, mapped onto the stream's field names: seq → seq, ts → ts,
        // prev_hash → prev_hash, action → kind, principal → actor, resource → resource,
        // outcome → outcome.
        ExportStream::Events => &[
            F::Seq,
            F::Ts,
            F::PrevHash,
            F::Kind,
            F::Actor,
            F::Resource,
            F::Outcome,
        ],
        // No producer at all (see PRODUCED_STREAMS) — the stream itself is rejected first.
        ExportStream::Costs
        | ExportStream::Decisions
        | ExportStream::Identity
        | ExportStream::Prompts
        | ExportStream::Completions => &[],
    }
}

/// The streams a built-in `export:` MODULE can carry.
///
/// Checked so that `module: prometheus` + `streams: [logs]` is a LOUD error instead of a sink that
/// validates and receives nothing: the module is the transport, the projection is what rides it, and
/// a projection the transport cannot carry is a configuration mistake, not an empty subscription.
/// `None` for a module this build does not know (the unknown-module diagnostic owns that case).
pub(crate) fn module_streams(module: &str) -> Option<&'static [ExportStream]> {
    match module {
        crate::config::EXPORT_MODULE_PROMETHEUS => Some(&[ExportStream::Metrics]),
        crate::config::EXPORT_MODULE_REQUEST_LOG_WEBHOOK
        | crate::config::EXPORT_MODULE_REQUEST_LOG_FILE => Some(&[ExportStream::Logs]),
        crate::config::EXPORT_MODULE_OTLP => Some(&[ExportStream::Traces]),
        _ => None,
    }
}

// ───────────────────────────────────────────────────────────────────────────────────────────────
// THE PROJECTION ITSELF
// ───────────────────────────────────────────────────────────────────────────────────────────────

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
    /// Build a projection from an explicit stream + field set. Private-by-module on purpose: config
    /// resolution ([`resolve_projection`]) is the only place a projection is minted, so a projection
    /// can never be widened by a caller that "just needs one more field".
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

    /// A projection minted directly from parts, for tests only. Deliberately `#[cfg(test)]`: in a
    /// real build the ONLY way to obtain a projection is [`resolve_projection`], which is what makes
    /// "the operator grants, nothing else does" a structural property rather than a convention.
    #[cfg(test)]
    pub(crate) fn for_test(streams: &[ExportStream], fields: &[ExportField]) -> Projection {
        Projection::from_parts(streams, fields)
    }

    /// Does this sink subscribe to `stream`?
    #[inline]
    pub(crate) fn wants_stream(self, stream: ExportStream) -> bool {
        self.streams & (1u16 << stream_bit(stream)) != 0
    }

    /// Is `field` of `stream` granted to this sink? BOTH halves must hold — a field granted for one
    /// stream must not leak in through another the sink did not subscribe to.
    #[inline]
    pub(crate) fn grants(self, stream: ExportStream, field: ExportField) -> bool {
        self.wants_stream(stream) && self.fields & (1u64 << field.bit()) != 0
    }

    /// Nothing subscribed — the zero-cost default generation (no `export:` block at all).
    #[inline]
    pub(crate) fn is_empty(self) -> bool {
        self.streams == 0
    }

    /// The UNION of two projections. Used to build the compute gate; never to build a sink's own
    /// projection (a sink's grant is exactly what its own config says).
    #[inline]
    pub(crate) fn union(self, other: Projection) -> Projection {
        Projection {
            streams: self.streams | other.streams,
            fields: self.fields | other.fields,
        }
    }

    /// The granted fields of `stream`, in the frozen catalog order — for diagnostics and tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn granted_fields(self, stream: ExportStream) -> Vec<ExportField> {
        ExportField::ALL
            .iter()
            .copied()
            .filter(|f| self.grants(stream, *f))
            .collect()
    }
}

/// A stream's bit position in [`Projection`]'s stream mask — its index in the frozen vocabulary, so
/// the position is derived, never hand-assigned.
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
    /// Fold every configured instance's projection into the generation's union.
    pub(crate) fn of<'a>(projections: impl IntoIterator<Item = &'a Projection>) -> ProjectionUnion {
        ProjectionUnion(
            projections
                .into_iter()
                .fold(Projection::default(), |acc, p| acc.union(*p)),
        )
    }

    /// Does ANY configured sink subscribe to `stream`? The single check the hot path makes before
    /// building a record for it.
    #[inline]
    pub(crate) fn wants_stream(self, stream: ExportStream) -> bool {
        self.0.wants_stream(stream)
    }

    /// Nothing subscribed anywhere — the zero-cost default.
    #[inline]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}

// ───────────────────────────────────────────────────────────────────────────────────────────────
// THE ENFORCEMENT: a record that CANNOT carry an ungranted field
// ───────────────────────────────────────────────────────────────────────────────────────────────

/// A record being built TO A PROJECTION. **The only way to build an export payload in core.**
///
/// WHY THIS TYPE EXISTS RATHER THAN A `json!` LITERAL PLUS A FILTER. A filter is a step someone can
/// forget, reorder, or short-circuit, and the failure mode is silent over-disclosure. Here the
/// projection is a CONSTRUCTOR ARGUMENT and [`ProjectedRecord::set`] is the only writer: the field
/// key is an [`ExportField`] (so a producer cannot invent a key as a string), the value is dropped
/// unless the projection grants it, and the inner map is private with no way in. Writing the wrong
/// thing is not merely untested — it does not typecheck. Same discipline as `config::migrate`'s
/// `Taken<T>` (take-on-match, no `unwrap_or_default`) and the cache's generation guard.
///
/// A dropped write is NOT a silent failure of the kind this release keeps finding: the operator
/// asked for exactly this by writing `fields:`, validation already refused every combination that
/// would under-deliver a field they DID ask for (see [`resolve_projection`]), and the whole point of
/// an exhaustive override is that what is not listed does not arrive.
pub(crate) struct ProjectedRecord {
    projection: Projection,
    stream: ExportStream,
    /// Private, and there is no constructor from a `Value`, no `DerefMut`, and no accessor — so
    /// `set` is the only path by which a key can enter this map.
    fields: serde_json::Map<String, Value>,
}

impl ProjectedRecord {
    /// Start a record for `stream`, bounded by `projection`.
    pub(crate) fn new(projection: Projection, stream: ExportStream) -> ProjectedRecord {
        ProjectedRecord {
            projection,
            stream,
            fields: serde_json::Map::new(),
        }
    }

    /// Offer `field` to the record. Written IFF the projection grants it for this record's stream;
    /// otherwise the value is dropped here and never serialized. The value is computed by the caller
    /// — this is the DISCLOSURE gate, not the COMPUTE gate (that one is [`ProjectionUnion`], read
    /// before the producer runs at all).
    pub(crate) fn set(&mut self, field: ExportField, value: impl Into<Value>) -> &mut Self {
        if self.projection.grants(self.stream, field) {
            self.fields
                .insert(field.as_token().to_string(), value.into());
        }
        self
    }

    /// Finish the record. Consumes the builder, so nothing can be added after the payload is taken.
    pub(crate) fn finish(self) -> Value {
        Value::Object(self.fields)
    }
}

// ───────────────────────────────────────────────────────────────────────────────────────────────
// CONFIG RESOLUTION + VALIDATION
// ───────────────────────────────────────────────────────────────────────────────────────────────

/// Resolve ONE `export:` instance's `streams:` / `fields:` / `durable:` keys into its [`Projection`],
/// accumulating every problem into `errors` (never short-circuiting, so `--validate` reports the
/// whole config at once — the posture `resolve_export` takes everywhere else).
///
/// `name` is the instance name and `module` its `module:` value, both only for diagnostics.
/// `streams`/`fields` are the RAW operator tokens: parsing happens here so every diagnostic is ours
/// (serde's "unknown variant" could not say that `audit` was REMOVED and why).
///
/// Returns the projection to enforce. On error the returned projection is EMPTY — a config that
/// failed validation never boots, and an empty projection grants nothing if it somehow did.
pub(crate) fn resolve_projection(
    name: &str,
    module: &str,
    streams: Option<&[String]>,
    fields: Option<&[String]>,
    durable: bool,
    errors: &mut Vec<String>,
) -> Projection {
    let before = errors.len();

    // `durable:` — the KEY is part of the frozen surface; the core spool that backs it is a later
    // unit. Accepting `true` and not spooling would be precisely the "reports success while quietly
    // not taking effect" defect, so it is a LOUD refusal until the spool lands.
    if durable {
        errors.push(format!(
            "export.{name}.durable: `true` is NOT YET IMPLEMENTED in this release — core does not \
             spool this sink's records, so accepting it would promise a completeness guarantee \
             nothing delivers. The key is reserved and the spool arrives in a later release; set \
             `durable: false` (or omit it) meanwhile."
        ));
    }

    // ── streams: ────────────────────────────────────────────────────────────────────────────────
    let module_carries = module_streams(module);
    let subscribed: Vec<ExportStream> = match streams {
        None => {
            // Absent ⇒ the module's own streams. NOT "nothing": an instance that subscribed to
            // nothing would be a sink that validates and receives nothing, which is the shape this
            // whole module exists to refuse.
            module_carries.unwrap_or(&[]).to_vec()
        }
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

    // ── fields: — the EXHAUSTIVE OVERRIDE ───────────────────────────────────────────────────────
    let granted: Vec<ExportField> = match fields {
        // No override ⇒ the default projection: every subscribed stream's documented default field
        // set, intersected with what this release actually produces.
        None => subscribed
            .iter()
            .flat_map(|s| produced_fields(*s).iter().copied())
            .collect(),
        Some(list) => resolve_fields_override(name, list, &subscribed, errors),
    };

    if errors.len() != before {
        return Projection::default();
    }
    Projection::from_parts(&subscribed, &granted)
}

/// The `fields:` half of [`resolve_projection`]. Split out because it carries the pinned-field rule,
/// which is the subtle part: `fields:` bounds DISCLOSURE and must NOT be able to break STRUCTURE.
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

    // A stream whose PINNED fields this release cannot yet produce cannot be projected with
    // `fields:` at all: the rule would demand a field, and the producer cannot supply it. Refusing
    // here — once, with both halves of the reason — beats letting the operator discover it as a
    // contradictory pair of errors, and beats the alternative of quietly not enforcing the pin.
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

    // THE PINNED-FIELD RULE. `fields:` bounds DISCLOSURE; it must not break STRUCTURE. Omitting a
    // pinned field would let an operator configure records that look complete and cannot be
    // reassembled into a request (or, on `events`, a chain with no link to verify) — so it is a
    // config error with the reason attached, never a silent no-op that "helpfully" adds it back.
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

/// Why a given field is pinned — the REASON half of the pinned-field error, so the operator learns
/// the rule from the message instead of being told "no".
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

/// Render a stream list as its tokens, for a diagnostic.
fn tokens(streams: &[ExportStream]) -> String {
    streams
        .iter()
        .map(|s| s.as_token())
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Render every field the subscribed streams document, deduplicated in catalog order.
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
