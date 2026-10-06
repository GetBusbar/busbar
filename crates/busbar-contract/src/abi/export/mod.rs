// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND'S ABI: its version and its table (the design's locked plugin ABI: one
//! mechanism, every shape in `abi/`). M0 landed the skeleton; this is M3-SHAPES
//! (`abi-v2-perkind.md` B.5): `deliver`, `scrape`, `status`, `check` and `serve`, and the frozen
//! [`ExportStream`] tail. The one dispatcher calls this table (`busbar-plugin-loader`,
//! `dispatch::kinds::export`).
//!
//! **ARCHITECT REVIEW RULING (fresh-Opus M3-SHAPES review, 2026-09-28), folded in on top of the
//! first landing:**
//! 2. `scrape`'s rendered-exposition buffer is HOST-owned and lives in [`ScrapeIn`]
//!    (`buf`/`cap`), never a plugin-owned pointer in `out`: the host zeroes `out` before the call,
//!    so nothing the plugin needs may live there. [`ScrapeOut`] carries `written`/`needed`: too
//!    small a `cap` means the plugin writes nothing, sets `needed`, and the host re-invokes ONCE
//!    with a bigger buffer.
//! 3. Off-path plugin-owned results ([`ServeOut::body`], [`StatusOut::status`],
//!    [`CheckOut::findings`]) are documented as memory class (iv): held live under `head.lease`
//!    until `release(lease)`.
//!
//! **SECOND REVIEW PASS (ARCHITECT ruling, 2026-09-28), folded in on the same landing:**
//! - [`Tail::routes`] carries [`Route`] entries (`path`, `method`, `auth`), not bare path
//!   strings: none/key/admin auth cannot be read off a path alone.
//! - [`ScrapeSample`] carries its own `name` and [`ScrapeLabel`] key/value pairs (not
//!   value-only, family-shared keys): a histogram's `_bucket`/`_sum`/`_count` legs and a
//!   summary's `quantile` legs need their own series name and their own `le`/`quantile` label,
//!   and `value` is the recorder's own string spelling, not `f64` — so the exposition `scrape`
//!   renders can reproduce the host's byte for byte.
//! - [`CheckIn`] carries `instances`/`instances_len` ([`CheckInstance`]): the OLD
//!   `Check{instances}` exists precisely for checks that read across every instance of a sink's
//!   module.
//!
//! B.5, transcribed:
//! - **Tail:** `streams[]`, pinned to the 1.5.5 `ExportStream::ALL` order (metrics, logs, traces,
//!   costs, decisions, events, identity, prompts, completions — `decisions` is a FROZEN wire word,
//!   unchanged by this move).
//! - `deliver{stream u8, batch jsonl}` — built at batch time with the `fields:` projection applied
//!   KERNEL-side (never in this kind's shapes: the batch a plugin receives is already projected).
//! - `scrape(families)` over the host snapshot service.
//! - `status` (1.5.5 blob), `check`, `serve`.
//! - **Listener.** `/metrics` is served on the data listener through the export route exception,
//!   confined to `/metrics` or `/exports/<name>/*`, the reserved paths and the 64-header cap.
//!   `/metrics/hooks` stays a core route. (Kernel routing; not a new shape here.)
//! - **Behaviour.** Webhook and otlp use driver tickets (the shared mechanism's
//!   [`Ticket`](super::mechanism::ticket::Ticket) `drive`/`DriveIn` lifecycle slot, not a new
//!   export op). The `Host` and `Started` 1.5.5 response variants are retired: `deliver` answers
//!   only READY/PENDING/FAILED/REFUSED/FAULT, with no host-op round trip and no separate `start`.
//!
//! ASSUMPTIONS (M3-SHAPES, noted for the SLOT-LOG; none are money- or customer-visible, so none is
//! an owner question):
//! - `deliver` is OFF-PATH, `may_pend`, [`DeadlineClass::WriteBehind`](super::mechanism::call::DeadlineClass::WriteBehind)
//!   (a sink write, coalesced like a store batch write, never on a request's critical path).
//! - `scrape` is REQUEST-PATH (P) — `/metrics` is answered per HTTP request — `may_pend`,
//!   [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call).
//! - `status` and `check` are OFF-PATH (O), not `may_pend` (fast, in-memory).
//! - `serve` is OFF-PATH (O) per B.4's hook precedent for a plugin's own HTTP surface, `may_pend`,
//!   [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call).
//! - No Statement tail beyond `streams[]` is stated for export; `check`'s phases (`limits` /
//!   `instances`, 1.5.5 `CheckPhase`) are carried as a `u32` `in` field rather than a new type.

use super::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead};
use serde::{Deserialize, Serialize};

pub mod validate;
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The export kind's ABI version: v1.5.5 shipped `2` (`EXPORT_ABI_VERSION`), so 1.6.0 ships `3`.
pub const ABI_VERSION: u32 = 3;

/// [`InHead::op`] values the export kind adds after the shared lifecycle, in table order.
///
/// # Examples
/// ```
/// use busbar_contract::abi::export::{slot, SLOTS};
/// use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
/// assert_eq!(slot::DELIVER, LIFECYCLE_SLOTS + 0);
/// assert_eq!(slot::SCRAPE, LIFECYCLE_SLOTS + 1);
/// assert_eq!(slot::STATUS, LIFECYCLE_SLOTS + 2);
/// assert_eq!(slot::CHECK, LIFECYCLE_SLOTS + 3);
/// assert_eq!(slot::SERVE, LIFECYCLE_SLOTS + 4);
/// assert_eq!(SLOTS, LIFECYCLE_SLOTS + 5);
/// ```
pub mod slot {
    use super::LIFECYCLE_SLOTS;

    /// `deliver`.
    pub const DELIVER: u32 = LIFECYCLE_SLOTS;
    /// `scrape`.
    pub const SCRAPE: u32 = LIFECYCLE_SLOTS + 1;
    /// `status`.
    pub const STATUS: u32 = LIFECYCLE_SLOTS + 2;
    /// `check`.
    pub const CHECK: u32 = LIFECYCLE_SLOTS + 3;
    /// `serve`.
    pub const SERVE: u32 = LIFECYCLE_SLOTS + 4;
}

/// How many slots the export kind's whole table holds (the lifecycle plus its five own ops).
pub const SLOTS: u32 = LIFECYCLE_SLOTS + 5;

/// The export kind's ops table. Leads with the shared [`OpsHead`]; kind op `k` is at slot index
/// [`LIFECYCLE_SLOTS`]` + k` ([`slot`]).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle.
    pub head: OpsHead,
    /// Hand one already-projected batch for a declared stream to the sink. OFF-PATH, `may_pend`,
    /// [`DeadlineClass::WriteBehind`](super::mechanism::call::DeadlineClass::WriteBehind). In
    /// [`DeliverIn`], out [`OutHead`] (nothing to read back).
    pub deliver: Option<Op>,
    /// Render the host recorder's snapshot as this sink's exposition text. REQUEST-PATH,
    /// `may_pend`, [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call). In
    /// [`ScrapeIn`], out [`ScrapeOut`].
    pub scrape: Option<Op>,
    /// What the sink has to report when the host renders its status exposition. OFF-PATH, not
    /// `may_pend`. In [`InHead`], out [`StatusOut`] (the 1.5.5 status blob, unchanged).
    pub status: Option<Op>,
    /// The sink's own configuration/operational checks. OFF-PATH, not `may_pend`. In
    /// [`CheckIn`], out [`CheckOut`].
    pub check: Option<Op>,
    /// The sink's own HTTP surface (`/exports/<name>/*`). OFF-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call). In [`ServeIn`], out
    /// [`ServeOut`].
    pub serve: Option<Op>,
}

/// `deliver`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeliverIn {
    /// The head.
    pub head: InHead,
    /// The dedupe/replay id the kernel mints, one per batch (the same discipline as the store's
    /// additive writes).
    pub op_id: [u8; 16],
    /// Which declared [`ExportStream`] this batch belongs to.
    pub stream: u8,
    /// Alignment padding.
    pub _reserved: [u8; 7],
    /// The already-projected batch, JSON LINES (`fields:` already applied kernel-side).
    pub batch: Blob,
}

/// One observability stream an export sink can carry OUT of the engine — the FROZEN word-space of
/// the export projection grammar, the same discipline as the hook phase names.
///
/// `#[serde(rename_all = "snake_case")]` pins the wire spelling so a plugin author in any language
/// matches on a stable token, never the Rust variant name. [`ExportStream::as_token`] is the SAME
/// spelling rendered without serde, so config parsing and the wire cannot drift apart.
///
/// FREEZE RULES:
/// - ADDING a stream is ADDITIVE and allowed — an existing config keeps its meaning and an existing
///   sink receives nothing new (it did not subscribe, and `fields:` is an exhaustive override).
/// - RENAMING or SPLITTING a stream is a BREAK for every export plugin and every operator config.
/// - The DEFAULT FIELD SET of a stream ([`ExportStream::default_fields`]) is part of the documented
///   contract: adding a field to it widens what a `fields:`-less sink receives, so it is a
///   DISCLOSURE change and belongs in release notes as one.
///
/// ONE TYPE, BOTH LANES: the discriminant is the stream's position in [`ExportStream::ALL`], the
/// order the export kind's Statement tail (`streams[]`) and [`DeliverIn`] carry it in; the serde
/// token is [`ExportStream::as_token`].
///
/// `audit` is deliberately NOT here. It was a USE CASE masquerading as a data type: an auditor is a
/// SINK whose projection includes the right streams (`logs` + `identity` + `decisions` + `events` +
/// `costs`), which is strictly more expressive than one opaque `audit` firehose.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportStream {
    /// Aggregate counters/gauges/histograms; no individual attribution. Lowest sensitivity.
    Metrics = 0,
    /// The per-request operational record.
    Logs = 1,
    /// The per-request span tree.
    Traces = 2,
    /// Per-request tokens + spend.
    Costs = 3,
    /// Per-request ROUTING PROVENANCE — candidates, exclusions and their reasons, the selection,
    /// failovers, hook verdicts. The stream that answers "why did this go THERE".
    Decisions = 4,
    /// Engine lifecycle, hash-chained: admin mutations, config applies, plugin loads AND refusals,
    /// boot, shutdown. The only non-aggregate stream that is not per-request.
    Events = 5,
    /// Per-request WHO — the pseudonymization switch: a sink without it gets the same records with
    /// nobody's name attached.
    Identity = 6,
    /// Request content. Highest sensitivity.
    Prompts = 7,
    /// Response content. Highest sensitivity.
    Completions = 8,
}

impl ExportStream {
    /// Every stream in the frozen vocabulary, in ascending sensitivity order — the ONE list every
    /// catalog walk, diagnostic and validator iterates.
    pub const ALL: &'static [ExportStream] = &[
        ExportStream::Metrics,
        ExportStream::Logs,
        ExportStream::Traces,
        ExportStream::Costs,
        ExportStream::Decisions,
        ExportStream::Events,
        ExportStream::Identity,
        ExportStream::Prompts,
        ExportStream::Completions,
    ];

    /// The stable snake_case wire/config token for this stream — the SAME spelling serde emits.
    /// Rendered without serde so a config diagnostic can name the token without a JSON round-trip.
    pub const fn as_token(self) -> &'static str {
        match self {
            ExportStream::Metrics => "metrics",
            ExportStream::Logs => "logs",
            ExportStream::Traces => "traces",
            ExportStream::Costs => "costs",
            // plane-purity: frozen-wire ExportDefCfg `streams:` token (frozen since 1.5.5)
            ExportStream::Decisions => "decisions",
            ExportStream::Events => "events",
            ExportStream::Identity => "identity",
            ExportStream::Prompts => "prompts",
            ExportStream::Completions => "completions",
        }
    }

    /// Parse a config/wire token into a stream. `None` for anything not in the frozen vocabulary —
    /// INCLUDING the retired `audit`, so the caller can emit its own named diagnostic rather than a
    /// generic "unknown variant".
    pub fn from_token(tok: &str) -> Option<ExportStream> {
        ExportStream::ALL
            .iter()
            .copied()
            .find(|s| s.as_token() == tok)
    }

    /// Every stream in the vocabulary as its token, joined for a diagnostic ("the streams are …").
    pub fn vocabulary() -> String {
        ExportStream::ALL
            .iter()
            .map(|s| s.as_token())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// The DOCUMENTED DEFAULT FIELD SET a sink receives when it subscribes to this stream and writes
    /// no `fields:` override. Part of the contract — see the FREEZE RULES on [`ExportStream`].
    ///
    /// `metrics` is deliberately EMPTY: its unit is the documented metric CATALOG (families), not
    /// record fields, so `fields:` does not apply to it and a `fields:` list aimed at it is a config
    /// error rather than a filter that silently matches nothing.
    pub const fn default_fields(self) -> &'static [ExportField] {
        use ExportField as F;
        match self {
            ExportStream::Metrics => &[],
            ExportStream::Logs => &[
                F::CorrelationId,
                F::Ts,
                F::IngressProtocol,
                F::Pool,
                F::ModelRequested,
                F::ModelServed,
                F::Provider,
                F::Outcome,
                F::Status,
                F::LatencyMs,
            ],
            ExportStream::Traces => &[
                F::TraceId,
                F::SpanId,
                F::ParentSpanId,
                F::Name,
                F::Start,
                F::DurationUs,
                F::Pool,
                F::Ingress,
                F::Op,
                F::Lane,
                F::Provider,
                F::Model,
            ],
            ExportStream::Costs => &[
                F::CorrelationId,
                F::Ts,
                F::TokensIn,
                F::TokensOut,
                F::CostCents,
                F::Pool,
                F::Model,
            ],
            ExportStream::Decisions => &[
                F::CorrelationId,
                F::Ts,
                F::Candidates,
                F::Excluded,
                F::Selected,
                F::Failovers,
                F::Hooks,
            ],
            ExportStream::Events => &[
                F::Seq,
                F::Ts,
                F::PrevHash,
                F::Kind,
                F::Actor,
                F::Resource,
                F::Outcome,
            ],
            ExportStream::Identity => &[
                F::CorrelationId,
                F::Ts,
                F::Subject,
                F::IdentityProvider,
                F::KeyId,
                F::Groups,
            ],
            ExportStream::Prompts => &[F::CorrelationId, F::Ts, F::Model, F::Messages],
            ExportStream::Completions => &[
                F::CorrelationId,
                F::Ts,
                F::Model,
                F::Content,
                F::FinishReason,
            ],
        }
    }

    /// The STRUCTURAL fields of this stream — the ones a `fields:` override may NOT remove.
    ///
    /// THE PINNED-FIELD RULE. Splitting one request across several streams means a sink receives
    /// several record sets that must REASSEMBLE into one request, so `correlation_id` (the join key)
    /// is pinned on EVERY per-request stream, and `seq`/`ts`/`prev_hash` are pinned on `events`
    /// (drop `prev_hash` and the hash chain is gone). **`fields:` bounds DISCLOSURE; it must not be
    /// able to break STRUCTURE.** Omitting one is a LOUD config error, never a silent no-op —
    /// otherwise an operator can configure records that look complete and cannot be joined.
    ///
    /// Every pinned field is also a default field (asserted in this module's tests), so the pinned
    /// set can only ever narrow a `fields:` list, never widen the stream's contract.
    pub const fn pinned_fields(self) -> &'static [ExportField] {
        use ExportField as F;
        match self {
            // Aggregate: no records, so nothing structural to pin.
            ExportStream::Metrics => &[],
            // Per-request streams: the join key.
            ExportStream::Logs
            | ExportStream::Costs
            | ExportStream::Decisions
            | ExportStream::Identity
            | ExportStream::Prompts
            | ExportStream::Completions => &[F::CorrelationId],
            // A span tree is joined by its own ids, not by the request correlation id.
            ExportStream::Traces => &[F::TraceId, F::SpanId],
            // The chain: position, time, and the link to the previous record.
            ExportStream::Events => &[F::Seq, F::Ts, F::PrevHash],
        }
    }
}

/// One FIELD of one export record — the frozen field vocabulary the `fields:` projection key selects
/// from. Snake_case on the wire and in config (see [`ExportField::as_token`]).
///
/// A field name is shared across streams where it means the same thing (`correlation_id`, `ts`,
/// `pool`, `model`), which is what makes a single `fields:` list projectable across a sink's whole
/// subscription. Two spellings are deliberately NOT collapsed: `model_requested` and `model_served`
/// are separate fields because a failover or a router override means the caller did not get what
/// they asked for, and an auditor reconstructing an incident needs both — collapsing them destroys
/// that distinction permanently and silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportField {
    /// The join key across every per-request stream.
    CorrelationId,
    /// Record timestamp (epoch seconds).
    Ts,
    /// The ingress protocol the request arrived on.
    IngressProtocol,
    /// The pool that served the request.
    Pool,
    /// The model the CALLER asked for.
    ModelRequested,
    /// The model that actually SERVED the request (may differ after a failover/override).
    ModelServed,
    /// The upstream provider.
    Provider,
    /// The router's outcome classification.
    Outcome,
    /// The HTTP status returned to the caller.
    Status,
    /// End-to-end latency in milliseconds.
    LatencyMs,
    /// Trace id (span tree root identity).
    TraceId,
    /// Span id.
    SpanId,
    /// Parent span id (absent on a root span).
    ParentSpanId,
    /// Span name.
    Name,
    /// Span start.
    Start,
    /// Span duration in microseconds.
    DurationUs,
    /// Ingress, as a span attribute.
    Ingress,
    /// Operation, as a span attribute.
    Op,
    /// Lane, as a span attribute.
    Lane,
    /// The model, where a stream carries only one (costs/prompts/completions/traces).
    Model,
    /// Prompt tokens.
    TokensIn,
    /// Completion tokens.
    TokensOut,
    /// Spend, in cents.
    CostCents,
    /// The authenticated subject.
    Subject,
    /// The identity provider that authenticated the subject.
    IdentityProvider,
    /// The key id the request authenticated with.
    KeyId,
    /// The subject's groups.
    Groups,
    /// The routing candidates considered.
    Candidates,
    /// The excluded candidates AND the reason each was excluded.
    Excluded,
    /// The selected candidate.
    Selected,
    /// The failovers performed.
    Failovers,
    /// The hook verdicts (name, phase, verdict).
    Hooks,
    /// The event's position in the hash chain.
    Seq,
    /// The previous event's hash — the chain link.
    PrevHash,
    /// The event kind.
    Kind,
    /// The actor that caused the event.
    Actor,
    /// The resource the event acted on.
    Resource,
    /// The prompt messages (role + content).
    Messages,
    /// The completion content.
    Content,
    /// The completion finish reason.
    FinishReason,
}

impl ExportField {
    /// Every field in the frozen vocabulary — the ONE list every catalog walk iterates. Ordered to
    /// match the enum declaration so a field's index is stable (an index is used as a bit position
    /// by the engine's projection masks).
    pub const ALL: &'static [ExportField] = &[
        ExportField::CorrelationId,
        ExportField::Ts,
        ExportField::IngressProtocol,
        ExportField::Pool,
        ExportField::ModelRequested,
        ExportField::ModelServed,
        ExportField::Provider,
        ExportField::Outcome,
        ExportField::Status,
        ExportField::LatencyMs,
        ExportField::TraceId,
        ExportField::SpanId,
        ExportField::ParentSpanId,
        ExportField::Name,
        ExportField::Start,
        ExportField::DurationUs,
        ExportField::Ingress,
        ExportField::Op,
        ExportField::Lane,
        ExportField::Model,
        ExportField::TokensIn,
        ExportField::TokensOut,
        ExportField::CostCents,
        ExportField::Subject,
        ExportField::IdentityProvider,
        ExportField::KeyId,
        ExportField::Groups,
        ExportField::Candidates,
        ExportField::Excluded,
        ExportField::Selected,
        ExportField::Failovers,
        ExportField::Hooks,
        ExportField::Seq,
        ExportField::PrevHash,
        ExportField::Kind,
        ExportField::Actor,
        ExportField::Resource,
        ExportField::Messages,
        ExportField::Content,
        ExportField::FinishReason,
    ];

    /// The stable snake_case wire/config token for this field — the SAME spelling serde emits, and
    /// the SAME key the engine writes into a projected record.
    pub const fn as_token(self) -> &'static str {
        match self {
            ExportField::CorrelationId => "correlation_id",
            ExportField::Ts => "ts",
            ExportField::IngressProtocol => "ingress_protocol",
            ExportField::Pool => "pool",
            ExportField::ModelRequested => "model_requested",
            ExportField::ModelServed => "model_served",
            ExportField::Provider => "provider",
            ExportField::Outcome => "outcome",
            ExportField::Status => "status",
            ExportField::LatencyMs => "latency_ms",
            ExportField::TraceId => "trace_id",
            ExportField::SpanId => "span_id",
            ExportField::ParentSpanId => "parent_span_id",
            ExportField::Name => "name",
            ExportField::Start => "start",
            ExportField::DurationUs => "duration_us",
            ExportField::Ingress => "ingress",
            ExportField::Op => "op",
            ExportField::Lane => "lane",
            ExportField::Model => "model",
            ExportField::TokensIn => "tokens_in",
            ExportField::TokensOut => "tokens_out",
            ExportField::CostCents => "cost_cents",
            ExportField::Subject => "subject",
            ExportField::IdentityProvider => "identity_provider",
            ExportField::KeyId => "key_id",
            ExportField::Groups => "groups",
            ExportField::Candidates => "candidates",
            ExportField::Excluded => "excluded",
            ExportField::Selected => "selected",
            ExportField::Failovers => "failovers",
            ExportField::Hooks => "hooks",
            ExportField::Seq => "seq",
            ExportField::PrevHash => "prev_hash",
            ExportField::Kind => "kind",
            ExportField::Actor => "actor",
            ExportField::Resource => "resource",
            ExportField::Messages => "messages",
            ExportField::Content => "content",
            ExportField::FinishReason => "finish_reason",
        }
    }

    /// Parse a config/wire token into a field. `None` for anything not in the frozen vocabulary, so
    /// the caller emits its own named diagnostic.
    pub fn from_token(tok: &str) -> Option<ExportField> {
        ExportField::ALL
            .iter()
            .copied()
            .find(|f| f.as_token() == tok)
    }

    /// This field's stable BIT POSITION — its index in [`ExportField::ALL`]. The engine's projection
    /// mask is a bitset over these positions, the same shape `RequestedSignals` uses for hook
    /// signals; the position is derived from the frozen list, never hand-assigned.
    pub fn bit(self) -> u32 {
        ExportField::ALL
            .iter()
            .position(|f| *f == self)
            .expect("every field is in ExportField::ALL") as u32
    }
}

/// One metric FAMILY of the host recorder's snapshot (K9a S6): its name, its type, its help text,
/// and its samples in order — the unit a text exposition is made of.
///
/// STABLE AND LOSSLESS. `kind` is the exposition's own type token (`counter` | `gauge` |
/// `histogram` | `summary` | `untyped`); a histogram's `_bucket` / `_sum` / `_count` series and a
/// summary's `quantile` series are SAMPLES of their family, carried as the recorder wrote them. A
/// sample's value is the recorder's own spelling of the number, so rendering the snapshot back in
/// the text format reproduces the host's exposition byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricFamily {
    /// The family name, as its `# TYPE` line spells it.
    pub name: String,
    /// `counter` | `gauge` | `histogram` | `summary` | `untyped`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The `# HELP` text, when the recorder has one (as written: escaped, one line).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// The samples, in order.
    #[serde(default)]
    pub samples: Vec<MetricSample>,
}

/// One SAMPLE line of a [`MetricFamily`] (K9a S6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricSample {
    /// The series name — the family name, or it with `_bucket` / `_sum` / `_count`.
    pub name: String,
    /// The labels in order, each value as the exposition writes it (escaped), `le` / `quantile`
    /// included where the recorder wrote them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<(String, String)>,
    /// The value, in the recorder's own spelling.
    pub value: String,
}

/// The point of the configuration's VALIDATION a sink's `check` is asked at — so a
/// sink's lines land where the operator has always read them among the configuration's errors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckPhase {
    /// Among the operational limits' checks (a bound a sink's instances share).
    Limits,
    /// After the limits (each instance's own settings).
    #[default]
    Instances,
}

/// [`ScrapeFamily::kind`]: a counter.
pub const SCRAPE_KIND_COUNTER: u8 = 0;
/// [`ScrapeFamily::kind`]: a gauge.
pub const SCRAPE_KIND_GAUGE: u8 = 1;
/// [`ScrapeFamily::kind`]: a histogram (`_bucket`/`_sum`/`_count` legs as separate
/// [`ScrapeSample`]s).
pub const SCRAPE_KIND_HISTOGRAM: u8 = 2;
/// [`ScrapeFamily::kind`]: a summary (`quantile` legs as separate [`ScrapeSample`]s).
pub const SCRAPE_KIND_SUMMARY: u8 = 3;
/// [`ScrapeFamily::kind`]: untyped.
pub const SCRAPE_KIND_UNTYPED: u8 = 4;

/// One label on a [`ScrapeSample`]: a key AND its value, ARCHITECT review ruling (fresh-Opus
/// M3-SHAPES review, parity item) — a value-only array cannot carry a histogram's `le` or a
/// summary's `quantile` label, which is exactly what makes the 1.5.5 exposition losslessly
/// reproducible.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeLabel {
    /// The label key.
    pub key: AbiStr,
    /// The label value.
    pub value: AbiStr,
}

/// One sample of a [`ScrapeFamily`]'s snapshot: its own series name (a histogram's `_bucket`/
/// `_sum`/`_count` and a summary's `quantile` legs are each their own named series), its labels
/// and its value as the recorder's OWN STRING SPELLING (not `f64` — ARCHITECT review ruling:
/// re-rendering a re-parsed float would not reproduce the host's exposition byte for byte).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeSample {
    /// This sample's own series name (the family name, or the family name plus its `_bucket`/
    /// `_sum`/`_count` suffix).
    pub name: AbiStr,
    /// This sample's labels.
    pub labels: *const ScrapeLabel,
    /// How many.
    pub labels_len: usize,
    /// The recorder's own spelling of the value, unchanged.
    pub value: AbiStr,
}

/// One metric family of the host recorder's snapshot, handed to `scrape` so the sink can render
/// its own exposition.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeFamily {
    /// The family name.
    pub name: AbiStr,
    /// Its help text.
    pub help: AbiStr,
    /// Its unit; absent = none.
    pub unit: AbiStr,
    /// [`SCRAPE_KIND_COUNTER`] | [`SCRAPE_KIND_GAUGE`] | [`SCRAPE_KIND_HISTOGRAM`] |
    /// [`SCRAPE_KIND_SUMMARY`] | [`SCRAPE_KIND_UNTYPED`].
    pub kind: u8,
    /// Alignment padding.
    pub _reserved: [u8; 7],
    /// The samples, each carrying its own labels (ARCHITECT review ruling: labels moved onto the
    /// sample, not shared at the family level, so a histogram/summary series keeps its `le`/
    /// `quantile` label).
    pub samples: *const ScrapeSample,
    /// How many.
    pub samples_len: usize,
}

/// `scrape`'s `in`. ARCHITECT review ruling 2 (fresh-Opus M3-SHAPES review, 2026-09-28): the
/// rendered-exposition buffer is HOST-owned and lives here, in the `in` (request-path results are
/// host buffers, never a plugin-owned pointer in `out`; the host zeroes `out` before the call, so
/// nothing the plugin needs may live there).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeIn {
    /// The head.
    pub head: InHead,
    /// The host recorder's WHOLE snapshot (the SEH fix-forward ruling, 2026-09-27) — every
    /// family, not filtered to this instance's Statement — in the 1.5.5 recorder's render order,
    /// kind-then-name.
    pub families: *const ScrapeFamily,
    /// How many.
    pub families_len: usize,
    /// The host-owned buffer the plugin renders its exposition text into.
    pub buf: *mut u8,
    /// `buf`'s capacity, in bytes.
    pub cap: usize,
}

/// `scrape`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeOut {
    /// The head.
    pub head: OutHead,
    /// How many bytes the plugin wrote into [`ScrapeIn::buf`].
    pub written: usize,
    /// `0` unless `written == 0` because `buf` was too small: the byte length the plugin needed.
    /// The host re-invokes ONCE with a buffer at least this large.
    pub needed: usize,
}

/// `status`'s `out`. OFF-PATH: `status` is a plugin-owned result, memory class (iv) — live under
/// `head.lease` until `release(lease)` (ARCHITECT review ruling 3).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatusOut {
    /// The head.
    pub head: OutHead,
    /// The 1.5.5 status JSON, unchanged, as a [`super::mechanism::call::BLOB_JSON`] blob, under
    /// `head.lease` (off-path JSON-as-payload is allowed here per the mechanism's one JSON rule).
    pub status: Blob,
}

/// [`CheckIn::phase`]: among the operational limits' checks (a bound this sink's instances
/// share) — the OLD `CheckPhase::Limits`.
pub const CHECK_PHASE_LIMITS: u32 = 0;
/// [`CheckIn::phase`]: after the limits, each instance's own settings — the OLD
/// `CheckPhase::Instances` (the 1.5.5 default).
pub const CHECK_PHASE_INSTANCES: u32 = 1;

/// One instance `check` may read across, at [`CHECK_PHASE_INSTANCES`] (ARCHITECT review ruling,
/// fresh-Opus M3-SHAPES review, parity item: the OLD `Check{instances}` exists precisely for
/// checks that read across every instance of a sink's module, not only the one being called).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckInstance {
    /// The instance's name.
    pub name: AbiStr,
    /// The instance's settings blob.
    pub settings: Blob,
}

/// `check`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckIn {
    /// The head.
    pub head: InHead,
    /// [`CHECK_PHASE_LIMITS`] | [`CHECK_PHASE_INSTANCES`].
    pub phase: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// Every instance of this sink's module (meaningful mainly at
    /// [`CHECK_PHASE_INSTANCES`]).
    pub instances: *const CheckInstance,
    /// How many.
    pub instances_len: usize,
}

/// `check`'s `out`. OFF-PATH: `findings` is a plugin-owned result, memory class (iv) — live under
/// `head.lease` until `release(lease)` (ARCHITECT review ruling 3).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckOut {
    /// The head.
    pub head: OutHead,
    /// The sink's check findings, as a [`super::mechanism::call::BLOB_JSON`] blob, under
    /// `head.lease` (so they keep their place among the configuration's other errors, the 1.5.5
    /// `CheckPhase` ordering).
    pub findings: Blob,
}

/// `serve`'s `in`: one HTTP request dispatched to this sink's own routes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServeIn {
    /// The head.
    pub head: InHead,
    /// The HTTP method.
    pub method: AbiStr,
    /// The path, confined to `/metrics` or `/exports/<name>/*`.
    pub path: AbiStr,
    /// The raw query string; absent = none.
    pub query: AbiStr,
    /// Header name/value pairs, interleaved (`name`, `value`, `name`, `value`, …); capped at 64
    /// pairs (the 64-header cap).
    pub headers: *const AbiStr,
    /// How many `AbiStr` entries `headers` holds (twice the header count).
    pub headers_len: usize,
    /// The request body; absent = none.
    pub body: Blob,
}

/// `serve`'s `out`. OFF-PATH: the response is a plugin-owned result, memory class (iv) — the
/// headers and body live under `head.lease` until `release(lease)` (ARCHITECT review ruling 3).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServeOut {
    /// The head.
    pub head: OutHead,
    /// The HTTP status code.
    pub status_code: u16,
    /// Alignment padding.
    pub _reserved: [u8; 6],
    /// Response header name/value pairs, interleaved, under `head.lease` until `release(lease)`
    /// (an off-path list, memory class iv).
    pub headers_out: *const AbiStr,
    /// How many `AbiStr` entries `headers_out` holds.
    pub headers_out_len: usize,
    /// The response body, under `head.lease` until `release(lease)` (memory class iv).
    pub body: Blob,
}

/// [`Route::auth`]: no auth required before `serve` — OLD `RouteAuth::None`.
pub const ROUTE_AUTH_NONE: u32 = 0;
/// [`Route::auth`]: a data-plane key required before `serve` — OLD `RouteAuth::Key`.
pub const ROUTE_AUTH_KEY: u32 = 1;
/// [`Route::auth`]: admin auth required, reachable only on the admin listener — OLD
/// `RouteAuth::Admin`.
pub const ROUTE_AUTH_ADMIN: u32 = 2;

/// One HTTP route this instance serves via `serve` (ARCHITECT review ruling, fresh-Opus
/// M3-SHAPES review, parity item): `{path, method}` is the collision key the kernel checks at
/// load; `auth` is enforced by the kernel BEFORE `serve` is ever called.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// The path, confined to `/metrics` or `/exports/<name>/*`.
    pub path: AbiStr,
    /// The HTTP method.
    pub method: AbiStr,
    /// [`ROUTE_AUTH_NONE`] | [`ROUTE_AUTH_KEY`] | [`ROUTE_AUTH_ADMIN`].
    pub auth: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// The export kind's Statement tail: the streams this instance carries and the routes it serves.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Tail {
    /// The head.
    pub head: KindTailHead,
    /// This instance's declared streams, as [`ExportStream`] bytes.
    pub streams: *const u8,
    /// How many.
    pub streams_len: usize,
    /// The HTTP routes this instance serves via `serve` (ARCHITECT review ruling: 1.5.5 asked
    /// each instance at load, e.g. the `Routes` op; here it is a Statement fact).
    pub routes: *const Route,
    /// How many.
    pub routes_len: usize,
}

/// The export kind's [`super::mechanism::lifecycle::CancelOut::disposition`] vocabulary.
///
/// ASSUMPTION (M3-SHAPES): B.5 states no cancel disposition vocabulary. `deliver`, `scrape` and
/// `serve` are the `may_pend` ops; the dispositions below cover all three uniformly (a batch/
/// exposition/response either landed or did not — a telemetry sink has no partial-delivery
/// concept of its own, unlike a chunked streaming reply's own disposition vocabulary).
pub mod cancel {
    /// The pending op was aborted before it produced anything (deliver: the batch was not
    /// accepted; scrape/serve: no bytes were written to the host buffer).
    pub const ABORTED: u32 = 0;
    /// The op had already completed when the cancel arrived (a race with the deadline); its
    /// result stands.
    pub const RACED_TO_COMPLETION: u32 = 1;
}

// THE SDK's VIEW OF THE EXPORT TABLE (`abi::sdk::door`): each kind op's `in`/`out`, stated next to
// the table, so `plugin_door!` refuses an export plugin that wires a kind op to another op's
// structs. Every struct named here is plain data (integers, raw pointers, `AbiStr`/`Blob`, nested
// plain structs): every bit pattern is a valid value, which is what `AbiIn`/`AbiOut` promise.
//
// SAFETY (all below): `#[repr(C)]`, leading with `InHead`/`OutHead`, plain data only.
unsafe impl super::sdk::door::AbiIn for DeliverIn {}
unsafe impl super::sdk::door::AbiIn for ScrapeIn {}
unsafe impl super::sdk::door::AbiIn for CheckIn {}
unsafe impl super::sdk::door::AbiIn for ServeIn {}
unsafe impl super::sdk::door::AbiOut for ScrapeOut {}
unsafe impl super::sdk::door::AbiOut for StatusOut {}
unsafe impl super::sdk::door::AbiOut for CheckOut {}
unsafe impl super::sdk::door::AbiOut for ServeOut {}

super::sdk::door::slot_structs!(
    /// Each export kind op's `in`/`out` for [`plugin_door!`](crate::plugin_door), per [`Ops`]' docs.
    /// A plugin wiring a slot to another op's structs does not compile:
    ///
    /// ```compile_fail,E0271
    /// use busbar_contract::abi::export::{CheckIn, CheckOut, DeliverIn, ScrapeIn, ScrapeOut};
    /// use busbar_contract::abi::export::{ServeIn, ServeOut, StatusOut};
    /// use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    /// use busbar_contract::abi::mechanism::lifecycle::*;
    /// use busbar_contract::abi::sdk::door::Slot;
    /// # use std::ffi::c_void;
    /// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
    /// #     struct $n;
    /// #     impl Slot for $n { type In = $i; type Out = $o;
    /// #         fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
    /// # } }
    /// # ready!(V, ValidateIn, OutHead); ready!(Op_, OpenIn, OpenOut); ready!(Rf, RefreshIn, OutHead);
    /// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut); ready!(Dr, DriveIn, OutHead);
    /// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
    /// # ready!(Deliver, DeliverIn, OutHead); ready!(Status, InHead, StatusOut);
    /// # ready!(Check, CheckIn, CheckOut); ready!(Serve, ServeIn, ServeOut);
    /// ready!(Scrape, DeliverIn, OutHead); // `deliver`'s structs on `scrape`: refused
    /// busbar_contract::plugin_door! {
    ///     ops: busbar_contract::abi::export::Ops,
    ///     statement: busbar_contract::abi::sdk::door::statement("wrong", "0", 1),
    ///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
    ///                  cancel: Cn, release: Rl, close: Cl },
    ///     kind_ops: { deliver: Deliver, scrape: Scrape, status: Status, check: Check, serve: Serve },
    /// }
    /// # fn main() { let _ = door(); }
    /// ```
    ///
    /// With `Scrape` reading [`ScrapeIn`] and writing [`ScrapeOut`] the same plugin compiles
    /// (`abi/sdk/tests/door_tests.rs`, `an_export_plugin_wires_every_kind_op`).
    Ops {
        slot::DELIVER => DeliverIn, OutHead;
        slot::SCRAPE => ScrapeIn, ScrapeOut;
        slot::STATUS => InHead, StatusOut;
        slot::CHECK => CheckIn, CheckOut;
        slot::SERVE => ServeIn, ServeOut;
    }
);

#[cfg(test)]
#[path = "tests/stream_tests.rs"]
mod tests;
