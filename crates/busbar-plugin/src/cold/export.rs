// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **export** payload schema (kind = [`crate::cold::kind::EXPORT`]) that rides the kind-neutral `call`.
//!
//! ## One transport, every export op
//!
//! A `kind: export` plugin is a telemetry SINK behind the frozen six-symbol C ABI — the seam that
//! carries the engine's observability streams OUT to an external backend (the frozen vocabulary is
//! [`ExportStream`]). Like every other kind it exports the SAME six neutral symbols ([`crate::cold::symbol`]) at
//! `busbar_abi() == TRANSPORT_VERSION`; only its manifest `kind` and its own tiny request enum
//! ([`ExportRequest`]) distinguish it. Every op rides the ONE `busbar_call` as an op-discriminated
//! JSON envelope — the variant IS the op-code, so the C symbol set never grows.
//!
//! ## The ops
//!
//! - `streams` — asked ONCE at load: which observability streams does THIS instance carry? The
//!   engine retains the answer and only routes deliveries for streams the plugin declared.
//! - `deliver` — hand one already-serialized batch for a declared stream to the sink. The payload is
//!   carried as an opaque [`serde_json::Value`] the engine built; the export ABI adds the envelope,
//!   never a second copy of the batch semantics.
//! - `routes` / `http_endpoint` — the sink's HTTP surface (see [`crate::cold::endpoint`]).
//! - `status` — what the sink has to report when the host renders its exposition (additive).

use crate::cold::endpoint::{EndpointRequest, EndpointResponse, Route};
use serde::{Deserialize, Serialize};

/// The export-plugin PAYLOAD schema version (the signed manifest's `abi_version` for `kind: export`).
/// v1: the initial `streams`/`deliver` wire. v2 (1.5.3): the PROJECTION GRAMMAR — the [`ExportStream`]
/// vocabulary was expanded and the `audit` stream REMOVED (an auditor is a projection made of other
/// streams, not a data type), so a v1 sink that declared `audit` no longer has a stream to declare.
/// A REMOVED wire token is a breaking payload change, so the floor moves rather than accepting a
/// token the engine can no longer route. This is the per-kind PAYLOAD axis, NOT the transport axis
/// — an export plugin exports the SAME six neutral symbols ([`crate::cold::symbol`]) as every other kind, at
/// `busbar_abi() == TRANSPORT_VERSION`. Named the same way [`crate::cold::SECRET_ABI_VERSION`] and
/// [`crate::cold::hook::HOOK_ABI_VERSION`] are, so the loader floor and the SDK's declared version share one
/// const and cannot silently drift apart.
///
/// v2 -> v3 (1.6.0, DECISIONS #85 — THE OBSERVABILITY ENVELOPE): an export response is now
/// [`crate::cold::observe::Envelope`]`<ExportResponse>` — `{ result, metrics[], diagnostics[] }` —
/// instead of a bare `ExportResponse`. **This is the bump #85 called for and the only one it
/// required.**
///
/// WHY THIS KIND AND WHY ONLY THIS KIND, so nobody has to reconstruct the reasoning later:
///
/// * `export` is where the defect was. [`ExportResponse::Delivered`] is a UNIT variant and the cold
///   tier has no host-callback vtable, so a sink could not report the metrics it produced or the
///   diagnostics it raised — which is precisely what made the four `busbar-export-*` crates
///   unbuildable without losing operator-visible surfaces.
/// * It costs nothing to bump. There is no published export plugin, and `DynExport::deliver` has no
///   production caller, so widening this window refuses nobody and changes no shipped behaviour.
/// * The other four cold kinds do NOT move here, and not because the envelope is export-only — the
///   envelope TYPE and the host seam that folds it are kind-NEUTRAL and already carry every kind
///   (see `plugin-loader`'s `decode_response`, which is generic over the kind's response type). They
///   do not move because each carries a cost this change has no mandate to pay: the store's
///   `ABI_VERSION` is coupled to `plugin-loader`'s `STORE_ABI_WITH_NEW_OPS` (=5), so bumping 4->5
///   would silently switch every v5 store onto the eight neutral plane-record verbs — a behaviour
///   change disguised as a version bump; `hook` and `secret` have SINGLE-POINT supported windows
///   (`[N, N]`), so bumping either refuses every existing plugin of that kind unless the window is
///   widened to `[1, N]` in the same breath, and `hook` is a 1.6.0 FUNCTIONAL FIXED POINT whose
///   behaviour may not move at all. Adopting the envelope on each of those is a one-line change to
///   that kind's constant once those costs are accepted; it is not a redesign.
///
/// THE FLOOR STAYS AT 2. A sink built before the envelope answers a BARE `ExportResponse` and keeps
/// loading: the loader's decoder accepts both shapes and they are disjoint (every response variant
/// is externally tagged by its Rust variant name, and none of them is named `result`). That is the
/// same per-kind ADAPTER the store's usage-ledger ops already run on, not a permanent wire fork —
/// when this kind's floor rises past 3 the bare arm is dead code and is deleted.
pub const EXPORT_ABI_VERSION: u32 = 3;

/// The export ABI's MINOR — the count of ADDITIVE host seams on top of [`EXPORT_ABI_VERSION`].
///
/// THE POLICY. [`EXPORT_ABI_VERSION`] moves only on a BREAKING payload change (a removed or
/// renamed token, a re-tagged variant) and the loader refuses a manifest outside its supported
/// window. This minor moves on every ADDITIVE change to what a sink and the host may say to each
/// other — a new op, a new response variant, a new manifest declaration — and is never a refusal
/// reason in either direction: a sink built at an older minor answers `STATUS_UNSUPPORTED` to an op
/// it cannot decode (the host reads that as the op's documented "nothing to say" answer, the
/// `routes`/`status` precedent) and never states a declaration it does not know, and a host at an
/// older minor never asks the newer op. The same append-only discipline [`crate::ABI_MINOR`] holds
/// for the HOT lane's `repr(C)` structs, applied to this kind's JSON.
///
/// 0: `streams` / `deliver` / `routes` / `http_endpoint` / `status` (the v3 surface).
/// 1 (K9a S1): the FIRST-PARTY METRIC NAMESPACE — a manifest's `declares.metrics`
///   ([`crate::cold::observe::SeriesDecl`]).
/// 2 (K9a S2): the `validate` op ([`ExportRequest::Validate`] / [`ExportResponse::Validated`]).
/// 3 (K9a S3): PLUGIN DIAGNOSTICS — a manifest's `declares.diagnostics`
///   ([`crate::cold::observe::DiagnosticDecl`]).
/// 4 (K9a S4): the DESTINATION HANDLE — a manifest's `declares.destinations`, the host-executed
///   [`HostOp`]s a delivery may answer with ([`ExportResponse::Host`]), and the op that resumes it
///   with their [`HostResult`]s ([`ExportRequest::Resume`]).
/// 5 (K9a S5): the EGRESS CARRIER — [`HostOp::Http`] / [`HostResult::Http`]: the host performs a
///   sink's outbound HTTP request through its own egress.
pub const EXPORT_ABI_MINOR: u32 = 5;

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
/// `audit` is deliberately NOT here. It was a USE CASE masquerading as a data type: an auditor is a
/// SINK whose projection includes the right streams (`logs` + `identity` + `decisions` + `events` +
/// `costs`), which is strictly more expressive than one opaque `audit` firehose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportStream {
    /// Aggregate counters/gauges/histograms; no individual attribution. Lowest sensitivity.
    Metrics,
    /// The per-request operational record.
    Logs,
    /// The per-request span tree.
    Traces,
    /// Per-request tokens + spend.
    Costs,
    /// Per-request ROUTING PROVENANCE — candidates, exclusions and their reasons, the selection,
    /// failovers, hook verdicts. The stream that answers "why did this go THERE".
    Decisions,
    /// Engine lifecycle, hash-chained: admin mutations, config applies, plugin loads AND refusals,
    /// boot, shutdown. The only non-aggregate stream that is not per-request.
    Events,
    /// Per-request WHO — the pseudonymization switch: a sink without it gets the same records with
    /// nobody's name attached.
    Identity,
    /// Request content. Highest sensitivity.
    Prompts,
    /// Response content. Highest sensitivity.
    Completions,
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

/// An export operation, serialized as the `call` request payload. One self-describing enum keeps the
/// C ABI to a single `call` symbol; the `op` tag is the op-code. Serialized with the op as a JSON tag
/// so a plugin matches on it directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ExportRequest {
    /// `streams` — which [`ExportStream`]s does this instance carry? Asked once at load; the reply is
    /// [`ExportResponse::Streams`].
    Streams,
    /// `deliver` — hand one batch for `stream` to the sink. `payload` is the engine-built batch as an
    /// opaque JSON value. Reply: [`ExportResponse::Delivered`].
    Deliver {
        /// The declared stream this batch belongs to.
        stream: ExportStream,
        /// The already-serialized batch (opaque to the ABI; built by the engine).
        payload: serde_json::Value,
    },
    /// `routes` — asked ONCE at load: which HTTP [`Route`]s does this instance serve? The engine
    /// collision-checks + namespace-confines the answer, then mounts them (see the `endpoint`
    /// module doc). Reply: [`ExportResponse::Routes`]. ADDITIVE: an older sink that cannot decode this
    /// op declares no routes (the loader treats the undecodable-variant signal as "no HTTP surface").
    Routes,
    /// `http_endpoint` — dispatch one inbound HTTP request matched to a registered route of THIS
    /// plugin. Fires only for a matched plugin route, off the data-plane hot path; the engine already
    /// enforced the route's declared auth. Reply: [`ExportResponse::Endpoint`].
    ///
    /// `#[serde(rename = "http_endpoint")]` pins the wire op tag to its ORIGINAL spelling — the Rust
    /// identifier is neutralized (`Endpoint`, not `HttpEndpoint`) but the byte on the wire is
    /// unchanged, so no plugin (any language) sees a break.
    #[serde(rename = "http_endpoint")]
    Endpoint {
        /// The host-built inbound request (bounded headers, no raw `Authorization`).
        request: EndpointRequest,
    },
    /// `status` — asked by the host when it RENDERS its own exposition (a `/metrics` scrape): what
    /// does this sink have to report right now? The sink answers the metrics and diagnostics it
    /// observed since it last reported, and the host validates, bounds and folds them exactly as it
    /// folds the observability envelope (#85) — so a sink contributes to `/metrics` even between
    /// deliveries, the way a hook's `HookStatus.metrics` does. Reply: [`ExportResponse::Status`].
    ///
    /// ADDITIVE, and why that needs no [`EXPORT_ABI_VERSION`] bump: a sink built before this op
    /// cannot decode it and answers `STATUS_UNSUPPORTED`, which the host reads as "nothing to
    /// report" and keeps the sink loaded — the precedent is [`ExportRequest::Routes`].
    Status,
    /// `validate` — asked by the host while it VALIDATES the configuration (`--validate`, boot, a
    /// config apply): are `settings`, as the operator wrote them for the `instance` named, a
    /// configuration this sink accepts? Reply: [`ExportResponse::Validated`] — every problem, each
    /// a complete operator-facing line the host reports VERBATIM among the configuration's errors,
    /// so a sink's settings errors surface at the same moment and in the same words a built-in
    /// module's do (`export.<instance>.settings: …`).
    ///
    /// ADDITIVE (export ABI minor 2): a sink built before the op answers `STATUS_UNSUPPORTED`,
    /// which the host reads as "nothing to report" — its settings meet the sink at `open`, as they
    /// always did.
    Validate {
        /// The `export:` instance name the settings belong to (for the sink's own error lines).
        instance: String,
        /// The instance's `settings:` block exactly as configured.
        settings: serde_json::Value,
    },
    /// `resume` — the host performed the [`HostOp`]s a `deliver` (or an earlier `resume`) answered
    /// with ([`ExportResponse::Host`]), and hands back one [`HostResult`] per op, in order, under
    /// the `token` the sink chose. The sink answers as it would have answered the delivery —
    /// [`ExportResponse::Delivered`] — or with more ops (the host bounds the rounds).
    ///
    /// This is how a COLD sink has the host act for it without a host-callback vtable: the sink
    /// never opens a path or dials a socket, it ASKS, and the host executes under its own rules and
    /// reports what happened (export ABI minor 4). A sink that never answers `Host` never sees it.
    Resume {
        /// The token the sink's `Host` answer carried, echoed so a sink serving concurrent
        /// deliveries can tell whose ops these were.
        token: u64,
        /// One result per op, in the order the ops were asked.
        results: Vec<HostResult>,
    },
}

/// One act a sink asks the HOST to perform for it (K9a S4): the host executes it under its own
/// rules and hands the outcome back on [`ExportRequest::Resume`].
///
/// A DESTINATION is named by the settings key the sink's manifest declares
/// (`declares.destinations`): the host resolves the key against the OPERATOR's settings for the
/// instance and opens the path found there itself — so a sink can write only where the operator's
/// configuration pointed a declared destination, and never names a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HostOp {
    /// Append `data` to the destination (opened for append, created if absent, per write — the
    /// file an external rotator moved is not written through a stale handle). When `rotate_at` is
    /// set and the destination already holds at least that many bytes, the host rotates it first
    /// (as [`HostOp::Rotate`] with `keep`), under the same per-destination lock as the write.
    Write {
        /// The declared destination (a settings key).
        destination: String,
        /// The bytes to append, as UTF-8.
        data: String,
        /// Rotate first when the destination holds at least this many bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rotate_at: Option<u64>,
        /// Archives a rotation keeps (`<path>.1` … `<path>.<keep>`).
        #[serde(default = "default_keep")]
        keep: u32,
    },
    /// Rotate the destination by rename: drop `<path>.<keep>`, shift `<path>.<i>` to
    /// `<path>.<i+1>`, then rename `<path>` to `<path>.1`. A failed step is reported, never
    /// escalated into truncating the live file.
    Rotate {
        /// The declared destination (a settings key).
        destination: String,
        /// Archives kept.
        #[serde(default = "default_keep")]
        keep: u32,
    },
    /// Flush the destination to stable storage.
    Flush {
        /// The declared destination (a settings key).
        destination: String,
    },
    /// Perform one outbound HTTP request through the HOST's egress (K9a S5) — its URL policy (the
    /// SSRF and cloud-metadata refusal), its TLS, its timeouts. The sink never dials; a request the
    /// policy refuses is a [`HostResult::Failed`] with step `refused`.
    Http(HttpRequest),
}

/// An outbound HTTP request a sink asks the host to carry (K9a S5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// The method, e.g. `POST`.
    pub method: String,
    /// The target URL.
    pub url: String,
    /// Request headers, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    /// The request body, as UTF-8.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
    /// The end-to-end deadline in milliseconds; `0` is the host's default ceiling.
    #[serde(default)]
    pub timeout_ms: u64,
}

/// What the far end answered a carried [`HttpRequest`] (K9a S5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// The response status.
    pub status: u16,
    /// The response body as UTF-8 (lossy), read up to the host's cap.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
}

fn default_keep() -> u32 {
    9
}

/// What the host did with one [`HostOp`] (K9a S4), handed back in order on
/// [`ExportRequest::Resume`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum HostResult {
    /// The op completed. `rotation` is present when a rotation ran as part of it.
    Done {
        /// The rotation that ran first, if one did.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rotation: Option<Rotation>,
    },
    /// The far end answered a carried [`HostOp::Http`].
    Http(HttpResponse),
    /// The op did not complete: `step` names which host act failed (`destination` — no such
    /// destination was granted; `open`; `append`; `flush`; `refused` — the host's egress policy
    /// refused the request, or this host carries none; `request` — the request failed in flight),
    /// `error` says why.
    Failed {
        /// The host act that failed.
        step: String,
        /// Why, in the host's words.
        error: String,
        /// The rotation that ran before the failure, if one did.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rotation: Option<Rotation>,
    },
}

/// What a rotation did (K9a S4): where the live file went, whether that rename happened, and every
/// step that failed on the way — so a sink reports each the way it chooses, and nothing is lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rotation {
    /// `<path>.1` — where the live file was renamed to.
    pub archive: String,
    /// Whether the live file was renamed (false: the host keeps APPENDING to it rather than
    /// truncating recorded data).
    pub renamed: bool,
    /// Every failed step, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub faults: Vec<RotationFault>,
}

/// One failed step of a [`Rotation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationFault {
    /// `retention` (dropping the oldest archive) | `shift` (moving an archive up) | `rename` (the
    /// live file to `<path>.1`).
    pub step: String,
    /// The file the step acted on.
    pub from: String,
    /// Where it was going, for `shift` and `rename`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Why it failed.
    pub error: String,
}

/// The success payload for an export `call`, matched to the request variant. A module-level FAILURE (a
/// sink that genuinely errored) rides `STATUS_ERR` with a UTF-8 message, NOT here.
///
/// UNLIKE [`ExportRequest`] (`op`-tagged, snake_case), this type carries NO `#[serde(...)]` attribute,
/// so it serializes with serde's default externally-tagged representation — the SAME asymmetry
/// [`crate::cold::hook::HookReply`] carries and for the same reason: this is JSON over the frozen C-ABI
/// transport, so a tagging change is a wire-breaking change, not a cosmetic one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportResponse {
    /// `streams` — the streams this instance carries.
    Streams(Vec<ExportStream>),
    /// `deliver` — the batch was accepted by the sink (nothing to read back).
    Delivered,
    /// `routes` — the HTTP routes this instance serves (collected once at load).
    Routes(Vec<Route>),
    /// `http_endpoint` — the plugin's response to a dispatched inbound request, relayed verbatim.
    ///
    /// `#[serde(rename = "Http")]` pins the externally-tagged wire key to its ORIGINAL spelling (this
    /// type carries no `#[serde(...)]` container attribute, so the default tag is the bare variant
    /// name — renaming the Rust identifier to `Endpoint` would otherwise flip the wire key from
    /// `"Http"` to `"Endpoint"`).
    #[serde(rename = "Http")]
    Endpoint(EndpointResponse),
    /// `status` — what the sink observed since it last reported, in the observability envelope's
    /// own entry shapes (`busbar_plugin::cold::observe::PluginMetric` /
    /// `PluginDiagnostic` as JSON values), so the host runs them through the SAME validator and fold
    /// it runs the envelope's arrays through. Either list may be empty or absent on the wire.
    Status {
        /// Metric entries (validated, bounded and folded by the host; never trusted as-is).
        #[serde(default)]
        metrics: Vec<serde_json::Value>,
        /// Diagnostic entries (a code the host's catalogue does not hold is dropped by the host).
        #[serde(default)]
        diagnostics: Vec<serde_json::Value>,
    },
    /// `validate` — every problem with the settings, one complete operator-facing line each;
    /// empty when the sink accepts them.
    Validated(Vec<String>),
    /// `deliver` / `resume` — the sink needs the host to act first: perform `ops` in order, then
    /// [`ExportRequest::Resume`] with `token` and their results.
    Host {
        /// The sink's own correlation token, echoed on the resume.
        token: u64,
        /// The acts, in order.
        ops: Vec<HostOp>,
    },
}

#[cfg(test)]
#[path = "tests/export_tests.rs"]
mod tests;
