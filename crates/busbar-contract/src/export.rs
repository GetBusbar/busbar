//! The `kind: export` WIRE FACE — what an export-sink plugin implements, and the frozen vocabulary
//! its trait names, both moved to the one crate a plugin manifest may name
//! (`docs/design/1.6.0-one-face-per-kind.md` section 2). MOVED BY IDENTITY out of two homes:
//! `ExportStream`/`ExportField` out of `busbar_plugin::cold::export` (which keeps the envelope —
//! `EXPORT_ABI_VERSION`, `ExportRequest`, `ExportResponse` — and re-exports both types at the path
//! it has always published them under), and `ExportHandler` out of the plugin tooling's SDK crate
//! (which keeps the C glue and the op-dispatch match and re-exports the trait the same way).
//!
//! `kinds::Export` (this crate's `kinds` module) is the KIND FACE — what core, the root and the
//! units name. This is the WIRE FACE — what a plugin authors against.

use crate::http_endpoint::{HttpEndpointRequest, HttpEndpointResponse, Route};
use serde::{Deserialize, Serialize};

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

/// The sync contract a `kind: export` plugin author implements. [`streams`](ExportHandler::streams)
/// declares which observability streams THIS instance carries (asked once at load); `deliver` hands
/// one already-serialized batch for a declared stream to the sink and has a DEFAULT no-op, so a trivial
/// sink implements only `streams`.
pub trait ExportHandler: Send + Sync {
    /// The [`ExportStream`]s this instance carries. Asked once at load; the engine only routes
    /// deliveries for streams named here.
    fn streams(&self) -> Vec<ExportStream>;
    /// Accept one batch for `stream`. `payload` is the engine-built batch as an opaque JSON value.
    /// Default: no-op (a sink that reports streams but drops batches).
    fn deliver(&self, _stream: ExportStream, _payload: &serde_json::Value) {}
    /// The HTTP [`Route`]s this instance serves — its OWN compiled-in declarations, collected once at
    /// load (a metrics sink declares `GET /metrics`). Default: none (a push-only sink has no HTTP
    /// surface). The engine collision-checks + namespace-confines these before mounting.
    fn routes(&self) -> Vec<Route> {
        Vec::new()
    }
    /// Serve one inbound HTTP request matched to a declared route. Fires only for a matched route (the
    /// engine already enforced the route's auth). Default: `404` — the fallback for a sink that
    /// declared no routes / a partial impl.
    fn handle_http(&self, _req: &HttpEndpointRequest) -> HttpEndpointResponse {
        HttpEndpointResponse {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}
