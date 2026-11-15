//! The frozen export-stream vocabulary: [`ExportStream`], its wire tokens and its default field sets.
//!
//! Moved out of `abi::export` (WBS W0-D1A) so the stream vocabulary has one home; the export kind
//! and every consumer name it from here.

use crate::abi::export::ExportField;
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
    /// Request and response content as chunked lines, one stream (IF r33 section 49). Highest
    /// sensitivity. 7 and 8 stay reserved for `prompts` and `completions`, which are never produced.
    /// No producer exists in 1.6.0, so a `content` subscription is refused at config load.
    Content = 9,
}

impl ExportStream {
    /// Every stream in the frozen vocabulary, in ascending sensitivity order — the ONE list every
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
        ExportStream::Content,
    ];

    /// The stable snake_case wire/config token for this stream — the SAME spelling serde emits.
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
            ExportStream::Content => "content",
        }
    }

    /// Parse a config/wire token into a stream. `None` for anything not in the frozen vocabulary —
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
            ExportStream::Content => &[
                F::CorrelationId,
                F::Ts,
                F::DeploymentId,
                F::NodeId,
                F::ContentRef,
            ],
        }
    }

    /// The STRUCTURAL fields of this stream — the ones a `fields:` override may NOT remove.
    pub const fn pinned_fields(self) -> &'static [ExportField] {
        use ExportField as F;
        match self {
            ExportStream::Metrics => &[],

            ExportStream::Logs
            | ExportStream::Costs
            | ExportStream::Decisions
            | ExportStream::Identity
            | ExportStream::Prompts
            | ExportStream::Completions => &[F::CorrelationId],

            ExportStream::Traces => &[F::TraceId, F::SpanId],

            ExportStream::Events => &[F::Seq, F::Ts, F::PrevHash],

            ExportStream::Content => &[F::CorrelationId, F::DeploymentId, F::NodeId],
        }
    }
}
