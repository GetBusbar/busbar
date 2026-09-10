// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The "decision observability" signal CATALOG: a single, append-only
//! enumeration of every observable busbar can produce about a request/decision/outcome, plus the
//! compact wire value type and bag it rides the hook projections in. It is part of the hooks-kind
//! FACE of this contract: it sits in the same crate as [`crate::RoutingRequest`]/
//! [`crate::Candidate`] so those projections carry a `signals` field directly, and a hook-plugin
//! author reaches `Signal::CandidateBreakerState` through the same contract every other plugin
//! is written against.
//!
//! ADDITIVE BY CONSTRUCTION: [`Signal`] is `#[non_exhaustive]` (a new variant never breaks an
//! exhaustive `match` in an out-of-tree consumer — there can be none, since the type forbids one),
//! and every projection's `signals` bag is OMITTED from the wire entirely when no consumer
//! declared anything (see `busbar::hooks::wire`'s `#[serde(flatten)]` field) — a busbar binary
//! that ships a new catalog entry changes nothing for a hook that never asked for it.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// One entry per observable busbar can produce about a request, organized by the PHASE it is
/// available at (the doc-comment groups below — Request / Candidate / Routing / Response — mirror
/// the decision-observability phase vocabulary; the underlying wire `HookStage` enum keeps its
/// existing `Request|Route|Attempt|Completion` variant names unchanged, see
/// `crate::hooks`/`busbar::config::HookStage`'s own doc comment).
///
/// Append-only: adding a variant is a strictly additive change to every consumer — an old wire
/// payload that never named the new entry is unaffected, and a hook binary that doesn't reference
/// it needs no recompile. `#[non_exhaustive]` so no downstream `match` can be exhaustive over this
/// type (a new variant can never be a downstream compile break).
///
/// Each variant is a pure enumeration KEY, not a payload: its wire name comes from [`Signal::name`]
/// (a fixed string table, never a `Display`/`Debug` derive, so the wire name is stable independent
/// of Rust enum internals/renames) and its VALUE is produced by a phase-specific compute function
/// that lives in the engine (`busbar::proxy::signals`) — never here, since a compute fn reads
/// engine-internal state (`&dyn Store`, the pristine ingress body) this crate does not have.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    // ── Request phase (available from the pristine ingress body, pre-forward) ──────────────────
    /// The model the caller asked for. THE ONLY form: the `RoutingRequest::requested_model` core
    /// field this entry was the catalog twin of is gone — it was projected by no transport, so it
    /// was a member no hook could ever read, and a reserved member with no reader is a promise the
    /// wire never kept. Declaring this entry is how a consumer asks for the value, and the day a
    /// request-phase compute fn is wired to the neutral gate seam the subject the PLANE names
    /// (`Plane::hook_subject`) is what fills it.
    RequestedModel,
    /// Total prompt chars (system + every turn). Catalog form of `RoutingRequest::total_chars` —
    /// still a CORE field today; listed for completeness (a consumer that gets the request
    /// projection some OTHER way, e.g. the request-log preset, can still ask for it by name).
    RequestTotalChars,
    /// Conversation-turn count. Catalog form of `RoutingRequest::message_count` (still CORE today).
    RequestMessageCount,
    /// Tool-definition count. THE ONLY form, for the same reason as [`Signal::RequestedModel`]: the
    /// reserved core field it was the twin of had no reader on any transport and is gone.
    RequestToolCount,
    /// System-prompt-only chars. THE ONLY form, on the same reasoning; `has_tools` and `total_chars`
    /// stay core fields because the wire does project those.
    RequestSystemChars,

    // ── Candidate phase (per-candidate, read from already-maintained store state) ───────────────
    /// The circuit breaker's current FSM state for this candidate lane in this pool
    /// (`closed`/`open`/`half_open`) — a PURE projection of an already-maintained atomic (no new
    /// tracking; see `busbar::store::LaneRuntime::breaker_state_snapshot_in`). O(1), always
    /// computable when declared.
    CandidateBreakerState,
    /// This candidate lane's recent error rate (errors / total outcomes) over the breaker's
    /// existing sliding outcome window — the SAME window the breaker trip decision already
    /// consults (`busbar::store::in_memory::breaker::OutcomeWindow`), so this is a projection of
    /// already-tracked state, not new collection. `None`-shaped (absent from the wire) when the
    /// lane has served no outcomes in the window yet.
    CandidateErrorRate,
    /// p95 end-to-end latency for this candidate lane. DEFERRED: no bounded sketch/reservoir
    /// exists in the store today, and collection must be gated the same way the projection is —
    /// an always-on reservoir is a cost every deployment would pay whether or not any consumer
    /// declared this signal. The variant is reserved in the catalog (declarable today, so a
    /// future collector need not touch the wire contract) but its compute fn does not exist yet —
    /// TODO(latency-p95): wire a maintained reservoir once its own always-on collection cost is
    /// independently justified, then implement the compute fn and remove this doc note.
    CandidateLatencyP95Ms,

    // ── Routing phase (known once the policy has decided) ───────────────────────────────────────
    /// The resolved policy's stable name (`policy.name()` — already a `&'static str` in hand at
    /// decision time; free to project). Reserved for the request-log/decision-observability
    /// consumer, which is not wired yet.
    RoutingPolicy,

    // ── Response phase (known once the upstream response completes) ────────────────────────────
    /// Output token count. DEFERRED wiring: the outcome-signal plumbing (`OutcomeInputs`, the
    /// response/completion-tap outcome slice) is a separate, larger seam that does not exist
    /// yet — the variant is reserved in the catalog so a future response-phase consumer can
    /// declare it without a wire change, but no compute fn exists yet. TODO(outcome-signals):
    /// wire once the response tap's `OutcomeInputs` seam lands.
    ResponseTokensOut,
}

impl Signal {
    /// Every catalog entry, in declaration order — the source of truth an exhaustiveness test
    /// checks [`Signal::name`] against (mirrors the `KNOWN_PROTOCOLS`-driven exhaustiveness
    /// pattern already used elsewhere in the codebase for a similarly append-only vocabulary).
    pub const ALL: &'static [Signal] = &[
        Signal::RequestedModel,
        Signal::RequestTotalChars,
        Signal::RequestMessageCount,
        Signal::RequestToolCount,
        Signal::RequestSystemChars,
        Signal::CandidateBreakerState,
        Signal::CandidateErrorRate,
        Signal::CandidateLatencyP95Ms,
        Signal::RoutingPolicy,
        Signal::ResponseTokensOut,
    ];

    /// The stable wire/config key for this signal — snake_case, matching the `#[serde(rename_all =
    /// "snake_case")]` derive above exactly (pinned by a same-crate test), so a hand-written match
    /// arm can never silently drift from the derived (de)serialization.
    pub fn name(self) -> &'static str {
        match self {
            Signal::RequestedModel => "requested_model",
            Signal::RequestTotalChars => "request_total_chars",
            Signal::RequestMessageCount => "request_message_count",
            Signal::RequestToolCount => "request_tool_count",
            Signal::RequestSystemChars => "request_system_chars",
            Signal::CandidateBreakerState => "candidate_breaker_state",
            Signal::CandidateErrorRate => "candidate_error_rate",
            Signal::CandidateLatencyP95Ms => "candidate_latency_p95_ms",
            Signal::RoutingPolicy => "routing_policy",
            Signal::ResponseTokensOut => "response_tokens_out",
        }
    }

    /// A dense, stable bit position for this signal — the `RequestedSignals` bitmask's index.
    /// Ordinal into [`Signal::ALL`], NOT the enum's discriminant (keeps the bitmask stable even if
    /// a future variant is inserted between existing ones rather than only appended, as long as
    /// `ALL` is updated in the same change — checked by a same-crate test).
    pub fn bit(self) -> u32 {
        Self::ALL
            .iter()
            .position(|s| *s == self)
            .expect("Signal::ALL must list every variant") as u32
    }
}

/// A compact, closed scalar wire value — deliberately NOT `serde_json::Value`: a `Value` admits
/// nested objects/arrays, which would let a compute fn accidentally emit an unbounded structure
/// onto the hot decide/tap path. Every variant here is O(1) to construct. `Str` is a `Cow<'static,
/// str>` so the common case (a fixed label like a breaker-state name) allocates nothing.
#[derive(Debug, Clone, PartialEq)]
pub enum SignalValue {
    /// An unsigned counter or size.
    U64(u64),
    /// A signed quantity.
    I64(i64),
    /// A measured ratio or rate.
    F64(f64),
    /// A label; a fixed name allocates nothing.
    Str(Cow<'static, str>),
    /// A flag.
    Bool(bool),
}

impl Serialize for SignalValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SignalValue::U64(v) => serializer.serialize_u64(*v),
            SignalValue::I64(v) => serializer.serialize_i64(*v),
            SignalValue::F64(v) => serializer.serialize_f64(*v),
            SignalValue::Str(v) => serializer.serialize_str(v),
            SignalValue::Bool(v) => serializer.serialize_bool(*v),
        }
    }
}

/// The backing store: a fixed-capacity list with ONE slot per catalog entry. The bag UPSERTS — a
/// signal recorded twice replaces its value rather than appearing twice — so it can never hold more
/// entries than the catalog has names, and the bound the design states (one value per declared
/// signal) is a bound the type carries rather than an inline-capacity guess (`4`, once) that a fifth
/// declared signal quietly spilled past. Growing the catalog grows the capacity with it.
type SignalBagInner = crate::bounded::BoundedVec<(Signal, SignalValue), { Signal::ALL.len() }>;

/// The signal bag a projection (`RoutingRequest`, `Candidate`, and — once the response-phase seam
/// lands — the response tap payload) carries. `#[serde(flatten)]`-compatible: [`SignalBag`]
/// implements [`Serialize`] as a MAP keyed by [`Signal::name`], so on the wire its entries render
/// as flat top-level keys alongside the projection's own fields (`{"breaker_state": ...}` sits next
/// to `request_id`, not nested under a `signals` key) — and an EMPTY bag serializes as zero
/// additional keys, i.e. `#[serde(flatten)]` on an empty bag is byte-identical to the field not
/// existing at all. Default (no signals declared anywhere) never allocates: the list reserves at
/// the first upsert and never before.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SignalBag(SignalBagInner);

impl SignalBag {
    /// An empty bag — the zero-cost default every projection starts from.
    /// An empty bag; allocates nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many signals have been recorded.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Record one signal's computed value, REPLACING the value already recorded for the same
    /// signal if there is one — a bag holds at most one value per catalog entry, which is why it
    /// can never be full when a NEW signal arrives. The caller is responsible for only calling this
    /// behind a `requested.wants(signal)` gate (see `busbar::hooks::RequestedSignals`) — the bag
    /// itself does not enforce that; it is a plain container.
    pub fn upsert(&mut self, signal: Signal, value: SignalValue) {
        let mut value = Some(value);
        if self.get(signal).is_some() {
            // The replace path rebuilds in first-recorded order: the bounded list hands out no
            // mutable view of its items, by design, and a signal recorded twice is the rare case.
            let mut next = SignalBagInner::new();
            for (s, v) in std::mem::take(&mut self.0) {
                let v = value.take_if(|_| s == signal).unwrap_or(v);
                let _ = next.push((s, v));
            }
            self.0 = next;
        }
        // One slot per catalog entry and no duplicates: the list is full only when every signal
        // in the catalog is present, and then the branch above has already taken the value.
        let _ = value.map(|v| self.0.push((signal, v)));
    }

    /// Read back a previously-recorded value (test/debug convenience; the wire never round-trips
    /// through this — it serializes straight from `iter`).
    pub fn get(&self, signal: Signal) -> Option<&SignalValue> {
        self.iter().find(|(s, _)| *s == signal).map(|(_, v)| v)
    }

    /// The recorded signals, in first-recorded order — the wire serializes straight from this.
    pub fn iter(&self) -> impl Iterator<Item = &(Signal, SignalValue)> {
        self.0.as_slice().iter()
    }
}

impl Serialize for SignalBag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (signal, value) in self.iter() {
            map.serialize_entry(signal.name(), value)?;
        }
        map.end()
    }
}
