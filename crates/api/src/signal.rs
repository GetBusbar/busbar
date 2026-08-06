// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The "decision observability" signal CATALOG: a single, append-only
//! enumeration of every observable busbar can produce about a request/decision/outcome, plus the
//! compact wire value type and bag it rides the hook projections in. Lives here (`busbar-api`) —
//! not a new crate — because `busbar-plugin-sdk` (a hook-plugin author's actual dependency) and
//! `busbar-plugin-abi` both already depend on `busbar-api` directly, so both re-export [`Signal`]
//! wholesale (see `busbar_plugin_abi::signal` / `busbar_plugin_sdk`); a plugin author never needs
//! a raw `busbar-api` dependency to reference `Signal::CandidateBreakerState` at compile time.
//! Placing the catalog in the SAME crate as [`crate::RoutingRequest`]/[`crate::Candidate`] also
//! lets those projections carry a `signals` field directly, with no cross-crate cycle (`busbar-
//! plugin-abi` depends on `busbar-api`, not the other way around — a dependency the catalog must
//! not invert).
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
/// that lives in busbar core (`busbar::proxy::signals`) — never here, since a compute fn reads
/// engine-internal state (`&dyn Store`, the pristine ingress body) this crate does not have.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    // ── Request phase (available from the pristine ingress body, pre-forward) ──────────────────
    /// The model the caller asked for. Catalog form of the RESERVED `RoutingRequest::requested_model`
    /// core field — still projected as a core field today (this design does not migrate any
    /// existing core field, see the module doc); listed here so a future outcome/log consumer can
    /// declare it without a struct change.
    RequestedModel,
    /// Total prompt chars (system + every turn). Catalog form of `RoutingRequest::total_chars` —
    /// still a CORE field today; listed for completeness (a consumer that gets the request
    /// projection some OTHER way, e.g. the request-log preset, can still ask for it by name).
    RequestTotalChars,
    /// Conversation-turn count. Catalog form of `RoutingRequest::message_count` (still CORE today).
    RequestMessageCount,
    /// Tool-definition count. Catalog form of the RESERVED `RoutingRequest::tool_count` core field.
    RequestToolCount,
    /// System-prompt-only chars. Catalog form of the RESERVED `RoutingRequest::system_chars` field.
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
    U64(u64),
    I64(i64),
    F64(f64),
    Str(Cow<'static, str>),
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

/// The inline-capacity-4 backing store: the common case (0-4 signals declared for a given
/// projection) never spills to the heap. `4` covers every signal this catalog currently wires for
/// a single phase with room to spare; growing the catalog past 4 declared-at-once entries for one
/// projection only costs a heap spill, never a contract change.
type SignalBagInner = smallvec::SmallVec<[(Signal, SignalValue); 4]>;

/// The signal bag a projection (`RoutingRequest`, `Candidate`, and — once the response-phase seam
/// lands — the response tap payload) carries. `#[serde(flatten)]`-compatible: [`SignalBag`]
/// implements [`Serialize`] as a MAP keyed by [`Signal::name`], so on the wire its entries render
/// as flat top-level keys alongside the projection's own fields (`{"breaker_state": ...}` sits next
/// to `request_id`, not nested under a `signals` key) — and an EMPTY bag serializes as zero
/// additional keys, i.e. `#[serde(flatten)]` on an empty bag is byte-identical to the field not
/// existing at all. Default (no signals declared anywhere) never allocates: `SmallVec::new()` is a
/// stack-only empty state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SignalBag(SignalBagInner);

impl SignalBag {
    /// An empty bag — the zero-cost default every projection starts from.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Insert one signal's computed value. The caller is responsible for only calling this behind
    /// a `requested.wants(signal)` gate (see `busbar::hooks::RequestedSignals`) — the bag itself
    /// does not enforce that; it is a plain container.
    pub fn push(&mut self, signal: Signal, value: SignalValue) {
        self.0.push((signal, value));
    }

    /// Read back a previously-pushed value (test/debug convenience; the wire never round-trips
    /// through this — it serializes straight from `iter`).
    pub fn get(&self, signal: Signal) -> Option<&SignalValue> {
        self.0.iter().find(|(s, _)| *s == signal).map(|(_, v)| v)
    }

    pub fn iter(&self) -> impl Iterator<Item = &(Signal, SignalValue)> {
        self.0.iter()
    }

    /// Whether the bag has spilled its inline `SmallVec` capacity onto the heap. Test/proof aid
    /// for the "the default (nothing declared) path never allocates" guarantee: an empty or
    /// small (≤4) bag is always `false`.
    pub fn spilled(&self) -> bool {
        self.0.spilled()
    }
}

impl Serialize for SignalBag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (signal, value) in &self.0 {
            map.serialize_entry(signal.name(), value)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Signal::ALL` must list every variant exactly once, and `Signal::name`'s hand-written match
    /// must agree with the `#[serde(rename_all = "snake_case")]` derive — the exhaustiveness guard
    /// for this append-only catalog (mirrors the codebase's `KNOWN_PROTOCOLS` pattern).
    #[test]
    fn all_lists_every_variant_and_name_matches_serde() {
        for &s in Signal::ALL {
            let derived = serde_json::to_value(s).unwrap();
            assert_eq!(derived, serde_json::Value::String(s.name().to_string()));
        }
        // Round-trips through the derive too (config declaration parses these exact strings).
        for &s in Signal::ALL {
            let parsed: Signal = serde_json::from_value(serde_json::json!(s.name())).unwrap();
            assert_eq!(parsed, s);
        }
        // Bit positions are dense and unique (0..ALL.len()).
        let mut bits: Vec<u32> = Signal::ALL.iter().map(|s| s.bit()).collect();
        bits.sort_unstable();
        bits.dedup();
        assert_eq!(bits.len(), Signal::ALL.len());
        assert_eq!(bits, (0..Signal::ALL.len() as u32).collect::<Vec<_>>());
    }

    /// An empty bag flattens to zero keys — the "declared nothing" wire delta is truly zero.
    #[test]
    fn empty_bag_serializes_as_empty_map() {
        let bag = SignalBag::new();
        let v = serde_json::to_value(&bag).unwrap();
        assert_eq!(v, serde_json::json!({}));
        assert!(bag.is_empty());
    }

    /// A populated bag serializes each entry under its stable name, scalar-typed.
    #[test]
    fn populated_bag_serializes_flat_scalars() {
        let mut bag = SignalBag::new();
        bag.push(
            Signal::CandidateBreakerState,
            SignalValue::Str(Cow::Borrowed("closed")),
        );
        bag.push(Signal::CandidateErrorRate, SignalValue::F64(0.125));
        let v = serde_json::to_value(&bag).unwrap();
        assert_eq!(v["candidate_breaker_state"], "closed");
        assert_eq!(v["candidate_error_rate"], 0.125);
        assert_eq!(bag.len(), 2);
    }
}
