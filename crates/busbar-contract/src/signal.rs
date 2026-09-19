//! The routing SIGNAL catalog, value, and bounded bag (`1.6.0-hook-plugin.md` section 5 / Appendix A.7).
//!
//! An append-only catalog of observables a hook may declare an interest in, a compact closed scalar
//! value, and a bounded, FAIL-CLOSED, no-duplicate bag that carries them. The bag never silently
//! spills: exceeding its inline capacity is a real error in EVERY build (release included), which the
//! compute-gate seam routes through the pool's `on_error` disposition. Home is here in
//! `busbar-contract`, inside the dep-wall, so a plugin's `upsert` calls name only contract vocab.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// One append-only catalog entry per observable.
///
/// `#[non_exhaustive]` so a new variant is never a downstream compile break. The wire name comes from
/// [`Signal::name`] (a fixed snake_case table), and the bit position from [`Signal::ALL`] order.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    /// The model the request asked for.
    RequestedModel,
    /// Σ text-block chars in the request (system + messages).
    RequestTotalChars,
    /// The number of messages in the request.
    RequestMessageCount,
    /// The number of tools declared on the request.
    RequestToolCount,
    /// The system-preamble char count.
    RequestSystemChars,
    /// A candidate's circuit-breaker state.
    CandidateBreakerState,
    /// A candidate's observed error rate.
    CandidateErrorRate,
    /// A candidate's p95 end-to-end latency, in milliseconds.
    CandidateLatencyP95Ms,
    /// The routing policy/transport name that decided.
    RoutingPolicy,
    /// The tokens emitted on the response.
    ResponseTokensOut,
}

impl Signal {
    /// Every catalog entry, in declaration order (the order that fixes each signal's [`bit`](Signal::bit)).
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

    /// The fixed snake_case wire name (test-pinned, matches the `serde(rename_all)` spelling).
    #[must_use]
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

    /// The signal's ordinal into [`Signal::ALL`] (its stable bit position).
    #[must_use]
    pub fn bit(self) -> u32 {
        Signal::ALL
            .iter()
            .position(|s| *s == self)
            .expect("every Signal is in ALL") as u32
    }
}

/// A compact, CLOSED scalar wire value.
///
/// Deliberately NOT `serde_json::Value` — no nested/unbounded structures on the hot path. Every
/// variant is O(1) to construct and serializes as the bare scalar (see the [`Serialize`] impl).
#[derive(Debug, Clone, PartialEq)]
pub enum SignalValue {
    /// An unsigned integer.
    U64(u64),
    /// A signed integer.
    I64(i64),
    /// A floating-point number.
    F64(f64),
    /// A borrowed-or-owned string.
    Str(Cow<'static, str>),
    /// A flag.
    Bool(bool),
}

impl Serialize for SignalValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            SignalValue::U64(v) => serializer.serialize_u64(*v),
            SignalValue::I64(v) => serializer.serialize_i64(*v),
            SignalValue::F64(v) => serializer.serialize_f64(*v),
            SignalValue::Str(v) => serializer.serialize_str(v),
            SignalValue::Bool(v) => serializer.serialize_bool(*v),
        }
    }
}

/// The error an over-cap bag insert returns — FAIL-CLOSED in EVERY build (never a debug-assert or a
/// silent drop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalBagError {
    /// The bag is at its bounded inline capacity and cannot accept a new distinct signal.
    Overflow {
        /// The inline capacity that was reached.
        cap: usize,
    },
}

impl std::fmt::Display for SignalBagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalBagError::Overflow { cap } => {
                write!(f, "signal bag is full at {cap} signals")
            }
        }
    }
}

impl std::error::Error for SignalBagError {}

/// Inline capacity 4 — the common case never spills. Exceeding it is [`SignalBagError::Overflow`],
/// not a heap spill.
type SignalBagInner = smallvec::SmallVec<[(Signal, SignalValue); 4]>;

/// The signal bag a projection carries.
///
/// Serializes as a map keyed by [`Signal::name`]; an EMPTY bag renders zero keys and never allocates.
/// The bag enforces its own no-duplicate, in-bounds, fail-closed invariant via [`upsert`](SignalBag::upsert).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SignalBag(SignalBagInner);

impl SignalBag {
    /// A new, empty bag (allocates nothing).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the bag holds no signals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many signals the bag holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Read a signal's value, if present.
    #[must_use]
    pub fn get(&self, signal: Signal) -> Option<&SignalValue> {
        self.0.iter().find(|(s, _)| *s == signal).map(|(_, v)| v)
    }

    /// Every `(signal, value)` pair, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &(Signal, SignalValue)> {
        self.0.iter()
    }

    /// Test/proof aid — MUST be `false` on every path (overflow is an `Err`, not a spill).
    #[must_use]
    pub fn spilled(&self) -> bool {
        self.0.spilled()
    }

    /// Insert-or-replace, bounded and FAIL-CLOSED (replaces the old unchecked `push`).
    ///
    /// Replaces the value if `signal` is present (no duplicate keys); appends otherwise. Returns
    /// `Err(SignalBagError::Overflow)` — in RELEASE too, never a debug-assert or silent drop — when a
    /// NEW distinct signal would exceed inline capacity. The compute-gate seam treats an `Err` as a
    /// failed decision → the pool's `on_error` (default reject), matching the rest of the hook path.
    ///
    /// # Errors
    /// [`SignalBagError::Overflow`] when a new distinct signal would exceed the inline capacity.
    pub fn upsert(&mut self, signal: Signal, value: SignalValue) -> Result<(), SignalBagError> {
        if let Some(slot) = self.0.iter_mut().find(|(s, _)| *s == signal) {
            slot.1 = value;
            return Ok(());
        }
        if self.0.len() >= self.0.inline_size() {
            return Err(SignalBagError::Overflow {
                cap: self.0.inline_size(),
            });
        }
        self.0.push((signal, value));
        Ok(())
    }
}

impl Serialize for SignalBag {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (signal, value) in self.0.iter() {
            map.serialize_entry(signal.name(), value)?;
        }
        map.end()
    }
}
