// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CANDIDATE PROJECTION, written plane-neutral with the plane's own facts as a type parameter.
//!
//! One routable member, with the metadata and live signals a policy ranks on. Every plane has this
//! problem and has it identically: take the members a request could be served by, hand a policy a
//! read-only view of each, take back an order. What the planes do NOT agree on is what a member IS,
//! and that disagreement is the whole reason for the parameter.
//!
//! ## Where the line is, and why it is there
//!
//! A field belongs in the NEUTRAL core when every plane fills it and fills it the same way. A field
//! belongs in the plane when only that plane can fill it, or when the planes disagree about its
//! SHAPE rather than merely its value. The second half is the load-bearing half: a field two planes
//! fill differently is not a union of both spellings, it is a parameter.
//!
//! NEUTRAL, and each one is the same fact on every plane:
//!
//! - `idx`, the stable handle into the caller's own member table. Every plane has a member table and
//!   an ordered walk over it; the handle is an index either way.
//! - `weight`, the configured share. Members are weighted the same way whatever they serve, because
//!   the weighting is a property of the pool, not of what is at the end of the lane.
//! - `tags`, operator-declared grouping labels. TAGS GROUP, IDENTITY IDENTIFIES: the labels are the
//!   operator's vocabulary and mean nothing to the machine, so they cannot be plane-specific.
//! - `cost`, `latency_ms`, `available_concurrency`, `budget_remaining`, `rate_headroom`: the live
//!   signals. Each is measured by machinery that does not know or care what the lane carries.
//! - `signals`, the DECLARED, cost-gated bag. Its emptiness is the reason the list above can stay
//!   short: anything a single consumer wants goes there and is paid for only when declared, rather
//!   than becoming a field every request of every plane fills.
//!
//! PARAMETERISED ([`RoutingPlane::Facts`]), because the planes disagree on the shape and not just the
//! contents: what is being routed TO. There is no honest neutral spelling of it. Flattening the
//! union of every plane's facts into this struct would put a field on every request of every plane
//! that only one plane can ever fill, and would make the next plane's arrival an edit to this file
//! rather than an implementation of its trait.
//!
//! ## Why COST is neutral even though it looks like it belongs to a plane
//!
//! Cost is a comparable magnitude where smaller is cheaper. That is all a ranking needs, and every
//! plane can supply it. The UNIT is the plane's business and is never compared across planes,
//! because a ranking only ever runs within one pool. The alternative, a per-plane cost, would have
//! forced the one strategy that ranks on cost to be written once per plane, and the strategies
//! reading only neutral fields is the property that keeps a strategy a strategy rather than a plane
//! adapter.
//!
//! ## Why this is free
//!
//! The parameter is monomorphised. There is no vtable, no boxing and no branch: the projection a
//! plane builds is the same struct it was before, with the same fields laid out the same way. The
//! request path pays nothing for the split, which is the only acceptable price on a gateway whose
//! headline number is a microsecond count.

/// A ROUTING PLANE: the marker naming one plane and fixing the plane-specific facts its candidates
/// carry.
///
/// A marker TYPE rather than a value, because which plane a pool is on is settled at config load and
/// never per request. That is also what makes a cross-plane reference unrepresentable rather than
/// merely rejected: a slice of one plane's candidates cannot be handed to a policy resolved for
/// another, so the refusal is the type system's and not a validator's to remember.
///
/// ## Its relationship to the engine's runtime plane
///
/// The engine also carries a plane as a VALUE, for the jobs that genuinely are runtime decisions:
/// which plane an inbound request dispatches to, which config section declares a plane, which scope
/// kinds grant on it. Those are one-of-N choices made per request or per config document, and an
/// enum is the right shape for them.
///
/// This is the same notion at the other level, and the two must never disagree about which planes
/// exist. `KEY` is the join: it is spelled to match the runtime plane's own key, so the day both
/// live on one branch the reconciliation is a single equality assertion per plane rather than a
/// design question. Deliberately NOT a dependency in either direction: this crate is the contract
/// every plugin builds against, and it must not grow a dependency on the engine to say what a
/// candidate looks like.
pub trait RoutingPlane: Copy + std::fmt::Debug + Send + Sync + 'static {
    /// The plane's short stable key (`llm`, `mcp`, `a2a`). Read by audit records, metrics labels and
    /// operator-facing views; NEVER interpreted by the machine, which is why the machine cannot
    /// acquire a per-plane special case by accident. Exactly the role `mechanism()` plays for a
    /// pinned artifact, and the value that must equal the runtime plane's key.
    const KEY: &'static str;

    /// The plane-specific facts one candidate carries: what is at the end of this lane, said in the
    /// plane's own vocabulary.
    ///
    /// Borrowed for the projection's lifetime, because the projection is built once per request from
    /// state that outlives it and must not copy strings to do so. `Serialize` is the only capability
    /// the neutral machine asks of it, and it asks for exactly one reason: the facts ride the hook
    /// wire flattened alongside the neutral fields, so a hook sees ONE candidate object rather than
    /// a neutral object with a plane-shaped lump nested inside it.
    type Facts<'a>: serde::Serialize + Clone + std::fmt::Debug + Send + Sync;
}

/// One routable member, with the metadata + live signals a policy ranks on. Projected from the
/// caller's member table + config + store. `idx` is the stable handle the ordered walk speaks.
///
/// There is deliberately NO default parameter here, even though one would have saved churn at every
/// call site. A default would be this file naming one plane, and the one thing this file must not
/// know is which planes exist. A plane that wants the short spelling writes its own alias, next to
/// its own facts, where the noun belongs.
#[derive(Debug, Clone)]
pub struct Candidate<'a, P: RoutingPlane> {
    /// Index into the caller's member table - the ordered walk's lingua franca.
    pub idx: usize,
    /// The configured SWRR weight. Projected to the hook wire so an external hook can implement a
    /// weighted-variant strategy (the signal the built-in `weighted` floor uses).
    pub weight: u32,
    /// Free-form operator tags. Projected to the hook wire (omitted when empty).
    pub tags: &'a [String],
    // -- live signals (read per-request at the seam) ----------------------------------------------
    /// The operator-declared COST of serving one unit on this lane, where smaller is cheaper.
    /// `None` when the operator declared none. The unit is the plane's, and is never compared across
    /// planes because a ranking runs within one pool.
    pub cost: Option<f64>,
    /// Rolling EWMA of recent end-to-end latency for this lane, in milliseconds. `None` until the
    /// lane has served at least one request.
    pub latency_ms: Option<f64>,
    /// Currently-available concurrency permits on this lane's semaphore (free slots). A `least_busy`
    /// policy prefers the lane with the most headroom.
    pub available_concurrency: usize,
    /// Per-lane lifetime request budget remaining (`None` = unlimited). The `usage` policy prefers
    /// the lane with the most budget left; cheap (read from the store).
    pub budget_remaining: Option<i64>,
    /// Rate-limit HEADROOM as a fraction in `[0.0, 1.0]`: how much of the request's governance
    /// rate budget (the tighter of the caller key's RPM / TPM limit) is still available this window -
    /// `1.0` is fully-unused, `0.0` is at the cap. `None` when no rate limit applies (governance
    /// disabled, or the key has neither RPM nor TPM set). The `usage` policy prefers the candidate
    /// with the MOST headroom (furthest from an upstream 429). Rate limits are per-KEY in busbar
    /// today, so this value is currently the same across a request's candidates - `usage` then ranks
    /// deterministically by `idx` - but the field is per-candidate so a future per-lane rate signal
    /// drops in without a contract change.
    pub rate_headroom: Option<f64>,
    /// The declared-signal bag: candidate-phase [`crate::Signal`] entries a consumer explicitly
    /// declared, computed ONLY when declared. This is the pressure valve that keeps the neutral
    /// core small: a signal one consumer wants belongs here, where it is paid for on declaration,
    /// never as a field every request of every plane fills.
    pub signals: crate::SignalBag,
    /// The PLANE-SPECIFIC facts: what is at the end of this lane, in the plane's own vocabulary.
    pub facts: P::Facts<'a>,
}

#[cfg(test)]
#[path = "tests/candidate_genericity_tests.rs"]
mod candidate_genericity_tests;
