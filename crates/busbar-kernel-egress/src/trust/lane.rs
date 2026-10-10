// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Lanes, and the two different questions asked about them.
//!
//! **Is this lane offerable?** — a read-only peek. It transitions nothing and takes no probe, and it
//! is what the ordering natives consult while deciding who is asked first.
//!
//! **Will this lane have it?** — the one admission. It is the only mutating call, it happens once
//! per candidate after selection, and it is where an at-capacity lane is discovered.
//!
//! Keeping those apart is what makes the exclusion rule mean something: an ordering that peeked
//! could otherwise become a second selection loop with its own opinion about health, and then two
//! places would decide who is allowed instead of one.

/// Why a lane could not take the unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// Its breaker is open.
    BreakerOpen,
    /// It is at its concurrency limit.
    AtCapacity,
    /// It spent its lifetime request budget.
    BudgetExhausted,
    /// It is configured out or otherwise dead.
    Dead,
}

/// One pool member, as configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneCandidate {
    /// Its index in the lane table.
    pub idx: usize,
    /// Its configured weight. Zero means the operator is draining it.
    pub weight: u32,
}

/// The lane table's health, as this unit reads it.
pub trait LaneTable {
    /// Whether a lane is admissible at all: not dead, and not over its lifetime request budget.
    /// This is the filter that runs BEFORE the credit walk, so an exhausted lane never consumes a
    /// turn.
    fn lane_admissible(&self, lane: usize) -> bool;
}

/// The breaker, as this unit reads it.
pub trait BreakerView {
    /// The side-effect-free readiness peek. It must not drive a cell out of its open state and must
    /// not take a single-flight probe: an enumeration is not a dispatch.
    fn ready(&self, pool: &str, lane: usize, now: u64) -> bool;

    /// The one admission. Mutating, called once per candidate after selection. Discovers an
    /// at-capacity lane, and is where a half-open probe is actually taken.
    fn try_admit(&self, pool: &str, lane: usize, now: u64) -> Result<(), Unavailable>;
}

/// The breaker together with the two things it must be asked ABOUT: which pool, and at what moment.
///
/// One value rather than three arguments because the readiness peek is asked from two places — the
/// pre-walk that filters a lane out before the credit walk, and the verify step that decides what
/// may be sealed — and they must ask the SAME question. A pool name or a clock read that differed
/// between them would be two opinions about health, and then the pick order is a property of
/// whichever loop ran rather than a stated policy. The moment is the unit's pinned arrival epoch,
/// never a fresh clock read: two peeks either side of a half-open window would disagree about a
/// lane nothing happened to.
pub struct BreakerQuery<'a> {
    /// The breaker to ask.
    pub breaker: &'a dyn BreakerView,
    /// The pool the request named, keyed as the breaker keys it.
    pub pool: &'a str,
    /// The unit's pinned arrival epoch.
    pub now: u64,
}

impl BreakerQuery<'_> {
    /// The readiness peek, over one lane of this pool at this moment.
    ///
    /// Every caller that excludes a lane for an open breaker goes through here, so there is exactly
    /// one spelling of the question and no way for two of them to drift apart.
    #[must_use]
    pub fn admits_lane(&self, lane: usize) -> bool {
        self.breaker.ready(self.pool, lane, self.now)
    }
}

/// Whether a lane survives the pre-walk filter: drained, not admissible, or breaker-open lanes do
/// not, and none of them consumes a turn.
///
/// A weight of zero is a selection-policy skip rather than an unavailability, so it is deliberately
/// not reported as a reason: the operator draining a member did not make it unhealthy.
pub fn survives_prewalk_filter(
    candidate: LaneCandidate,
    lanes: &dyn LaneTable,
    breaker: &dyn BreakerView,
    pool: &str,
    now: u64,
) -> bool {
    if candidate.weight == 0 {
        return false;
    }
    if !lanes.lane_admissible(candidate.idx) {
        return false;
    }
    BreakerQuery { breaker, pool, now }.admits_lane(candidate.idx)
}
