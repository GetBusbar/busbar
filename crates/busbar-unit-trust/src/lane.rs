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
    breaker.ready(pool, candidate.idx, now)
}
