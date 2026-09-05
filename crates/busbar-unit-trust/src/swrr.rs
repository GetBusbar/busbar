// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The weighted floor: smooth weighted round-robin over the healthy subset.
//!
//! Every deployment that names no strategy gets this, which is why it is a floor rather than an
//! option. The algorithm is the classic one — add each member's weight to its running credit, take
//! the member with the most credit, subtract the total from it — and its one property worth stating
//! is that the credits sum to zero after every selection, so the sequence is proportional to the
//! weights with no drift and no burst.
//!
//! Two rules are enforced here rather than left to the caller:
//!
//! - A weight of zero is skipped. Without that, an all-zero healthy set has a total of zero, every
//!   credit stays put, and the maximum-finder degenerates into always answering with the first
//!   candidate — so a member the operator drained would receive all the traffic instead of none.
//! - The filter runs before the walk, so an excluded lane never consumes a turn.

use crate::lane::{survives_prewalk_filter, BreakerView, LaneCandidate, LaneTable};
use std::collections::HashMap;

/// The running credits, one per lane.
///
/// Per pool: two pools that happen to share a lane keep independent credit, because they are
/// independent proportional sequences.
#[derive(Debug, Default)]
pub struct SwrrState {
    credits: HashMap<(String, usize), i64>,
}

impl SwrrState {
    /// A fresh set of credits.
    pub fn new() -> Self {
        SwrrState::default()
    }

    /// The credit a lane currently holds. For tests and for the operator's own report.
    pub fn credit(&self, pool: &str, lane: usize) -> i64 {
        self.credits
            .get(&(pool.to_string(), lane))
            .copied()
            .unwrap_or(0)
    }

    /// Clear one lane's credit — what a recovery does when a lane rejoins, so it starts level rather
    /// than owed.
    pub fn reset(&mut self, pool: &str, lane: usize) {
        self.credits.remove(&(pool.to_string(), lane));
    }
}

/// Select one lane from the candidates, or `None` when every one of them is filtered out.
///
/// The filter is applied first and in full: drained, not admissible and breaker-open lanes are gone
/// before a single credit moves.
pub fn select_weighted(
    state: &mut SwrrState,
    pool: &str,
    candidates: &[LaneCandidate],
    lanes: &dyn LaneTable,
    breaker: &dyn BreakerView,
    now: u64,
) -> Option<usize> {
    let healthy: Vec<LaneCandidate> = candidates
        .iter()
        .copied()
        .filter(|c| survives_prewalk_filter(*c, lanes, breaker, pool, now))
        .collect();
    if healthy.is_empty() {
        return None;
    }

    let total: i64 = healthy.iter().map(|c| i64::from(c.weight)).sum();
    let mut best: Option<(usize, i64)> = None;
    for c in &healthy {
        let key = (pool.to_string(), c.idx);
        let credit = state.credits.entry(key).or_insert(0);
        *credit += i64::from(c.weight);
        // Ties go to the earlier candidate, so a pool of equal weights walks its members in
        // configuration order — which is what an operator reading the pool expects to see.
        let take = match best {
            None => true,
            Some((_, best_credit)) => *credit > best_credit,
        };
        if take {
            best = Some((c.idx, *credit));
        }
    }

    let (winner, _) = best?;
    if let Some(credit) = state.credits.get_mut(&(pool.to_string(), winner)) {
        *credit -= total;
    }
    Some(winner)
}
