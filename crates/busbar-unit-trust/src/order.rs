// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Who is asked first — and never who is allowed.
//!
//! Everything in this module answers ONE question: in what order are the candidates offered? None
//! of it admits anything. The peek it uses is side-effect-free and the only mutating admission is
//! the one the walk calls on whatever an ordering yields. That separation is why session affinity,
//! a ranked policy and the weighted floor can all live here without becoming a second selection loop
//! with its own opinion about health.
//!
//! They are all HOOKS, and they say so: each declares that it may change the selected destination,
//! and the pre and post head of the pick lands in the audit record. An ordering that could silently
//! move a unit to a different lane without declaring it would be a hook in everything but name.

use crate::lane::{BreakerView, LaneCandidate, LaneTable, Unavailable};
use crate::swrr::{select_weighted, SwrrState};
use std::collections::HashSet;

/// A candidate-ordering hook.
///
/// The floor implementations in this crate — affinity, the ranked walk, the weighted floor — are
/// registered as hooks like any other, at the same seat, so an operator's own ordering and the
/// built-in one are reconciled by one rule rather than two.
pub trait OrderingHook {
    /// The hook's name, for the audit record.
    fn name(&self) -> &'static str;

    /// Its priority in the chain. Lower runs earlier; the LAST ordering in the chain is the one that
    /// wins the reconcile.
    fn priority(&self) -> u16;

    /// Whether this hook may change the selected destination. Every ordering hook may, by
    /// definition, and every one of them declares it rather than being exempted.
    fn may_change_destination(&self) -> bool {
        true
    }

    /// The ordering this hook wants, as lane indices, or an abstention.
    fn order(&self, candidates: &[LaneCandidate]) -> OrderVerdict;
}

/// What an ordering hook answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderVerdict {
    /// This ranked order, best first.
    Order(Vec<usize>),
    /// No opinion — fall through to whatever the chain decides next.
    Abstain,
}

/// Reconcile the ordering hooks over the FINAL, post-restriction candidate set.
///
/// Three rules, and each is a decision that was got wrong once:
///
/// - The chain is stable-sorted by priority, so ties keep their source order — globals before pool
///   hooks, then configuration order.
/// - The LAST ordering in the chain wins. It outranks every earlier one.
/// - The winner is re-validated against the surviving set, because a hook fired against the set as
///   it was at the start may name a member a restriction has since removed. If nothing survives the
///   filter, the winner ABSTAINS — and abstaining falls through to the pool's base ordering, never
///   back to a lower-priority hook's stale answer. That last clause is the whole reason this is one
///   function: written as a loop that only assigns on success, the previous iteration's value is
///   left standing and a lower-priority hook silently wins.
pub fn reconcile_order(
    hooks: &[&dyn OrderingHook],
    candidates: &[LaneCandidate],
) -> Option<(Vec<usize>, &'static str)> {
    let mut chain: Vec<&&dyn OrderingHook> = hooks.iter().collect();
    chain.sort_by_key(|h| h.priority());

    let surviving: HashSet<usize> = candidates.iter().map(|c| c.idx).collect();
    let mut winner: Option<(Vec<usize>, &'static str)> = None;
    for hook in chain {
        if let OrderVerdict::Order(order) = hook.order(candidates) {
            let filtered: Vec<usize> =
                order.into_iter().filter(|i| surviving.contains(i)).collect();
            if !filtered.is_empty() {
                winner = Some((filtered, hook.name()));
            } else {
                // This hook outranks every earlier one and has abstained. The fall-through is the
                // pool's BASE ordering, never a lower-priority hook's leftover.
                winner = None;
            }
        }
    }
    winner
}

/// The session-affinity position: which candidate a session key pins to.
///
/// The hash is taken once, at the boundary, with a stable function rather than a per-process seeded
/// one, so a session pins to the same member across restarts.
///
/// Two skips, and both are the same rule the rest of selection already follows: a drained member is
/// never pinned to — otherwise a session whose hash lands on a member the operator is bleeding off
/// keeps pinning to it and silently defeats the drain — and neither is one this request already
/// tried. Both are selection-policy skips rather than unavailability, so neither is recorded as a
/// reason.
pub fn sticky_position(
    candidates: &[LaneCandidate],
    affinity_key_hash: Option<u64>,
    excluded: &HashSet<usize>,
) -> Option<usize> {
    let hash = affinity_key_hash?;
    if candidates.is_empty() {
        return None;
    }
    let pos = (hash as usize) % candidates.len();
    (candidates[pos].weight != 0 && !excluded.contains(&candidates[pos].idx)).then_some(pos)
}

/// What the walk produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickOutcome {
    /// A lane was admitted.
    Admitted(Pick),
    /// Nowhere to send this hop. The caller falls through to the pool's exhaustion terminal, which
    /// renders the operator-facing answer from the recorded reasons.
    NoneAdmissible,
}

/// The admitted lane, and what was passed over on the way to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pick {
    /// The lane index admitted.
    pub lane: usize,
    /// Its position in this pool's membership.
    pub position: usize,
}

/// One pick over a pool's membership.
///
/// The order of the offers is fixed:
///
/// 1. Session affinity, offered first and exactly once — before even the deadline guard, which is
///    where the fast path has always sat.
/// 2. The deadline guard: never spin or re-select past the request's deadline.
/// 3. This hop's candidate set: the pool, minus the caller's cross-hop exclusions, minus the
///    positions this pick has already burned.
/// 4. Selection: the ranked order when a hook won the reconcile, otherwise the weighted floor.
///
/// A REFUSED STICKY IS NOT LOCALLY EXCLUDED, and that is deliberate rather than an oversight: the
/// affinity offer records its reason and falls THROUGH to the floor, which may legitimately pick the
/// same lane again and try it a second time. Anything reading the recorded reasons therefore has to
/// expect the doubled at-capacity entry, and does.
#[allow(clippy::too_many_arguments)]
pub fn pick(
    pool: &str,
    candidates: &[LaneCandidate],
    lanes: &dyn LaneTable,
    breaker: &dyn BreakerView,
    swrr: &mut SwrrState,
    policy_order: Option<&[usize]>,
    affinity_key_hash: Option<u64>,
    excluded: &HashSet<usize>,
    passed_over: &mut Vec<(usize, Unavailable)>,
    now: u64,
    deadline_passed: bool,
) -> PickOutcome {
    passed_over.clear();
    if candidates.is_empty() {
        return PickOutcome::NoneAdmissible;
    }

    let sticky = sticky_position(candidates, affinity_key_hash, excluded);
    let mut sticky_offered = false;
    let mut sticky_grace = false;
    let mut local_excluded: HashSet<usize> = HashSet::new();
    let mut last_refused: Option<usize> = None;

    loop {
        if let Some(position) = last_refused {
            if !(sticky_grace && Some(position) == sticky) {
                local_excluded.insert(position);
            }
        }
        sticky_grace = false;

        // 1. Session affinity, before anything else.
        let position = if !sticky_offered {
            sticky_offered = true;
            match sticky {
                Some(p) => {
                    sticky_grace = true;
                    Some(p)
                }
                None => next_position(
                    pool,
                    candidates,
                    lanes,
                    breaker,
                    swrr,
                    policy_order,
                    excluded,
                    &local_excluded,
                    now,
                    deadline_passed,
                ),
            }
        } else {
            next_position(
                pool,
                candidates,
                lanes,
                breaker,
                swrr,
                policy_order,
                excluded,
                &local_excluded,
                now,
                deadline_passed,
            )
        };

        let Some(position) = position else {
            return PickOutcome::NoneAdmissible;
        };
        let Some(candidate) = candidates.get(position) else {
            // An ordering that names a position outside the pool has nothing to admit. Treat it as
            // the end of that ordering rather than trusting the index.
            return PickOutcome::NoneAdmissible;
        };

        // The one admission, once per candidate, after selection.
        match breaker.try_admit(pool, candidate.idx, now) {
            Ok(()) => {
                return PickOutcome::Admitted(Pick {
                    lane: candidate.idx,
                    position,
                })
            }
            Err(why) => {
                passed_over.push((position, why));
                last_refused = Some(position);
            }
        }
    }
}

/// Steps two through four: the deadline guard, this hop's candidate set, and the selection.
#[allow(clippy::too_many_arguments)]
fn next_position(
    pool: &str,
    candidates: &[LaneCandidate],
    lanes: &dyn LaneTable,
    breaker: &dyn BreakerView,
    swrr: &mut SwrrState,
    policy_order: Option<&[usize]>,
    excluded: &HashSet<usize>,
    local_excluded: &HashSet<usize>,
    now: u64,
    deadline_passed: bool,
) -> Option<usize> {
    // 2. Never spin or re-select past the deadline.
    if deadline_passed {
        return None;
    }

    // 3. This hop's set.
    let hop: Vec<LaneCandidate> = candidates
        .iter()
        .enumerate()
        .filter(|(position, c)| {
            !excluded.contains(&c.idx) && !local_excluded.contains(position)
        })
        .map(|(_, c)| *c)
        .collect();
    if hop.is_empty() {
        return None;
    }

    // 4. Selection. Two paths and only two.
    let picked_lane = match policy_order {
        Some(order) => {
            // The first ranked lane that is still in this hop's set, is not drained, and is ready.
            //
            // The drain check is here as well as in the floor because the readiness peek does not
            // look at weight: without it a ranked ordering could put a drained lane first and yield
            // it, which is exactly the operator intent the drain expresses. A ranked ordering that
            // qualifies nowhere falls THROUGH to the floor over the same set, so an unranked but
            // healthy lane is lowest-priority rather than stranded.
            let preferred = order.iter().copied().find(|idx| {
                hop.iter()
                    .any(|c| c.idx == *idx && c.weight != 0)
                    && breaker.ready(pool, *idx, now)
            });
            match preferred {
                Some(idx) => idx,
                None => select_weighted(swrr, pool, &hop, lanes, breaker, now)?,
            }
        }
        // The default: the weighted floor, one predictable branch.
        None => select_weighted(swrr, pool, &hop, lanes, breaker, now)?,
    };

    // The walk indexes by POSITION and the floor answers with a LANE. A lane appears at most once in
    // a pool's membership, so the first match is the match.
    candidates.iter().position(|c| c.idx == picked_lane)
}
