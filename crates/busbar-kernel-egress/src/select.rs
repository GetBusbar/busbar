// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pick: who is asked first, and who is allowed.

use busbar_contract::clock::Deadline;
use std::sync::Mutex;

use foldhash::{HashMap, HashSet};

use busbar_contract::caps::{Pass, Route};

use crate::pool::Member;
use crate::ports::{Admit, Breaker, Capacity, DestinationId, Permit, Unavailable};

#[cfg(any(test, feature = "test-support"))]
mod test_support;

/// The request's own state across the whole walk: the deadline, everything it has already tried,
/// the pools it has already been through, and why the last pick found nothing.
#[derive(Debug, Clone)]
pub struct RequestCtx {
    /// The walk's deadline in whole seconds since the epoch, computed once at the start.
    deadline_secs: u64,
    /// The same deadline in milliseconds, for the one wait that needs sub-second precision.
    deadline_millis: u128,
    /// Every member this request has already dispatched to, across every hop and every pool.
    excluded: HashSet<DestinationId>,
    /// Why each member was passed over on the LAST pick. Replaced wholesale each pick, so a spill
    /// into another pool reports that pool's own exhaustion and never a stale earlier one.
    excluded_reasons: Vec<(DestinationId, Unavailable)>,
    /// Every pool this request has already routed through, for the spill loop guard: the pools'
    /// own shared names.
    visited_pools: HashSet<busbar_contract::kept::Text>,
    /// The pick's working lists, kept from one pick to the next so a pick allocates nothing.
    scratch: PickScratch,
}

/// The lists one pick works through, emptied between uses.
#[derive(Debug, Clone, Default)]
struct PickScratch {
    /// The members still in play: position, destination, weight.
    candidates: Vec<(usize, DestinationId, u32)>,
    /// Those of them the breaker would send to now: destination, weight, tier.
    healthy: Vec<(DestinationId, u32, u32)>,
    /// Those of the lowest tier: destination, weight.
    offered: Vec<(DestinationId, u32)>,
    /// Positions this pick has already been refused by.
    local_excluded: HashSet<usize>,
}

impl RequestCtx {
    /// Start a request whose walk may take `timeout_secs` from `now`.
    #[must_use]
    pub fn new(timeout_secs: u64, now_secs: u64, now_millis: u128) -> Self {
        Self {
            deadline_secs: now_secs.saturating_add(timeout_secs),
            deadline_millis: now_millis.saturating_add(u128::from(timeout_secs) * 1000),
            excluded: HashSet::default(),
            excluded_reasons: Vec::new(),
            visited_pools: HashSet::default(),
            scratch: PickScratch::default(),
        }
    }

    /// Whether the walk's deadline has passed.
    #[must_use]
    pub fn expired(&self, now_secs: u64) -> bool {
        now_secs >= self.deadline_secs
    }

    /// The walk's deadline on the host's monotonic clock, from the same reading `new` was given.
    #[must_use]
    pub fn deadline(&self) -> Deadline {
        Deadline::at(
            u64::try_from(self.deadline_millis.saturating_mul(1_000_000)).unwrap_or(u64::MAX),
        )
    }

    /// How many milliseconds are left of the walk's deadline.
    #[must_use]
    pub fn remaining_ms(&self, now_millis: u128) -> u64 {
        let left = self.deadline_millis.saturating_sub(now_millis);
        u64::try_from(left).unwrap_or(u64::MAX)
    }

    /// Mark a member as already tried, for every later hop of this request.
    pub fn exclude(&mut self, destination: DestinationId) {
        self.excluded.insert(destination);
    }

    /// Whether this request has already tried a member.
    #[must_use]
    pub fn is_excluded(&self, destination: DestinationId) -> bool {
        self.excluded.contains(&destination)
    }

    /// A completed exchange may continue on its admitted destination. Keep the original
    /// deadline and all other exclusions; this does not reopen a failed-over destination.
    pub(crate) fn continuing(&self, destination: DestinationId) -> Self {
        let mut next = self.clone();
        next.excluded.remove(&destination);
        next
    }

    /// Why each member was passed over on the last pick.
    #[must_use]
    pub fn excluded_reasons(&self) -> &[(DestinationId, Unavailable)] {
        &self.excluded_reasons
    }

    /// Mark a pool as routed through, for the spill loop guard.
    pub fn mark_pool_visited(&mut self, pool: &busbar_contract::kept::Text) {
        if !self.visited_pools.contains(pool.as_str()) {
            self.visited_pools.insert(pool.clone());
        }
    }

    /// Whether this request has already routed through a pool.
    #[must_use]
    pub fn is_pool_visited(&self, pool: &str) -> bool {
        self.visited_pools.contains(pool)
    }
}

/// The weighted floor's own memory over one pool: one running credit per member.
///
/// This is the smooth weighted round robin every deployment gets when it names no ranking of its
/// own. It is stateful by nature — the smoothness IS the memory — so it belongs to the unit and
/// not to a request. Each pool carries its own ([`crate::pool::Pool::floor`]), because the same
/// destination in two pools is two independent rotations: a turn locks only its own pool's
/// credits and looks no pool name up.
#[derive(Debug, Default)]
pub struct WeightedFloor {
    credits: Mutex<HashMap<DestinationId, i64>>,
}

/// A copy of a pool is a copy of its configuration; the rotation memory starts afresh.
impl Clone for WeightedFloor {
    fn clone(&self) -> Self {
        Self::default()
    }
}

/// The rotation memory is not part of what a pool is: two pools configured alike are equal.
impl PartialEq for WeightedFloor {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for WeightedFloor {}

impl WeightedFloor {
    /// A floor with no history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// One turn of the rotation over exactly these members.
    pub(crate) fn take_turn(&self, offered: &[(DestinationId, u32)]) -> Option<DestinationId> {
        if offered.is_empty() {
            return None;
        }
        let mut pool_credits = self.credits.lock().unwrap_or_else(|e| e.into_inner());
        let total: i64 = offered
            .iter()
            .map(|(_, w)| i64::from(*w))
            .fold(0_i64, i64::saturating_add);
        if total <= 0 {
            return None;
        }
        let mut best: Option<(DestinationId, i64)> = None;
        for (destination, weight) in offered {
            let entry = pool_credits.entry(*destination).or_insert(0_i64);
            *entry = entry.saturating_add(i64::from(*weight));
            let current = *entry;

            if best.is_none_or(|(_, b)| current > b) {
                best = Some((*destination, current));
            }
        }
        let (winner, _) = best?;
        if let Some(entry) = pool_credits.get_mut(&winner) {
            *entry = entry.saturating_sub(total);
        }
        Some(winner)
    }
}

/// A won recovery probe, released if the dispatch that won it never records an outcome.
pub struct ProbeGuard<'a> {
    breaker: &'a dyn Breaker,
    pool: &'a str,
    destination: DestinationId,
    epoch: u64,
    now: u64,
    armed: bool,
}

impl<'a> ProbeGuard<'a> {
    /// Arm a guard over a probe this dispatch won.
    #[must_use]
    pub fn new(
        breaker: &'a dyn Breaker,
        pool: &'a str,
        destination: DestinationId,
        epoch: u64,
        now: u64,
    ) -> Self {
        Self {
            breaker,
            pool,
            destination,
            epoch,
            now,
            armed: true,
        }
    }

    /// Hand the probe to something that will record its own outcome. From here the guard releases
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Hand the probe on and yield the epoch it was won at, so the dispatch that takes it can arm
    #[must_use]
    pub(crate) fn take_epoch(&mut self) -> u64 {
        self.armed = false;
        self.epoch
    }
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.breaker
                .release_probe(self.pool, self.destination, self.epoch, self.now);
        }
    }
}

/// A ranking hook's preference over the members, by destination, best first.
pub type Preference<'a> = Option<&'a [DestinationId]>;

/// What one pick found.
#[must_use = "a pick holds a concurrency permit and possibly a recovery probe"]
pub struct Picked<'a> {
    /// Which member.
    pub destination: DestinationId,
    /// Its concurrency slot.
    pub permit: Permit,
    /// The recovery probe this pick won, where it won one, still owned by the pick.
    pub probe: Option<ProbeGuard<'a>>,
}

impl Picked<'_> {
    /// Hand this pick's probe, where it won one, to the dispatch that is about to run and will
    pub fn take_probe_epoch(&mut self) -> Option<u64> {
        self.probe.as_mut().map(ProbeGuard::take_epoch)
    }
}

/// Everything a pick reads.
pub struct PickInput<'a, 't> {
    /// The breaker unit.
    pub breaker: &'a dyn Breaker,
    /// The pool's permit store.
    pub capacity: &'a dyn Capacity,
    /// The pool's weighted floor.
    pub floor: &'a WeightedFloor,
    /// Which pool cell this pick is against.
    pub pool: &'a str,
    /// The pool's membership, with its blocklist already applied.
    pub members: &'a [Member],
    /// The session-affinity hash, where the request carries one.
    pub affinity: Option<u64>,
    /// A ranking hook's preference, where one was resolved.
    pub preference: Preference<'a>,
    /// This second, read once for the whole pick.
    pub now: u64,
    /// The capability token proving the loop is at the route step for this unit right now
    pub token: &'t Pass<Route>,
}

/// Pick one member of the pool for this hop, or find that there is nowhere to send it.
pub fn pick_among<'a>(input: &PickInput<'a, '_>, ctx: &mut RequestCtx) -> Option<Picked<'a>> {
    let mut scratch = std::mem::take(&mut ctx.scratch);
    scratch.local_excluded.clear();
    let mut order = Order::new(input, ctx, &mut scratch);
    let mut passed_over = std::mem::take(&mut ctx.excluded_reasons);
    passed_over.clear();
    let mut refused: Option<usize> = None;

    let picked = loop {
        let Some(position) = order.next(refused, ctx) else {
            break None;
        };
        let destination = input.members[position].destination;
        match try_admit(input, destination) {
            Ok(admitted) => break Some((destination, admitted)),
            Err(why) => {
                passed_over.push((destination, why));
                refused = Some(position);
            }
        }
    };
    ctx.scratch = scratch;

    if picked.is_none() && passed_over.is_empty() && !ctx.expired(input.now) {
        for member in input.members {
            if member.weight == 0 || ctx.is_excluded(member.destination) {
                continue;
            }
            if let Some(why) =
                input
                    .breaker
                    .unavailable(input.pool, member.destination, input.now, input.token)
            {
                passed_over.push((member.destination, why));
            }
        }
    }

    ctx.excluded_reasons = passed_over;

    let (destination, admitted) = picked?;
    Some(Picked {
        destination,
        permit: admitted.permit,
        probe: admitted.probe,
    })
}

/// A successful admission: the breaker said yes and a slot was taken.
struct Admitted<'a> {
    permit: Permit,
    probe: Option<ProbeGuard<'a>>,
}

/// The single mutating admission: the breaker, then the pool's own capacity.
fn try_admit<'a>(
    input: &PickInput<'a, '_>,
    destination: DestinationId,
) -> Result<Admitted<'a>, Unavailable> {
    let admit: Admit = input
        .breaker
        .try_admit(input.pool, destination, input.now)?;
    let probe = admit
        .probe_epoch
        .map(|epoch| ProbeGuard::new(input.breaker, input.pool, destination, epoch, input.now));
    match input.capacity.try_acquire(destination) {
        Some(permit) => Ok(Admitted { permit, probe }),
        None => {
            drop(probe);
            Err(Unavailable::AtCapacity {
                drain_hint_ms: None,
            })
        }
    }
}

/// The order: session affinity first, then a ranking hook's preference, then the weighted floor.
struct Order<'a, 'b, 't, 's> {
    input: &'b PickInput<'a, 't>,
    /// The affinity position, when there is one and it is still in play.
    sticky: Option<usize>,
    sticky_offered: bool,
    /// Whether the last offer was the sticky one, so a refusal of it is forgiven once.
    sticky_grace: bool,
    /// The request's reused working lists.
    scratch: &'s mut PickScratch,
}

impl<'a, 'b, 't, 's> Order<'a, 'b, 't, 's> {
    fn new(input: &'b PickInput<'a, 't>, ctx: &RequestCtx, scratch: &'s mut PickScratch) -> Self {
        let sticky = input.affinity.and_then(|hash| {
            if input.members.is_empty() {
                return None;
            }
            let position = (hash as usize) % input.members.len();
            let member = &input.members[position];
            (member.weight != 0 && !ctx.is_excluded(member.destination)).then_some(position)
        });
        Self {
            input,
            sticky,
            sticky_offered: false,
            sticky_grace: false,
            scratch,
        }
    }

    fn next(&mut self, refused: Option<usize>, ctx: &RequestCtx) -> Option<usize> {
        if let Some(position) = refused {
            if !(self.sticky_grace && Some(position) == self.sticky) {
                self.scratch.local_excluded.insert(position);
            }
        }
        self.sticky_grace = false;

        if !self.sticky_offered {
            self.sticky_offered = true;
            if let Some(position) = self.sticky {
                self.sticky_grace = true;
                return Some(position);
            }
        }

        if ctx.expired(self.input.now) {
            return None;
        }

        let PickScratch {
            candidates,
            healthy,
            offered,
            local_excluded,
        } = &mut *self.scratch;
        candidates.clear();
        for (position, member) in self.input.members.iter().enumerate() {
            if ctx.is_excluded(member.destination) || local_excluded.contains(&position) {
                continue;
            }
            candidates.push((position, member.destination, member.weight));
        }
        if candidates.is_empty() {
            return None;
        }

        let input = self.input;
        healthy.clear();
        healthy.extend(
            candidates
                .iter()
                .filter(|(_, destination, weight)| {
                    *weight != 0
                        && input.breaker.admissible(*destination)
                        && input
                            .breaker
                            .ready(input.pool, *destination, input.now, input.token)
                })
                .map(|(position, destination, weight)| {
                    (*destination, *weight, input.members[*position].tier)
                }),
        );

        let lowest = healthy.iter().map(|(_, _, tier)| *tier).min();
        offered.clear();
        offered.extend(
            healthy
                .iter()
                .filter(|(_, _, tier)| Some(*tier) == lowest)
                .map(|(destination, weight, _)| (*destination, *weight)),
        );

        let picked = match input.preference {
            Some(preference) => preference
                .iter()
                .copied()
                .find(|destination| offered.iter().any(|(d, _)| d == destination))
                .or_else(|| input.floor.take_turn(offered)),
            None => input.floor.take_turn(offered),
        }?;

        candidates
            .iter()
            .find(|(_, destination, _)| *destination == picked)
            .map(|(position, _, _)| *position)
    }
}
