// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pick: who is asked first, and who is allowed.
//!
//! Those are two different questions and this module keeps them apart. The ORDER — session
//! affinity, a ranking hook's preference, the weighted floor every deployment gets when it names
//! none — answers only the first, and nothing in it may change a breaker cell's state. The
//! ADMISSION answers the second and is the single mutating call in the whole pick: it consults the
//! breaker, wins or loses the single-flight recovery probe, and takes a concurrency permit.
//!
//! That split is what the exclusion point depends on. A member that is drained, dead, out of
//! lifetime budget or breaker-suppressed is filtered BEFORE the weighted credit walk, so it never
//! consumes a turn; only a member that is at capacity — or that loses a probe race — reaches the
//! admission after selection, and so is the only kind that does consume one. Ordering a suppressed
//! member last instead of excluding it would spend its turn and change the order of every request
//! after it.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use busbar_caps::{Route, UnitToken};

use crate::pool::Member;
use crate::ports::{Admit, Breaker, Capacity, DestinationId, Permit, Unavailable};

/// The request's own state across the whole walk: the deadline, everything it has already tried,
/// the pools it has already been through, and why the last pick found nothing.
#[derive(Debug)]
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
    /// Every pool this request has already routed through, for the spill loop guard.
    visited_pools: HashSet<String>,
}

impl RequestCtx {
    /// Start a request whose walk may take `timeout_secs` from `now`.
    #[must_use]
    pub fn new(timeout_secs: u64, now_secs: u64, now_millis: u128) -> Self {
        Self {
            deadline_secs: now_secs.saturating_add(timeout_secs),
            deadline_millis: now_millis.saturating_add(u128::from(timeout_secs) * 1000),
            excluded: HashSet::new(),
            excluded_reasons: Vec::new(),
            visited_pools: HashSet::new(),
        }
    }

    /// Whether the walk's deadline has passed.
    #[must_use]
    pub fn expired(&self, now_secs: u64) -> bool {
        now_secs >= self.deadline_secs
    }

    /// How many whole seconds are left of the walk's deadline.
    #[must_use]
    pub fn remaining_secs(&self, now_secs: u64) -> u64 {
        self.deadline_secs.saturating_sub(now_secs)
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

    /// Why each member was passed over on the last pick.
    #[must_use]
    pub fn excluded_reasons(&self) -> &[(DestinationId, Unavailable)] {
        &self.excluded_reasons
    }

    /// Mark a pool as routed through, for the spill loop guard.
    pub fn mark_pool_visited(&mut self, pool: &str) {
        self.visited_pools.insert(pool.to_string());
    }

    /// Whether this request has already routed through a pool.
    #[must_use]
    pub fn is_pool_visited(&self, pool: &str) -> bool {
        self.visited_pools.contains(pool)
    }
}

/// The weighted floor's own memory: one running credit per pool member.
///
/// This is the smooth weighted round robin every deployment gets when it names no ranking of its
/// own. It is stateful by nature — the smoothness IS the memory — so it belongs to the unit and
/// not to a request. The credit is kept per pool as well as per member, because the same
/// destination in two pools is two independent rotations.
///
/// Keyed two levels deep rather than on a `(String, DestinationId)` pair: the pool is a borrowed
/// `&str` for the whole walk, and a pair key would make a turn own a fresh copy of that name once
/// per offered member, on the request path, every hop. Two levels hashes and owns the name once —
/// on first sight of the pool — and every member lookup after that borrows.
#[derive(Debug, Default)]
pub struct WeightedFloor {
    credits: Mutex<HashMap<String, HashMap<DestinationId, i64>>>,
}

impl WeightedFloor {
    /// A floor with no history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many owned pool names the floor is holding, and how many credits.
    ///
    /// The bound made observable: the first number is what the pool name costs, and it is a
    /// function of the number of pools alone.
    pub(crate) fn tracked(&self) -> (usize, usize) {
        let credits = self.credits.lock().unwrap_or_else(|e| e.into_inner());
        (
            credits.len(),
            credits.values().map(HashMap::len).sum::<usize>(),
        )
    }

    /// One turn of the rotation over exactly these members.
    ///
    /// Every member offered here has already passed the filter — non-zero weight, usable
    /// destination, ready cell — so a turn is only ever spent on a member that could have taken
    /// the request. Returns `None` when nothing was offered.
    pub(crate) fn take_turn(
        &self,
        pool: &str,
        offered: &[(DestinationId, u32)],
    ) -> Option<DestinationId> {
        if offered.is_empty() {
            return None;
        }
        let mut credits = self.credits.lock().unwrap_or_else(|e| e.into_inner());
        let total: i64 = offered
            .iter()
            .map(|(_, w)| i64::from(*w))
            .fold(0_i64, i64::saturating_add);
        if total <= 0 {
            return None;
        }
        // The pool name is owned once, here, and only on first sight of the pool. Every member
        // lookup below borrows it.
        if !credits.contains_key(pool) {
            credits.insert(pool.to_string(), HashMap::new());
        }
        let pool_credits = credits
            .get_mut(pool)
            .expect("the pool was just put in the map");
        let mut best: Option<(DestinationId, i64)> = None;
        for (destination, weight) in offered {
            let entry = pool_credits.entry(*destination).or_insert(0_i64);
            *entry = entry.saturating_add(i64::from(*weight));
            let current = *entry;
            // Ties go to the earlier member in the offered order, which is the operator's own
            // configured order — the same tie-break the previous release's rotation made.
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
///
/// Winning a probe puts the cell in its half-open state with the probe marked in flight, and the
/// mark is normally cleared by the request recording what happened. If the future holding it is
/// dropped part-way — a client that went away while the upstream call was open — no cleanup runs,
/// and without this the cell would stay half-open until the slow out-of-band prober noticed.
///
/// The release is owner-checked against the epoch captured at the win. A guard can be dropped
/// LATE, after its own request already recorded an outcome and a peer has since won a newer probe
/// on the same cell; an unchecked release would revert that peer's live probe.
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
    /// nothing.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Whether the guard would still release on drop.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.armed
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
///
/// A member the ranking omits is lowest priority but still reachable: when no ranked member
/// qualifies the pick falls through to the weighted floor over the same candidates, so a partial
/// ranking never strands the rest.
pub type Preference<'a> = Option<&'a [DestinationId]>;

/// What one pick found.
#[derive(Debug)]
#[must_use = "a pick holds a concurrency permit and possibly a recovery probe"]
pub struct Picked {
    /// Which member.
    pub destination: DestinationId,
    /// Its concurrency slot.
    pub permit: Permit,
    /// The recovery probe this pick won, where it won one.
    pub probe_epoch: Option<u64>,
}

/// Everything a pick reads.
pub struct PickInput<'a> {
    /// The breaker unit.
    pub breaker: &'a dyn Breaker,
    /// The pool's permit store.
    pub capacity: &'a dyn Capacity,
    /// The weighted floor's memory.
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
    /// (`busbar-caps`'s `&UnitToken<Route>`, per CG-29), lent down to every
    /// [`crate::ports::Breaker::ready`] / [`crate::ports::Breaker::cooldown_remaining`] call the
    /// pick makes.
    pub token: &'a UnitToken<Route>,
}

/// Pick one member of the pool for this hop, or find that there is nowhere to send it.
///
/// The loop below is the walk over the order, and it is deliberately small: the order says who is
/// next, the admission says yes or no, and a no is recorded and the order is asked again. Nothing
/// else happens here — no waiting, no spilling, no bypassing. Those are the terminals' job, and
/// keeping them out of this loop is what makes "the pick never blocks" a structural fact rather
/// than a rule someone has to remember.
pub fn pick_among(input: &PickInput<'_>, ctx: &mut RequestCtx) -> Option<Picked> {
    let mut order = Order::new(input, ctx);
    let mut passed_over: Vec<(DestinationId, Unavailable)> = Vec::new();
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

    // The exclusion record is this pick's own, replaced wholesale: a spill that re-runs the pick
    // against another pool must report that pool's exhaustion, never the primary's.
    ctx.excluded_reasons = passed_over;

    let (destination, admitted) = picked?;
    Some(Picked {
        destination,
        permit: admitted.permit,
        probe_epoch: admitted.probe_epoch,
    })
}

/// A successful admission: the breaker said yes and a slot was taken.
struct Admitted {
    permit: Permit,
    probe_epoch: Option<u64>,
}

/// The single mutating admission: the breaker, then the pool's own capacity.
///
/// The order matters and so does the failure path. A member whose breaker admits but whose slots
/// are all held is at capacity, which is the one exclusion reason that waiting can cure — and a
/// probe won on the way in must be given back here, because nothing was dispatched to record an
/// outcome that would have cleared it.
fn try_admit(input: &PickInput<'_>, destination: DestinationId) -> Result<Admitted, Unavailable> {
    let admit: Admit = input
        .breaker
        .try_admit(input.pool, destination, input.now)?;
    match input.capacity.try_acquire(destination) {
        Some(permit) => Ok(Admitted {
            permit,
            probe_epoch: admit.probe_epoch,
        }),
        None => {
            if let Some(epoch) = admit.probe_epoch {
                input
                    .breaker
                    .release_probe(input.pool, destination, epoch, input.now);
            }
            Err(Unavailable::AtCapacity {
                drain_hint_ms: None,
            })
        }
    }
}

/// The order: session affinity first, then a ranking hook's preference, then the weighted floor.
struct Order<'a, 'b> {
    input: &'b PickInput<'a>,
    /// The affinity position, offered first and exactly once.
    sticky: Option<usize>,
    sticky_offered: bool,
    /// Set for exactly one call after the affinity position was offered.
    sticky_grace: bool,
    /// Positions this order will not offer again. Local to the pick: it never touches the
    /// request's cross-hop exclusion set.
    local_excluded: HashSet<usize>,
}

impl<'a, 'b> Order<'a, 'b> {
    fn new(input: &'b PickInput<'a>, ctx: &RequestCtx) -> Self {
        // Session affinity is a preference, not a constraint, and it is skipped in exactly two
        // cases: a drained member, and one this request has already tried. Both are selection
        // policy rather than availability, so neither is recorded as an exclusion reason.
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
            local_excluded: HashSet::new(),
        }
    }

    fn next(&mut self, refused: Option<usize>, ctx: &RequestCtx) -> Option<usize> {
        if let Some(position) = refused {
            // A refused affinity position is deliberately NOT locally excluded. The affinity fast
            // path records its reason and falls through to the weighted floor, which may
            // legitimately offer the same member again and attempt it a second time. The wait
            // terminal is written against that: it dedups the doubled at-capacity reason by
            // member.
            if !(self.sticky_grace && Some(position) == self.sticky) {
                self.local_excluded.insert(position);
            }
        }
        self.sticky_grace = false;

        // 1. Session affinity, before anything else and before the deadline guard — exactly where
        //    the fast path sat.
        if !self.sticky_offered {
            self.sticky_offered = true;
            if let Some(position) = self.sticky {
                self.sticky_grace = true;
                return Some(position);
            }
        }

        // 2. Never spin or re-select past the walk's deadline.
        if ctx.expired(self.input.now) {
            return None;
        }

        // 3. This hop's candidates: the membership minus what the request has tried and minus what
        //    this pick has burned.
        let mut candidates: Vec<(usize, DestinationId, u32)> = Vec::new();
        for (position, member) in self.input.members.iter().enumerate() {
            if ctx.is_excluded(member.destination) || self.local_excluded.contains(&position) {
                continue;
            }
            candidates.push((position, member.destination, member.weight));
        }
        if candidates.is_empty() {
            return None;
        }

        // 4. The health filter, applied BEFORE any turn is spent. A drained member, an unusable
        //    destination, or a suppressed cell is excluded here — never ranked last and attempted.
        let offered: Vec<(DestinationId, u32)> = candidates
            .iter()
            .filter(|(_, destination, weight)| {
                *weight != 0
                    && self.input.breaker.admissible(*destination)
                    && self.input.breaker.ready(
                        self.input.pool,
                        *destination,
                        self.input.now,
                        self.input.token,
                    )
            })
            .map(|(_, destination, weight)| (*destination, *weight))
            .collect();

        // 5. A ranking hook's preference, honouring exactly the filter above: the first ranked
        //    member that is in this hop's candidates and passed the filter. If none qualifies —
        //    every preferred member unhealthy or already tried, or the ranking covered only a
        //    subset — fall through to the weighted floor over the same candidates, so an omitted
        //    member is lowest priority but never stranded.
        let picked = match self.input.preference {
            Some(preference) => preference
                .iter()
                .copied()
                .find(|destination| offered.iter().any(|(d, _)| d == destination))
                .or_else(|| self.input.floor.take_turn(self.input.pool, &offered)),
            None => self.input.floor.take_turn(self.input.pool, &offered),
        }?;

        // The floor answers with a destination; the walk indexes the membership by position. A
        // destination appears at most once in a pool, so the first match is the match.
        candidates
            .iter()
            .find(|(_, destination, _)| *destination == picked)
            .map(|(position, _, _)| *position)
    }
}
