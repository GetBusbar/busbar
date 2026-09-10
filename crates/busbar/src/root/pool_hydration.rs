// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pool table the egress unit walks, built from the same configuration the shipping candidate
//! resolution reads.
//!
//! ## Why this is the root's and not the unit's
//!
//! The egress unit owns the pool — the membership, the weights, the deadline, the hop cap, the
//! blocklist and the terminal. What it does not own, and must not, is where those values come
//! from: a unit that parsed configuration would be a unit whose behaviour changed when the
//! configuration grammar did. So the pool arrives as a value, and building that value from the
//! deployment's own configuration is composition — which is this file.
//!
//! ## The identity this file is written to hold
//!
//! The shipping route step resolves its candidate set from the plane's lowered tables: a
//! configured pool answers with its members in configuration order, and a bare destination name
//! answers with the single member it resolves to, on the default cell. This builds the same
//! membership, in the same order, with the same per-member overrides, off the same neutral carrier
//! the plane's own lowering reads — [`busbar_substrate::plane_host::PlaneBuildInput`]. Not a
//! re-derivation from a second source: the same document, read once more, into the shape the unit
//! takes.
//!
//! The cell beside this file states that as an equality rather than as a comment. It drives the
//! plane's OWN lowering over a boot fixture, projects the result through the neutral tables view,
//! and demands that every configured pool's members agree with this table's — position for
//! position, lane for lane, weight for weight. A drift in either direction turns it red.
//!
//! ## What is deliberately not decided here
//!
//! Nothing. Every value below is read across; where the configuration names none, the fall-through
//! is the one the shipping resolution takes — the pool's own `failover:` block, else the
//! deployment-wide default the carrier holds, else the unit's own declared defaults, which carry
//! the same two names and the same two numbers the previous release's did.
//!
//! ## Dark
//!
//! Nothing served reaches this table. It is composed, and the cells drive it through the unit's own
//! surface; the route step still resolves its candidates the way it always has. Re-pointing that is
//! the next landing's, and it is a separate one on purpose: a table that is built and a table that
//! is walked are two claims, and proving them in one commit means a divergence cannot be bisected
//! to either.

use busbar_contract::LaneId;
use busbar_substrate::plane_host::{
    FailoverInput, OnExhaustedInput, PlaneBuildInput, PoolInput, PoolMemberInput,
};
use busbar_unit_egress::pool::{Failover, Member, OnExhausted, Pool, PoolTable};
use busbar_unit_egress::ports::DestinationId;

/// The name of the cell a destination with no configured pool routes on.
///
/// The empty string, because that is what it is: the previous release keyed the breaker's default
/// cell on it and the egress unit's pool table keys the same cell on the same name. Named here so
/// the two readings below say it once.
pub const DEFAULT_CELL: &str = "";

/// How the root seats a member's lane name.
///
/// The pool's member carries the lane the trust unit sealed, and a [`LaneId`] is a static name —
/// which means something has to have interned it. The root's interner is the one thing that may,
/// and it is `&mut`, so it arrives as a closure rather than as a borrow held across the whole
/// build: hydration runs once at boot, beside every other interning this root does, and a table
/// that could intern later would be a table that could grow the vocabulary on a request.
pub type SeatLaneName<'a> = &'a mut dyn FnMut(&str) -> &'static str;

/// The destination a lane index names.
///
/// One line, and it is the whole of the correspondence: the shipping candidate set keys a pool
/// member by its index into the deployment's lane table, and the egress and breaker units key a
/// pool member by a destination. They are the same number. Written as a function rather than
/// inlined at each use so that the claim is in one place if it ever stops being true.
#[must_use]
pub fn destination_of_lane(lane_idx: usize) -> DestinationId {
    DestinationId::new(lane_idx as u64)
}

/// The lane index a destination names — the other direction of [`destination_of_lane`].
#[must_use]
pub fn lane_of_destination(destination: DestinationId) -> usize {
    destination.get() as usize
}

/// One configured pool's membership, in configuration order.
fn members_of(
    pool: &PoolInput,
    input: &PlaneBuildInput,
    seat: &mut dyn FnMut(&str) -> &'static str,
) -> Vec<Member> {
    pool.members
        .iter()
        .map(|m| member_of(m, input, seat))
        .collect()
}

/// One member, with the overrides the configuration declared for it and the facts its lane
/// declared.
///
/// The two axes are kept apart on purpose. `weight`, `attempt_timeout_ms` are the MEMBER's — the
/// same pool member's own overrides the plane's lowering copies onto its weighted lane. The
/// context window is the LANE's: it is a property of the model, not of one pool's use of it, and
/// the walk reads it only to exclude the members that share a limit which has just refused a
/// request.
fn member_of(
    m: &PoolMemberInput,
    input: &PlaneBuildInput,
    seat: &mut dyn FnMut(&str) -> &'static str,
) -> Member {
    let lane = input.lanes.get(m.lane_idx);
    Member {
        destination: destination_of_lane(m.lane_idx),
        name: m.model.clone(),
        weight: m.weight,
        attempt_timeout_ms: m.attempt_timeout_ms,
        // `usize` to `u64`: the unit states a context window in the same width the wire does. A
        // deployment whose window does not fit a `u64` is not a deployment.
        context_max: lane.and_then(|l| l.context_max).map(|n| n as u64),
        lane: lane.map(|l| LaneId::new(seat(&l.model))),
    }
}

/// What bounds the walk over one pool.
///
/// The fall-through is the shipping one, in the shipping order: the pool's own block, else the
/// deployment-wide default the carrier holds, else the unit's own declared defaults — which carry
/// the same two names and the same two numbers.
fn failover_of(pool: &PoolInput, input: &PlaneBuildInput) -> Failover {
    let declared: Option<&FailoverInput> =
        pool.failover.as_ref().or(input.default_failover.as_ref());
    match declared {
        Some(f) => Failover {
            timeout_secs: f.timeout_secs,
            max_hops: f.max_hops,
            exclusions: f.exclusions.clone().unwrap_or_default(),
        },
        None => Failover::default(),
    }
}

/// What to do when the walk finds nowhere to send. Arm for arm, and exhaustive on purpose: a
/// terminal the carrier gains and this does not carry breaks the build here rather than falling
/// through to a shed nobody configured.
fn on_exhausted_of(pool: &PoolInput) -> OnExhausted {
    match &pool.on_exhausted {
        OnExhaustedInput::Status503 => OnExhausted::Status503,
        OnExhaustedInput::FallbackPool(name) => OnExhausted::FallbackPool(name.clone()),
        OnExhaustedInput::LeastBad => OnExhausted::LeastBad,
        OnExhaustedInput::Queue { max_ms } => OnExhausted::Queue { max_ms: *max_ms },
    }
}

/// Every configured pool, as the egress unit takes them.
///
/// Configuration order throughout: the carrier holds the pools in the order the document declared
/// them and each pool holds its members in the order the document declared them, and both survive
/// into the table. That is not a nicety — the weighted order's rotation and the walk's first pick
/// are both stated against the membership's own order, so a table that reordered would route
/// differently on the first request and identically on every subsequent one, which is the hardest
/// kind of difference to see.
#[must_use]
pub fn hydrate(input: &PlaneBuildInput, seat: SeatLaneName<'_>) -> PoolTable {
    let mut table = PoolTable::new();
    for p in &input.pools {
        table.insert(Pool {
            name: p.name.clone(),
            members: members_of(p, input, seat),
            failover: failover_of(p, input),
            on_exhausted: on_exhausted_of(p),
        });
    }
    table
}

/// The default cell one bare destination name routes on.
///
/// A destination that names no configured pool resolves to the single lane it names, weight one,
/// on the cell with no name. That is the shipping resolution's second arm, and it is a POOL of its
/// own rather than a row in the table above: the table is keyed by pool name and every bare
/// destination shares the one empty name, so one table cannot hold them all at once. The caller
/// asks for the one it is routing.
///
/// `None` when the deployment declares no lane by that name — which is the candidate miss the
/// route step refuses on, and it is answered here as an absence rather than as an empty pool so a
/// caller cannot mistake "nobody configured" for "configured with nobody".
#[must_use]
pub fn default_cell_for(
    input: &PlaneBuildInput,
    destination: &str,
    seat: SeatLaneName<'_>,
) -> Option<Pool> {
    let lane_idx = input.lanes.iter().position(|l| l.model == destination)?;
    let member = PoolMemberInput {
        model: destination.to_string(),
        lane_idx,
        weight: 1,
        reasoning: None,
        attempt_timeout_ms: None,
        tier: None,
        cost_per_mtok: None,
        tags: Vec::new(),
    };
    Some(Pool {
        name: DEFAULT_CELL.to_string(),
        members: vec![member_of(&member, input, seat)],
        failover: match input.default_failover.as_ref() {
            Some(f) => Failover {
                timeout_secs: f.timeout_secs,
                max_hops: f.max_hops,
                exclusions: f.exclusions.clone().unwrap_or_default(),
            },
            None => Failover::default(),
        },
        on_exhausted: OnExhausted::default(),
    })
}

#[cfg(test)]
#[path = "tests/pool_hydration.rs"]
mod tests;
