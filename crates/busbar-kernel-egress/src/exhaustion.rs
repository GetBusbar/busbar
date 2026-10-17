// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the pool does AFTER the walk finds nowhere to send.
//!
//! Nothing in this module is a second selection loop and nothing here decides who is healthy. The
//! spill re-enters the walk's one pick against another pool; the wait parks for a bounded time and
//! then re-asks the same admission every path asks; the last-resort route is the ONE documented
//! breaker bypass in the unit and it says so by owning no probe; and the shed is a refusal with an
//! honest wait computed from the pool's own members. The walk ([`crate::walk::Walk`]) runs them in
//! that order and marks every dispatch they make degraded: an upstream's own answer is relayed to
//! the client as it came, and only an attempt that produced no answer at all moves on.

use busbar_contract::caps::{Pass, Route};

use crate::pool::{Member, Pool};
use crate::ports::{Breaker, Permit};
use crate::walk::WalkPorts;

/// The wait a shed advertises when nothing else justifies a longer one, in whole seconds.
///
/// A busy concurrency slot has no scheduled recovery the way a cooldown does, so there is no
/// window to quote. Advertising the bare one-second floor reads to a rate-aware client as "retry
/// immediately", which just collides with the same saturation again; a small non-trivial floor
/// asks it to back off briefly instead. Saturation is the COMMON shed, so this must not be one.
pub const AT_CAPACITY_RETRY_AFTER_SECS: u64 = 2;

/// The wait a shed advertises, reflecting the actual reason the pool had nowhere to send.
///
/// Exhaustion has two causes and they want different backoff, so they are separated here.
///
/// If any usable member has a GENUINE cooldown still to run, advertise the soonest of them: the
/// client should come back when a benched member is due to be probed again. A member that is
/// merely at capacity reports no cooldown, and its zero is ignored here rather than being taken as
/// the minimum — which is what used to let one busy member mask a sibling in a long cooldown.
///
/// Otherwise advertise the floor above. That covers saturation, and it also covers the case where
/// there are no members to read at all — a spill that looped back on itself, or one aimed at a
/// pool that was never configured. An empty candidate set is exactly where least is known about
/// when a slot frees, so it gets the honest floor and never the deceptive bare one.
///
/// Always at least one second, because a zero-second wait means nothing.
pub fn retry_after_secs(
    breaker: &dyn Breaker,
    members: &[Member],
    pool: &str,
    now: u64,
    token: &Pass<Route>,
) -> u64 {
    members
        .iter()
        // A member that is dead or out of lifetime budget sits outside the cooldown machinery
        // entirely and reports zero, so filter to the usable ones exactly as the shed always did.
        .filter(|m| breaker.admissible(m.destination))
        .map(|m| breaker.cooldown_remaining(pool, m.destination, now, token))
        .filter(|remaining| *remaining > 0)
        .min()
        .unwrap_or(AT_CAPACITY_RETRY_AFTER_SECS)
        .max(1)
}

/// THE LAST RESORT: the member with the soonest cooldown and a free slot, even though it is
/// suppressed.
///
/// This is the ONE documented breaker bypass in the unit, and two details of it matter.
///
/// It ranks by soonest cooldown and then takes the first member with a FREE slot, rather than
/// insisting on the single best one. The soonest member may itself be at capacity, and refusing
/// outright because the best member is momentarily busy — while a slightly worse sibling is idle —
/// defeats the whole point of a last resort. Members that are dead or out of budget are filtered
/// first, so their zero cooldown never sorts them to the front.
///
/// It owns NO probe and the walk passes none on: handing it the cell's current epoch instead would
/// be actively unsafe, since a half-open cell's epoch may be a PEER's, and an owner-checked release
/// keyed on it would revert the peer's live probe.
pub fn least_bad(
    ports: &WalkPorts<'_>,
    pool: &Pool,
    token: &Pass<Route>,
) -> Option<(Member, Permit)> {
    let now = ports.clock.now_secs();
    let members = pool.admissible_members();
    let mut ranked: Vec<&Member> = members
        .iter()
        .filter(|m| ports.breaker.admissible(m.destination))
        .collect();
    ranked.sort_by_key(|m| {
        ports
            .breaker
            .cooldown_remaining(&pool.name, m.destination, now, token)
    });
    ranked.into_iter().find_map(|m| {
        ports
            .capacity
            .try_acquire(m.destination)
            .map(|p| ((*m).clone(), p))
    })
}
