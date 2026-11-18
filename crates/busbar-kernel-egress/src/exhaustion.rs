// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the pool does AFTER the walk finds nowhere to send.

use busbar_contract::caps::{Pass, Route};

use crate::pool::{Member, Pool};
use crate::ports::{Breaker, Permit};
use crate::walk::WalkPorts;

/// The wait a shed advertises when nothing else justifies a longer one, in whole seconds.
pub const AT_CAPACITY_RETRY_AFTER_SECS: u64 = 2;

/// The wait a shed advertises, reflecting the actual reason the pool had nowhere to send.
pub fn retry_after_secs(
    breaker: &dyn Breaker,
    members: &[Member],
    pool: &str,
    now: u64,
    token: &Pass<Route>,
) -> u64 {
    members
        .iter()
        .filter(|m| breaker.admissible(m.destination))
        .map(|m| breaker.cooldown_remaining(pool, m.destination, now, token))
        .filter(|remaining| *remaining > 0)
        .min()
        .unwrap_or(AT_CAPACITY_RETRY_AFTER_SECS)
        .max(1)
}

/// THE LAST RESORT: the member with the soonest cooldown and a free slot, even though it is
pub fn least_bad(
    ports: &WalkPorts<'_>,
    pool: &Pool,
    members: &[Member],
    now: u64,
    token: &Pass<Route>,
) -> Option<(Member, Permit)> {
    // The members in order of soonest cooldown, ties in configured order: each round takes the
    // least `(cooldown, position)` past the last one tried, so nothing is collected or sorted.
    let mut tried: Option<(u64, usize)> = None;
    loop {
        let (rank, member) = members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.weight != 0 && ports.breaker.admissible(m.destination))
            .map(|(position, m)| {
                let cooldown =
                    ports
                        .breaker
                        .cooldown_remaining(&pool.name, m.destination, now, token);
                ((cooldown, position), m)
            })
            .filter(|(rank, _)| tried.is_none_or(|last| *rank > last))
            .min_by_key(|(rank, _)| *rank)?;
        if let Some(permit) = ports.capacity.try_acquire(member.destination) {
            return Some((member.clone(), permit));
        }
        tried = Some(rank);
    }
}
