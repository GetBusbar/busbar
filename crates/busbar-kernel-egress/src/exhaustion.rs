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
    token: &Pass<Route>,
) -> Option<(Member, Permit)> {
    let now = ports.clock.now_secs();
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
