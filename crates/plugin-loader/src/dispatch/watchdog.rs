// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CROSSING WATCHDOG, in every build. A crossing never blocks by contract; one that has not
//! RETURNED within its class budget (`Budgets`) is a BREACH, a wedged plugin, and the watchdog:
//!
//! 1. counts the breach against the INSTANCE, and on its Nth (`DispatchConfig::quarantine_after`,
//!    THE DESIGN A.8) QUARANTINES it: it is never called again; every later op on it, on any
//!    worker, answers FAULT without a crossing (a pending op resumed or cancelled on another worker
//!    too), its connector streams go, a diagnostic names it, and `bb_plugin_quarantined_total`
//!    ([`super::DispatchStats::quarantined`]) counts it. Below N the instance keeps serving; the
//!    breach's own op and worker are settled by 2 and 3 all the same. A hook comes back out of
//!    quarantine through its door's timed trial (R2, `hook_door`);
//! 2. marks the WORKER dead and settles EVERY ticket it held as FAULT — the hung op, every pending
//!    and queued op of any instance on that worker, and its driver tickets (which stop driving);
//!    their `max_inflight` units, drain counts and lifecycle exclusions are given back, their
//!    completion handles are forgotten;
//! 3. starts a fresh worker at the same index, its slab's every generation bumped, so no ticket of
//!    the old worker (and no late wake for one) can ever name a ticket of the new one.
//!
//! The hung thread cannot be killed. It keeps the op's frame and the instance (so the library stays
//! mapped) until the plugin returns, if ever; it then sees its worker is dead and exits without
//! touching any state. Nothing it held is freed under the plugin.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::DeadlineClass;

use super::plugin::Instance;
use super::worker::Pool;

pub(crate) fn breach(pool: &Pool, inst: &Instance) -> bool {
    let n = inst
        .breaches
        .fetch_add(1, Ordering::AcqRel)
        .saturating_add(1);
    let of = pool.env.quarantine_after;
    if n < of {
        tracing::warn!(
            plugin = inst.name(),
            breach = n,
            quarantine_after = of,
            "plugin crossing outlived its watch budget; its worker is replaced and the op is FAULT"
        );
        return inst.faulted.load(Ordering::Acquire);
    }
    if !inst.faulted.swap(true, Ordering::AcqRel) {
        pool.env.stats.quarantined.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            plugin = inst.name(),
            breaches = n,
            metric = super::worker::QUARANTINED_TOTAL,
            "plugin quarantined: every new call answers FAULT without a crossing"
        );
    }

    inst.revoke();
    true
}

/// Wakes at the earliest deadline its own last scan saw, never sooner than `period` and never later
/// than `min_budget` (the smallest class budget), so a crossing that started after a scan is seen no
/// later than today's fixed-period poll would: its deadline is at least `min_budget` away. Workers
/// publish nothing new; only this thread computes its wake.
pub(crate) fn spawn(pool: Weak<Pool>, period: Duration, min_budget: Duration) {
    std::thread::Builder::new()
        .name("busbar-dispatch-watchdog".into())
        .spawn(move || {
            // The sweep's scratch: one buffer for the watchdog thread's life, cleared per scan.
            let mut live = crate::cold::dispatch::runtime::watchdog_scratch();
            let mut next = next_wake(period, min_budget, None);
            loop {
                std::thread::sleep(next);
                let Some(pool) = pool.upgrade() else {
                    return;
                };
                if pool.stop.load(Ordering::Acquire) {
                    return;
                }
                next = next_wake(period, min_budget, scan(&pool, &mut live));
            }
        })
        .expect("spawn the dispatch watchdog");
}

/// `max(period, min(earliest, min_budget))`.
pub(crate) fn next_wake(
    period: Duration,
    min_budget: Duration,
    earliest: Option<Duration>,
) -> Duration {
    earliest
        .map_or(min_budget, |e| e.min(min_budget))
        .max(period)
}

/// Scan every slot and ticketless call; answer the time until the earliest deadline still owed.
fn scan(pool: &Pool, live: &mut Vec<Arc<Instance>>) -> Option<Duration> {
    pool.env
        .stats
        .watchdog_scans
        .fetch_add(1, Ordering::Relaxed);
    // One clock read per sweep: every crossing and every ticketless call is judged against it.
    let now = super::now_ns();
    let mut earliest: Option<Duration> = None;
    for (i, slot) in pool.slots.iter().enumerate() {
        let w = slot.get();
        let started = w.crossing_since.load(Ordering::Acquire);
        let budget = w.crossing_budget.load(Ordering::Relaxed);
        if started == 0 {
            continue;
        }
        let elapsed = now.saturating_sub(started);
        if elapsed > budget {
            crate::off_path::watchdog::replace(pool, i, &w, started);
        } else {
            let left = Duration::from_nanos(budget - elapsed);
            earliest = Some(earliest.map_or(left, |e| e.min(left)));
        }
    }
    if let Some(left) = ticketless(pool, now, live) {
        earliest = Some(earliest.map_or(left, |e| e.min(left)));
    }
    earliest
}

fn ticketless(pool: &Pool, now: u64, live: &mut Vec<Arc<Instance>>) -> Option<Duration> {
    live.clear();
    // One pass both drops the dead adoptions and takes the live ones.
    crate::cold::dispatch::runtime::live_adoptions(&pool.adopted, live);
    let now = super::instant_at(now);
    let mut earliest: Option<Duration> = None;
    for inst in live.drain(..) {
        let fresh = {
            let mut calls = inst.lock_calls();
            let mut fresh = 0;
            for (started, slot, counted) in calls.values_mut() {
                if *counted {
                    continue;
                }
                let budget = pool.env.budgets.of(*slot, DeadlineClass::Call);
                let elapsed = now.saturating_duration_since(*started);
                if elapsed > budget {
                    *counted = true;
                    fresh += 1;
                } else {
                    let left = budget - elapsed;
                    earliest = Some(earliest.map_or(left, |e| e.min(left)));
                }
            }
            fresh
        };
        let mut quarantined = false;
        for _ in 0..fresh {
            quarantined = breach(pool, &inst);
        }
        if quarantined {
            inst.wake.exports.wake_waiters(inst.wake);

            inst.let_go_held();
        }
    }
    earliest
}

#[cfg(test)]
#[path = "watchdog_tests.rs"]
mod tests;
