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
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::DeadlineClass;

use super::plugin::Instance;
use super::worker::{spawn_worker, Pool, Worker};

/// Count one breach against `inst`; quarantine it on the pool's Nth. `true` when the instance is
/// quarantined now (by this breach or an earlier one).
fn breach(pool: &Pool, inst: &Instance) -> bool {
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
    // A quarantine is a FAULT AND REVOKE: its handle names nothing any more.
    inst.revoke();
    true
}

/// Start the watchdog of `pool`; it ends when the pool does.
pub(crate) fn spawn(pool: Weak<Pool>, period: Duration) {
    std::thread::Builder::new()
        .name("busbar-dispatch-watchdog".into())
        .spawn(move || loop {
            std::thread::sleep(period);
            let Some(pool) = pool.upgrade() else {
                return;
            };
            if pool.stop.load(Ordering::Acquire) {
                return;
            }
            scan(&pool);
        })
        .expect("spawn the dispatch watchdog");
}

fn scan(pool: &Pool) {
    for (i, slot) in pool.slots.iter().enumerate() {
        let w = slot.get();
        let hung = w
            .crossing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|c| c.started.elapsed() > c.budget)
            .map(|c| c.started);
        if let Some(started) = hung {
            replace(pool, i, &w, started);
        }
    }
    ticketless(pool);
}

/// The ticket-less crossings of every adopted instance: one past its budget faults its instance
/// (a caller's thread cannot be replaced; the instance is never called again).
fn ticketless(pool: &Pool) {
    let mut adopted = pool.adopted.lock().unwrap_or_else(|e| e.into_inner());
    adopted.retain(|w| w.strong_count() > 0);
    let live: Vec<_> = adopted
        .iter()
        .filter_map(std::sync::Weak::upgrade)
        .collect();
    drop(adopted);
    for inst in live {
        // Each hung call is ONE breach, however many scans see it hung: only calls at or above
        // the instance's counted mark are new.
        let from = inst.ticketless_counted.load(Ordering::Acquire);
        let fresh: Vec<u64> = inst
            .lock_calls()
            .iter()
            .filter(|&&(id, started, s)| {
                id >= from && started.elapsed() > pool.env.budgets.of(s, DeadlineClass::Call)
            })
            .map(|&(id, _, _)| id)
            .collect();
        let Some(&last) = fresh.iter().max() else {
            continue;
        };
        inst.ticketless_counted
            .fetch_max(last + 1, Ordering::AcqRel);
        let mut quarantined = false;
        for _ in &fresh {
            quarantined = breach(pool, &inst);
        }
        if quarantined {
            // A quarantined instance never crosses again: its connector streams go now.
            if let Some((id, table)) = inst.wake.conn.get() {
                super::conn_services::purge(*id, table);
            }
        }
    }
}

/// Replace worker `i` if it is STILL inside the crossing that began at `started`: re-checked under
/// the state lock and the crossing lock, so a crossing that returned meanwhile is never faulted.
fn replace(pool: &Pool, i: usize, old: &Arc<Worker>, started: Instant) {
    let (gone, gens, breached, quarantined) = {
        let mut st = old.lock();
        if st.dead {
            return;
        }
        let crossing = old.crossing.lock().unwrap_or_else(|e| e.into_inner());
        let Some(record) = crossing.as_ref().filter(|c| c.started == started) else {
            return;
        };
        let quarantined = breach(pool, &record.instance);
        let breached = Arc::clone(&record.instance);
        drop(crossing);
        st.dead = true;
        // Every slot's next mint counter; a spent one RETIRED (`None`), never handed out again.
        let gens: Vec<Option<u32>> = st
            .entries
            .iter()
            .map(|e| super::worker::next_count(e.count))
            .collect();
        (Worker::fault_all(&mut st), gens, breached, quarantined)
    };
    // A quarantined instance never crosses again: its connector streams go now, outside the locks.
    if quarantined {
        if let Some((id, table)) = breached.wake.conn.get() {
            super::conn_services::purge(*id, table);
        }
    }
    pool.env.services.forget_worker(old.index);
    pool.env.services.held.untrack_worker(old.index);
    let conns: Vec<_> = gone.iter().flat_map(|e| e.conns.iter().copied()).collect();
    super::conn_services::forget_worker(&conns, old.index);
    let (orphans, gone) = old.orphans(gone, &breached);
    let (w, rx) = Worker::new(old.index, gens, pool.env.ticket_key);
    *pool.slots[i]
        .current
        .write()
        .unwrap_or_else(|e| e.into_inner()) = w.clone();
    pool.env.stats.replacements.fetch_add(1, Ordering::Relaxed);
    spawn_worker(w, rx, pool.env.clone());
    // Only now, with the fresh worker serving: every `Meta` settles its reply as FAULT as it drops
    // and gives back what it held, so a caller that sees the FAULT finds the new worker in place.
    drop(gone);
    // A healthy instance's pending op is told it ended (`cancel`) before its frame and lent memory
    // go: off the watchdog's thread, so a `cancel` that hangs never stops the watchdog (the
    // ticket-less watch judges it). A thread that cannot be started drops them as before.
    if !orphans.is_empty() {
        let _ = std::thread::Builder::new()
            .name("busbar-orphan-cancel".into())
            .spawn(move || orphans.into_iter().for_each(super::worker::Orphan::cancel));
    }
}
