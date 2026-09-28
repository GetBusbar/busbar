// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CROSSING WATCHDOG, in every build. A crossing never blocks by contract; one that has not
//! RETURNED within its class budget (`Budgets`) is a wedged plugin, and the watchdog:
//!
//! 1. marks the INSTANCE faulted — it is never called again; every later op on it, on any worker,
//!    answers FAULT without a crossing (a pending op resumed or cancelled on another worker too);
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

use super::ticket::next_generation;
use super::worker::{spawn_worker, Pool, Worker};

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
            .map(|c| c.instance.clone());
        if let Some(instance) = hung {
            instance.faulted.store(true, Ordering::Release);
            replace(pool, i, &w);
        }
    }
}

fn replace(pool: &Pool, i: usize, old: &Arc<Worker>) {
    let (gone, gens) = {
        let mut st = old.lock();
        if st.dead {
            return;
        }
        st.dead = true;
        let gens: Vec<u32> = st
            .entries
            .iter()
            .map(|e| next_generation(e.generation))
            .collect();
        (Worker::fault_all(&mut st), gens)
    };
    pool.env.completions.forget_worker(old.index);
    let (w, rx) = Worker::new(old.index, gens);
    *pool.slots[i]
        .current
        .write()
        .unwrap_or_else(|e| e.into_inner()) = w.clone();
    pool.env.stats.replacements.fetch_add(1, Ordering::Relaxed);
    spawn_worker(w, rx, pool.env.clone());
    // Only now, with the fresh worker serving: every `Meta` settles its reply as FAULT as it drops
    // and gives back what it held, so a caller that sees the FAULT finds the new worker in place.
    drop(gone);
}
