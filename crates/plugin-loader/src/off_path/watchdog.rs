// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `dispatch::watchdog`'s worker replacement: run on the watchdog thread only, once per wedged
//! worker (a crossing that outlived its class budget), never per request. Its one caller is
//! `dispatch::watchdog::scan`; it settles the wedged worker's tickets and starts its successor.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::dispatch::watchdog::breach;
use crate::dispatch::worker::{spawn_worker, Pool, Worker};

pub(crate) fn replace(pool: &Pool, i: usize, old: &Arc<Worker>, started: u64) {
    let (gone, gens, breached, quarantined) = {
        let mut st = old.lock();
        if st.dead || old.crossing_since.load(Ordering::Acquire) != started {
            return;
        }
        let Some(breached) = st.crossing.clone() else {
            return;
        };
        let quarantined = breach(pool, &breached);
        st.dead = true;

        // Its successor's slab generations.
        let gens = crate::cold::dispatch::runtime::successor_counts(&st.entries);
        (Worker::fault_all(&mut st), gens, breached, quarantined)
    };

    if quarantined {
        breached.wake.exports.wake_waiters(breached.wake);
        breached.let_go_held();
    }
    pool.env.services.forget_worker(old.index);
    pool.env.services.held.untrack_worker(old.index);
    // The connections its faulted tickets held.
    let conns = crate::cold::dispatch::runtime::wedged_conns(&gone);
    crate::dispatch::conn_services::forget_worker(&conns, old.index);
    let (orphans, gone) = old.orphans(gone, &breached);
    let (w, rx) = Worker::new(old.index, gens, pool.env.ticket_key);
    *pool.slots[i]
        .current
        .write()
        .unwrap_or_else(|e| e.into_inner()) = w.clone();
    pool.env.stats.replacements.fetch_add(1, Ordering::Relaxed);
    spawn_worker(w, rx, pool.env.clone());

    drop(gone);

    if !orphans.is_empty() {
        let retained = Arc::new(std::sync::Mutex::new(Some(orphans)));
        let crossing = Arc::clone(&retained);
        let spawned = std::thread::Builder::new()
            .name("busbar-orphan-cancel".into())
            .spawn(move || {
                let batch = crossing.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(batch) = batch {
                    batch
                        .into_iter()
                        .for_each(crate::dispatch::worker::Orphan::cancel);
                }
            });
        if spawned.is_err() {
            let batch = retained.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(mut batch) = batch {
                for orphan in &mut batch {
                    orphan.fault_replies();
                }
                std::mem::forget(batch);
                tracing::error!("could not start orphan cancellation; retained still-lent frames");
            }
        }
    }
}
