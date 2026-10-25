// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CROSSING WATCHDOG, in every build. A crossing never blocks by contract; one that has not
//! RETURNED within its class budget (`Budgets`), or its op's own longer watch budget, is a BREACH,
//! a wedged plugin, and the watchdog:
//!
//! 1. counts the breach against the INSTANCE, and on its Nth (`DispatchConfig::quarantine_after`,
//!    THE DESIGN A.8) QUARANTINES it: it is never called again; every later op on it answers
//!    FAULT without a crossing (a pending op resumed or cancelled too), its connector streams go, a
//!    diagnostic names it, and `bb_plugin_quarantined_total`
//!    ([`super::DispatchStats::quarantined`]) counts it. Below N the instance keeps serving. A hook
//!    comes back out of quarantine through its door's timed trial (R2, `hook_door`);
//! 2. answers the breached crossing's op FAULT now, whatever N: the crossing runs on, owning its
//!    frame and what it was lent, and ends the op when it returns.
//!
//! The hung thread cannot be killed. It keeps the op's frame and the instance (so the library stays
//! mapped) until the plugin returns, if ever. Nothing it held is freed under the plugin.

use std::sync::atomic::Ordering;
use std::sync::Weak;
use std::time::Duration;

use super::dispatcher::Pool;
use super::plugin::Instance;

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
            "plugin crossing outlived its watch budget; the op is FAULT"
        );
        return inst.faulted.load(Ordering::Acquire);
    }
    if !inst.faulted.swap(true, Ordering::AcqRel) {
        pool.env.stats.quarantined.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            plugin = inst.name(),
            breaches = n,
            metric = super::dispatcher::QUARANTINED_TOTAL,
            "plugin quarantined: every new call answers FAULT without a crossing"
        );
    }
    // A quarantine is a FAULT AND REVOKE (#74): its handle names nothing any more.
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

/// The crossings of every adopted instance: one past its budget is a breach.
fn scan(pool: &Pool) {
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
        let fresh: Vec<(u64, Option<super::plugin::Breach>)> = inst
            .lock_calls()
            .iter()
            .filter(|c| {
                c.id >= from
                    && c.started.elapsed() > pool.env.budgets.of(c.slot, c.class).max(c.watch)
            })
            .map(|c| (c.id, c.breach.clone()))
            .collect();
        let Some(last) = fresh.iter().map(|(id, _)| *id).max() else {
            continue;
        };
        inst.ticketless_counted
            .fetch_max(last + 1, Ordering::AcqRel);
        let mut quarantined = false;
        for (_, told) in &fresh {
            quarantined = breach(pool, &inst);
            // The breached crossing's op is answered FAULT now; the crossing runs on, owning what
            // it was lent, and ends the op when it returns.
            if let Some(tell) = told {
                tell();
            }
        }
        if quarantined {
            // A quarantined instance never crosses again: its connector streams go now.
            if let Some((id, table)) = inst.wake.conn.get() {
                super::conn_services::purge(*id, table);
            }
        }
    }
}
