// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TICK DRIVER, for every kind whose instances keep their own schedule (an auth instance's
//! token refresh, a secret instance's token refresh or version watch): one driver ticket per
//! instance, ticked at each `next_tick_ns` it answers, until it answers `0` or the instance closes.
//!
//! A tick that answers neither READY nor PENDING does not stop the schedule: it is reported
//! (BUSBAR-8029, once, then at most once a minute) and retried on the host's backoff (1 s doubling
//! to 60 s, full jitter). Only a closed or faulted instance ends it.
//!
//! Every end other than the plugin's own `next_tick_ns == 0` (no driver ticket, a READY or PENDING
//! with no frame, a closed or faulted instance) sets the caller's `failed` flag: the schedule has
//! stopped without the plugin asking it to, so the instance must not be carried into the next
//! build (WASTE-AUTH-SECRETS W2).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::diagnostic::PLUGIN_TICK_FAILED;
use busbar_contract::retry::Backoff;

use super::{Dispatcher, Kind, Plugin};

/// The backoff a failed tick is retried on.
pub const TICK_BACKOFF: Backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));

const REPORT_EVERY: Duration = Duration::from_secs(60);

pub async fn ticks<K: Kind>(
    plugin: &Plugin<K>,
    dispatcher: &Dispatcher,
    worker: u32,
    failed: &AtomicBool,
) {
    ticks_on(plugin, dispatcher, worker, TICK_BACKOFF, failed).await;
}

pub(crate) async fn ticks_on<K: Kind>(
    plugin: &Plugin<K>,
    dispatcher: &Dispatcher,
    worker: u32,
    backoff: Backoff,
    failed: &AtomicBool,
) {
    let Some(driver) = dispatcher.driver(plugin, worker) else {
        failed.store(true, Ordering::Release);
        return;
    };
    let _recycled = Recycled { dispatcher, driver };
    let mut schedule = Schedule {
        failures: 0,
        reported: None,
    };
    let mut wait = Wait::Until(0);
    loop {
        pause(wait).await;
        match turn(plugin, dispatcher, driver, backoff, failed, &mut schedule).await {
            Some(next) => wait = next,
            None => return,
        }
    }
}

/// When the next tick is due: at the plugin's own `next_tick_ns`, or a backoff after a failure.
#[derive(Clone, Copy)]
enum Wait {
    Until(u64),
    For(Duration),
}

/// A tick schedule's failure state, carried from turn to turn.
struct Schedule {
    failures: u32,
    /// The dispatch clock reading of the last failure report.
    reported: Option<u64>,
}

/// Wait until the next tick is due.
async fn pause(wait: Wait) {
    match wait {
        Wait::Until(at) => {
            let now = super::now_ns();
            if at > now {
                tokio::time::sleep(Duration::from_nanos(at - now)).await;
            }
        }
        Wait::For(delay) => {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// One tick, judged against the one clock reading taken at its start: when the next is due, or
/// `None` when the schedule ends.
async fn turn<K: Kind>(
    plugin: &Plugin<K>,
    dispatcher: &Dispatcher,
    driver: Ticket,
    backoff: Backoff,
    failed: &AtomicBool,
    schedule: &mut Schedule,
) -> Option<Wait> {
    let now = super::now_ns();
    let done = dispatcher.tick_copy(plugin, driver, now).await;
    match (done.outcome, done.frame.map(|f| f.out.next_tick_ns)) {
        (Outcome::Ready | Outcome::Pending, next) => {
            if schedule.failures > 0 {
                tracing::info!(
                    instance = plugin.name(),
                    kind = ?K::CODE,
                    failures = schedule.failures,
                    "a plugin instance's tick succeeded again; its schedule continues"
                );
            }
            schedule.failures = 0;
            schedule.reported = None;
            match next {
                Some(0) => None,
                Some(next) => Some(Wait::Until(next)),
                None => {
                    failed.store(true, Ordering::Release);
                    tracing::warn!(
                        instance = plugin.name(),
                        kind = ?K::CODE,
                        "a plugin instance's tick answered no frame: its tick schedule has stopped"
                    );
                    None
                }
            }
        }
        (outcome, _) => {
            let ended = !plugin.inner.is_open() || plugin.inner.faulted.load(Ordering::Acquire);
            schedule.failures = schedule.failures.saturating_add(1);
            let failures = schedule.failures;
            let wait = backoff.delay(failures, busbar_contract::retry::unit());
            let due = schedule
                .reported
                .is_none_or(|at| Duration::from_nanos(now.saturating_sub(at)) >= REPORT_EVERY);
            if ended {
                failed.store(true, Ordering::Release);
                tracing::error!(
                    diag = %PLUGIN_TICK_FAILED.banner(),
                    instance = plugin.name(),
                    kind = ?K::CODE,
                    ?outcome,
                    failures,
                    "a plugin instance's tick failed and the instance is closed or faulted: \
                     its tick schedule ends with it"
                );
                return None;
            }
            if due {
                schedule.reported = Some(now);
                tracing::warn!(
                    diag = %PLUGIN_TICK_FAILED.banner(),
                    instance = plugin.name(),
                    kind = ?K::CODE,
                    ?outcome,
                    failures,
                    retry_in_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                    "a plugin instance's tick failed: it is retried with backoff"
                );
            }
            Some(Wait::For(wait))
        }
    }
}

struct Recycled<'a> {
    dispatcher: &'a Dispatcher,
    driver: Ticket,
}

impl Drop for Recycled<'_> {
    fn drop(&mut self) {
        self.dispatcher.recycle(self.driver);
    }
}

/// Spawn `plugin`'s tick driver on the current runtime, else the one the dispatcher was handed;
/// `None` when there is neither (a host with no runtime drives no ticks).
#[must_use]
pub fn spawn<K: Kind>(
    plugin: Arc<Plugin<K>>,
    dispatcher: Arc<Dispatcher>,
    worker: u32,
    failed: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    let runtime = tokio::runtime::Handle::try_current()
        .ok()
        .or_else(|| dispatcher.runtime_handle().cloned())?;
    Some(runtime.spawn(async move { ticks(&plugin, &dispatcher, worker, &failed).await }))
}

#[cfg(test)]
#[path = "tests/auth_ticks_tests.rs"]
mod tests;
