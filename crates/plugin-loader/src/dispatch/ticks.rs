// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TICK DRIVER, for every kind whose instances keep their own schedule (an auth instance's
//! token refresh, a secret instance's token refresh or version watch): one driver ticket per
//! instance, ticked at each `next_tick_ns` it answers, until it answers `0` or the instance closes.
//!
//! A tick that answers neither READY nor PENDING does not stop the schedule: it is reported
//! (BUSBAR-8029, once, then at most once a minute) and retried on the host's backoff (1 s doubling
//! to 60 s, full jitter). Only a closed or faulted instance ends it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::diagnostic::PLUGIN_TICK_FAILED;
use busbar_contract::retry::Backoff;

use super::{Dispatcher, Kind, Plugin};

/// The backoff a failed tick is retried on.
pub const TICK_BACKOFF: Backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));

const REPORT_EVERY: Duration = Duration::from_secs(60);

pub async fn ticks<K: Kind>(plugin: &Plugin<K>, dispatcher: &Dispatcher, worker: u32) {
    ticks_on(plugin, dispatcher, worker, TICK_BACKOFF).await;
}

pub(crate) async fn ticks_on<K: Kind>(
    plugin: &Plugin<K>,
    dispatcher: &Dispatcher,
    worker: u32,
    backoff: Backoff,
) {
    let Some(driver) = dispatcher.driver(plugin, worker) else {
        return;
    };
    let _recycled = Recycled { dispatcher, driver };
    let mut at = 0;
    let mut failures = 0_u32;
    let mut reported: Option<Instant> = None;
    loop {
        let now = super::now_ns();
        if at > now {
            tokio::time::sleep(Duration::from_nanos(at - now)).await;
        }

        let done = dispatcher.tick_copy(plugin, driver, super::now_ns()).await;
        match (done.outcome, done.frame.map(|f| f.out.next_tick_ns)) {
            (Outcome::Ready | Outcome::Pending, next) => {
                if failures > 0 {
                    tracing::info!(
                        instance = plugin.name(),
                        kind = ?K::CODE,
                        failures,
                        "a plugin instance's tick succeeded again; its schedule continues"
                    );
                }
                failures = 0;
                reported = None;
                match next {
                    Some(next) if next != 0 => at = next,
                    _ => return,
                }
            }
            (outcome, _) => {
                let ended = !plugin.inner.is_open()
                    || plugin
                        .inner
                        .faulted
                        .load(std::sync::atomic::Ordering::Acquire);
                failures = failures.saturating_add(1);
                let wait = backoff.delay(failures, busbar_contract::retry::unit());
                let due = reported.is_none_or(|at| at.elapsed() >= REPORT_EVERY);
                if ended {
                    tracing::error!(
                        diag = %PLUGIN_TICK_FAILED.banner(),
                        instance = plugin.name(),
                        kind = ?K::CODE,
                        ?outcome,
                        failures,
                        "a plugin instance's tick failed and the instance is closed or faulted: \
                         its tick schedule ends with it"
                    );
                    return;
                }
                if due {
                    reported = Some(Instant::now());
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
                at = super::now_ns()
                    .saturating_add(u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX));
            }
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
) -> Option<tokio::task::JoinHandle<()>> {
    let runtime = tokio::runtime::Handle::try_current()
        .ok()
        .or_else(|| dispatcher.runtime_handle().cloned())?;
    Some(runtime.spawn(async move { ticks(&plugin, &dispatcher, worker).await }))
}

#[cfg(test)]
#[path = "tests/auth_ticks_tests.rs"]
mod tests;
