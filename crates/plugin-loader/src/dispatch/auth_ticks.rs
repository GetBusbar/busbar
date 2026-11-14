// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;

use super::kinds::auth::Auth;
use super::{Dispatcher, Plugin};

/// Tick `plugin` on its own schedule until it answers `next_tick_ns == 0`. Every other end (no
/// driver ticket, a failed tick, a Ready/Pending with no frame) sets `failed`: the schedule has
/// stopped without the plugin asking it to, so the instance must not be carried into the next
/// build (WASTE-AUTH-SECRETS W2).
pub async fn ticks(
    plugin: &Plugin<Auth>,
    dispatcher: &Dispatcher,
    worker: u32,
    failed: &AtomicBool,
) {
    let Some(driver) = dispatcher.driver(plugin, worker) else {
        failed.store(true, Ordering::Release);
        return;
    };
    let _recycled = Recycled { dispatcher, driver };
    let mut at = 0;
    loop {
        let now = super::now_ns();
        if at > now {
            tokio::time::sleep(std::time::Duration::from_nanos(at - now)).await;
        }

        let done = dispatcher.tick_copy(plugin, driver, super::now_ns()).await;
        match (done.outcome, done.frame.map(|f| f.out.next_tick_ns)) {
            (Outcome::Ready | Outcome::Pending, Some(0)) => return,
            (Outcome::Ready | Outcome::Pending, Some(next)) => at = next,
            (Outcome::Ready | Outcome::Pending, None) => {
                failed.store(true, Ordering::Release);
                tracing::warn!(
                    instance = plugin.name(),
                    "auth tick answered no frame: the refresh schedule for this instance has stopped"
                );
                return;
            }
            (outcome, _) => {
                failed.store(true, Ordering::Release);
                tracing::warn!(
                    instance = plugin.name(),
                    ?outcome,
                    "auth tick failed: the refresh schedule for this instance has stopped"
                );
                return;
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

#[must_use]
pub fn spawn(
    plugin: Arc<Plugin<Auth>>,
    dispatcher: Arc<Dispatcher>,
    worker: u32,
    failed: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    Some(runtime.spawn(async move { ticks(&plugin, &dispatcher, worker, &failed).await }))
}

#[cfg(test)]
#[path = "tests/auth_ticks_tests.rs"]
mod tests;
