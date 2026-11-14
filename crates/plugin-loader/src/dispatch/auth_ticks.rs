// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;

use super::kinds::auth::Auth;
use super::{Dispatcher, Plugin};

pub async fn ticks(plugin: &Plugin<Auth>, dispatcher: &Dispatcher, worker: u32) {
    let Some(driver) = dispatcher.driver(plugin, worker) else {
        return;
    };
    let _recycled = Recycled { dispatcher, driver };
    let mut at = None;
    loop {
        if let Some(at) = at {
            // The schedule names an instant on the dispatch clock: wait for it without a reading.
            tokio::time::sleep_until(tokio::time::Instant::from_std(super::instant_at(at))).await;
        }
        match tick(plugin, dispatcher, driver).await {
            Some(next) => at = Some(next),
            None => return,
        }
    }
}

/// One scheduled tick: the op reads the dispatch clock once, at its entry, and answers the next
/// tick's instant, or `None` when the schedule has stopped.
async fn tick(plugin: &Plugin<Auth>, dispatcher: &Dispatcher, driver: Ticket) -> Option<u64> {
    let done = dispatcher.tick_copy(plugin, driver, super::now_ns()).await;
    match (done.outcome, done.frame.map(|f| f.out.next_tick_ns)) {
        (Outcome::Ready | Outcome::Pending, Some(next)) if next != 0 => Some(next),
        (Outcome::Ready | Outcome::Pending, _) => None,
        (outcome, _) => {
            tracing::warn!(
                instance = plugin.name(),
                ?outcome,
                "auth tick failed: the refresh schedule for this instance has stopped"
            );
            None
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
) -> Option<tokio::task::JoinHandle<()>> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    Some(runtime.spawn(async move { ticks(&plugin, &dispatcher, worker).await }))
}

#[cfg(test)]
#[path = "tests/auth_ticks_tests.rs"]
mod tests;
