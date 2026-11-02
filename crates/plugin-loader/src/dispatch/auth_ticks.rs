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
    let mut at = 0;
    loop {
        let now = super::now_ns();
        if at > now {
            tokio::time::sleep(std::time::Duration::from_nanos(at - now)).await;
        }

        let done = dispatcher.tick_copy(plugin, driver, super::now_ns()).await;
        match (done.outcome, done.frame.map(|f| f.out.next_tick_ns)) {
            (Outcome::Ready | Outcome::Pending, Some(next)) if next != 0 => at = next,
            _ => return,
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
