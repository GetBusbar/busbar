// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE AUTH INSTANCE'S TICK SCHEDULE, ON THE ONE CLOCK (THE DESIGN: "one clock, which also drives
//! every plugin's `tick`"; the auth kind's lifecycle includes `tick`): [`ticks`] is the one schedule
//! both directions run. An outbound instance's refreshes a minted credential ahead of expiry
//! ([`super::auth_outbound::OutboundInstance::ticks`]); an inbound instance's refreshes its key set
//! ahead of the TTL (`crate::auth_door::AuthInstance`, started at its open by [`spawn`]).

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::Outcome;

use super::kinds::auth::Auth;
use super::{Dispatcher, Plugin};

/// THE INSTANCE'S TICK SCHEDULE, on its driver ticket: `tick` at once, then at each `next_tick_ns`
/// it answers, on the dispatcher's clock; it ends when an answer names `0`, is not READY or
/// PENDING, or no driver ticket can be minted. It waits on the runtime's timer and holds no
/// `max_inflight` slot; what pends inside a tick goes on through `drive`, which its wakes call.
pub async fn ticks(plugin: &Plugin<Auth>, dispatcher: &Dispatcher, worker: u32) {
    let Some(driver) = dispatcher.driver(plugin, worker) else {
        return;
    };
    let mut at = 0;
    loop {
        let now = super::now_ns();
        if at > now {
            tokio::time::sleep(std::time::Duration::from_nanos(at - now)).await;
        }
        let done = dispatcher.tick(plugin, driver, super::now_ns()).await;
        match (done.outcome, done.frame.map(|f| f.out.next_tick_ns)) {
            (Outcome::Ready | Outcome::Pending, Some(next)) if next != 0 => at = next,
            _ => return,
        }
    }
}

/// [`ticks`] for `plugin`, spawned on the runtime the caller runs on; `None` off any runtime. The
/// handle stops the schedule when it is aborted (the instance retired or replaced).
#[must_use]
pub fn spawn(
    plugin: Plugin<Auth>,
    dispatcher: Arc<Dispatcher>,
    worker: u32,
) -> Option<tokio::task::JoinHandle<()>> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    Some(runtime.spawn(async move { ticks(&plugin, &dispatcher, worker).await }))
}

#[cfg(test)]
#[path = "tests/auth_ticks_tests.rs"]
mod tests;
