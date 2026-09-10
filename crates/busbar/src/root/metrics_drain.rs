// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The maintenance drain: the loop that runs the kernel's maintenance tick.
//!
//! THE INVARIANT it exists for is not this file's — it is stated where the drain itself lives
//! (`busbar_substrate::metrics`): an observation costs BOUNDED memory whether or not anyone ever
//! scrapes `/metrics`. Two layers buffer raw per-request samples on the way to their aggregate
//! form, and both used to fold only inside `render()`, i.e. only when a scrape arrived. A gateway
//! nobody scrapes therefore retained one `f64` per request forever.
//!
//! WHAT WAS WRONG WITH THE FIX. The tick that closed that leak was a raw `std::thread::Builder`
//! detached OS thread — `loop { sleep(interval); drain_pending(); }` — spawned from the recorder
//! install. No join handle, no supervision, and no shutdown arm: the process could not stop it, and
//! on every exit whatever had buffered since its last sleep was dropped. That is the last interval
//! of observations before a shutdown, which is the interval an operator diagnosing a shutdown most
//! wants.
//!
//! WHAT IS HERE. The DECISION is [`maintenance_tick`] — `Idle`, `Drain` or
//! `Final`, with `stopping` winning over the interval so the final fold is never skipped by a stop
//! that lands mid-interval. The LOOP is a task like every other background task of this process,
//! on the same shutdown broadcast, and it returns when that broadcast fires. The CADENCE is what
//! `metrics::configure` handed back, derived beside the retention window it comes from rather than
//! re-divided here.

use std::time::Duration;

use busbar_kernel::tick::{maintenance_tick, Maintenance};

/// Run the maintenance tick until the shutdown broadcast fires, then fold one last time.
///
/// `interval` is the drain cadence `metrics::configure` returned — one rolling bucket of the
/// operator's declared retention window. `drain` is the fold itself, taken as a function rather
/// than named here so this loop is exactly the loop and can be driven in a test against a counter.
///
/// Returns the number of drains it ran, the final one included, so a caller (or a test) can say
/// what the tick actually did rather than assume it.
pub async fn run<F>(
    interval: Duration,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    drain: F,
) -> u64
where
    F: Fn(),
{
    let interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
    let mut drains = 0u64;
    loop {
        // One sleep, one stop arm, and the decision between them. `select!` here is what the
        // detached thread could not have: the stop is a first-class arm of the wait, so a shutdown
        // that lands one millisecond into a twenty-minute sleep is answered in that millisecond
        // instead of twenty minutes later or, as it was, never.
        let stopping = tokio::select! {
            _ = tokio::time::sleep(interval) => false,
            _ = shutdown.recv() => true,
        };
        match maintenance_tick(interval_ms, interval_ms, stopping) {
            Maintenance::Idle => {}
            Maintenance::Drain => {
                drain();
                drains += 1;
            }
            Maintenance::Final => {
                drain();
                drains += 1;
                return drains;
            }
        }
    }
}
