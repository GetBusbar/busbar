// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE SHUTDOWN TAIL. Every way the process stops serving ends here, once, before it exits:
//! the listener path after its graceful drain, and the line-serve mode (busbar as a child process
//! speaking on stdin/stdout) at stdin EOF. What the caller was already answered for has to reach
//! the store before the process is gone, whichever transport the answer went out on (ruling H2
//! U10; BUSBAR-1.6.0.md THE DESIGN, §7):
//!
//! 1. the budget and metering write-behind, each final flush awaited off the runtime;
//! 2. the plane record write-behind, drained ([`crate::root::serve::drain_records`]);
//! 3. the journal's lane to the configured store, drained under the same deadline
//!    ([`crate::root::serve::RECORD_DRAIN`]): on a node with no data directory the store is where
//!    the chain is kept, so a record still queued at exit is a settled unit the store never saw —
//!    and so is one the journal still holds back after a full lane turned it away, which is
//!    re-offered each time the lane empties;
//! 4. the node's lease on its host name, released, so the host's next boot resumes its chain.
//!
//! Two tails were two lists, and the line-serve one had lost steps 2 and 3 (audit busbar-src #1).
//! One function is one list.

use std::sync::{Arc, Mutex};

use busbar_kernel::governance::GovState;

use crate::root::durability::Durability;
use crate::root::serve::{drain_records, LateServices, RECORD_DRAIN};

/// Run the shutdown tail: flush `governance`'s write-behind, drain the plane records `late`
/// queued, then drain the journal lane of the book `journal` holds (a book over the configured
/// store has one; none, or a book with no lane, has nothing queued). Governance waits for its store
/// calls to return; the record drains retain their deadlines. Failures are logged, never fatal.
pub async fn tail(
    governance: Option<Arc<GovState>>,
    late: &LateServices,
    journal: Option<&Arc<Mutex<Durability>>>,
) {
    // The background flusher is not joined by either caller. Own and await the final writes here
    // before retiring records and the host lease. Store progress may require this runtime, so the
    // synchronous final methods run on the blocking pool. A failed write reports terminal loss;
    // completion of the attempt alone does not promise persistence.
    if let Some(gov) = governance {
        let budgets = gov.clone();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        match tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || budgets.flush_budgets_final())
        })
        .await
        {
            Ok(n) => tracing::info!(flushed = n, "budget shutdown flush completed"),
            Err(error) => tracing::error!(
                panicked = error.is_panic(),
                cancelled = error.is_cancelled(),
                "budget shutdown flush task failed"
            ),
        }
        // A budget task panic must not skip the independent metering flush or record retirement.
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        match tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || gov.flush_metering_final())
        })
        .await
        {
            Ok(n) => tracing::info!(flushed = n, "metering shutdown flush completed"),
            Err(error) => tracing::error!(
                panicked = error.is_panic(),
                cancelled = error.is_cancelled(),
                "metering shutdown flush task failed"
            ),
        }
    }
    // THE PLANE RECORD WRITE-BEHIND, drained before the store closes.
    if !drain_records(late).await {
        tracing::warn!("plane record writes were still queued at shutdown");
    }
    // THE JOURNAL'S LANE TO THE STORE, drained the same way and under the same deadline — with
    // what the journal holds back after a full lane turned it away: that batch is outside the lane,
    // so it is re-offered before each drain until the journal holds nothing back (audit root r4
    // B-6). An empty lane takes it whole, so a drained lane is followed by one more offer at most.
    let Some(book) = journal else {
        return;
    };
    let Some(lane) = book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .lane()
        .cloned()
    else {
        return;
    };
    let until = std::time::Instant::now() + RECORD_DRAIN;
    let drained = loop {
        let held = book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .offer_held_back();
        let draining = lane.clone();
        let left = until.saturating_duration_since(std::time::Instant::now());
        let drained = tokio::task::spawn_blocking(move || draining.drain(left))
            .await
            .unwrap_or(false);
        if held == 0 || !drained || std::time::Instant::now() >= until {
            break drained && held == 0;
        }
    };
    if !drained {
        tracing::warn!("journal records were still queued for the store at shutdown");
        return;
    }
    // THE NODE'S LEASE ON ITS HOST NAME, held on that lane, released once its chain reached the
    // store, so the next boot of this host resumes it at once. Off the runtime: it waits on
    // the store.
    let _released = tokio::task::spawn_blocking(move || lane.release_held_lease()).await;
}

#[cfg(test)]
#[path = "tests/shutdown.rs"]
mod tests;
