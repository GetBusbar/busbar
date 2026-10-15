// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE SHUTDOWN TAIL. Every way the process stops serving ends here, once, before it exits:
//! the listener path after its graceful drain, and the line-serve mode (busbar as a child process
//! speaking on stdin/stdout) at stdin EOF. What the caller was already answered for has to reach
//! the store before the process is gone, whichever transport the answer went out on (ruling H2
//! U10; BUSBAR-1.6.0.md THE DESIGN, §7):
//!
//! 1. the budget and metering write-behind, flushed synchronously;
//! 2. the plane record write-behind, drained ([`crate::root::serve::drain_records`]);
//! 3. the journal's lane to the configured store, drained under the same deadline
//!    ([`crate::root::serve::RECORD_DRAIN`]): on a node with no data directory the store is where
//!    the chain is kept, so a record still queued at exit is a settled unit the store never saw.
//!
//! Two tails were two lists, and the line-serve one had lost steps 2 and 3 (audit busbar-src #1).
//! One function is one list.

use std::sync::{Arc, Mutex};

use busbar_kernel::governance::GovState;

use crate::root::durability::Durability;
use crate::root::serve::{drain_records, LateServices, RECORD_DRAIN};

/// Run the shutdown tail: flush `governance`'s write-behind, drain the plane records `late`
/// queued, then drain the journal lane of the book `journal` holds (a book over the configured
/// store has one; none, or a book with no lane, has nothing queued). Returns once each has drained
/// or its deadline passed; a step that did not drain is logged, never fatal.
pub async fn tail(
    governance: Option<Arc<GovState>>,
    late: &LateServices,
    journal: Option<&Arc<Mutex<Durability>>>,
) {
    // BUDGET WRITE-BEHIND: one FINAL, SYNCHRONOUS flush after the graceful drain, so a graceful stop
    // persists the freshest accrued spend/requests before the process exits. The background
    // flusher's shutdown arm also flushes, but it is a fire-and-forget task that could lose the race
    // with process exit; flushing inline here guarantees durability (this call blocks briefly under
    // the budget lock, off any request path — the serving side has already stopped).
    if let Some(gov) = governance {
        let n = gov.flush_budgets();
        tracing::info!(flushed = n, "budget counters flushed on shutdown");
        // The flusher task's own shutdown arm also flushes metering, but it is fire-and-forget and
        // can lose the race with process exit (same reason the budget flush above is inline here).
        let m = gov.flush_metering();
        tracing::info!(flushed = m, "metering rows flushed on shutdown");
    }
    // THE PLANE RECORD WRITE-BEHIND, drained before the store closes.
    if !drain_records(late).await {
        tracing::warn!("plane record writes were still queued at shutdown");
    }
    // THE JOURNAL'S LANE TO THE STORE, drained the same way and under the same deadline.
    if let Some(lane) = journal.and_then(|book| {
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .lane()
            .cloned()
    }) {
        let drained = tokio::task::spawn_blocking(move || lane.drain(RECORD_DRAIN))
            .await
            .unwrap_or(false);
        if !drained {
            tracing::warn!("journal records were still queued for the store at shutdown");
        }
    }
}

#[cfg(test)]
#[path = "tests/shutdown.rs"]
mod tests;
