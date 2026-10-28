// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE SHUTDOWN TAIL. Every way the process stops serving ends here, once, before it exits:
//! the listener path after its graceful drain, and the line-serve mode (busbar as a child process
//! speaking on stdin/stdout) at stdin EOF. What the caller was already answered for has to reach
//! the store before the process is gone, whichever transport the answer went out on (ruling H2
//! U10; BUSBAR-1.6.0.md THE DESIGN, §7):
//!
//! 1. the budget and metering write-behind, flushed synchronously;
//! 2. the plane record write-behind, drained ([`crate::root::serve::drain_records`]), and the admin
//!    audit writer ([`busbar_kernel::audit::auditlog::audit_written_within`]);
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
    // THE ADMIN AUDIT WRITER, drained the same way: every admin mutation answered before the stop
    // has its record written (or queued for recovery) before the store closes.
    if !busbar_kernel::audit::auditlog::audit_written_within(RECORD_DRAIN).await {
        tracing::warn!("admin audit records were still being written at shutdown");
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
    }
    // THE NODE'S LEASE ON ITS HOST NAME, held on that lane, released once its chain reached the
    // store, so the next boot of this host resumes it at once. Off the runtime: it waits on
    // the store.
    let _released = tokio::task::spawn_blocking(move || lane.release_held_lease()).await;
}

#[cfg(test)]
#[path = "tests/shutdown.rs"]
mod tests;
