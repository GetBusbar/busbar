// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `AdmissionGate`: the ONE non-blocking "try to get a slot, or don't" mechanic the export fan-out
//! sheds with. It arrives here BY IDENTITY out of the engine's `limits::admission` — same
//! semantics, same `busbar_admission_denied_total{gate}` counter, same "this function has no
//! opinion about what a `None` means".
//!
//! WHY IT IS HERE AND NOT IN AN EXPORT CRATE. The shed is the ROOT'S decision, not the sink's. A
//! crate of kind `export` is a sink: it takes an item and ships it. Capacity — how many deliveries
//! of THIS instance may be in flight before the next one is dropped on the floor — is a property of
//! the composition, decided by whoever loaded the sink and knows what else is running beside it. So
//! the root sheds BEFORE it calls the sink, and hands the surviving delivery the permit that keeps
//! its slot held for as long as the delivery runs. A sink that had to carry its own gate would also
//! have to name a semaphore, a metrics recorder and a policy that is not its business.
//!
//! It is deliberately NOT on the frozen neutral spine and NOT in a unit crate (a plugin-kind crate
//! may never name one). The 77-line inbound tower `Layer`/`Service` half — the OUTERMOST request
//! cap, whose only caller is the engine's `router.rs` — is a different thing wearing the same
//! mechanic, and it stays with its caller and dies with it. The spine's own
//! `proxy_vocab::spawn_bounded_tap` is a third hand-copied replica of these same twenty-four lines;
//! it dies with the crate that holds it.

use std::sync::Arc;

// The counter's NAME through the crate that already re-exports it, so this gate lands on the same
// `busbar_admission_denied_total` series as every other gate in the process without the root
// growing a second spelling of it. `::metrics` below is the recorder crate itself.
use busbar_core::metrics;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A single non-blocking capacity gate: `permits` slots, handed out via [`try_enter`](Self::try_enter)
/// and returned automatically when the returned permit is dropped. `name` identifies the gate on the
/// shared `busbar_admission_denied_total{gate="..."}` counter — pick a short, stable, non-request-derived
/// string (a compile-time constant at every call site today, so the label space is fixed at build time).
pub(crate) struct AdmissionGate {
    sem: Arc<Semaphore>,
    name: &'static str,
}

impl AdmissionGate {
    /// `permits == Semaphore::MAX_PERMITS` is the crate-wide "unbounded" sentinel already used by the
    /// store's lane semaphores (`Semaphore::new` accepts it directly — it is not a magic infinity,
    /// just the largest permit count `Semaphore` supports) — a gate built with it will, for any
    /// realistic request volume, never observe `try_enter` return `None`.
    pub(crate) fn new(permits: usize, name: &'static str) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(permits)),
            name,
        }
    }

    /// Try to take one slot, without waiting. `Some` carries an owned, `'static` permit — drop it (or
    /// let it fall out of scope, including inside a spawned task or an async block it was moved into)
    /// to return the slot. `None` means the gate is saturated: the caller decides what that means
    /// (shed, drop, skip — this function has no opinion), but every denial is counted here first, so
    /// `busbar_admission_denied_total{gate}` observes EVERY gate uniformly even if a call site also
    /// keeps its own bespoke drop counter.
    pub(crate) fn try_enter(&self) -> Option<OwnedSemaphorePermit> {
        match self.sem.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                ::metrics::counter!(metrics::ADMISSION_DENIED_TOTAL, "gate" => self.name)
                    .increment(1);
                None
            }
        }
    }
}
