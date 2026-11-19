// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE CORE'S AUDIT STATE AND THE FLUSHER THAT PULLS IT (design 2, A1, A3, A5, A8).
//!
//! A request on a core hands its record to that core's [`CoreAudit`] and answers: an audit line's
//! inputs go to the core's [`CoreOutbox`]; a refusal of a request with no identity only bumps a
//! count per (listener, reason). Neither signs, hashes, takes a lock another core holds, or wakes
//! anyone. The [`CoreFlusher`] pulls every core on its own timer (`advanced.usage_flush_interval_ms`),
//! links the lines into the node's chain in monotonic order, writes one aggregate line per
//! non-zero (listener, reason) count, and commits the group; the notary then signs the new head.
//! A core's state is made when its listener loop starts and released when that loop ends.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use busbar_contract::caps::{ReasonCode, StepName};
use busbar_kernel::outbox::CoreOutbox;
use busbar_kernel_audit::AuditInputs;
use tokio::sync::Notify;
use tokio::time::Instant;

/// How old the last good flush may be before requests that create a record are refused with the
/// catalogue's "durability unavailable" (A8). A health check is never judged by it.
pub(crate) const STALL_LIMIT: Duration = Duration::from_secs(2);

/// Refusals of one (listener, reason) on one core since the last pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefusalCount {
    /// The listener the requests arrived on.
    pub(crate) listener: Box<str>,
    /// Where and why they were refused.
    pub(crate) step: StepName,
    pub(crate) reason: ReasonCode,
    /// The status they were answered with.
    pub(crate) status: u16,
    /// How many.
    pub(crate) count: u64,
}

/// ONE CORE'S AUDIT STATE: owned by the core's listener loop, handed to each connection on it.
pub(crate) struct CoreAudit {
    records: CoreOutbox<AuditInputs>,
    refused: Mutex<Vec<RefusalCount>>,
}

impl std::fmt::Debug for CoreAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreAudit").finish_non_exhaustive()
    }
}

impl CoreAudit {
    fn new(wake: Arc<Notify>) -> Self {
        Self {
            records: CoreOutbox::new(wake),
            refused: Mutex::new(Vec::new()),
        }
    }

    /// The core's outbox of audit lines (append; the flusher pulls).
    pub(crate) fn records(&self) -> &CoreOutbox<AuditInputs> {
        &self.records
    }

    /// Count one refusal of a request that has no identity. Allocates only for a (listener,
    /// reason, status) not yet seen since the last pull; the pull releases them.
    pub(crate) fn count_refusal(
        &self,
        listener: &str,
        step: StepName,
        reason: ReasonCode,
        status: u16,
    ) {
        let mut refused = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(seen) = refused.iter_mut().find(|seen| {
            seen.step == step
                && seen.reason == reason
                && seen.status == status
                && &*seen.listener == listener
        }) {
            seen.count = seen.count.saturating_add(1);
            return;
        }
        refused.push(RefusalCount {
            listener: listener.into(),
            step,
            reason,
            status,
            count: 1,
        });
    }

    fn drain_refusals(&self) -> Vec<RefusalCount> {
        std::mem::take(&mut *self.refused.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Counts held, not yet pulled.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn refusals_held(&self) -> Vec<RefusalCount> {
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// One pull of every live core.
#[derive(Default)]
pub(crate) struct Pulled {
    /// Lines a flush built but the journal refused, oldest first: staged before `lines`.
    pub(crate) kept: Vec<busbar_kernel_audit::Prepared>,
    /// Every line, with the core it came from, in the node's monotonic order.
    pub(crate) lines: Vec<(Arc<CoreAudit>, AuditInputs)>,
    /// Every core pulled and the ticket its pull reached.
    pub(crate) cores: Vec<(Arc<CoreAudit>, u64)>,
    /// Every count, merged across cores.
    pub(crate) refusals: Vec<RefusalCount>,
}

/// THE FLUSHER'S STATE: the cores it pulls, its wake (asked only by an administrative change or a
/// metered request under `advanced.wait_for_commit`), and the age of its last good flush.
pub(crate) struct CoreFlusher {
    wake: Arc<Notify>,
    /// Every core's state; a core is released by the first pull after its loop let it go.
    cores: Mutex<Vec<Arc<CoreAudit>>>,
    /// Pulled but not yet committed, carried to the next pull.
    carry: Mutex<Pulled>,
    epoch: Instant,
    /// Milliseconds since `epoch` of the last flush that committed everything it pulled.
    last_good_ms: AtomicU64,
    /// The wall reading (ms) the previous flush took: where the next refusal interval starts.
    last_wall_ms: AtomicU64,
}

impl std::fmt::Debug for CoreFlusher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreFlusher").finish_non_exhaustive()
    }
}

impl Default for CoreFlusher {
    fn default() -> Self {
        Self {
            wake: Arc::new(Notify::new()),
            cores: Mutex::new(Vec::new()),
            carry: Mutex::new(Pulled::default()),
            epoch: Instant::now(),
            last_good_ms: AtomicU64::new(0),
            last_wall_ms: AtomicU64::new(0),
        }
    }
}

impl CoreFlusher {
    /// A new core's state, pulled by this flusher while the core's listener loop holds it.
    pub(crate) fn core(&self) -> Arc<CoreAudit> {
        let core = Arc::new(CoreAudit::new(Arc::clone(&self.wake)));
        self.cores
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&core));
        core
    }

    /// The wake an early pull rings.
    pub(crate) fn wake(&self) -> &Notify {
        &self.wake
    }

    /// Take everything held: the carry from a flush that did not commit, then every core. A core
    /// whose listener loop and connections have all let go is drained one last time and released
    /// here, so nothing it was handed is lost when its loop ends before the flush.
    pub(crate) fn pull(&self) -> Pulled {
        let mut pulled =
            std::mem::take(&mut *self.carry.lock().unwrap_or_else(PoisonError::into_inner));
        let cores = std::mem::take(&mut *self.cores.lock().unwrap_or_else(PoisonError::into_inner));
        let mut kept = Vec::with_capacity(cores.len());
        for core in cores {
            let drained = core.records.drain();
            // Only this pull holds a released core: nothing can append to it after this drain.
            if Arc::strong_count(&core) > 1 {
                kept.push(Arc::clone(&core));
            }
            for count in core.drain_refusals() {
                match pulled.refusals.iter_mut().find(|seen| {
                    seen.step == count.step
                        && seen.reason == count.reason
                        && seen.status == count.status
                        && seen.listener == count.listener
                }) {
                    Some(seen) => seen.count = seen.count.saturating_add(count.count),
                    None => pulled.refusals.push(count),
                }
            }
            if drained.through == 0 {
                continue;
            }
            pulled.lines.extend(
                drained
                    .items
                    .into_iter()
                    .map(|inputs| (Arc::clone(&core), inputs)),
            );
            pulled.cores.push((core, drained.through));
        }
        self.cores
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(kept);
        // One merged order for the node: its monotonic readings; a stable sort keeps each core's
        // own order and the cores' pull order on a tie.
        pulled.lines.sort_by_key(|(_, inputs)| inputs.mono);
        pulled
    }

    /// Keep what a flush did not commit for the next pull, in front of anything newer.
    pub(crate) fn carry(&self, pulled: Pulled) {
        let mut carry = self.carry.lock().unwrap_or_else(PoisonError::into_inner);
        let newer = std::mem::replace(&mut *carry, pulled);
        carry.kept.extend(newer.kept);
        carry.lines.extend(newer.lines);
        carry.cores.extend(newer.cores);
        carry.refusals.extend(newer.refusals);
    }

    /// The interval a flush's refusal counts cover: from the previous flush's wall reading to
    /// `now_ms`, this flush's one reading. The first flush's interval starts at its own reading.
    pub(crate) fn interval(&self, now_ms: u64) -> (u64, u64) {
        let from = self.last_wall_ms.swap(now_ms, Ordering::AcqRel);
        (if from == 0 { now_ms } else { from }, now_ms)
    }

    /// Record a flush that committed everything it pulled, at `now`.
    pub(crate) fn good(&self, now: Instant) {
        let ms = u64::try_from(now.saturating_duration_since(self.epoch).as_millis())
            .unwrap_or(u64::MAX);
        self.last_good_ms.fetch_max(ms.max(1), Ordering::AcqRel);
    }

    /// The flusher's loop started: from now on its age is judged.
    pub(crate) fn started(&self, now: Instant) {
        self.good(now);
    }

    /// Whether the last good flush is older than [`STALL_LIMIT`] at `now`. A flusher that never
    /// started (a process with no serving node) is not judged.
    #[must_use]
    pub(crate) fn stalled(&self, now: Instant) -> bool {
        let last = self.last_good_ms.load(Ordering::Acquire);
        last != 0
            && now.saturating_duration_since(self.epoch + Duration::from_millis(last)) > STALL_LIMIT
    }
}

#[cfg(test)]
#[path = "../tests/core_audit.rs"]
mod tests;
