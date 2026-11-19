// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `shutdown.drain_incomplete` RECORDS (SHUTDOWN-HANG §5). Whoever closes a writer that never
//! retired (a same-host successor, a recovery adopter, or the start-up expired-lease pass) offers
//! one admin audit record at the moment it observes the close applied. One process-wide ledger,
//! beside the process-static admin audit queue whose rows it tracks, holds every such record
//! until a flush that began after it confirms it, so none is lost silently: a record the queue
//! refuses is held, named, retried and listed at exit.
//!
//! Lock order: `WriterRetirements.state` -> this ledger's `state` -> the admin queue's rows.
//! No await is ever made while a std lock is held.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

/// `(epoch, writer)`.
pub type Target = (u64, [u8; 16]);

/// Who observed an open writer's close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedBy {
    Successor,
    Adopter,
    ExpiredLeasePass,
}

impl ObservedBy {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ObservedBy::Successor => "successor",
            ObservedBy::Adopter => "adopter",
            ObservedBy::ExpiredLeasePass => "expired_lease_pass",
        }
    }
}

/// What the record needs about the writer that did not retire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndrainedWriter {
    pub node: Option<u64>,
    pub other_nodes: Vec<u64>,
    pub epoch: u64,
    pub writer: [u8; 16],
    pub host: Option<String>,
    pub observed_by: ObservedBy,
}

impl UndrainedWriter {
    #[must_use]
    pub fn target(&self) -> Target {
        (self.epoch, self.writer)
    }

    /// The record's resource, and the identity every stderr line carries.
    #[must_use]
    pub fn resource(&self) -> String {
        let others: Vec<String> = self.other_nodes.iter().map(u64::to_string).collect();
        format!(
            "writer={} epoch={} node={} other_nodes=[{}] host={} observed_by={}",
            hex::encode(self.writer),
            self.epoch,
            self.node
                .map_or_else(|| "none".to_string(), |n| n.to_string()),
            others.join(","),
            self.host.as_deref().unwrap_or("none"),
            self.observed_by.as_str(),
        )
    }

    /// Offers the record to the admin audit queue; the queue's refusal is returned.
    pub(crate) fn offer(&self) -> Result<(), String> {
        crate::audit::auditlog::try_emit_admin_hostless_now(
            "shutdown.drain_incomplete",
            &format!(
                "{} cause=\"previous process did not retire (incomplete drain, crash or kill)\" \
                 checkpoint_rows=not_counted",
                self.resource()
            ),
            "recorded",
            "system",
        )
        .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Retry {
    Idle,
    Running,
    Closed,
}

/// Which caller runs a settle pass: the retry task stops once `finish` has closed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retrier {
    Owner,
    Task,
}

struct LedgerState {
    /// One entry per closer that retains a close of the target: several `WriterRetirements` in
    /// one process (F5's, an adopter's) may race the same writer, and one closer's decision
    /// never removes another's retained close (#258).
    retained: BTreeMap<Target, Vec<UndrainedWriter>>,
    recorded: BTreeMap<Target, (u64, UndrainedWriter)>,
    generation: u64,
    record_failed: BTreeMap<Target, UndrainedWriter>,
    unconfirmed: BTreeMap<Target, UndrainedWriter>,
    retry: Retry,
    retried: u64,
    confirmed: u64,
}

impl LedgerState {
    /// One closer's retained entry for `seen` leaves; the others stay.
    fn release(&mut self, seen: &UndrainedWriter) {
        let target = seen.target();
        let Some(closers) = self.retained.get_mut(&target) else {
            return;
        };
        let at = closers.iter().position(|held| held == seen).unwrap_or(0);
        if at < closers.len() {
            closers.remove(at);
        }
        if closers.is_empty() {
            self.retained.remove(&target);
        }
    }
}

type Flight = (
    u64,
    tokio::task::JoinHandle<busbar_contract::records::RecordStoreResult<()>>,
);

/// The one process-wide ledger.
pub struct RecordLedger {
    state: Mutex<LedgerState>,
    /// The one flush in flight: its mark and handle. Never aborted; a timed-out wait keeps it.
    pass: tokio::sync::Mutex<Option<Flight>>,
}

/// One copy of the ledger, taken under its lock, for the exit snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitReport {
    /// Recorded and not confirmed, retained with a close that may still apply, or a decision
    /// this process lost: each printed `drain_incomplete_unconfirmed`.
    pub unconfirmed: Vec<UndrainedWriter>,
    /// Closed and refused by the queue: each printed `drain_incomplete_unrecorded`.
    pub unrecorded: Vec<UndrainedWriter>,
}

/// One settle pass's counts, for F5's Info line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassCounts {
    pub recorded: usize,
    pub record_failed: Vec<UndrainedWriter>,
    pub flush_failed: usize,
}

impl PassCounts {
    #[must_use]
    pub fn clean(&self) -> bool {
        self.record_failed.is_empty() && self.flush_failed == 0
    }
}

pub static UNDRAINED_RECORDS: LazyLock<RecordLedger> = LazyLock::new(|| RecordLedger {
    state: Mutex::new(LedgerState {
        retained: BTreeMap::new(),
        recorded: BTreeMap::new(),
        generation: 0,
        record_failed: BTreeMap::new(),
        unconfirmed: BTreeMap::new(),
        retry: Retry::Idle,
        retried: 0,
        confirmed: 0,
    }),
    pass: tokio::sync::Mutex::new(None),
});

#[must_use]
pub fn undrained_records() -> &'static RecordLedger {
    &UNDRAINED_RECORDS
}

/// The bound of one flush wait, as the admin queue's own background drain.
const FLUSH_WAIT: Duration = Duration::from_secs(2);
const RETRY_EVERY: Duration = Duration::from_secs(1);

impl RecordLedger {
    fn lock(&self) -> std::sync::MutexGuard<'_, LedgerState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Called in the same critical section that retains an open writer's close attempt.
    pub(crate) fn retain(&self, seen: &UndrainedWriter) {
        self.lock()
            .retained
            .entry(seen.target())
            .or_default()
            .push(seen.clone());
    }

    /// The close of `seen` was decided. Called once per decision, under the closer's lock.
    /// Returns the refusal, if the queue refused the record (the caller names it after
    /// releasing its locks).
    pub(crate) fn decided(&self, seen: &UndrainedWriter, applied: bool) -> Option<String> {
        let mut state = self.lock();
        state.release(seen);
        if !applied {
            return None;
        }
        match seen.offer() {
            Ok(()) => {
                let generation = state.generation;
                state.generation = generation.saturating_add(1);
                state
                    .recorded
                    .insert(seen.target(), (generation, seen.clone()));
                None
            }
            Err(error) => {
                state.record_failed.insert(seen.target(), seen.clone());
                Some(error)
            }
        }
    }

    /// A decision this process lost with no driver in flight: printed at exit, never recorded.
    pub(crate) fn lost(&self, seen: &UndrainedWriter) {
        let mut state = self.lock();
        state.release(seen);
        state.unconfirmed.insert(seen.target(), seen.clone());
    }

    /// The generation of the next record.
    pub fn mark(&self) -> u64 {
        self.lock().generation
    }

    /// Every record made before `mark` reached the store: a flush that began after them drained
    /// the queue to empty.
    pub fn confirm_before(&self, mark: u64) {
        let mut state = self.lock();
        let before = state.recorded.len();
        state
            .recorded
            .retain(|_, (generation, _)| *generation >= mark);
        let confirmed = before - state.recorded.len();
        state.confirmed = state.confirmed.saturating_add(confirmed as u64);
    }

    /// Re-offers every refused record; each accepted one is recorded with the next generation.
    pub fn retry_unrecorded(&self) -> usize {
        self.retry_from(Retrier::Owner)
    }

    fn retry_from(&self, retrier: Retrier) -> usize {
        let mut state = self.lock();
        if retrier == Retrier::Task && state.retry == Retry::Closed {
            return 0;
        }
        let refused: Vec<(Target, UndrainedWriter)> = state
            .record_failed
            .iter()
            .map(|(t, s)| (*t, s.clone()))
            .collect();
        let mut accepted = 0;
        for (target, seen) in refused {
            if seen.offer().is_ok() {
                state.record_failed.remove(&target);
                let generation = state.generation;
                state.generation = generation.saturating_add(1);
                state.recorded.insert(target, (generation, seen));
                state.retried = state.retried.saturating_add(1);
                accepted += 1;
            }
        }
        accepted
    }

    #[must_use]
    pub fn has_unrecorded(&self) -> bool {
        !self.lock().record_failed.is_empty()
    }

    /// One read under the lock, for every closer at once.
    #[must_use]
    pub fn exit_report(&self) -> ExitReport {
        let state = self.lock();
        let mut unconfirmed: Vec<UndrainedWriter> =
            state.recorded.values().map(|(_, s)| s.clone()).collect();
        unconfirmed.extend(
            state
                .retained
                .values()
                .filter_map(|closers| closers.first().cloned()),
        );
        unconfirmed.extend(state.unconfirmed.values().cloned());
        ExitReport {
            unconfirmed,
            unrecorded: state.record_failed.values().cloned().collect(),
        }
    }

    /// From `finish`'s [5] on, only `finish` retries.
    pub fn close_retry_task(&self) {
        self.lock().retry = Retry::Closed;
    }

    /// Starts the one retry task if none runs and the ledger is not closed. Sync.
    pub fn ensure_retry_task(&'static self) {
        let mut state = self.lock();
        if state.retry != Retry::Idle {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        state.retry = Retry::Running;
        drop(state);
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(RETRY_EVERY).await;
                let counts = self.settle_pass(Retrier::Task).await;
                let mut state = self.lock();
                if state.retry == Retry::Closed {
                    return;
                }
                if counts.clean() {
                    state.retry = Retry::Idle;
                    let (confirmed, retried) = (state.confirmed, state.retried);
                    drop(state);
                    tracing::info!(confirmed, retried, "drain_incomplete_records settled");
                    return;
                }
            }
        });
    }

    /// One bounded pass: re-offer refused records, then one flush of the admin queue awaited
    /// for at most 2 s (the flush is never aborted; a timed-out wait keeps its handle and mark
    /// for the next pass), confirming every record made before its mark on success.
    pub async fn settle_pass(&self, retrier: Retrier) -> PassCounts {
        self.retry_from(retrier);
        let mut flush_failed = false;
        {
            let mut pass = self.pass.lock().await;
            if pass.is_none() {
                let mark = self.mark();
                *pass = Some((mark, tokio::spawn(crate::audit::auditlog::flush_pending())));
            }
            let waited = match pass.as_mut() {
                Some((mark, handle)) => {
                    Some((*mark, tokio::time::timeout(FLUSH_WAIT, handle).await))
                }
                None => None,
            };
            match waited {
                Some((mark, Ok(Ok(Ok(()))))) => {
                    self.confirm_before(mark);
                    *pass = None;
                }
                Some((_, Ok(_))) => {
                    flush_failed = true;
                    *pass = None;
                }
                Some((_, Err(_))) => flush_failed = true,
                None => {}
            }
        }
        let state = self.lock();
        PassCounts {
            recorded: state.recorded.len(),
            record_failed: state.record_failed.values().cloned().collect(),
            flush_failed: if flush_failed {
                state.recorded.len()
            } else {
                0
            },
        }
    }
}

/// Test-only: where one target sits in the ledger (SHUTDOWN-HANG 8.14, 8.15).
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Placement {
    pub(crate) retained: bool,
    /// The record's generation, while recorded and not confirmed.
    pub(crate) recorded: Option<u64>,
    pub(crate) record_failed: bool,
    pub(crate) unconfirmed: bool,
}

#[cfg(test)]
impl RecordLedger {
    pub(crate) fn placement(&self, target: Target) -> Placement {
        let state = self.lock();
        Placement {
            retained: state.retained.contains_key(&target),
            recorded: state
                .recorded
                .get(&target)
                .map(|(generation, _)| *generation),
            record_failed: state.record_failed.contains_key(&target),
            unconfirmed: state.unconfirmed.contains_key(&target),
        }
    }
}

/// Test-only: this ledger and the admin audit queue it offers to are process-wide, and the test
/// harness runs tests in parallel threads of one process. One test's confirmation, retry or full
/// queue is another's lost or refused record, so every test that offers to, settles, confirms or
/// fills them holds this for its whole run.
#[cfg(test)]
static LEDGER_TESTS: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Test-only: the one exclusive hold on the ledger and the admin audit queue. Every holder starts
/// alike, whatever ran before it: the native audit owner installed, and the queue drained.
#[cfg(test)]
pub(crate) async fn ledger_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = LEDGER_TESTS.lock().await;
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    assert!(
        crate::audit::auditlog::flush_pending().await.is_ok(),
        "the admin audit queue drains before the test"
    );
    guard
}

/// Test-only: fills the admin audit queue to its bound from a thread with no runtime, so no drain
/// is spawned while it fills (a drain is spawned only on a runtime). Returns the rows it added.
#[cfg(test)]
pub(crate) fn fill_admin_queue() -> usize {
    std::thread::spawn(|| {
        let mut filled = 0;
        while crate::audit::auditlog::try_emit_admin_hostless_now("test.fill", "x", "ok", "system")
            .is_ok()
        {
            filled += 1;
            assert!(
                filled <= crate::audit::auditlog::MAX_PENDING_AUDIT,
                "the admin audit queue is bounded"
            );
        }
        filled
    })
    .join()
    .expect("the fill thread returns")
}

/// Test-only: `retry_unrecorded` from a thread with no runtime, so its offers spawn no drain and
/// meet the queue exactly as the caller left it.
#[cfg(test)]
pub(crate) fn retry_unrecorded_without_drain() -> usize {
    std::thread::spawn(|| undrained_records().retry_unrecorded())
        .join()
        .expect("the retry thread returns")
}

#[cfg(test)]
#[path = "tests/undrained_tests.rs"]
mod tests;
