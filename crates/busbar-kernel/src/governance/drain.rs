// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHUTDOWN-HANG F4/F4a: the drain clock every shutdown wait and the money driver read, the one
//! governed admission gate custody can see, and the spend-custody classification that decides a
//! non-retired exit's code (0 clean, 75 spend saved but streams cut, 70 spend unsaved).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use super::{GovState, LimitBlocked};

/// The shutdown drain budget, from the first shutdown signal to exit: the 20 s decision 174 set.
/// Fixed; there is no config key for it.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(20);

/// The terminal-backlog cap of governed admission: 1,000 finished units per second of drain budget
/// (20,000 at 20 s), sized from the networked store's settlement target. Fixed; there is no config
/// key for it.
pub const MAX_PENDING_CHECKPOINTS: u64 = 1_000 * DRAIN_TIMEOUT.as_secs();

/// The phase limits of one armed drain. Every bounded shutdown wait names one explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    /// C1 = deadline - reserve: the request phase ends and governed admission closes.
    Requests,
    /// C2 = deadline - reserve / 2: the settle wait ends.
    Settle,
    /// C3 = deadline - reserve / 4: plane records, the money join and the seal phase end.
    Seal,
    /// The deadline itself: only the journal flush and the retirement.
    Deadline,
}

/// The one shutdown clock. Unarmed until the first shutdown broadcast; no limit exists before.
pub struct DrainClock {
    budget: Duration,
    reserve: Duration,
    deadline: watch::Sender<Option<Instant>>,
    expired: watch::Sender<bool>,
    requests_done: watch::Sender<bool>,
    money_stop: watch::Sender<bool>,
    passes: watch::Sender<u64>,
}

impl DrainClock {
    #[must_use]
    pub fn new(budget: Duration) -> Arc<Self> {
        Arc::new(Self {
            budget,
            reserve: budget / 4,
            deadline: watch::Sender::new(None),
            expired: watch::Sender::new(false),
            requests_done: watch::Sender::new(false),
            money_stop: watch::Sender::new(false),
            passes: watch::Sender::new(0),
        })
    }

    #[must_use]
    pub fn budget(&self) -> Duration {
        self.budget
    }

    /// Arm once, at the first broadcast: later calls change nothing. Arming spawns the one
    /// deadline timer, so the deadline and a second signal take the same `expire_now` path.
    pub fn arm(self: &Arc<Self>, deadline: Instant) -> bool {
        let armed = self.deadline.send_if_modified(|at| {
            if at.is_some() {
                return false;
            }
            *at = Some(deadline);
            true
        });
        if armed {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let clock = Arc::clone(self);
                runtime.spawn(async move {
                    tokio::time::sleep_until(deadline).await;
                    clock.expire_now();
                });
            }
        }
        armed
    }

    /// The armed deadline, if armed.
    #[must_use]
    pub fn armed_at(&self) -> Option<Instant> {
        *self.deadline.borrow()
    }

    /// Resolves when the clock is armed, at once if it already is.
    pub async fn armed(&self) -> Instant {
        let mut rx = self.deadline.subscribe();
        let armed = match rx.wait_for(Option::is_some).await {
            Ok(at) => *at,
            Err(_) => None,
        };
        match armed {
            Some(at) => at,
            // The sender lives in `self`, so this is unreachable while `self` is borrowed.
            None => std::future::pending().await,
        }
    }

    /// Wakes every waiter at once: the deadline timer and a second signal both call this.
    pub fn expire_now(&self) {
        self.expired.send_replace(true);
    }

    #[must_use]
    pub fn expired(&self) -> bool {
        *self.expired.borrow()
    }

    #[must_use]
    pub fn expired_rx(&self) -> watch::Receiver<bool> {
        self.expired.subscribe()
    }

    /// A phase's limit under the armed `deadline`. Code that has not awaited `armed()` holds no
    /// deadline, so it cannot compute a limit.
    #[must_use]
    pub fn limit(&self, deadline: Instant, cut: Cut) -> Instant {
        let back = match cut {
            Cut::Requests => self.reserve,
            Cut::Settle => self.reserve / 2,
            Cut::Seal => self.reserve / 4,
            Cut::Deadline => Duration::ZERO,
        };
        deadline.checked_sub(back).unwrap_or(deadline)
    }

    pub fn set_requests_done(&self) {
        self.requests_done.send_replace(true);
    }

    #[must_use]
    pub fn requests_done(&self) -> bool {
        *self.requests_done.borrow()
    }

    /// Fired just before the seal phase: the money driver ends its unit work at the next batch
    /// boundary, runs the final budget and metering flushes, and returns.
    pub fn stop_money(&self) {
        self.money_stop.send_replace(true);
    }

    #[must_use]
    pub fn money_stopped(&self) -> bool {
        *self.money_stop.borrow()
    }

    #[must_use]
    pub fn money_stop_rx(&self) -> watch::Receiver<bool> {
        self.money_stop.subscribe()
    }

    /// The money driver bumps this after every completed drain pass.
    pub fn note_pass(&self) {
        self.passes.send_modify(|n| *n = n.saturating_add(1));
    }

    #[must_use]
    pub fn passes_rx(&self) -> watch::Receiver<u64> {
        self.passes.subscribe()
    }
}

const CLOSED: u64 = 1 << 63;

/// One governed admission gate: a live-admission count that only falls after the unit's terminal
/// checkpoint is staged, a closed bit set at C1, and a cap on the terminal backlog (finished
/// units not yet settled). Every `AdmitGrant` passes through `enter`.
pub struct AdmissionGate {
    /// Bit 63 = closed; bits 0..=62 = live governed admissions.
    word: AtomicU64,
    /// The number of `ended` entries in the unit checkpoint book; changed only under its lock.
    terminal: Arc<AtomicU64>,
    cap: AtomicU64,
    /// Rising-edge latch for the paused diagnostic.
    full: AtomicBool,
}

impl AdmissionGate {
    /// A gate whose terminal backlog is the unit checkpoint book's own mirror.
    pub(crate) fn over(terminal: Arc<AtomicU64>) -> Self {
        Self {
            word: AtomicU64::new(0),
            terminal,
            cap: AtomicU64::new(MAX_PENDING_CHECKPOINTS),
            full: AtomicBool::new(false),
        }
    }
}

/// One live governed admission's count. Dropped with the last `Arc` of its `AdmitGrant`.
pub struct GateHold(Arc<AdmissionGate>);

impl Drop for GateHold {
    fn drop(&mut self) {
        self.0.word.fetch_sub(1, Ordering::Release);
    }
}

impl std::fmt::Debug for GateHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GateHold")
    }
}

impl AdmissionGate {
    /// The closed bit first (a closing instance says "retry elsewhere"), then the cap, then the
    /// count, which a `close` between the two checks still refuses.
    pub(crate) fn enter(self: &Arc<Self>) -> Result<GateHold, LimitBlocked> {
        if self.word.load(Ordering::Acquire) & CLOSED != 0 {
            return Err(LimitBlocked::Draining);
        }
        let backlog = self.terminal.load(Ordering::Relaxed);
        let cap = self.cap.load(Ordering::Relaxed);
        if backlog.saturating_mul(10) < cap.saturating_mul(9)
            && self.full.load(Ordering::Relaxed)
            && self.full.swap(false, Ordering::Relaxed)
        {
            tracing::info!(
                backlog,
                cap,
                "governed admission resumed: settlement backlog below 90% of its cap"
            );
        }
        if backlog >= cap {
            if !self.full.swap(true, Ordering::Relaxed) {
                crate::diag_warn!(
                    crate::diagnostics::GOVERNED_ADMISSION_PAUSED,
                    cause = "custody_full",
                    backlog,
                    cap,
                    "governed admission paused: finished requests await settlement in the store"
                );
            }
            return Err(LimitBlocked::CustodyFull { backlog, cap });
        }
        self.word
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |w| {
                (w & CLOSED == 0).then_some(w + 1)
            })
            .map(|_| GateHold(Arc::clone(self)))
            .map_err(|_| LimitBlocked::Draining)
    }

    /// Idempotent. After it, `live()` only falls.
    pub fn close(&self) {
        if self.word.fetch_or(CLOSED, Ordering::AcqRel) & CLOSED == 0 {
            crate::diag_warn!(
                crate::diagnostics::GOVERNED_ADMISSION_PAUSED,
                cause = "drain",
                backlog = self.terminal(),
                cap = self.cap(),
                "governed admission closed: the gateway is shutting down"
            );
        }
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.word.load(Ordering::Acquire) & CLOSED != 0
    }

    #[must_use]
    pub fn live(&self) -> u64 {
        self.word.load(Ordering::Acquire) & !CLOSED
    }

    #[must_use]
    pub fn terminal(&self) -> u64 {
        self.terminal.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn cap(&self) -> u64 {
        self.cap.load(Ordering::Relaxed)
    }

    /// Test seam: production keeps [`MAX_PENDING_CHECKPOINTS`]. At least 1.
    #[cfg(test)]
    pub fn set_cap(&self, cap: u64) {
        self.cap.store(cap.max(1), Ordering::Relaxed);
    }
}

/// One item of spend custody at exit, listed on stderr as evidence (never an import).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyItem {
    pub kind: &'static str,
    pub detail: String,
}

/// §5's three lists. 70 iff `unpersisted` or `in_doubt` is non-empty; otherwise 75.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpendCustody {
    pub unpersisted: Vec<CustodyItem>,
    pub in_doubt: Vec<CustodyItem>,
    pub custody_only: Vec<CustodyItem>,
}

impl SpendCustody {
    /// Some completed spend is not in durable custody.
    #[must_use]
    pub fn spend_unsaved(&self) -> bool {
        !self.unpersisted.is_empty() || !self.in_doubt.is_empty()
    }

    /// The exit code of a non-retired exit.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.spend_unsaved() {
            70
        } else {
            75
        }
    }
}

/// One item, its detail written once into its own buffer (a cold exit path).
fn item(kind: &'static str, detail: std::fmt::Arguments<'_>) -> CustodyItem {
    use std::fmt::Write as _;
    let mut text = String::new();
    let _ = text.write_fmt(detail);
    CustodyItem { kind, detail: text }
}

/// A persisted revision, or `none`.
struct Revision(Option<u64>);

impl std::fmt::Display for Revision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(n) => write!(f, "{n}"),
            None => f.write_str("none"),
        }
    }
}

impl GovState {
    /// The governed admission gate.
    #[must_use]
    pub fn admissions(&self) -> &Arc<AdmissionGate> {
        &self.admissions
    }

    /// Walks the owners `has_unsettled_persistence` walks and sorts each item into one list.
    /// A completed request is never in none: before a flight captures it, it is a dirty cell or a
    /// non-zero shard; a terminal unit is an `ended` entry until its removal after settlement.
    #[must_use]
    pub fn spend_custody(&self) -> SpendCustody {
        let mut out = SpendCustody::default();
        for unit in self.unit_checkpoint_states() {
            let id = hex::encode(unit.id);
            let kind = if !unit.ended {
                "running_unit"
            } else if unit.persisted != Some(unit.revision) {
                "terminal_unit"
            } else {
                "terminal_unit_persisted"
            };
            let entry = item(
                kind,
                format_args!(
                    "checkpoint={id} revision={} persisted={} principal={} group={}",
                    unit.revision,
                    Revision(unit.persisted),
                    unit.principal,
                    unit.group,
                ),
            );
            if kind == "terminal_unit" {
                out.unpersisted.push(entry);
            } else {
                out.custody_only.push(entry);
            }
        }
        if self.unit_checkpoints_flushing() {
            out.in_doubt.push(item(
                "unit_flush",
                format_args!("a unit checkpoint flush is running"),
            ));
        }
        for index in 0..super::GOV_SHARDS {
            let map = self.budget.shard_at(index).read();
            for (bucket, cell) in map.iter() {
                if cell.dirty
                    || cell.flushing != 0
                    || cell.correction.is_some()
                    || !cell.rolled.is_empty()
                    || !cell.rolled_eras.is_empty()
                {
                    out.unpersisted.push(item(
                        "budget_cell",
                        format_args!(
                            "bucket={bucket} window={} dirty={} flushing={} correction={} rolled={}",
                            cell.window_start,
                            cell.dirty,
                            cell.flushing,
                            cell.correction.is_some(),
                            cell.rolled.len() + cell.rolled_eras.len()
                        ),
                    ));
                }
            }
        }
        for (bucket, window) in self
            .budget_flushes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
        {
            out.in_doubt.push(item(
                "budget_flight",
                format_args!("bucket={bucket} window={window}"),
            ));
        }
        if self.budget_flush_runner.is_running() {
            out.in_doubt.push(item(
                "budget_flush",
                format_args!("a budget flush is running"),
            ));
        }
        let metering = &self.pending_metering;
        for shard in metering.shards.iter() {
            for (key, counts) in shard.lock().unwrap_or_else(|p| p.into_inner()).iter() {
                if !counts.is_zero() {
                    out.unpersisted.push(item(
                        "metering",
                        format_args!(
                            "group={}@{} key={} model={} requests={}",
                            key.5, key.1, key.0, key.2, counts.requests
                        ),
                    ));
                }
            }
        }
        let flights = metering
            .flight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len();
        if flights != 0 {
            out.in_doubt.push(item(
                "metering_flight",
                format_args!("{flights} metering write(s) unconfirmed"),
            ));
        }
        if metering.flush_runner.is_running() {
            out.in_doubt.push(item(
                "metering_flush",
                format_args!("a metering flush is running"),
            ));
        }
        // Judged on copies taken under the lock, so the judgement runs without it.
        let mut corrections: Vec<(String, super::state::ledger_adjust::PendingCorrection)> =
            Vec::new();
        for (key, correction) in self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            corrections.push((key.clone(), correction.clone()));
        }
        for (key, correction) in corrections {
            if correction.has_unsettled_persistence() {
                out.unpersisted
                    .push(item("correction", format_args!("correction={key}")));
            }
        }
        let (staged, selected) = self.recovery_custody_counts();
        if staged != 0 {
            out.in_doubt.push(item(
                "recovery_staged",
                format_args!("{staged} recovery original(s) staged and unconfirmed"),
            ));
        }
        if selected != 0 {
            out.custody_only.push(item(
                "recovery_selected",
                format_args!("{selected} recovery operation(s) selected, not yet settled"),
            ));
        }
        if self.has_unsettled_ticket_operations()
            || !self
                .deleting_budget_buckets
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty()
        {
            out.custody_only.push(item(
                "tickets",
                format_args!("ticket operations or bucket deletions remain"),
            ));
        }
        out
    }
}

/// What governance still owes the store, counted for the drain's progress line (SHUTDOWN-HANG
/// F4 "Progress").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DrainRemaining {
    /// Unit checkpoint entries in the book, running and terminal.
    pub checkpoints: u64,
    /// The terminal backlog: `ended` entries the money driver must still persist and settle.
    pub terminal_checkpoints: u64,
    /// Corrections held for persistence.
    pub corrections: u64,
    /// Budget flushes in flight.
    pub budget_flights: u64,
    /// Metering cells pending or in flight.
    pub metering: u64,
}

impl GovState {
    /// Counts only, read once per progress line; never on the request path.
    #[must_use]
    pub fn drain_remaining(&self) -> DrainRemaining {
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        DrainRemaining {
            checkpoints: count(self.unit_checkpoint_count()),
            terminal_checkpoints: self.admissions.terminal(),
            corrections: count(
                self.corrections
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .len(),
            ),
            budget_flights: count(
                self.budget_flushes
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .len(),
            ),
            metering: count(self.pending_metering.pending_cells()),
        }
    }
}

/// One unit still running at exit, joined with its checkpoint custody by checkpoint id
/// (SHUTDOWN-HANG F4 `open_at_exit`). A unit with no checkpoint entry (waiting on upstream, or a
/// stream before its first report) has neither revision.
#[derive(Debug)]
pub struct OpenAtExit {
    pub evidence: crate::plane_driver::OpenUnitEvidence,
    /// The revision the money driver last persisted, if any.
    pub persisted_revision: Option<u64>,
    /// The revision staged in the unit checkpoint book, if the unit has an entry.
    pub staged_revision: Option<u64>,
}

/// The running units at exit and the governed admissions alive beside them.
#[derive(Debug, Default)]
pub struct ExitAdmissions {
    pub units: Vec<OpenAtExit>,
    /// The gate's live count, read while the evidence holds every listed grant.
    pub live: u64,
    /// The distinct grants the evidence holds. A child unit shares its parent's grant, and each
    /// distinct grant holds exactly one gate count, so `live >= distinct_grants`.
    pub distinct_grants: u64,
}

impl ExitAdmissions {
    /// Admissions alive without an open unit (between admission and open, or a ticket
    /// reservation). `None` is an invariant breach, reported as such: never a wrapped value.
    #[must_use]
    pub fn admitted_not_open(&self) -> Option<u64> {
        self.live.checked_sub(self.distinct_grants)
    }
}

impl GovState {
    /// Joins the open-unit evidence with the unit checkpoint book, once, at exit.
    #[must_use]
    pub fn open_at_exit(
        &self,
        evidence: Vec<crate::plane_driver::OpenUnitEvidence>,
    ) -> ExitAdmissions {
        let mut grants: std::collections::BTreeSet<*const super::AdmitGrant> =
            std::collections::BTreeSet::new();
        for unit in &evidence {
            if let Some(grant) = &unit.grant {
                grants.insert(Arc::as_ptr(grant));
            }
        }
        let live = self.admissions.live();
        let mut custody: std::collections::BTreeMap<[u8; 16], (u64, Option<u64>)> =
            std::collections::BTreeMap::new();
        for state in self.unit_checkpoint_states() {
            custody.insert(state.id, (state.revision, state.persisted));
        }
        let mut units = Vec::with_capacity(evidence.len());
        for unit in evidence {
            let entry = custody.get(&unit.checkpoint).copied();
            units.push(OpenAtExit {
                persisted_revision: entry.and_then(|(_, persisted)| persisted),
                staged_revision: entry.map(|(staged, _)| staged),
                evidence: unit,
            });
        }
        ExitAdmissions {
            units,
            live,
            distinct_grants: u64::try_from(grants.len()).unwrap_or(u64::MAX),
        }
    }
}

#[cfg(test)]
#[path = "tests/drain_tests.rs"]
mod tests;
