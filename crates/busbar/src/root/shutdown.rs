// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHUTDOWN DRAIN (SHUTDOWN-HANG F4). One owner, [`ShutdownDrain`], holds the budget from the
//! first shutdown broadcast and bounds every wait on the way out; nothing in flight is ever
//! aborted (an overrun detaches it and the process exits through `process::exit`, as after
//! SIGKILL). Money is persisted from the first broadcast, beside the request drain, until just
//! before the seal phase. The exit is 0 when the writer retired, otherwise 75 (spend saved,
//! streams cut) or 70 (spend unsaved) by one classification of custody at that moment, with the
//! evidence on stderr; never 1 from the drain itself.
//!
//! Phases, in order: [1] requests (cut C1), [S] settle (C2), [3] plane records and the admin
//! audit queue (C3), [2] the money driver's join (C3), [4] the seal phase (C3; SEALING-FIX adds
//! the predecessor sealer, fence settle and final page here), [5] journal flush, final audit
//! drain and the checks (deadline), [6] retirement (deadline).
//!
//! LINT-RULES R16 (`crates/busbar/tests/shutdown_waits.rs`) parses this file: every `.await` is a
//! drain call, inside a drain call's argument, inside `impl ShutdownDrain`/`impl DrainHandle`, or
//! inside a private helper referenced only from drain arguments; no `.abort()`; no blocking call
//! outside a `spawn_blocking` closure.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, LazyLock, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_kernel::governance::GovState;
use busbar_kernel::persistence::journal::runtime::RuntimeJournal;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::Instant;

pub(crate) use busbar_kernel::governance::drain::{Cut, DrainClock};

use crate::root::durability::NodeBook;
use crate::root::serve::{drain_records, LateServices, RECORD_DRAIN};

/// Obtained only by a successful semantic drain and consumed by retirement.
/// Retaining the actual owners binds the final check to the drained generation.
pub(crate) struct Drained {
    governance: Option<Arc<GovState>>,
    runtime: Option<Arc<RuntimeJournal>>,
}

/// The phase a bounded wait belongs to, for the progress line and the detach count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Requests,
    Settle,
    Records,
    Money,
    MoneyFallback,
    Seal,
    Journal,
    Audit,
    Retire,
}

/// Every phase, in discriminant order: the progress line stores the current one as its index.
const PHASES: [Phase; 9] = [
    Phase::Requests,
    Phase::Settle,
    Phase::Records,
    Phase::Money,
    Phase::MoneyFallback,
    Phase::Seal,
    Phase::Journal,
    Phase::Audit,
    Phase::Retire,
];

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Requests => "requests",
            Phase::Settle => "settle",
            Phase::Records => "records",
            Phase::Money => "money",
            Phase::MoneyFallback => "money_fallback",
            Phase::Seal => "seal",
            Phase::Journal => "journal",
            Phase::Audit => "audit",
            Phase::Retire => "retire",
        }
    }
}

/// A bounded wait's result.
#[derive(Debug)]
pub(crate) enum Outcome<T> {
    Done(T),
    /// The phase's cut passed first.
    Cut,
    /// The deadline or a second signal fired first.
    Expired,
}

/// A bounded join's result: the task's answer, or the task itself, detached and still running.
pub(crate) enum Joined<T> {
    Done(Result<T, JoinError>),
    Detached(DrainHandle<T>),
}

/// The only owner of a shutdown-path task handle. It exposes no abort: an overrun detaches it.
pub(crate) struct DrainHandle<T> {
    inner: JoinHandle<T>,
}

impl<T: Send + 'static> DrainHandle<T> {
    pub(crate) fn spawn<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
    {
        Self {
            inner: tokio::spawn(future),
        }
    }
}

impl<T> DrainHandle<T> {
    /// Takes custody of a task spawned at boot (the flusher, work recovery, the lease refresh).
    pub(crate) fn adopt(inner: JoinHandle<T>) -> Self {
        Self { inner }
    }

    /// A poll-free check; it never waits and never cancels.
    pub(crate) fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
}

impl<T> Future for DrainHandle<T> {
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

/// The progress line's period (SHUTDOWN-HANG F4 "Progress": once per second and on every phase
/// change).
const PROGRESS_EVERY: Duration = Duration::from_secs(1);

/// The owners the progress line reads, registered once as `finish` takes them.
struct ProgressSources {
    gov: Option<Arc<GovState>>,
    late: Arc<LateServices>,
    journal: Option<Arc<RuntimeJournal>>,
    fence: Option<Arc<PredecessorFence>>,
}

/// The drain's shared counts: the bounded waits write them, the progress line reads them.
struct Progress {
    clock: Arc<DrainClock>,
    phase: AtomicU8,
    detached: AtomicU64,
    /// Request joins detached at C1 that have not finished yet.
    open_joins: AtomicU64,
    ticking: AtomicBool,
    sources: OnceLock<ProgressSources>,
}

impl Progress {
    /// `shutdown drain: phase=<p> remaining={..} live_admissions=<n> open_units=<n>
    /// open_joins=<n> held_units=<n> predecessor_fence=<settled|retained:n> elapsed=<s>`. A count
    /// whose owner this build does not have yet (the sealing design's unstamped audit pages and
    /// held units) reads `n/a`, never a made-up 0.
    fn line(&self) -> String {
        let phase = PHASES
            .get(usize::from(self.phase.load(Ordering::Relaxed)))
            .copied()
            .unwrap_or(Phase::Requests);
        let sources = self.sources.get();
        let gov = sources.and_then(|s| s.gov.as_ref());
        let remaining = gov.map(|g| g.drain_remaining()).unwrap_or_default();
        let kernel = sources.and_then(|s| s.late.kernel());
        let records = kernel.as_ref().map_or(0, |k| k.pending().queued());
        let open_units = kernel.as_ref().map_or(0, |k| k.open_unit_evidence().len());
        let journal = sources
            .and_then(|s| s.journal.as_ref())
            .map_or(0, |j| j.pending_records());
        let fence = match sources
            .and_then(|s| s.fence.as_ref())
            .map_or(0, |f| f.retained())
        {
            0 => "settled".to_string(),
            n => format!("retained:{n}"),
        };
        let elapsed = self
            .clock
            .armed_at()
            .and_then(|deadline| deadline.checked_sub(self.clock.budget()))
            .map(|armed| Instant::now().saturating_duration_since(armed))
            .unwrap_or_default();
        format!(
            "shutdown drain: phase={} remaining={{checkpoints={}, terminal_checkpoints={}, \
             corrections={}, budget_flights={}, metering={}, records={records}, \
             audit_unstamped=n/a, audit_queue={}, journal_records={journal}}} \
             live_admissions={} open_units={open_units} open_joins={} held_units=n/a \
             predecessor_fence={fence} elapsed={:.1}s",
            phase.name(),
            remaining.checkpoints,
            remaining.terminal_checkpoints,
            remaining.corrections,
            remaining.budget_flights,
            remaining.metering,
            if busbar_kernel::audit::auditlog::has_unsettled_audit() {
                "pending"
            } else {
                "empty"
            },
            gov.map_or(0, |g| g.admissions().live()),
            self.open_joins.load(Ordering::Relaxed),
            elapsed.as_secs_f64(),
        )
    }

    fn emit(&self) {
        tracing::info!("{}", self.line());
    }
}

/// The drain owner: the clock and the counts the exit reports.
pub(crate) struct ShutdownDrain {
    clock: Arc<DrainClock>,
    progress: Arc<Progress>,
}

impl ShutdownDrain {
    pub(crate) fn new(clock: Arc<DrainClock>) -> Self {
        Self {
            progress: Arc::new(Progress {
                clock: Arc::clone(&clock),
                phase: AtomicU8::new(0),
                detached: AtomicU64::new(0),
                open_joins: AtomicU64::new(0),
                ticking: AtomicBool::new(false),
                sources: OnceLock::new(),
            }),
            clock,
        }
    }

    pub(crate) fn clock(&self) -> &Arc<DrainClock> {
        &self.clock
    }

    pub(crate) fn detached(&self) -> u64 {
        self.progress.detached.load(Ordering::Relaxed)
    }

    /// The armed deadline's limit for `cut`, if armed.
    fn until(&self, cut: Cut) -> Option<Instant> {
        self.clock.armed_at().map(|at| self.clock.limit(at, cut))
    }

    /// The one body of every primitive. Unarmed, no limit exists: the future runs until it ends
    /// or the first broadcast arms the clock. Armed, it is cut at the phase's limit and returns
    /// at once on expiry (deadline or second signal).
    async fn limited<F: Future>(&self, cut: Cut, fut: F) -> Outcome<F::Output> {
        let mut fut = std::pin::pin!(fut);
        let mut expired = self.clock.expired_rx();
        let deadline = tokio::select! {
            biased;
            r = &mut fut => return Outcome::Done(r),
            at = self.clock.armed() => at,
        };
        let limit = self.clock.limit(deadline, cut);
        tokio::select! {
            biased;
            _ = expired.wait_for(|e| *e) => Outcome::Expired,
            r = tokio::time::timeout_at(limit, fut) => r.map_or(Outcome::Cut, Outcome::Done),
        }
    }

    /// For futures that own no write and only wait for a notification; dropping one cancels
    /// nothing.
    pub(crate) async fn wait<F: Future>(
        &self,
        phase: Phase,
        fut: F,
        cut: Cut,
    ) -> Outcome<F::Output> {
        let out = self.limited(cut, fut).await;
        if !matches!(out, Outcome::Done(_)) {
            tracing::info!(?phase, ?cut, "shutdown drain: phase cut");
        }
        out
    }

    /// A task's join under the phase's cut. On overrun the task is detached, never aborted.
    pub(crate) async fn bounded<T>(
        &self,
        phase: Phase,
        mut h: DrainHandle<T>,
        cut: Cut,
    ) -> Joined<T> {
        match self.limited(cut, &mut h).await {
            Outcome::Done(r) => Joined::Done(r),
            Outcome::Cut | Outcome::Expired => {
                self.progress.detached.fetch_add(1, Ordering::Relaxed);
                tracing::info!(?phase, ?cut, "shutdown drain: task detached at its cut");
                Joined::Detached(h)
            }
        }
    }

    pub(crate) async fn wait_requests<F: Future>(&self, fut: F) -> Outcome<F::Output> {
        self.wait(Phase::Requests, fut, Cut::Requests).await
    }

    pub(crate) async fn bounded_requests<T>(&self, h: DrainHandle<T>) -> Joined<T> {
        self.bounded(Phase::Requests, h, Cut::Requests).await
    }

    /// A phase change: recorded for the periodic line, and one line now.
    fn enter(&self, phase: Phase) {
        let index = PHASES.iter().position(|p| *p == phase).unwrap_or(0);
        self.progress
            .phase
            .store(u8::try_from(index).unwrap_or(0), Ordering::Relaxed);
        self.progress.emit();
    }

    /// The owners the progress line reads; the first registration stands.
    fn report_to(&self, sources: ProgressSources) {
        let _ = self.progress.sources.set(sources);
    }

    fn note_open_joins(&self, open: usize) {
        self.progress
            .open_joins
            .store(u64::try_from(open).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Once the clock is armed: one progress line per second until the drain owner is dropped
    /// (the process exits first). The task holds no owner of its own, only a weak reference.
    fn start_progress(&self) {
        if self.progress.ticking.swap(true, Ordering::Relaxed) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let progress = Arc::downgrade(&self.progress);
        runtime.spawn(async move {
            let mut every =
                tokio::time::interval_at(Instant::now() + PROGRESS_EVERY, PROGRESS_EVERY);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                every.tick().await;
                let Some(progress) = Weak::upgrade(&progress) else {
                    return;
                };
                progress.emit();
            }
        });
    }
}

/// The lease refresh runs until [6] fires this, immediately before `lease.release()`; every
/// non-retired exit leaves the writer lease to lapse on its own (SHUTDOWN-HANG F4 "Lease").
static RETIRE: LazyLock<tokio::sync::watch::Sender<bool>> =
    LazyLock::new(|| tokio::sync::watch::Sender::new(false));

/// The stop the node lease refresh watches.
pub(crate) fn retire_rx() -> tokio::sync::watch::Receiver<bool> {
    RETIRE.subscribe()
}

/// Everything the serve phase leaves to the drain. `finish` owns it from boot.
pub(crate) struct PostServe<'a> {
    /// The admin listener's serve future (listener mode).
    pub(crate) admin: Option<Pin<Box<dyn Future<Output = ()> + 'a>>>,
    /// The line server (line mode); its code is the exit code of a clean retirement.
    pub(crate) lines: Option<Pin<Box<dyn Future<Output = i32> + 'a>>>,
    /// Data runtimes and transport-plugin listener threads: requests like any other.
    pub(crate) threads: Vec<std::thread::JoinHandle<()>>,
    pub(crate) work_recovery: JoinHandle<()>,
    /// The control runtime's detached-task drain.
    pub(crate) control_drain: Pin<Box<dyn Future<Output = ()> + 'a>>,
    pub(crate) node_lease: Option<crate::root::boot::NodeLeaseTask>,
    /// The flusher: in drain mode it is the money driver [M].
    pub(crate) flusher: Option<JoinHandle<()>>,
    pub(crate) governance: Option<Arc<GovState>>,
    pub(crate) late: Arc<LateServices>,
    pub(crate) book: Option<NodeBook>,
    pub(crate) startup: busbar_kernel::persistence::startup::Startup,
    pub(crate) shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// The start-up predecessor task (F5) and its fence owner, joined and settled in [4].
    pub(crate) predecessor: Option<(JoinHandle<()>, Arc<PredecessorFence>)>,
}

use busbar_kernel::persistence::boot_identity::{undrained_records, PredecessorFence};

/// One synchronous read of the process-wide record ledger, printed on every exit path: the
/// records this process offered that no flush confirmed, closes that may still apply, and
/// records the queue refused.
fn print_exit_snapshot() {
    let report = undrained_records().exit_report();
    for seen in &report.unconfirmed {
        eprintln!("busbar: drain_incomplete_unconfirmed {}", seen.resource());
    }
    for seen in &report.unrecorded {
        eprintln!("busbar: drain_incomplete_unrecorded {}", seen.resource());
    }
}

/// The idle wait of the settle loop.
const DRAIN_PASS_IDLE: Duration = busbar_kernel::governance::DRAIN_PASS_IDLE;

/// The one shutdown sequence of both serve modes. Returns the process exit code.
pub(crate) async fn finish(post: PostServe<'_>, drain: &ShutdownDrain) -> i32 {
    let PostServe {
        admin,
        lines,
        threads,
        work_recovery,
        control_drain,
        node_lease,
        flusher,
        governance,
        late,
        book,
        startup,
        shutdown_tx,
        predecessor,
    } = post;
    drain.report_to(ProgressSources {
        gov: governance.clone(),
        late: Arc::clone(&late),
        journal: book.as_ref().map(|book| book.runtime_journal.clone()),
        fence: predecessor.as_ref().map(|(_, fence)| Arc::clone(fence)),
    });
    let mut failures: Vec<String> = Vec::new();

    // Serving: before the first broadcast these are ordinary awaits of the serve futures.
    let mut line_code = 0;
    if let Some(lines) = lines {
        match drain.wait_requests(lines).await {
            Outcome::Done(code) => line_code = code,
            _ => failures.push("line serving did not end by the request cut".into()),
        }
    }
    if let Some(admin) = admin {
        let served = drain.wait_requests(admin).await;
        if !matches!(served, Outcome::Done(())) {
            failures.push("admin listener did not drain by the request cut".into());
        }
    }
    let _ = shutdown_tx.send(());
    drain.clock().arm(Instant::now() + drain.clock().budget());
    drain.start_progress();
    let gov = governance.as_ref();

    // [1] Requests, all under C1: every request-serving join, then plane cleanup.
    drain.enter(Phase::Requests);
    let mut detached_joins: Vec<DrainHandle<Result<(), JoinError>>> = Vec::new();
    let threads = DrainHandle::spawn(tokio::task::spawn_blocking(move || {
        for handle in threads {
            let _ = handle.join();
        }
    }));
    let recovery = DrainHandle::adopt(work_recovery);
    let controlled = drain.wait_requests(control_drain).await;
    if !matches!(controlled, Outcome::Done(())) {
        failures.push("control tasks did not drain by the request cut".into());
    }
    match drain.bounded_requests(threads).await {
        Joined::Done(_) => {}
        Joined::Detached(handle) => detached_joins.push(handle),
    }
    match drain.bounded_requests(recovery).await {
        Joined::Done(Ok(())) => {}
        Joined::Done(Err(error)) => failures.push(format!("work recovery did not stop: {error}")),
        Joined::Detached(_) => {
            failures.push("work recovery did not stop by the request cut".into())
        }
    }
    let c1 = drain.until(Cut::Requests);
    let cleanup = drain
        .wait(
            Phase::Requests,
            async {
                let mut failed = Vec::new();
                if let Some(cards) = crate::root::kernel::ROOT_CARD.card_store() {
                    if let Err(error) = cards.stop_background().await {
                        failed.push(format!("price publisher did not stop: {error}"));
                    }
                }
                if let Some(kernel) = late.kernel() {
                    let left = c1.map_or(RECORD_DRAIN, |at| {
                        at.saturating_duration_since(Instant::now())
                            .min(RECORD_DRAIN)
                    });
                    if !kernel.drain_plane_cleanup(left).await {
                        failed.push("plane cancellations remain pending".to_string());
                    }
                }
                failed
            },
            Cut::Requests,
        )
        .await;
    match cleanup {
        Outcome::Done(failed) => failures.extend(failed),
        _ => failures.push("plane cleanup did not finish by the request cut".into()),
    }
    drain.note_open_joins(detached_joins.len());
    drain.clock().set_requests_done();
    if let Some(gov) = gov {
        gov.admissions().close();
    }

    // [S] Settle, until C2: planes idle, no governed admission alive, every detached request
    // join ended, and every ended unit settled by [M].
    drain.enter(Phase::Settle);
    let settle = drain
        .wait(
            Phase::Settle,
            async {
                let mut passes = drain.clock().passes_rx();
                loop {
                    let idle = match late.kernel() {
                        Some(kernel) => kernel.drain_plane_cleanup(DRAIN_PASS_IDLE).await,
                        None => true,
                    };
                    drain.note_open_joins(
                        detached_joins.iter().filter(|h| !h.is_finished()).count(),
                    );
                    if idle
                        && gov.is_none_or(|g| g.admissions().live() == 0)
                        && detached_joins.iter().all(DrainHandle::is_finished)
                        && !gov.is_some_and(|g| g.has_unsettled_persistence())
                    {
                        break;
                    }
                    tokio::select! {
                        _ = passes.changed() => {}
                        _ = tokio::time::sleep(DRAIN_PASS_IDLE) => {}
                    }
                }
            },
            Cut::Settle,
        )
        .await;
    let settled = matches!(settle, Outcome::Done(()));
    if !settled {
        failures.push("requests or governed units still running at the settle cut".into());
    }

    // [3] Plane records and the admin audit queue, until C3.
    drain.enter(Phase::Records);
    let c3 = drain.until(Cut::Seal);
    let records = drain
        .wait(
            Phase::Records,
            drain_records(
                &late,
                c3.map_or(RECORD_DRAIN, |at| {
                    at.saturating_duration_since(Instant::now())
                }),
            ),
            Cut::Seal,
        )
        .await;
    if !matches!(records, Outcome::Done(true)) {
        failures.push("plane record writes remain queued".into());
    }
    if let Some(error) = audit_failure(
        drain
            .bounded(
                Phase::Audit,
                DrainHandle::spawn(drain_audit_queue()),
                Cut::Seal,
            )
            .await,
    ) {
        failures.push(error);
    }

    // [2] money_stop, then the money driver's join, until C3. A panicked driver is replaced by
    // the fallback; nothing is aborted.
    drain.clock().stop_money();
    drain.enter(Phase::Money);
    if let Some(flusher) = flusher {
        match drain
            .bounded(Phase::Money, DrainHandle::adopt(flusher), Cut::Seal)
            .await
        {
            Joined::Done(Ok(())) => {}
            Joined::Done(Err(error)) => {
                failures.push(format!(
                    "background accounting flusher did not complete: {error}"
                ));
                if let Some(gov) = &governance {
                    match drain
                        .bounded(
                            Phase::MoneyFallback,
                            DrainHandle::spawn(money_fallback(gov.clone(), drain.clock().clone())),
                            Cut::Seal,
                        )
                        .await
                    {
                        Joined::Done(Ok(failed)) => failures.extend(failed),
                        Joined::Done(Err(error)) => {
                            failures.push(format!("money fallback failed: {error}"))
                        }
                        Joined::Detached(_) => {
                            failures.push("money fallback did not finish by the seal cut".into())
                        }
                    }
                }
            }
            Joined::Detached(_) => {
                failures.push("money driver did not finish by the seal cut".into());
            }
        }
    }

    // [4] The seal phase, until C3: the predecessor task's join (it was told to stop at the
    // first broadcast and stops at its next step boundary), then the fence settle, which
    // re-drives what it left retained and submits nothing new. Both detach on overrun.
    // SEALING-FIX adds the notary's final page here, bounded by Cut::Seal.
    drain.enter(Phase::Seal);
    if let Some((task, fence)) = predecessor {
        if let Joined::Detached(_) = drain
            .bounded(Phase::Seal, DrainHandle::adopt(task), Cut::Seal)
            .await
        {
            failures.push("the start-up predecessor task did not stop by the seal cut".into());
        }
        let settling = Arc::clone(&fence);
        if let Joined::Detached(_) = drain
            .bounded(
                Phase::Seal,
                DrainHandle::spawn(async move { settling.settle().await }),
                Cut::Seal,
            )
            .await
        {
            eprintln!(
                "busbar: shutdown predecessor_fence=retained:{}",
                fence.retained()
            );
        }
    }

    // [5] Close staging, flush the journal, drain the admin audit queue, then the checks.
    drain.enter(Phase::Journal);
    let runtime = book.as_ref().map(|book| book.runtime_journal.clone());
    if let Some(runtime) = &runtime {
        if let Err(error) = runtime.stop_staging() {
            failures.push(format!("journal staging did not close: {error:?}"));
        }
        let journal = runtime.clone();
        match drain
            .bounded(
                Phase::Journal,
                DrainHandle::spawn(async move { journal.flush().await }),
                Cut::Deadline,
            )
            .await
        {
            Joined::Done(Ok(Ok(()))) => {}
            Joined::Done(Ok(Err(error))) => {
                failures.push(format!("journal originals remain unresolved: {error:?}"))
            }
            Joined::Done(Err(error)) => {
                failures.push(format!("journal final driver failed: {error}"))
            }
            Joined::Detached(_) => failures
                .push("journal flush deadline reached; exact originals remain retained".into()),
        }
        if runtime.pending_records() != 0 {
            failures.push("native journal still owns unpublished originals".into());
        }
    }
    // A late audit producer must leave a visible failure after journal closure. The record
    // ledger's retry task closes first, so only this sequence retries; a record is confirmed
    // only by a drain that began after it (its mark). A record refused while the queue was
    // full gets a second round once the first drain has emptied it.
    let ledger = undrained_records();
    ledger.close_retry_task();
    ledger.retry_unrecorded();
    let mark = ledger.mark();
    let audit = audit_failure(
        drain
            .bounded(
                Phase::Audit,
                DrainHandle::spawn(drain_audit_queue()),
                Cut::Deadline,
            )
            .await,
    );
    match audit {
        Some(error) => failures.push(format!("final audit drain: {error}")),
        None => {
            if !busbar_kernel::audit::auditlog::has_unsettled_audit() {
                ledger.confirm_before(mark);
            }
            if ledger.has_unrecorded() {
                ledger.retry_unrecorded();
                let second = ledger.mark();
                let again = audit_failure(
                    drain
                        .bounded(
                            Phase::Audit,
                            DrainHandle::spawn(drain_audit_queue()),
                            Cut::Deadline,
                        )
                        .await,
                );
                match again {
                    Some(error) => failures.push(format!("final audit drain: {error}")),
                    None => ledger.confirm_before(second),
                }
            }
        }
    }
    if busbar_kernel::audit::auditlog::has_unsettled_audit() {
        failures.push("administrative audit still owns queued or active originals".into());
    }
    if gov.is_some_and(|gov| gov.has_unsettled_persistence()) {
        failures.push("governance still owns unsettled persistence".into());
    }
    if drain.clock().expired() {
        return incomplete(drain, gov, &late, "deadline", &failures);
    }
    if !settled || !failures.is_empty() {
        return incomplete(drain, gov, &late, "undrained", &failures);
    }

    // [6] Retire: the lease is released inside, after the refresh is stopped.
    drain.enter(Phase::Retire);
    let drained = Drained {
        governance: governance.clone(),
        runtime,
    };
    match drain
        .bounded(
            Phase::Retire,
            DrainHandle::spawn(retire_storage(startup, book, drained)),
            Cut::Deadline,
        )
        .await
    {
        Joined::Done(Ok(Ok(()))) => {}
        Joined::Done(Ok(Err(error))) => {
            return incomplete(drain, gov, &late, "retire_refused", &[error]);
        }
        Joined::Done(Err(error)) => {
            return incomplete(drain, gov, &late, "retire_refused", &[error.to_string()]);
        }
        Joined::Detached(_) => {
            return incomplete(
                drain,
                gov,
                &late,
                "deadline",
                &["retirement unconfirmed".to_string()],
            );
        }
    }
    if let Some(lease) = node_lease {
        match drain
            .bounded(Phase::Retire, DrainHandle::adopt(lease), Cut::Deadline)
            .await
        {
            Joined::Done(Ok(Ok(()))) => {}
            Joined::Done(Ok(Err(error))) => {
                tracing::error!(%error, "node lease refresh failed before retirement");
            }
            Joined::Done(Err(error)) => {
                tracing::error!(%error, "node lease task failed before retirement");
            }
            Joined::Detached(_) => {}
        }
    }
    print_exit_snapshot();
    line_code
}

/// A non-retired exit: one classification of custody at this moment, its evidence on stderr.
fn incomplete(
    drain: &ShutdownDrain,
    gov: Option<&Arc<GovState>>,
    late: &LateServices,
    cause: &'static str,
    failures: &[String],
) -> i32 {
    let custody = gov.map(|g| g.spend_custody()).unwrap_or_default();
    let code = custody.exit_code();
    let live = gov.map_or(0, |g| g.admissions().live());
    busbar_kernel::diag_warn!(
        busbar_kernel::diagnostics::SHUTDOWN_DRAIN_INCOMPLETE,
        cause,
        code,
        live_admissions = live,
        detached = drain.detached(),
        unpersisted = custody.unpersisted.len(),
        in_doubt = custody.in_doubt.len(),
        custody_only = custody.custody_only.len(),
        "shutdown drain incomplete"
    );
    eprintln!(
        "busbar: shutdown drain incomplete: cause={cause} code={code} live_admissions={live} detached={}",
        drain.detached()
    );
    for failure in failures {
        eprintln!("busbar: shutdown: {failure}");
    }
    for (list, items) in [
        ("unpersisted", &custody.unpersisted),
        ("in_doubt", &custody.in_doubt),
        ("custody_only", &custody.custody_only),
    ] {
        for item in items {
            eprintln!("busbar: shutdown {list} {} {}", item.kind, item.detail);
        }
    }
    if custody.spend_unsaved() {
        busbar_kernel::diag_error!(
            busbar_kernel::diagnostics::SHUTDOWN_SPEND_UNPERSISTED,
            unpersisted = custody.unpersisted.len(),
            in_doubt = custody.in_doubt.len(),
            "completed spend is not in durable custody; listed on stderr as evidence"
        );
    }
    for line in open_at_exit_lines(gov, late) {
        eprintln!("busbar: shutdown {line}");
    }
    print_exit_snapshot();
    code
}

/// Every unit still running at exit, one `open_at_exit { .. }` line each, joined with the unit
/// checkpoint book by checkpoint id (a unit with no checkpoint reads `none`), then the
/// admissions alive without an open unit (SHUTDOWN-HANG F4 "Running requests at exit"). One
/// walk, at exit; a running unit never changes the exit code.
fn open_at_exit_lines(gov: Option<&Arc<GovState>>, late: &LateServices) -> Vec<String> {
    use std::fmt::Write as _;
    let Some(gov) = gov else {
        return Vec::new();
    };
    let evidence = late
        .kernel()
        .map(|kernel| kernel.open_unit_evidence())
        .unwrap_or_default();
    let exit = gov.open_at_exit(evidence);
    let revision = |n: Option<u64>| n.map_or_else(|| "none".to_string(), |n| n.to_string());
    let mut lines = Vec::with_capacity(exit.units.len() + 1);
    for unit in &exit.units {
        let open = &unit.evidence;
        let mut reported = String::new();
        for (at, count) in open.reported.iter().enumerate() {
            let class = open
                .money
                .classes
                .get(count.class as usize)
                .map_or("?", String::as_str);
            let _ = write!(
                reported,
                "{}{class}={}",
                if at == 0 { "" } else { " " },
                count.amount
            );
        }
        lines.push(format!(
            "open_at_exit {{ unit: {}, checkpoint: {}, principal: {}, group: {}, lane: {}, \
             arrived: {}, reported: [{reported}], ledgered: {}, finished: {}, governed: {}, \
             persisted_revision: {}, staged_revision: {} }}",
            open.unit.get(),
            hex::encode(open.checkpoint),
            open.money.key.id,
            open.money.key.group.as_deref().unwrap_or("none"),
            open.money.lane,
            open.money.arrived,
            open.ledgered,
            open.finished,
            open.grant.is_some(),
            revision(unit.persisted_revision),
            revision(unit.staged_revision),
        ));
    }
    lines.push(match exit.admitted_not_open() {
        Some(n) => format!(
            "admitted_not_open={n} live={} distinct_grants={}",
            exit.live, exit.distinct_grants
        ),
        None => format!(
            "admission_count_mismatch live={} distinct_grants={}",
            exit.live, exit.distinct_grants
        ),
    });
    lines
}

fn audit_failure(joined: Joined<Result<(), String>>) -> Option<String> {
    match joined {
        Joined::Done(Ok(Ok(()))) => None,
        Joined::Done(Ok(Err(error))) => Some(error),
        Joined::Done(Err(error)) => Some(format!("administrative audit driver failed: {error}")),
        Joined::Detached(_) => Some("administrative audit drain did not finish by its cut".into()),
    }
}

/// The panic fallback for [M]: today's three drives, budgets final and metering final first,
/// then the unit drive under the paced C3 halt. It never closes staging or flushes the journal,
/// so the seal phase can still stage its final page.
async fn money_fallback(gov: Arc<GovState>, clock: Arc<DrainClock>) -> Vec<String> {
    let mut failures = Vec::new();
    let c3 = clock
        .armed_at()
        .map_or_else(Instant::now, |at| clock.limit(at, Cut::Seal));
    let budget_owner = gov.clone();
    match tokio::spawn(super::measurements::maintenance(async move {
        budget_owner.flush_budgets_final().await
    }))
    .await
    {
        Ok(flushed) => tracing::info!(flushed, "budget shutdown flush completed"),
        Err(error) => failures.push(format!("budget final driver failed: {error}")),
    }
    let metering_owner = gov.clone();
    match tokio::spawn(super::measurements::maintenance(async move {
        metering_owner.flush_metering_final().await
    }))
    .await
    {
        Ok(flushed) => tracing::info!(flushed, "metering shutdown flush completed"),
        Err(error) => failures.push(format!("metering final driver failed: {error}")),
    }
    let paced = PacedHalt::new(clock, c3);
    match tokio::spawn(super::measurements::maintenance(async move {
        gov.flush_unit_checkpoints_until(&|| paced.halt()).await
    }))
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => failures.push(format!("unit checkpoints remain unresolved: {error}")),
        Err(error) => failures.push(format!("unit checkpoint driver failed: {error}")),
    }
    failures
}

/// Stops before a batch that, at the previous batch's pace, would end after C3. A batch slower
/// than the one before it can still cross C3; [2] then detaches the fallback (stated limit).
pub(crate) struct PacedHalt {
    clock: Arc<DrainClock>,
    c3: Instant,
    origin: Instant,
    /// Nanoseconds since `origin` of the previous read; `u64::MAX` before the first.
    last_ns: AtomicU64,
}

impl PacedHalt {
    pub(crate) fn new(clock: Arc<DrainClock>, c3: Instant) -> Self {
        Self {
            clock,
            c3,
            origin: Instant::now(),
            last_ns: AtomicU64::new(u64::MAX),
        }
    }

    pub(crate) fn halt(&self) -> bool {
        let now = Instant::now();
        let at = u64::try_from(now.duration_since(self.origin).as_nanos()).unwrap_or(u64::MAX);
        let prev = self.last_ns.swap(at, Ordering::Relaxed);
        let step = if prev == u64::MAX {
            Duration::ZERO
        } else {
            Duration::from_nanos(at.saturating_sub(prev))
        };
        self.clock.expired() || now + step >= self.c3
    }
}

async fn drain_audit_queue() -> Result<(), String> {
    if !busbar_kernel::audit::auditlog::has_unsettled_audit() {
        return Ok(());
    }
    match tokio::spawn(busbar_kernel::audit::auditlog::flush_pending()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!(
            "administrative audit originals remain unresolved: {error}"
        )),
        Err(error) => Err(format!("administrative audit driver failed: {error}")),
    }
}

/// Native retirement requires the successful drain result from this same book.
/// The startup owner additionally refuses retirement while CoreStore retains any
/// uncertain physical attempt, including attempts owned outside governance.
async fn retire_storage(
    mut startup: busbar_kernel::persistence::startup::Startup,
    book: Option<NodeBook>,
    drained: Drained,
) -> Result<(), String> {
    use busbar_kernel::persistence::startup::Progress;
    let core = startup
        .store()
        .ok_or("Store was not admitted for retirement")?;
    if let Some(gov) = &drained.governance {
        if !Arc::ptr_eq(
            &core,
            &gov.core_store_handle().map_err(|error| error.to_string())?,
        ) {
            return Err("shutdown drain belongs to another governance Store".into());
        }
        if gov.has_unsettled_persistence() {
            return Err("governance acquired unsettled persistence after its final drain".into());
        }
    }
    match (&book, &drained.runtime) {
        (Some(book), Some(runtime)) if Arc::ptr_eq(&book.runtime_journal, runtime) => {
            if !runtime.is_bound_to(&core) {
                return Err("shutdown journal belongs to another Store".into());
            }
            if runtime.pending_records() != 0 {
                return Err(
                    "native journal still owns unpublished originals; writer was not retired"
                        .into(),
                );
            }
            if let Some(lease) = &book.node_lease {
                RETIRE.send_replace(true);
                lease.release().await?;
            }
        }
        (None, None) => {}
        _ => return Err("shutdown drain belongs to another journal generation".into()),
    }
    if busbar_kernel::audit::auditlog::has_unsettled_audit() {
        return Err("administrative audit acquired originals after its final drain".into());
    }
    startup
        .begin_retirement()
        .map_err(|error| format!("Store writer retirement refused: {error:?}"))?;
    loop {
        match startup
            .advance()
            .await
            .map_err(|error| format!("Store writer retirement: {error:?}"))?
        {
            Progress::Advanced => {}
            Progress::Retired => return Ok(()),
            _ => return Err("Store writer retirement remains unconfirmed".into()),
        }
    }
}

#[cfg(test)]
#[path = "tests/shutdown.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/shutdown_drain.rs"]
mod drain_tests;
