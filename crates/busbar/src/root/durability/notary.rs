// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT NOTARY (SEALING-FIX r20 §3.3): one task per node book, on the control runtime, that
//! signs the newest linked line's fingerprint every `audit.seal_every` ms. One stamp vouches for
//! every line before it (each line is linked to the one before), so no request ever signs.
//!
//! The task never blocks. It awaits only its timer, the head cell's wake, the live signer's reply
//! and its stop signal; each sign runs on the notary signer thread ([`super::signer`]). It changes
//! its state only in synchronous code after a reply arrived, so detaching it at any `.await`
//! leaves at most a signature nobody posts.
//!
//! Pages never overlap (G10): a sign starts only while no stamp run is pending, the next page
//! starts at `committed_through + 1` (every staged stamp included), and a staged stamp is never
//! replaced, only re-driven. A notary that exits for any reason but [`NotaryTask::stop`] is never
//! restarted: a rebuilt task would not know `committed_through`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_kernel::persistence::journal::head_cell::{Head, HeadCell};
use busbar_kernel::persistence::journal::runtime::{
    CutProgress, JournalCut, RuntimeError, RuntimeJournal, StagedRun,
};
use busbar_kernel_audit::{stamp_body, Fingerprint, Stamp, StampKind};
use busbar_kernel_wal::{Entry, RecordClass};
use tokio::sync::{oneshot, watch, Notify};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use super::signer::{Live, SignFailure, SignerHandle, SIGN_DEADLINE};

#[path = "original_notary.rs"]
pub(crate) mod original;
use busbar_contract::storage::StorageCredit;
use original::{
    OriginalNotaryReady, OriginalPageCursor, OriginalPageReceipt, OriginalPageTarget, PageDelivery,
    PageFunding,
};

/// The longest backoff after a refused store or a failing signer.
const MAX_BACKOFF: Duration = Duration::from_secs(1);

/// Consecutive sign failures before `AUDIT_STAMP_FAILED{reason: signer}`.
const SIGN_FAILURES_ALERT: u32 = 3;

/// The wait after an unresolved journal cut while it is re-driven at stop (§3.9 "At shutdown").
const CUT_SETTLE_RETRY: Duration = Duration::from_millis(50);

/// THE CUT'S FLOOR (b) (SEALING-FIX §3.9): the WAL `node_seq` of the oldest audit line a pending,
/// recovered or held checkpoint still names, read once per cut trigger off the request path.
pub(crate) type FloorHints = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// How the Ephemeral journal cut ended at stop (`journal_cut=` on the shutdown progress line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CutEnd {
    /// The journal is never cut (Local or Quorum), or cuts were never started.
    None,
    /// No cut attempt is left undecided.
    Settled,
    /// A cut attempt is still undecided; its store attempt stays retained (exit 75 through the
    /// retirement's `PendingWork`).
    Retained,
}

impl CutEnd {
    /// The progress line's value, `None` for a journal that is never cut.
    #[must_use]
    pub(crate) fn label(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Settled => Some("settled"),
            Self::Retained => Some("retained"),
        }
    }
}

/// Where the notary's one journal cut is: idle in its hands, or running on its own task (a cut
/// awaits the store, and the notary never blocks on one).
enum CutSeat {
    None,
    Idle(Box<JournalCut>),
    Running(JoinHandle<(JournalCut, CutProgress)>),
}

/// THE HEAD FEED: the cell the request path publishes to, and the wake for a parked notary.
#[derive(Debug, Default)]
pub(crate) struct HeadFeed {
    cell: HeadCell,
    wake: Notify,
    pub(super) original: Arc<original::OriginalChain>,
}

impl HeadFeed {
    /// Publish a newly staged line (the caller holds the node's `Durability` lock).
    pub(crate) fn publish(&self, head: &Head) {
        self.original.unwitnessed();
        if self.cell.publish(head) {
            self.wake.notify_one();
        }
    }

    /// Publish a recovery line only if it is newer than the head (SEALING-FIX §3.5).
    pub(crate) fn publish_max(&self, head: &Head) {
        self.original.unwitnessed();
        if self.cell.publish_max(head) {
            self.wake.notify_one();
        }
    }

    /// The head as it stands.
    #[must_use]
    pub(crate) fn head(&self) -> Head {
        self.cell.read().1
    }

    pub(super) fn publish_original(
        &self,
        head: Head,
        witness: Option<&original::OriginalLineWitness>,
    ) {
        self.original.publish(head, witness);
        if self.cell.publish(&head) {
            self.wake.notify_one();
        }
    }

    pub(super) fn bind_original(
        &self,
        journal: Arc<RuntimeJournal>,
        key: busbar_kernel_audit::AuditVerifyingKey,
    ) -> Result<(), &'static str> {
        self.original.bind(journal, key, self.head())
    }

    pub(crate) fn register_original_receiver(
        &self,
        receiver: std::sync::Weak<crate::root::plane_node::RetainedBook>,
    ) -> Result<(), &'static str> {
        self.original.register(receiver)
    }

    pub(crate) fn original_ready(&self) -> Option<OriginalNotaryReady> {
        self.original.ready()
    }

    pub(super) fn configure_original(&self, template: &Stamp) -> Result<(), &'static str> {
        if self.original.is_bound() {
            self.original.configure(template)?;
        }
        Ok(())
    }

    pub(super) fn stop_original(&self) {
        self.original.invalidate();
    }
}

/// What the notary stamps under.
#[derive(Debug, Clone)]
pub(crate) struct NotaryConfig {
    /// This node.
    pub(crate) node: u64,
    /// This process's host identity (`host_identity()`; may be empty).
    pub(crate) host: String,
    /// `audit.seal_every`, ms (1-1000).
    pub(crate) every_ms: u64,
    /// The WAL `node_seq` of this boot's committed `notary_key` line, 0 with no delegated key.
    pub(crate) key_cert: u64,
}

/// Where the notary starts: everything at or below `stamped_through` is already stamped, or was
/// sealed or recorded broken by the boot phase, and is never re-stamped.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NotaryStart {
    /// The chain `seq` of the last stamped (or boot-sealed) line.
    pub(crate) stamped_through: u64,
    /// That line's WAL `node_seq`, 0 before the first stamp.
    pub(crate) stamped_node_seq: u64,
}

/// THE NOTARY'S PROGRESS, for gauges and the stall alert only (`Relaxed`). Nothing reads it to
/// decide a stamp range.
#[derive(Debug, Default)]
pub(crate) struct NotaryProgress {
    /// The `to` of the last stamp known Applied.
    pub(crate) stamped_through: AtomicU64,
    /// The `to` of the last stamp staged.
    pub(crate) committed_through: AtomicU64,
    /// The WAL `node_seq` of line `stamped_through` (the Ephemeral journal cut's floor).
    pub(crate) stamped_node_seq: AtomicU64,
    /// The `linked_ms` of the oldest line no stamp covers yet; 0 for none.
    pub(crate) oldest_unstamped_ms: AtomicU64,
    /// Consecutive sign failures.
    pub(crate) sign_failures: AtomicU64,
    /// Whether a journal cut attempt is undecided right now.
    pub(crate) journal_cut_retained: AtomicBool,
}

/// What the task hands back when it ends: what the shutdown's final page needs.
#[derive(Debug)]
pub(crate) struct NotaryEnd {
    /// The last stamp known Applied.
    pub(crate) stamped_through: u64,
    /// The last stamp staged (a staged stamp still commits with the journal's final flush).
    pub(crate) committed_through: u64,
    /// Why stamping stopped before `stop()`, if it did.
    pub(crate) halted: Option<String>,
    /// How the Ephemeral journal cut ended.
    pub(crate) journal_cut: CutEnd,
    /// The final page (SEALING-FIX §3.6.3 step 3): `Some(true)` staged, `Some(false)` its sign failed
    /// (`audit_final=signer_failed`), `None` when no line was left unstamped or stamping had halted.
    pub(crate) final_staged: Option<bool>,
}

/// THE RUNNING NOTARY. The root keeps it to stop it at shutdown and to check it from the
/// maintenance tick.
#[derive(Debug)]
pub(crate) struct NotaryTask {
    join: JoinHandle<NotaryEnd>,
    exited: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
    progress: Arc<NotaryProgress>,
    every_ms: u64,
}

impl NotaryTask {
    /// Its progress.
    #[must_use]
    pub(crate) fn progress(&self) -> &Arc<NotaryProgress> {
        &self.progress
    }

    /// Set when the task's future is dropped or returns, a panic included (its unwind drops it).
    #[must_use]
    pub(crate) fn exited(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.exited)
    }

    /// The age the stall alert fires at: ten pages, at least one second.
    #[must_use]
    pub(crate) fn stall_after_ms(&self) -> u64 {
        self.every_ms.saturating_mul(10).max(1_000)
    }

    /// STOP: signal the task and hand back its join. The task finishes the step it is in (it never
    /// blocks) and returns its [`NotaryEnd`]; a panicked task answers with the `JoinError`.
    pub(crate) fn stop(self) -> JoinHandle<NotaryEnd> {
        let _ = self.stop.send(true);
        self.join
    }
}

/// A page being signed.
#[derive(Clone)]
struct Page {
    to: u64,
    to_node_seq: u64,
    first_ms: Option<u64>,
    original: Option<OriginalPageTarget>,
    upper: Option<u64>,
}

struct Funding {
    page: Page,
    cursor: Option<OriginalPageCursor>,
    credit: Option<StorageCredit>,
}

impl Funding {
    fn retry(page: Page, credit: Option<StorageCredit>) -> Self {
        let cursor = page.upper.map(OriginalPageCursor::start);
        Self {
            page,
            cursor,
            credit,
        }
    }
}

/// The one outstanding sign.
struct Signing {
    page: Page,
    rx: oneshot::Receiver<Result<Stamp, SignFailure>>,
    deadline: Instant,
    submitted_ms: u64,
    credit: Option<StorageCredit>,
}

/// The one staged, not yet confirmed stamp.
struct Inflight {
    run: Arc<StagedRun>,
    page: Page,
    driver: Option<JoinHandle<Result<(), RuntimeError>>>,
    backoff: Duration,
    retry_at: Instant,
    credit: Option<StorageCredit>,
    receipt: Option<OriginalPageReceipt>,
    cursor: Option<OriginalPageCursor>,
}

struct Notary {
    cfg: NotaryConfig,
    every: Duration,
    journal: Arc<RuntimeJournal>,
    feed: Arc<HeadFeed>,
    live: SignerHandle<Live>,
    progress: Arc<NotaryProgress>,
    stamped_through: u64,
    committed_through: u64,
    stamped_node_seq: u64,
    inflight: Option<Inflight>,
    signing: Option<Signing>,
    funding: Option<Funding>,
    sign_failures: u32,
    sign_backoff: Duration,
    sign_retry_at: Option<Instant>,
    signer_alerted: bool,
    store_alerted: bool,
    tail_first_ms: Option<u64>,
    seen_version: u64,
    parked: bool,
    halted: Option<String>,
    stopping: bool,
    /// The journal's one cut, on an Ephemeral journal (§3.9).
    cut: CutSeat,
    /// A stamp was confirmed since the last cut started: the cut's trigger.
    cut_due: bool,
    floor_hints: Option<FloorHints>,
    drain_clock: Option<Arc<busbar_kernel::governance::drain::DrainClock>>,
}

/// START THE NOTARY on the current runtime (the control runtime, from boot), with the cut's floor
/// (b) source. On an Ephemeral journal the notary takes the
/// journal's one cut and calls it after each confirmed stamp (SEALING-FIX §3.9).
#[cfg(test)]
pub(crate) fn spawn_with_floor(
    cfg: NotaryConfig,
    start: NotaryStart,
    journal: Arc<RuntimeJournal>,
    feed: Arc<HeadFeed>,
    live: SignerHandle<Live>,
    floor_hints: Option<FloorHints>,
    drain_clock: Option<Arc<busbar_kernel::governance::drain::DrainClock>>,
) -> NotaryTask {
    spawn_with_boot(
        cfg,
        start,
        journal,
        feed,
        live,
        NotaryRuntime {
            floor_hints,
            drain_clock,
            boot: None,
        },
    )
}

/// Cold ownership passed into the notary task; no slot is added to the request-path book.
pub(crate) struct NotaryRuntime {
    pub(crate) floor_hints: Option<FloorHints>,
    pub(crate) drain_clock: Option<Arc<busbar_kernel::governance::drain::DrainClock>>,
    pub(crate) boot: Option<super::boot_jobs::BootPreparation>,
}

pub(crate) fn spawn_with_boot(
    cfg: NotaryConfig,
    start: NotaryStart,
    journal: Arc<RuntimeJournal>,
    feed: Arc<HeadFeed>,
    live: SignerHandle<Live>,
    runtime: NotaryRuntime,
) -> NotaryTask {
    let NotaryRuntime {
        floor_hints,
        drain_clock,
        boot,
    } = runtime;
    let cut = journal
        .cutter()
        .map_or(CutSeat::None, |cut| CutSeat::Idle(Box::new(cut)));
    let every_ms = cfg.every_ms.clamp(1, 1_000);
    let cfg = NotaryConfig { every_ms, ..cfg };
    let progress = Arc::new(NotaryProgress::default());
    progress
        .stamped_through
        .store(start.stamped_through, Ordering::Relaxed);
    progress
        .committed_through
        .store(start.stamped_through, Ordering::Relaxed);
    progress
        .stamped_node_seq
        .store(start.stamped_node_seq, Ordering::Relaxed);
    let (stop, mut stop_rx) = watch::channel(false);
    let mut notary = Notary {
        cfg,
        every: Duration::from_millis(every_ms),
        journal,
        feed,
        live,
        progress: Arc::clone(&progress),
        stamped_through: start.stamped_through,
        committed_through: start.stamped_through,
        stamped_node_seq: start.stamped_node_seq,
        inflight: None,
        signing: None,
        funding: None,
        sign_failures: 0,
        sign_backoff: Duration::ZERO,
        sign_retry_at: None,
        signer_alerted: false,
        store_alerted: false,
        tail_first_ms: None,
        seen_version: 0,
        parked: false,
        halted: None,
        stopping: false,
        cut,
        cut_due: false,
        floor_hints,
        drain_clock,
    };
    let exited = Arc::new(AtomicBool::new(false));
    notary.feed.original.started(exited.clone());
    let flag = ExitFlag(Arc::clone(&exited));
    NotaryTask {
        join: tokio::spawn(async move {
            let _flag = flag;
            if let Some(mut boot) = boot {
                let preparation = boot.run();
                tokio::pin!(preparation);
                let mut watch = tokio::time::interval(busbar_kernel::host_records::FLUSH_INTERVAL);
                watch.set_missed_tick_behavior(MissedTickBehavior::Skip);
                let outcome = loop {
                    tokio::select! {
                        biased;
                        changed = stop_rx.changed() => {
                            if changed.is_err() || *stop_rx.borrow() {
                                break Err("shutdown before audit boot originals confirmed".into());
                            }
                        }
                        answer = &mut preparation => break answer,
                        _ = watch.tick() => {
                            let head = notary.feed.head();
                            if head.seq > notary.stamped_through {
                                let _ = notary.progress.oldest_unstamped_ms.compare_exchange(
                                    0, head.wall_ms, Ordering::Relaxed, Ordering::Relaxed);
                            }
                        }
                    }
                };
                match outcome {
                    Ok(key_cert) => notary.cfg.key_cert = key_cert,
                    Err(reason) => notary.halt(reason),
                }
            }
            notary.run(stop_rx).await
        }),
        exited,
        stop,
        progress,
        every_ms,
    }
}

/// Marks the notary exited when dropped: on return and on a panic's unwind alike.
struct ExitFlag(Arc<AtomicBool>);

impl Drop for ExitFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// The live reply, or never while no sign is outstanding.
async fn reply(signing: &mut Option<Signing>) -> Result<Stamp, SignFailure> {
    match signing {
        Some(signing) => match (&mut signing.rx).await {
            Ok(answer) => answer,
            Err(_) => Err(SignFailure::Gone),
        },
        None => std::future::pending().await,
    }
}

fn next_backoff(current: Duration, every: Duration) -> Duration {
    if current.is_zero() {
        every
    } else {
        (current * 2).min(MAX_BACKOFF)
    }
}

impl Notary {
    async fn run(mut self, mut stop: watch::Receiver<bool>) -> NotaryEnd {
        let mut interval = tokio::time::interval(self.every);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                biased;
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break;
                    }
                }
                answer = reply(&mut self.signing) => self.on_reply(answer),
                () = self.feed.wake.notified(), if self.parked => {
                    self.parked = false;
                    self.feed.cell.unpark();
                    interval.reset();
                    self.tick().await;
                }
                _ = interval.tick(), if !self.parked => self.tick().await,
            }
        }
        self.stopping = true;
        if self.parked {
            self.feed.cell.unpark();
        }
        let journal_cut = self.settle_cut().await;
        let final_staged = self.final_page().await;
        NotaryEnd {
            stamped_through: self.stamped_through,
            committed_through: self.committed_through,
            halted: self.halted,
            journal_cut,
            final_staged,
        }
    }

    /// AT STOP (§3.6.3 step 3, §3.9 "At shutdown"): start no new cut; await a running one, then
    /// re-drive a retained attempt until it is decided, waiting 50 ms after each unresolved try.
    /// The drain bounds this (`Cut::Seal`); detached at C3, the store attempt stays retained.
    async fn settle_cut(&mut self) -> CutEnd {
        let mut cut = match std::mem::replace(&mut self.cut, CutSeat::None) {
            CutSeat::None => return CutEnd::None,
            CutSeat::Idle(cut) => *cut,
            CutSeat::Running(running) => match running.await {
                Ok((cut, progress)) => {
                    self.on_cut(&cut, progress);
                    cut
                }
                // A panicked cut task left its store attempt as it was.
                Err(_) => return CutEnd::Retained,
            },
        };
        while cut.retained() {
            self.progress
                .journal_cut_retained
                .store(true, Ordering::Relaxed);
            match cut.settle().await {
                CutProgress::Retained => tokio::time::sleep(CUT_SETTLE_RETRY).await,
                progress => self.on_cut(&cut, progress),
            }
        }
        self.progress
            .journal_cut_retained
            .store(false, Ordering::Relaxed);
        CutEnd::Settled
    }

    /// The cut step of a tick: collect a finished cut, then start the next one after a confirmed
    /// stamp (§3.9: "after step 4, one cut at a time"). Never awaits the store: the cut runs on its
    /// own task and is collected at a later tick.
    async fn step_cut(&mut self) {
        let cut = match std::mem::replace(&mut self.cut, CutSeat::None) {
            CutSeat::None => {
                self.cut_due = false;
                return;
            }
            CutSeat::Running(running) if !running.is_finished() => {
                self.cut = CutSeat::Running(running);
                return;
            }
            CutSeat::Running(running) => match running.await {
                Ok((cut, progress)) => {
                    self.on_cut(&cut, progress);
                    Box::new(cut)
                }
                Err(join) => {
                    self.cut_due = false;
                    busbar_kernel::diag_error!(
                        busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                        node = self.cfg.node,
                        reason = "truncate",
                        cause = %join,
                        "the journal cut task ended unexpectedly; cuts stop for this process"
                    );
                    return;
                }
            },
            CutSeat::Idle(cut) => cut,
        };
        let draining = self
            .drain_clock
            .as_ref()
            .is_some_and(|clock| clock.armed_at().is_some());
        if !self.cut_due || self.stopping || draining || self.halted.is_some() {
            if draining {
                self.cut_due = false;
            }
            self.cut = CutSeat::Idle(cut);
            return;
        }
        let mut cut = *cut;
        self.cut_due = false;
        let floor = self.cut_floor();
        // A Store crossing may not answer before C3. Publish the undecided state before
        // spawning it so the shutdown snapshot cannot call an in-flight cut settled.
        self.progress
            .journal_cut_retained
            .store(true, Ordering::Release);
        self.cut = CutSeat::Running(tokio::spawn(async move {
            let progress = cut.truncate_through(floor).await;
            (cut, progress)
        }));
    }

    /// The notary's part of the floor, in journal ordinals (§3.9): (a) the WAL position of the
    /// newest durable stamp's `to` line (never the chain seq, never the stamp row's own seq), and
    /// (b) the row before the oldest audit line a checkpoint in custody names. The journal adds
    /// (c) the retained tail and (d) its pins.
    fn cut_floor(&self) -> u64 {
        if self.stamped_node_seq == 0 {
            return 0;
        }
        let stamped = self.journal.ordinal_of(self.stamped_node_seq);
        let held = self
            .floor_hints
            .as_ref()
            .and_then(|hints| hints())
            .map_or(u64::MAX, |seq| {
                self.journal.ordinal_of(seq).saturating_sub(1)
            });
        stamped.min(held)
    }

    fn on_cut(&self, cut: &JournalCut, progress: CutProgress) {
        self.progress
            .journal_cut_retained
            .store(cut.retained(), Ordering::Relaxed);
        if let CutProgress::Cut { base } = progress {
            tracing::debug!(
                node = self.cfg.node,
                base,
                "the journal was cut below its base"
            );
        }
    }

    /// THE FINAL PAGE, made by this task on stop (SEALING-FIX §3.6.3 step 3), so the notary's state
    /// has one stager only. An outstanding live sign is awaited and discarded (it was never staged,
    /// so `committed_through` does not include it); then, if lines are left unstamped, one `final`
    /// page `{committed_through + 1 ..= head}` is signed on the notary signer thread under
    /// [`SIGN_DEADLINE`] and staged. The journal's final flush commits it after every staged page,
    /// so pages stay contiguous and never overlap. The drain detaches this task at its cut.
    async fn final_page(&mut self) -> Option<bool> {
        if let Some(signing) = self.signing.take() {
            let _ = self.final_sign(signing.deadline, signing.rx).await;
        }
        if self.halted.is_some() {
            return None;
        }
        let head = self.feed.head();
        if head.seq <= self.committed_through {
            return None;
        }
        if self.seal_cut_expired() {
            return Some(false);
        }
        let stamp = Stamp {
            node: self.cfg.node,
            from: self.committed_through.saturating_add(1),
            to: head.seq,
            fingerprint: Fingerprint(head.fp),
            kind: StampKind::Final,
            sealer: self.cfg.node,
            host: self.cfg.host.clone(),
            every: self.cfg.every_ms,
            stamped_ms: busbar_kernel::store::now_ms(),
            down_from_ms: 0,
            down_to_ms: 0,
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            key_cert: self.cfg.key_cert,
            signature: Vec::new(),
        };
        let signed = match self.live.submit(stamp) {
            Ok(rx) => match self.final_sign(Instant::now() + SIGN_DEADLINE, rx).await {
                Some(stamp) => stamp,
                None => return Some(false),
            },
            Err(_) => return Some(false),
        };
        let Ok(body) = stamp_body(&signed) else {
            return Some(false);
        };
        let entry = Entry::new(RecordClass::Transaction, body).at(signed.stamped_ms / 1000, 0);
        if self.seal_cut_expired() {
            return Some(false);
        }
        match self.journal.stage_run(&[entry]) {
            Ok(_) => {
                self.committed_through = head.seq;
                self.publish_progress();
                Some(true)
            }
            Err(refused) => {
                if refused != RuntimeError::Closed {
                    busbar_kernel::diag_error!(
                        busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                        node = self.cfg.node,
                        reason = %format!("{refused:?}"),
                        "the final audit page was not staged; the next process on the host seals the tail"
                    );
                }
                Some(false)
            }
        }
    }

    fn seal_cut_expired(&self) -> bool {
        self.drain_clock.as_ref().is_some_and(|clock| {
            clock.expired()
                || clock.armed_at().is_some_and(|at| {
                    Instant::now() >= clock.limit(at, busbar_kernel::governance::drain::Cut::Seal)
                })
        })
    }

    /// Both the discarded live job and the final job share the seal phase's remaining time.
    /// A second shutdown signal ends the wait as well; detachment never grants a later stage.
    async fn final_sign(
        &self,
        deadline: Instant,
        rx: oneshot::Receiver<Result<Stamp, SignFailure>>,
    ) -> Option<Stamp> {
        if self.seal_cut_expired() {
            return None;
        }
        if let Some(clock) = &self.drain_clock {
            let deadline = clock.armed_at().map_or(deadline, |at| {
                deadline.min(clock.limit(at, busbar_kernel::governance::drain::Cut::Seal))
            });
            let mut expired = clock.expired_rx();
            tokio::select! {
                biased;
                _ = expired.wait_for(|value| *value) => None,
                result = tokio::time::timeout_at(deadline, rx) => result.ok()?.ok()?.ok(),
            }
        } else {
            tokio::time::timeout_at(deadline, rx).await.ok()?.ok()?.ok()
        }
    }

    /// One tick (§3.3 "One tick"): read the head, account the stall age, judge the in-flight
    /// stamp, then start a sign or park.
    async fn tick(&mut self) {
        let now = Instant::now();
        let (version, head) = self.feed.cell.read();
        self.seen_version = version;
        if head.seq > self.committed_through && self.tail_first_ms.is_none() {
            self.tail_first_ms = Some(head.wall_ms);
        }
        if self.signing.as_ref().is_some_and(|s| now >= s.deadline) {
            if let Some(gone) = self.signing.take() {
                self.funding = Some(Funding::retry(gone.page, gone.credit));
            }
            self.sign_failed(SignFailure::Deadline, now);
        }
        if self.halted.is_none() && self.step_inflight(now).await {
            self.maybe_sign(now, &head);
        }
        self.step_cut().await;
        self.publish_progress();
    }

    /// Steps 3 and 4: the in-flight stamp. Returns whether no stamp is in flight any more.
    async fn step_inflight(&mut self, now: Instant) -> bool {
        let Some(mut inflight) = self.inflight.take() else {
            return true;
        };
        match self.journal.is_confirmed(&inflight.run) {
            Ok(true) => {
                if !self.deliver_applied(&mut inflight) {
                    self.inflight = Some(inflight);
                    return false;
                }
                self.stamped_through = inflight.page.to;
                self.stamped_node_seq = inflight.page.to_node_seq;
                self.cut_due = !matches!(self.cut, CutSeat::None);
                if self.store_alerted {
                    self.store_alerted = false;
                    tracing::info!(
                        node = self.cfg.node,
                        stamped_through = self.stamped_through,
                        "audit stamps are committing again"
                    );
                }
                true
            }
            Ok(false) => {
                if let Some(driver) = inflight.driver.take() {
                    if !driver.is_finished() {
                        inflight.driver = Some(driver);
                        self.inflight = Some(inflight);
                        return false;
                    }
                    let driven = driver.await;
                    // Decided from the journal's state, never from the error variant (§3.3 step 3).
                    if let Some(failed) = self.journal.failed() {
                        self.halt(format!("journal failed: {failed:?}"));
                        self.inflight = Some(inflight);
                        return false;
                    }
                    if !matches!(driven, Ok(Ok(()))) {
                        inflight.backoff = next_backoff(inflight.backoff, self.every);
                        inflight.retry_at = now + inflight.backoff;
                        if !self.store_alerted {
                            self.store_alerted = true;
                            let reason = match &driven {
                                Ok(Err(e)) => format!("{e:?}"),
                                Ok(Ok(())) => "confirmed".to_string(),
                                Err(join) => format!("driver: {join}"),
                            };
                            busbar_kernel::diag_error!(
                                busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                                node = self.cfg.node,
                                reason = %reason,
                                unstamped_from = self.stamped_through.saturating_add(1),
                                "audit stamp not confirmed by the store; re-driven with backoff"
                            );
                        }
                    }
                } else if now >= inflight.retry_at {
                    let journal = Arc::clone(&self.journal);
                    let run = Arc::clone(&inflight.run);
                    inflight.driver =
                        Some(tokio::spawn(async move { journal.confirm(&run).await }));
                }
                self.inflight = Some(inflight);
                false
            }
            Err(RuntimeError::Authority) => {
                self.halt("authority: the stamp run belongs to another journal owner".into());
                self.inflight = Some(inflight);
                false
            }
            Err(other) => {
                if let Some(failed) = self.journal.failed() {
                    self.halt(format!("journal failed: {failed:?}"));
                } else {
                    tracing::debug!(error = ?other, "audit stamp confirmation unreadable; retried");
                }
                self.inflight = Some(inflight);
                false
            }
        }
    }

    fn deliver_applied(&mut self, inflight: &mut Inflight) -> bool {
        if let Some(credit) = inflight.credit.take() {
            let Some(target) = inflight.page.original.clone() else {
                inflight.credit = Some(credit);
                self.halt("original page lost its producer witness".into());
                return false;
            };
            match self
                .feed
                .original
                .applied(target, inflight.run.clone(), credit)
            {
                Ok(receipt) => inflight.receipt = Some(receipt),
                Err(credit) => {
                    inflight.credit = Some(credit);
                    self.halt("original applied page did not verify".into());
                    return false;
                }
            }
        }
        let Some(receipt) = &inflight.receipt else {
            return true;
        };
        if inflight.cursor.is_none() || inflight.page.upper.is_none() {
            self.halt("original page delivery lost its captured scan horizon".into());
            return false;
        }
        let Some(receiver) = self.feed.original.receiver() else {
            self.halt("original page receiver is unavailable".into());
            return false;
        };
        match crate::root::plane_node::deliver_original_page(&receiver, receipt, inflight.cursor) {
            PageDelivery::Complete => true,
            PageDelivery::Pending(next) if next.advances(inflight.cursor, inflight.page.upper) => {
                inflight.cursor = Some(next);
                false
            }
            PageDelivery::Pending(_) | PageDelivery::Refused => {
                self.halt("original page delivery refused or failed to progress".into());
                false
            }
        }
    }

    /// Step 5: start a sign over `committed_through + 1 ..= head.seq`, or park.
    fn maybe_sign(&mut self, now: Instant, head: &Head) {
        if self.signing.is_some() || self.inflight.is_some() || self.stopping {
            return;
        }
        if head.seq <= self.committed_through {
            // A due or running cut keeps the ticks coming until it is collected (§3.9).
            let cutting = self.cut_due || matches!(self.cut, CutSeat::Running(_));
            if self.committed_through == self.stamped_through && !cutting {
                self.parked = self.feed.cell.park(self.seen_version);
            }
            return;
        }
        if self.sign_retry_at.is_some_and(|at| now < at) {
            return;
        }
        if self.live.busy() {
            // The last sign passed its deadline and its thread has not returned.
            self.sign_failed(SignFailure::Busy, now);
            return;
        }
        let mut funding = match self.funding.take() {
            Some(funding) => funding,
            None => {
                let original = self
                    .feed
                    .original
                    .page(self.committed_through.saturating_add(1), *head);
                if self.feed.original.is_bound() && original.is_none() {
                    return;
                }
                Funding {
                    page: Page {
                        to: head.seq,
                        to_node_seq: head.node_seq,
                        first_ms: self.tail_first_ms.take(),
                        original,
                        upper: None,
                    },
                    cursor: None,
                    credit: None,
                }
            }
        };
        let credit = if let Some(credit) = funding.credit.take() {
            Some(credit)
        } else if let Some(target) = &funding.page.original {
            let Some(receiver) = self.feed.original.receiver() else {
                self.funding = Some(funding);
                self.halt("original page receiver is unavailable before signing".into());
                return;
            };
            let Some(bytes) = self.feed.original.bytes() else {
                self.funding = Some(funding);
                self.halt("original page retention bound is unavailable".into());
                return;
            };
            match crate::root::plane_node::fund_original_page(
                &receiver,
                target,
                bytes,
                funding.cursor,
            ) {
                PageFunding::Reserved(credit, upper)
                    if credit.len() >= bytes
                        && funding.page.upper.is_none_or(|held| held == upper) =>
                {
                    funding.page.upper = Some(upper);
                    Some(credit)
                }
                PageFunding::Empty(upper)
                    if funding.page.upper.is_none_or(|held| held == upper) =>
                {
                    funding.page.upper = Some(upper);
                    None
                }
                PageFunding::Pending(next) if next.advances(funding.cursor, funding.page.upper) => {
                    funding.page.upper = Some(next.upper);
                    funding.cursor = Some(next);
                    self.funding = Some(funding);
                    return;
                }
                PageFunding::Refused(cursor) => {
                    if let Some(cursor) = cursor {
                        if !cursor.preserves(funding.cursor, funding.page.upper) {
                            self.funding = Some(funding);
                            self.halt("original funding refusal changed its scan horizon".into());
                            return;
                        }
                        funding.page.upper = Some(cursor.upper);
                        funding.cursor = Some(cursor);
                    }
                    self.funding = Some(funding);
                    self.halt("original page storage refused".into());
                    return;
                }
                PageFunding::Reserved(credit, _) => {
                    funding.credit = Some(credit);
                    self.funding = Some(funding);
                    self.halt("original page reservation or scan horizon differs".into());
                    return;
                }
                PageFunding::Pending(_) | PageFunding::Empty(_) => {
                    self.funding = Some(funding);
                    self.halt("original funding scan changed horizon or failed to progress".into());
                    return;
                }
            }
        } else {
            None
        };
        let page = funding.page;
        let endpoint = page.original.as_ref().map_or(*head, |target| target.head());
        let submitted_ms = busbar_kernel::store::now_ms();
        let stamp = Stamp {
            node: self.cfg.node,
            from: self.committed_through.saturating_add(1),
            to: page.to,
            fingerprint: Fingerprint(endpoint.fp),
            kind: StampKind::Live,
            sealer: self.cfg.node,
            host: self.cfg.host.clone(),
            every: self.cfg.every_ms,
            stamped_ms: submitted_ms,
            down_from_ms: 0,
            down_to_ms: 0,
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            key_cert: self.cfg.key_cert,
            signature: Vec::new(),
        };
        match self.live.submit(stamp) {
            Ok(rx) => {
                self.signing = Some(Signing {
                    page,
                    rx,
                    deadline: now + SIGN_DEADLINE,
                    submitted_ms,
                    credit,
                });
            }
            Err(failure) => {
                self.funding = Some(Funding::retry(page, credit));
                self.sign_failed(failure, now);
            }
        }
    }

    /// The live signer answered (§3.3 step 5 "The reply arrives"): stage the stamp at once.
    fn on_reply(&mut self, answer: Result<Stamp, SignFailure>) {
        let now = Instant::now();
        let Some(signing) = self.signing.take() else {
            return;
        };
        let stamp = match answer {
            Ok(stamp) => stamp,
            Err(failure) => {
                self.funding = Some(Funding::retry(signing.page, signing.credit));
                self.sign_failed(failure, now);
                return;
            }
        };
        if let Some(target) = &signing.page.original {
            if stamp.host != self.cfg.host
                || stamp.every != self.cfg.every_ms
                || stamp.stamped_ms != signing.submitted_ms
                || stamp.signature.len() != 64
                || stamp.crypto != busbar_contract::crypto::BACKEND
                || stamp.sig_alg != busbar_kernel_audit::SIGNATURE_ALGORITHM
                || !self.feed.original.verify(target, &stamp)
            {
                self.funding = Some(Funding::retry(signing.page, signing.credit));
                self.halt("the original notary reply differs from its submitted page".into());
                return;
            }
        }
        self.sign_ok();
        let entry = match stamp_body(&stamp) {
            Ok(body) => Entry::new(RecordClass::Transaction, body).at(stamp.stamped_ms / 1000, 0),
            Err(_) => {
                self.funding = Some(Funding::retry(signing.page, signing.credit));
                self.halt("a stamp body exceeds the journal field bound".into());
                return;
            }
        };
        match self.journal.stage_run(&[entry]) {
            Ok(run) => {
                self.committed_through = signing.page.to;
                // The next request confirm carries it; only if none does within a tick does
                // step 3 drive it alone (§3.3 step 5, r17).
                let cursor = signing.page.upper.map(OriginalPageCursor::start);
                self.inflight = Some(Inflight {
                    run,
                    page: signing.page,
                    driver: None,
                    backoff: Duration::ZERO,
                    retry_at: now + self.every,
                    credit: signing.credit,
                    receipt: None,
                    cursor,
                });
            }
            Err(RuntimeError::Closed) if self.stopping => {
                self.funding = Some(Funding::retry(signing.page, signing.credit));
            }
            Err(refused) => {
                self.funding = Some(Funding::retry(signing.page, signing.credit));
                if let Some(failed) = self.journal.failed() {
                    self.halt(format!("journal failed: {failed:?}"));
                } else if refused == RuntimeError::Closed {
                    busbar_kernel::diag_error!(
                        busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                        node = self.cfg.node,
                        reason = "closed",
                        "audit stamp refused: journal staging closed before the notary stopped"
                    );
                }
                // Any other refusal staged nothing: the range is free, retried next tick (§3.3 step
                // 6). A refused stage costs no store write, so it needs no backoff.
            }
        }
        self.publish_progress();
    }

    fn sign_ok(&mut self) {
        if self.signer_alerted {
            tracing::info!(node = self.cfg.node, "audit stamp signer answering again");
        }
        self.sign_failures = 0;
        self.sign_backoff = Duration::ZERO;
        self.sign_retry_at = None;
        self.signer_alerted = false;
    }

    /// The signer error branch (§3.3): nothing posted, `committed_through` unchanged, capped
    /// backoff, alert after three in a row. A gone thread stops stamping for good.
    fn sign_failed(&mut self, failure: SignFailure, now: Instant) {
        if failure == SignFailure::Gone {
            self.feed.original.invalidate();
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                node = self.cfg.node,
                reason = "signer_panic",
                unstamped_from = self.stamped_through.saturating_add(1),
                "the audit notary signer thread is gone; stamping stops"
            );
            self.halted = Some("signer_panic".into());
            return;
        }
        self.sign_failures = self.sign_failures.saturating_add(1);
        self.sign_backoff = next_backoff(self.sign_backoff, self.every);
        self.sign_retry_at = Some(now + self.sign_backoff);
        let invalid = failure == SignFailure::Invalid;
        if (self.sign_failures >= SIGN_FAILURES_ALERT || invalid) && !self.signer_alerted {
            self.signer_alerted = true;
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                node = self.cfg.node,
                reason = "signer",
                cause = %failure,
                unstamped_from = self.stamped_through.saturating_add(1),
                "audit stamp signer unavailable; lines stay durable and linked"
            );
        }
    }

    /// Stop stamping for this process (the journal failed, or an invariant broke). Lines after
    /// `stamped_through` are left to the next process on the host.
    fn halt(&mut self, why: String) {
        self.feed.original.invalidate();
        if self.halted.is_none() {
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                node = self.cfg.node,
                reason = %why,
                unstamped_from = self.stamped_through.saturating_add(1),
                "audit notary stops stamping"
            );
            self.halted = Some(why);
        }
    }

    fn publish_progress(&self) {
        let p = &self.progress;
        p.stamped_through
            .store(self.stamped_through, Ordering::Relaxed);
        p.committed_through
            .store(self.committed_through, Ordering::Relaxed);
        p.stamped_node_seq
            .store(self.stamped_node_seq, Ordering::Relaxed);
        p.sign_failures
            .store(u64::from(self.sign_failures), Ordering::Relaxed);
        let oldest = self
            .inflight
            .as_ref()
            .and_then(|f| f.page.first_ms)
            .or_else(|| self.signing.as_ref().and_then(|s| s.page.first_ms))
            .or_else(|| self.funding.as_ref().and_then(|s| s.page.first_ms))
            .or(self.tail_first_ms)
            .unwrap_or(0);
        p.oldest_unstamped_ms.store(oldest, Ordering::Relaxed);
    }
}
