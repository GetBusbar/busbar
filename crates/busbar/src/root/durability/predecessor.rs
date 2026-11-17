// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PREDECESSOR SEALER (SEALING-FIX r20 §3.6.2): the start-up task that seals the crash tails
//! of the processes that ran on this host before this one.
//!
//! Every process takes a fresh node, so a crashed process's unstamped tail is in a journal the
//! next process never opens. This task, spawned after `Ready` beside the notary, lists every node
//! registered on this host that was already dead when this process took its node, and for each
//! one without a seal row: fences its writer for good (the fence mark commits with the fence),
//! walks its tail back to its last valid stamp, signs one `after_restart` page or one break notice
//! on the Bootstrap signer thread, and writes the outcome once, by a compare-and-set that needs the
//! seal row absent. Then it runs SHUTDOWN-HANG F5 once.
//!
//! It never seals a node of another host (decision 141), a node that renewed its lease after this
//! process's take (a running sibling), or anything when the host has no name. Every failure is
//! retried with a capped backoff and alerted once; nothing is silent. It stops cooperatively at the
//! first shutdown broadcast, at a step boundary, and never drops a fence or seal write mid-flight.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_kernel::persistence::boot_identity::{
    HostNode, HostNodes, ObservedBy, PredecessorFence, PredecessorRetire, RetireError, SealOutcome,
    SealRow, SealState, TailView, UndrainedWriter,
};
use busbar_kernel_audit::{
    break_body, break_from_journal_body, stamp_body, stamp_from_journal_body, AuditVerifyingKey,
    BreakAt, BreakNotice, BreakReason, Stamp, StampKind, WalkContext, WalkOutcome,
};
use tokio::sync::watch;

use super::restart_seal::{
    break_notice, broken_finding, restart_page, tail_items, CleanTail, RecipeUnsupported,
};
use super::signer::{Seal, SignFailure, SignerHandle};
use super::Durability;

/// A step that has not answered within this long is alerted, and still awaited.
const STEP_ALERT: Duration = Duration::from_secs(1);

/// The capped retry backoff (50 ms, 100 ms, … 1 s).
const FIRST_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(1);

/// Journal records read per backward batch (§3.6.2 step 2).
const BATCH: u64 = 256;

/// Existing journal history budget, counted in WAL records rather than decoded audit lines.
const WALK_RECORDS_MAX: u64 = 1_048_576;

/// What the boot book hands the sealer about this process.
#[derive(Debug, Clone)]
pub(crate) struct PredecessorInputs {
    /// This process's node.
    pub(crate) own: u64,
    /// The store clock (ms) at this process's `take_node`.
    pub(crate) taken_at_ms: u64,
    /// The bound deployment key's public half (hex): restart pages, break notices and `key_cert =
    /// 0` stamps verify under it.
    pub(crate) key_hex: String,
}

/// How the task ended, for its Info line and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SealerDone {
    pub(crate) sealed: usize,
    pub(crate) skipped: usize,
    pub(crate) siblings: usize,
}

/// One step's outcome when it gives up.
enum Stop {
    /// The fence mark changed meaning: restart this node at its mark read.
    Restart,
    /// The shutdown flag is set: stop at this boundary.
    Flag,
    /// This predecessor is skipped for this process (already reported).
    Skip,
    /// The Bootstrap signer is gone: leave the rest to the next process.
    SignerGone,
}

#[derive(Debug, PartialEq, Eq)]
enum LostSeal {
    ExistingRow,
    RetrySigned,
    Restart,
}

fn after_lost_seal(id: u64, state: &SealState, add_to_mark: bool) -> LostSeal {
    if state.row.is_some() {
        LostSeal::ExistingRow
    } else if add_to_mark && state.mark.as_ref().is_some_and(|mark| mark.is_open_for(id)) {
        LostSeal::RetrySigned
    } else {
        LostSeal::Restart
    }
}

struct Sealer {
    fence: Arc<PredecessorFence>,
    inputs: PredecessorInputs,
    key: AuditVerifyingKey,
    host: String,
    handle: SignerHandle<Seal>,
    book: Option<Arc<Mutex<Durability>>>,
    stop: watch::Receiver<bool>,
    alerted: BTreeSet<u64>,
    done: SealerDone,
    listed_ms: u64,
    listed_at: Instant,
}

/// THE TASK: seal every dead predecessor on this host, then SHUTDOWN-HANG F5 once. With no key or
/// no Bootstrap handle (a keyless book) only F5 runs.
pub(crate) async fn run(
    fence: Arc<PredecessorFence>,
    sealing: Option<(PredecessorInputs, SignerHandle<Seal>)>,
    book: Option<Arc<Mutex<Durability>>>,
    stop: watch::Receiver<bool>,
) -> SealerDone {
    let mut done = SealerDone::default();
    if let Some((inputs, handle)) = sealing {
        match AuditVerifyingKey::from_hex(&inputs.key_hex) {
            Ok(key) => {
                let mut sealer = Sealer {
                    host: fence.host().to_owned(),
                    fence: Arc::clone(&fence),
                    inputs,
                    key,
                    handle,
                    book,
                    stop: stop.clone(),
                    alerted: BTreeSet::new(),
                    done: SealerDone::default(),
                    listed_ms: 0,
                    listed_at: Instant::now(),
                };
                sealer.seal_all().await;
                done = sealer.done;
            }
            Err(error) => tracing::info!(
                ?error,
                "the predecessor sealer has no usable deployment key; it seals nothing"
            ),
        }
    }
    if !*stop.borrow() {
        fence.run(stop).await;
    }
    done
}

impl Sealer {
    fn stopped(&self) -> bool {
        *self.stop.borrow()
    }

    async fn seal_all(&mut self) {
        if self.host.is_empty() {
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_PREDECESSOR_REFUSED,
                node = "none",
                reason = "host_unknown",
                "this process has no host name: it seals no predecessor (set HOSTNAME)"
            );
            self.finding(
                "audit predecessor sealing refused: this process has no host name (set HOSTNAME)"
                    .into(),
            );
            return;
        }
        let own = self.inputs.own;
        let fence = Arc::clone(&self.fence);
        let Ok(listed) = self.read(0, "host_scan", || fence.host_nodes(own)).await else {
            return;
        };
        let HostNodes {
            listed_ms,
            nodes,
            refused,
        } = listed;
        self.listed_ms = listed_ms;
        self.listed_at = Instant::now();
        for node in refused {
            self.refuse(
                node.id.unwrap_or(0),
                node.reason,
                "the host or archive row does not match its id reservation",
            );
        }
        'nodes: for node in nodes {
            if self.stopped() {
                break;
            }
            loop {
                match self.seal_one(&node).await {
                    Ok(()) | Err(Stop::Skip) => break,
                    Err(Stop::Restart) => continue,
                    Err(Stop::Flag) => break 'nodes,
                    Err(Stop::SignerGone) => {
                        tracing::info!(
                            "the Bootstrap signer is gone; the remaining predecessors are left to the next process on the host"
                        );
                        break 'nodes;
                    }
                }
            }
        }
        tracing::info!(
            sealed = self.done.sealed,
            skipped = self.done.skipped,
            siblings = self.done.siblings,
            "predecessor_sealer done"
        );
    }

    /// The sibling bound: a predecessor's last renewal was no later than this process's take.
    fn bound(&self) -> u64 {
        self.inputs
            .taken_at_ms
            .saturating_add(self.fence.lease_ttl_ms())
    }

    fn sibling(&mut self, id: u64) -> Result<(), Stop> {
        self.done.siblings += 1;
        tracing::info!(
            node = id,
            "a node on this host renewed its lease after this process started: a running sibling, never sealed"
        );
        Err(Stop::Skip)
    }

    async fn seal_one(&mut self, node: &HostNode) -> Result<(), Stop> {
        let id = node.id;
        if node.lease_expires_ms.is_some_and(|e| e > self.bound()) {
            return self.sibling(id);
        }
        let state = self.seal_state(node).await?;
        if let Some(row) = &state.row {
            self.check_row(id, row);
            return Err(Stop::Skip);
        }
        self.fence_writer(id, node.epoch, node.writer).await?;

        let state = self.seal_state(node).await?;
        if let Some(row) = &state.row {
            self.check_row(id, row);
            return Err(Stop::Skip);
        }
        let ttl = self.fence.lease_ttl_ms();
        let unsealed_fenced = match &state.mark {
            Some(mark) if mark.lease_expires_ms > self.bound() => return self.sibling(id),
            Some(mark) if mark.is_open_for(id) => false,
            None if !state.mark_present()
                && node.lease_expires_ms.is_none()
                && self.listed_ms
                    >= self
                        .inputs
                        .taken_at_ms
                        .saturating_add(ttl.saturating_mul(2)) =>
            {
                self.refuse(
                    id,
                    "sibling_unknown",
                    "its liveness at this process's start cannot be shown",
                );
                return Err(Stop::Skip);
            }
            _ => true,
        };

        let fence = Arc::clone(&self.fence);
        let mut fenced_owner = (node.epoch, node.writer);
        let tail = loop {
            let tail = self
                .read(id, "tail_view", || fence.journal_tail(id))
                .await?;
            match &tail {
                Some(view) if view.owner != fenced_owner => {
                    self.fence_writer(id, view.owner.0, view.owner.1).await?;
                    fenced_owner = view.owner;
                    // An owner may have appended before its fence committed. Only a fresh
                    // coherent owner/head observation after the fence grants the walk's tail.
                }
                _ => break tail,
            }
        };
        let outcome = match tail {
            None => SealOutcome::Clean { through: 0 },
            Some(view) => {
                let walked = self.walk(id, &view).await?;
                self.outcome(id, walked, unsealed_fenced).await?
            }
        };
        let row = SealRow {
            sealer: self.inputs.own,
            outcome,
        };
        self.write(node, row, state, !unsealed_fenced).await
    }

    /// Step 1: fence the writer for good, waiting out a live lease up to the sibling bound.
    async fn fence_writer(&mut self, id: u64, epoch: u64, writer: [u8; 16]) -> Result<(), Stop> {
        let seen = UndrainedWriter {
            node: Some(id),
            other_nodes: Vec::new(),
            epoch,
            writer,
            host: Some(self.host.clone()),
            observed_by: ObservedBy::Successor,
        };
        let fence = Arc::clone(&self.fence);
        let mut backoff = FIRST_BACKOFF;
        loop {
            if self.stopped() {
                return Err(Stop::Flag);
            }
            // Never raced with the stop flag: a fence write is awaited to its result.
            let answer = self
                .alerting(
                    id,
                    "fence",
                    fence.retire_predecessor(epoch, writer, seen.clone()),
                )
                .await;
            match answer {
                Ok(PredecessorRetire::Retired { closed_open }) => {
                    if closed_open {
                        tracing::info!(
                            node = id,
                            "closed a predecessor writer that never retired; its shutdown.drain_incomplete record is offered"
                        );
                    }
                    return Ok(());
                }
                Ok(PredecessorRetire::Live { retry_at_ms }) => {
                    if retry_at_ms > self.bound() {
                        return self.sibling(id);
                    }
                    let wait = retry_at_ms.saturating_sub(self.store_now_ms());
                    let wait = Duration::from_millis(wait).clamp(
                        FIRST_BACKOFF,
                        Duration::from_millis(self.fence.lease_ttl_ms()),
                    );
                    self.nap(wait).await?;
                }
                Ok(PredecessorRetire::Pending) => self.nap(FIRST_BACKOFF).await?,
                Err(RetireError::Permanent(error)) => {
                    self.refuse(id, "permanent", &error);
                    return Err(Stop::Skip);
                }
                Err(RetireError::Transient(error)) => {
                    self.alert(id, "fence", &error);
                    self.nap(backoff).await?;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    async fn seal_state(&mut self, node: &HostNode) -> Result<SealState, Stop> {
        let fence = Arc::clone(&self.fence);
        let (id, epoch, writer) = (node.id, node.epoch, node.writer);
        self.read(id, "seal_state", || fence.seal_state(id, epoch, writer))
            .await
    }

    /// Step 2: walk the tail backwards in batches until the walk reaches an anchor or the start.
    async fn walk(&mut self, id: u64, view: &TailView) -> Result<WalkOutcome, Stop> {
        let mut walk = busbar_kernel_audit::restart::BackwardWalk::default();
        let mut records_read = 0;
        let mut to = view.count;
        let mut expect_hash = view.hash;
        loop {
            let from = to.saturating_sub(BATCH - 1).max(1);
            let fence = Arc::clone(&self.fence);
            let batch = self
                .read(id, "tail_read", || fence.journal_records(id, from, to))
                .await?;
            if batch.last().map(|r| r.hash) != Some(expect_hash) {
                self.refuse(
                    id,
                    "permanent",
                    "its journal frames do not link to its head",
                );
                return Err(Stop::Skip);
            }
            expect_hash = batch.first().map_or([0; 32], |r| r.prev_hash);
            let complete = from == 1;
            records_read += to - from + 1;
            let key = self.key.clone();
            let host = self.host.clone();
            let walked = tokio::task::spawn_blocking(move || {
                let cx = WalkContext {
                    node: id,
                    host: &host,
                    key: &key,
                    complete,
                };
                let items = match tail_items(&batch) {
                    Ok(items) => items,
                    Err(RecipeUnsupported) => return (walk, WalkOutcome::Unsupported),
                };
                for item in items.iter().rev() {
                    let outcome = walk.push(item, &cx);
                    if outcome != WalkOutcome::NeedMore {
                        return (walk, outcome);
                    }
                }
                let outcome = if complete {
                    walk.finish(&cx)
                } else if records_read >= WALK_RECORDS_MAX {
                    walk.budget_break()
                } else {
                    WalkOutcome::NeedMore
                };
                (walk, outcome)
            })
            .await;
            let Ok((back, outcome)) = walked else {
                self.refuse(id, "permanent", "the walk task failed");
                return Err(Stop::Skip);
            };
            walk = back;
            if outcome != WalkOutcome::NeedMore || complete {
                return Ok(outcome);
            }
            if self.stopped() {
                return Err(Stop::Flag);
            }
            to = from - 1;
        }
    }

    /// Step 3: what to write for the walk's result, signing on the Bootstrap thread.
    async fn outcome(
        &mut self,
        id: u64,
        walked: WalkOutcome,
        unsealed_fenced: bool,
    ) -> Result<SealOutcome, Stop> {
        let now_ms = busbar_kernel::store::now_ms();
        let fenced_break = |last_good: u64, from: u64, to: u64, js: (u64, u64)| BreakAt {
            last_good,
            unsealed_from: from,
            unsealed_to: to,
            journal_from: js.0,
            journal_to: js.1,
            reason: BreakReason::UnsealedFenced,
        };
        let at = match walked {
            WalkOutcome::Foreign { anchor_host } => {
                busbar_kernel::diag_error!(
                    busbar_kernel::diagnostics::AUDIT_PREDECESSOR_REFUSED,
                    node = id,
                    reason = "foreign_host",
                    anchor_host = %anchor_host,
                    "a predecessor's last stamp names another host; its tail is not signed or recorded as sealed"
                );
                self.finding(format!(
                    "audit predecessor {id} not sealed: its last stamp names host {anchor_host:?}"
                ));
                self.done.skipped += 1;
                return Err(Stop::Skip);
            }
            WalkOutcome::Unsupported | WalkOutcome::NeedMore => {
                self.refuse(
                    id,
                    "recipe_unsupported",
                    "its records use a recipe or algorithm this build cannot compute",
                );
                return Err(Stop::Skip);
            }
            WalkOutcome::Nothing {
                through,
                through_node_seq,
            } => {
                if !unsealed_fenced {
                    return Ok(SealOutcome::Clean { through });
                }
                fenced_break(
                    through,
                    through.saturating_add(1),
                    through,
                    (through_node_seq, through_node_seq),
                )
            }
            WalkOutcome::Clean {
                from,
                to,
                from_node_seq,
                fingerprint,
                to_node_seq,
                every,
                down_from_ms,
            } => {
                if unsealed_fenced {
                    fenced_break(from - 1, from, to, (from_node_seq, to_node_seq))
                } else {
                    let tail = CleanTail {
                        from,
                        to,
                        fingerprint,
                        every,
                        down_from_ms,
                    };
                    let page = restart_page(id, self.inputs.own, &self.host, tail, now_ms);
                    let signed = self.sign_page(id, page).await?;
                    let body = stamp_body(&signed).map_err(|_| {
                        self.refuse(id, "permanent", "its restart page exceeds the field bound");
                        Stop::Skip
                    })?;
                    return Ok(SealOutcome::Stamp(body));
                }
            }
            WalkOutcome::Break(mut at) => {
                if unsealed_fenced {
                    at.reason = BreakReason::UnsealedFenced;
                }
                at
            }
        };
        let notice = break_notice(id, self.inputs.own, &self.host, &at, now_ms);
        let signed = self.sign_break(id, notice).await?;
        let body = break_body(&signed).map_err(|_| {
            self.refuse(id, "permanent", "its break notice exceeds the field bound");
            Stop::Skip
        })?;
        Ok(SealOutcome::Break(body))
    }

    async fn sign_page(&mut self, id: u64, page: Stamp) -> Result<Stamp, Stop> {
        let mut backoff = FIRST_BACKOFF;
        loop {
            match self.handle.submit_restart(page.clone()).await {
                Ok(signed) => return Ok(signed),
                Err(failure) => backoff = self.sign_failed(id, failure, backoff).await?,
            }
        }
    }

    async fn sign_break(&mut self, id: u64, notice: BreakNotice) -> Result<BreakNotice, Stop> {
        let mut backoff = FIRST_BACKOFF;
        loop {
            match self.handle.submit_break(notice.clone()).await {
                Ok(signed) => return Ok(signed),
                Err(failure) => backoff = self.sign_failed(id, failure, backoff).await?,
            }
        }
    }

    async fn sign_failed(
        &mut self,
        id: u64,
        failure: SignFailure,
        backoff: Duration,
    ) -> Result<Duration, Stop> {
        if failure == SignFailure::Gone {
            return Err(Stop::SignerGone);
        }
        self.alert(id, "sign", &failure.to_string());
        self.nap(backoff).await?;
        Ok((backoff * 2).min(MAX_BACKOFF))
    }

    /// Step 4: write once. A lost compare-and-set re-reads: another successor's row ends it; a
    /// changed mark still open for the node (another node of the writer was sealed meanwhile) is
    /// retried with the same outcome, never signed again.
    async fn write(
        &mut self,
        node: &HostNode,
        row: SealRow,
        mut state: SealState,
        add_to_mark: bool,
    ) -> Result<(), Stop> {
        let id = node.id;
        let fence = Arc::clone(&self.fence);
        let mut backoff = FIRST_BACKOFF;
        loop {
            // Never raced with the stop flag: a seal write is awaited to its result.
            let answer = self
                .alerting(
                    id,
                    "seal",
                    fence.seal_node(id, node.epoch, node.writer, &row, &state, add_to_mark),
                )
                .await;
            match answer {
                Ok(true) => {
                    self.won(id, &row);
                    return Ok(());
                }
                Ok(false) => {
                    let next = self.seal_state(node).await?;
                    match after_lost_seal(id, &next, add_to_mark) {
                        LostSeal::ExistingRow => {
                            if let Some(row) = &next.row {
                                self.check_row(id, row);
                            }
                            self.cleared(id);
                            return Ok(());
                        }
                        LostSeal::RetrySigned => {
                            state = next;
                        }
                        LostSeal::Restart => return Err(Stop::Restart),
                    }
                }
                Err(RetireError::Permanent(error)) => {
                    self.refuse(id, "permanent", &error);
                    return Err(Stop::Skip);
                }
                Err(RetireError::Transient(error)) => {
                    self.alert(id, "seal", &error);
                    self.nap(backoff).await?;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    fn won(&mut self, id: u64, row: &SealRow) {
        self.done.sealed += 1;
        self.cleared(id);
        let sealer = self.inputs.own;
        match &row.outcome {
            SealOutcome::Clean { through } => tracing::info!(
                node = id,
                sealer,
                through,
                "a predecessor had nothing unstamped; its seal row is written"
            ),
            SealOutcome::Stamp(body) => {
                let (from, to) = stamp_from_journal_body(body)
                    .ok()
                    .flatten()
                    .map_or((0, 0), |s| (s.from, s.to));
                tracing::info!(
                    diag = %busbar_kernel::diagnostics::AUDIT_SEALED_AFTER_RESTART.banner(),
                    node = id, sealer, from, to,
                    "a crashed predecessor's unstamped audit tail was sealed after restart"
                );
            }
            SealOutcome::Break(body) => {
                if let Ok(Some(notice)) = break_from_journal_body(body) {
                    let at = BreakAt {
                        last_good: notice.last_good,
                        unsealed_from: notice.unsealed_from,
                        unsealed_to: notice.unsealed_to,
                        journal_from: notice.journal_from,
                        journal_to: notice.journal_to,
                        reason: notice.reason,
                    };
                    busbar_kernel::diag_error!(
                        busbar_kernel::diagnostics::AUDIT_CHAIN_BROKEN_AT_BOOT,
                        node = id, sealer, last_good = at.last_good,
                        unsealed_from = at.unsealed_from, unsealed_to = at.unsealed_to,
                        reason = at.reason.as_str(),
                        "a crashed predecessor's audit chain is broken after its last valid stamp; recorded, never sealed"
                    );
                    self.finding(broken_finding(id, &at));
                }
            }
        }
    }

    /// A present seal row is trusted only if it decodes, names the node and verifies.
    fn check_row(&mut self, id: u64, row: &[u8]) {
        let valid =
            SealRow::parse(row).is_ok_and(|row| match row.outcome {
                SealOutcome::Clean { .. } => true,
                SealOutcome::Stamp(body) => stamp_from_journal_body(&body)
                    .ok()
                    .flatten()
                    .is_some_and(|s| {
                        s.node == id
                            && s.sealer == row.sealer
                            && s.kind == StampKind::AfterRestart
                            && s.key_cert == 0
                            && s.verify(&self.key).is_ok()
                    }),
                SealOutcome::Break(body) => break_from_journal_body(&body)
                    .ok()
                    .flatten()
                    .is_some_and(|b| {
                        b.node == id && b.sealer == row.sealer && b.verify(&self.key).is_ok()
                    }),
            });
        if valid {
            self.done.skipped += 1;
        } else {
            self.refuse(
                id,
                "seal_row_invalid",
                "its seal row does not decode or verify; it is never trusted or replaced",
            );
        }
    }

    /// A read retried on a capped backoff; it may be dropped at the stop flag (no custody).
    async fn read<T, F, Fut>(&mut self, id: u64, step: &'static str, mut f: F) -> Result<T, Stop>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, RetireError>>,
    {
        let mut backoff = FIRST_BACKOFF;
        loop {
            let mut stop = self.stop.clone();
            let answer = tokio::select! {
                biased;
                _ = stop.wait_for(|s| *s) => return Err(Stop::Flag),
                answer = self.alerting(id, step, f()) => answer,
            };
            match answer {
                Ok(value) => return Ok(value),
                Err(RetireError::Permanent(error)) => {
                    self.refuse(id, "permanent", &error);
                    return Err(Stop::Skip);
                }
                Err(RetireError::Transient(error)) => {
                    self.alert(id, step, &error);
                    self.nap(backoff).await?;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    /// Await `step` to its result beside a [`STEP_ALERT`] timer that never cancels it.
    async fn alerting<T>(
        &mut self,
        id: u64,
        step: &'static str,
        fut: impl Future<Output = T>,
    ) -> T {
        tokio::pin!(fut);
        tokio::select! {
            out = &mut fut => return out,
            () = tokio::time::sleep(STEP_ALERT) => self.alert(id, step, "no_answer"),
        }
        fut.await
    }

    /// Sleep `d`, or stop at the flag.
    async fn nap(&mut self, d: Duration) -> Result<(), Stop> {
        let mut stop = self.stop.clone();
        tokio::select! {
            _ = stop.wait_for(|s| *s) => Err(Stop::Flag),
            () = tokio::time::sleep(d) => Ok(()),
        }
    }

    fn store_now_ms(&self) -> u64 {
        let elapsed = u64::try_from(self.listed_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.listed_ms.saturating_add(elapsed)
    }

    /// `AUDIT_PREDECESSOR_SEAL_FAILED`, once per predecessor until it is sealed.
    fn alert(&mut self, id: u64, step: &'static str, cause: &str) {
        if self.alerted.insert(id) {
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_PREDECESSOR_SEAL_FAILED,
                node = id,
                step,
                cause,
                "sealing a crashed predecessor is failing; retried with backoff"
            );
        }
    }

    fn cleared(&mut self, id: u64) {
        if self.alerted.remove(&id) {
            tracing::info!(
                node = id,
                "the crashed predecessor is sealed; its seal alert clears"
            );
        }
    }

    /// `AUDIT_PREDECESSOR_REFUSED` and a `restart_findings` entry: nothing is written for the node
    /// by this process.
    fn refuse(&mut self, id: u64, reason: &'static str, cause: &str) {
        self.done.skipped += 1;
        busbar_kernel::diag_error!(
            busbar_kernel::diagnostics::AUDIT_PREDECESSOR_REFUSED,
            node = id,
            reason,
            cause,
            "a crashed predecessor on this host is not sealed by this process"
        );
        self.finding(format!(
            "audit predecessor {id} not sealed ({reason}): {cause}"
        ));
    }

    fn finding(&self, text: String) {
        if let Some(book) = &self.book {
            book.lock()
                .unwrap_or_else(|p| p.into_inner())
                .restart_findings
                .push(text);
        }
    }
}

#[cfg(test)]
#[path = "../tests/durability_predecessor.rs"]
mod tests;
