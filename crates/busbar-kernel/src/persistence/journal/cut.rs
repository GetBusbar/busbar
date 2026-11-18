// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EPHEMERAL JOURNAL CUT (SEALING-FIX r20 §3.9): no replay, no lane, its own logical id.
//!
//! - Cut points come from group commit: every Applied group of an Ephemeral journal offers its head,
//!   original-byte seal and audit tail as a [`Boundary`]; one is kept every `BOUNDARY_STRIDE`
//!   records, in a ring of `BOUNDARIES`, with no allocation.
//! - [`JournalCut::truncate_through`] (the notary's alone: [`RuntimeJournal::cutter`] hands out the
//!   one cut) picks, in one `state` critical section and reading no row, the newest boundary at or
//!   below `min(floor, head.count − RETAIN_TAIL, pins.min − 1)` that is at least `CUT_BATCH` past
//!   the base. It never takes `driving` and never waits for a pinned group.
//! - Two steps, each one candidate under `LogicalId { journal namespace, node ++ "cut" }`, never the
//!   append's id: (1) move the base (`O@0` exact, `B@0` as read; `Put B@0`), then (2) delete the
//!   rows below it in chunks of exact `Delete`s (`O@0` exact). Rows are deleted only after the base
//!   has moved past them. An append touches `H@0` and rows above the head, a cut `B@0` and rows at
//!   or below a past head: they commute.
//! - One attempt at a time. `Uncertain`/`Busy` re-drives that exact attempt next time; `NoEffect`
//!   drops it; any other decision (only a foreign writer could change `O@0` or `B@0`) raises
//!   `AUDIT_STAMP_FAILED{reason: truncate}` and stops cuts for this process.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use busbar_contract::persistence::Decision;

use super::super::base::{ordinal, AuditTail, Base, CUT_BATCH, KEEP_MAX, RETAIN_TAIL};
use super::*;
use crate::persistence::commit::SubmitResult;

/// A boundary is kept when it is at least this many records past the last kept one.
pub(super) const BOUNDARY_STRIDE: u64 = 256;
/// The boundary ring's capacity; when full, the newest slot is overwritten.
pub(super) const BOUNDARIES: usize = 64;
/// Consecutive unresolved or dropped cut attempts before the alert is raised once.
const FAILURES_ALERT: u32 = 3;

/// A possible cut point: an Applied group's head, its original-byte seal and the audit tail after
/// it.
#[derive(Clone, Copy)]
pub(super) struct Boundary {
    head: Head,
    records_seal: [u8; 32],
    tail: AuditTail,
}

/// The cut's part of the journal `state`.
#[derive(Default)]
pub(super) struct CutState {
    /// The current base and its exact stored bytes (the next move's `B@0` predicate).
    base: Option<(Base, Secret<Vec<u8>>)>,
    boundaries: VecDeque<Boundary>,
    last_boundary: u64,
    /// The newest Applied audit line.
    tail: AuditTail,
    /// Copies of this boot's `Bootstrap` originals: each enters a base's `keep` once the cut
    /// passes its `node_seq` (§3.9 "Kept rows first").
    keep: Vec<Record>,
}

impl CutState {
    pub(super) fn ephemeral() -> Self {
        Self {
            boundaries: VecDeque::with_capacity(BOUNDARIES),
            ..Self::default()
        }
    }
}

impl CutState {
    pub(super) fn base_count(&self) -> u64 {
        self.base.as_ref().map_or(0, |(base, _)| base.count())
    }

    /// Keep a copy of a record readers above a future base still name. Bounded: at most
    /// `KEEP_MAX` copies (one `Bootstrap` per boot in practice); a further one is not kept.
    pub(super) fn note_kept(&mut self, record: &Record) {
        if self.keep.len() < KEEP_MAX
            && self.keep.iter().all(|kept| kept.node_seq < record.node_seq)
        {
            self.keep.push(record.clone());
        } else {
            tracing::warn!(
                node_seq = record.node_seq,
                "journal cut keeps no further copy of a Bootstrap original"
            );
        }
    }

    /// An Applied group: track the audit tail and keep the group's head as a boundary when it is
    /// far enough past the last one. One compare per group; a 120-byte copy per boundary.
    pub(super) fn applied(&mut self, head: Head, records_seal: [u8; 32], line: Option<AuditTail>) {
        if let Some(line) = line {
            self.tail = line;
        }
        if head.count < self.last_boundary.saturating_add(BOUNDARY_STRIDE) {
            return;
        }
        let boundary = Boundary {
            head,
            records_seal,
            tail: self.tail,
        };
        if self.boundaries.len() >= BOUNDARIES {
            if let Some(newest) = self.boundaries.back_mut() {
                *newest = boundary;
            }
        } else {
            self.boundaries.push_back(boundary);
        }
        self.last_boundary = head.count;
    }
}

/// One cut candidate.
#[derive(Clone)]
enum Step {
    /// Move the base from `previous` (the `B@0` bytes read; `None` for absent) to `base`.
    Move {
        previous: Option<Secret<Vec<u8>>>,
        base: Base,
        encoded: Secret<Vec<u8>>,
    },
    /// Delete rows `from..=to`, all at or below the current base.
    Delete { from: u64, to: u64 },
}

/// What one crossing of a cut candidate decided.
enum Outcome {
    Applied,
    NoEffect,
    Retained,
    Refused(String),
}

/// What [`JournalCut::truncate_through`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutProgress {
    /// No boundary is far enough below the floor; nothing was written.
    Idle,
    /// The base is at `base` and every row at or below it is deleted.
    Cut { base: u64 },
    /// An attempt's outcome is unknown (or it could not cross): the same attempt is re-driven
    /// next, and no new cut is computed until it is decided.
    Retained,
    /// A definite no-effect dropped the attempt; the next trigger recomputes.
    Dropped,
    /// Cuts are stopped for this process.
    Stopped,
}

/// THE ONE CUT of an Ephemeral journal, owned by the audit notary (§3.9).
pub struct JournalCut {
    journal: Arc<RuntimeJournal>,
    attempt: Option<Step>,
    /// Every row at or below this ordinal is deleted.
    deleted_through: u64,
    failures: u32,
    alerted: bool,
    stopped: bool,
}

impl std::fmt::Debug for JournalCut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalCut")
            .field("node", &self.journal.node)
            .field("retained", &self.attempt.is_some())
            .field("deleted_through", &self.deleted_through)
            .field("stopped", &self.stopped)
            .finish()
    }
}

impl JournalCut {
    /// CUT THROUGH `floor` (a journal ordinal; the notary's floors (a) and (b)): finish deleting
    /// below the current base, else move the base to the newest boundary allowed, then delete
    /// below it. A retained attempt is re-driven first, and nothing new is computed until it is
    /// decided.
    pub async fn truncate_through(&mut self, floor: u64) -> CutProgress {
        if self.stopped {
            return CutProgress::Stopped;
        }
        if self.attempt.is_none() && self.deleted_through >= self.journal.base_count() {
            match self.journal.plan_move(floor) {
                Some(step) => self.attempt = Some(step),
                None => return CutProgress::Idle,
            }
        }
        self.drive().await
    }

    /// AT SHUTDOWN (§3.9 "At shutdown"): re-drive a retained attempt only; never computes a cut.
    pub async fn settle(&mut self) -> CutProgress {
        if self.stopped {
            return CutProgress::Stopped;
        }
        if self.attempt.is_none() {
            return CutProgress::Idle;
        }
        self.drive().await
    }

    /// Whether an attempt is retained (`journal_cut=retained`).
    #[must_use]
    pub fn retained(&self) -> bool {
        self.attempt.is_some()
    }

    async fn drive(&mut self) -> CutProgress {
        loop {
            let step = match self.attempt.clone() {
                Some(step) => step,
                None => {
                    let base = self.journal.base_count();
                    if self.deleted_through >= base {
                        return CutProgress::Cut { base };
                    }
                    let chunk = self
                        .journal
                        .store
                        .limits()
                        .scan_items
                        .saturating_sub(1)
                        .max(1);
                    let from = self.deleted_through.saturating_add(1);
                    let to = base.min(from.saturating_add(chunk as u64 - 1));
                    let step = Step::Delete { from, to };
                    self.attempt = Some(step.clone());
                    step
                }
            };
            match self.journal.submit_cut(&step).await {
                Outcome::Applied => {
                    self.attempt = None;
                    self.failures = 0;
                    self.alerted = false;
                    match step {
                        Step::Move { base, encoded, .. } => self.journal.base_moved(base, encoded),
                        Step::Delete { to, .. } => self.deleted_through = to,
                    }
                }
                Outcome::NoEffect => {
                    self.attempt = None;
                    self.failed("no_effect");
                    return CutProgress::Dropped;
                }
                Outcome::Retained => {
                    self.failed("retained");
                    return CutProgress::Retained;
                }
                Outcome::Refused(why) => {
                    self.attempt = None;
                    self.stopped = true;
                    crate::diag_error!(
                        crate::diagnostics::AUDIT_STAMP_FAILED,
                        node = self.journal.node,
                        reason = "truncate",
                        decision = %why,
                        "the Ephemeral journal cut was refused; cuts stop for this process"
                    );
                    return CutProgress::Stopped;
                }
            }
        }
    }

    fn failed(&mut self, how: &str) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= FAILURES_ALERT && !self.alerted {
            self.alerted = true;
            crate::diag_error!(
                crate::diagnostics::AUDIT_STAMP_FAILED,
                node = self.journal.node,
                reason = "truncate",
                outcome = how,
                failures = self.failures,
                "the Ephemeral journal cut has not been decided; it is re-driven"
            );
        }
    }
}

impl RuntimeJournal {
    /// THE ONE CUT of this journal (§3.9), for the audit notary: `Some` once, and only on an
    /// Ephemeral journal. Local and Quorum journals are never cut.
    #[must_use]
    pub fn cutter(self: &Arc<Self>) -> Option<JournalCut> {
        if self.pins.is_none() || self.cut_taken.swap(true, Ordering::AcqRel) {
            return None;
        }
        Some(JournalCut {
            journal: Arc::clone(self),
            attempt: None,
            deleted_through: 0,
            failures: 0,
            alerted: false,
            stopped: false,
        })
    }

    /// Whether this journal can be cut (its Store is `Durability::Ephemeral`).
    #[must_use]
    pub fn is_cut_capable(&self) -> bool {
        self.pins.is_some()
    }

    /// The journal ordinal of this node's `seq` (§3.9: `seq − head.sequence + head.count` on an
    /// Ephemeral journal); 0 for seq 0.
    #[must_use]
    pub fn ordinal_of(&self, seq: u64) -> u64 {
        if seq == 0 {
            return 0;
        }
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        ordinal(&state.verified.head, seq)
    }

    /// A hold on row `seq` (§3.9 floor (d)), for a structure that keeps naming the row after its
    /// run is gone (`carried`). Take it while the run, or another pin, still covers `seq`. `None`
    /// on a journal that is never cut.
    #[must_use]
    pub fn pin(&self, seq: u64) -> Option<Pin> {
        self.pins.as_ref().map(|pins| pins.pin(seq))
    }

    /// The ordinal of the newest row the replay base covers; 0 without a base.
    #[must_use]
    pub fn base_count(&self) -> u64 {
        self.state.lock().map_or(0, |state| state.cut.base_count())
    }

    /// The audit tail at the base (`keep.tail`, §3.2), if a cut moved one.
    #[must_use]
    pub fn base_tail(&self) -> Option<AuditTail> {
        self.state
            .lock()
            .ok()?
            .cut
            .base
            .as_ref()
            .map(|(base, _)| base.tail())
    }

    /// Plan the base move in one `state` critical section, reading no row: the newest boundary at
    /// or below `min(floor, head.count − RETAIN_TAIL, pins.min − 1)` and at least `CUT_BATCH` past
    /// the base. Pins are read under the same lock that `stage_run` inserts them under.
    fn plan_move(&self, floor: u64) -> Option<Step> {
        let state = self.state.lock().ok()?;
        if state.failed.is_some() {
            return None;
        }
        let head = state.verified.head;
        let base_count = state.cut.base_count();
        let mut limit = floor.min(head.count.saturating_sub(RETAIN_TAIL));
        if let Some(seq) = self.pins.as_ref().and_then(|pins| pins.min()) {
            limit = limit.min(ordinal(&head, seq).saturating_sub(1));
        }
        let boundary = state
            .cut
            .boundaries
            .iter()
            .rev()
            .find(|b| b.head.count <= limit && b.head.count >= base_count.saturating_add(CUT_BATCH))
            .copied()?;
        let base = Base {
            head: boundary.head,
            records_seal: boundary.records_seal,
            tail: boundary.tail,
            keep: state
                .cut
                .keep
                .iter()
                .filter(|kept| kept.node_seq <= boundary.head.sequence)
                .cloned()
                .collect(),
        };
        let encoded = base.encode().ok()?;
        Some(Step::Move {
            previous: state.cut.base.as_ref().map(|(_, raw)| raw.clone()),
            base,
            encoded,
        })
    }

    /// Step (1) Applied: readers now start at `base`; boundaries at or below it are popped.
    fn base_moved(&self, base: Base, encoded: Secret<Vec<u8>>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let count = base.count();
        state.cut.boundaries.retain(|b| b.head.count > count);
        state.cut.base = Some((base, encoded));
    }

    async fn submit_cut(&self, step: &Step) -> Outcome {
        match self.try_submit_cut(step).await {
            Ok(outcome) => outcome,
            Err(Error::Access(AccessError::OperationConflict)) => {
                Outcome::Refused("operation conflict".into())
            }
            Err(Error::Authority) => Outcome::Refused("authority".into()),
            // Nothing crossed (overloaded, closing, a refused read): the same attempt is
            // re-driven next.
            Err(_) => Outcome::Retained,
        }
    }

    async fn try_submit_cut(&self, step: &Step) -> Result<Outcome> {
        let journal = StoreJournal::new(&self.store, self.node)?;
        let owner = self
            .live_head()
            .map_err(|_| Error::Authority)?
            .owner
            .clone()
            .ok_or(Error::Authority)?;
        let mut digest = Sha256::new();
        digest.update(b"busbar.journal.cut/1\0");
        digest.update(self.node.to_be_bytes());
        digest.update(owner.expose(&crate::seal::lend()));
        let mut predicates = vec![Predicate {
            address: journal.address(b'O', 0),
            expected: ExpectedValue::Exact(owner),
        }];
        let mut mutations = Vec::new();
        match step {
            Step::Move {
                previous, encoded, ..
            } => {
                digest.update([1]);
                match previous {
                    None => digest.update([0]),
                    Some(previous) => {
                        let previous = previous.expose(&crate::seal::lend());
                        digest.update([1]);
                        digest.update((previous.len() as u64).to_be_bytes());
                        digest.update(previous);
                    }
                }
                let new = encoded.expose(&crate::seal::lend());
                digest.update((new.len() as u64).to_be_bytes());
                digest.update(new);
                predicates.push(Predicate {
                    address: journal.address(b'B', 0),
                    expected: previous.as_ref().map_or(ExpectedValue::Absent, |raw| {
                        ExpectedValue::Exact(raw.clone())
                    }),
                });
                mutations.push(Mutation::Put {
                    address: journal.address(b'B', 0),
                    value: encoded.clone(),
                });
            }
            Step::Delete { from, to } => {
                digest.update([2]);
                digest.update(from.to_be_bytes());
                digest.update(to.to_be_bytes());
                let rows = usize::try_from(to.saturating_sub(*from).saturating_add(1))
                    .map_err(|_| Error::Budget)?;
                mutations
                    .try_reserve_exact(rows)
                    .map_err(|_| Error::Budget)?;
                // Exact deletes, never `DeleteRange` (a memory store's range delete scans the
                // whole namespace).
                for at in *from..=*to {
                    mutations.push(Mutation::Delete(journal.address(b'R', at)));
                }
            }
        }
        let mut operation = [0u8; 16];
        operation[..8].copy_from_slice(&self.node.to_be_bytes());
        operation[8..11].copy_from_slice(b"cut");
        let permit = match self.store.claim_logical(
            LogicalId {
                namespace: journal.namespace.0,
                operation,
            },
            digest.finish(),
        )? {
            LogicalClaim::Prepare(permit) => permit,
            LogicalClaim::Retained(id) => return Ok(outcome(self.store.retry(id).await?)),
            LogicalClaim::Busy => return Ok(Outcome::Retained),
        };
        let candidate = PreparedCandidate::new(Candidate {
            id: self.store.next_id()?,
            codec: CANDIDATE_VERSION,
            predicates,
            mutations,
            time: None,
            result: Secret::default(),
        })
        .map_err(|_| Error::Invalid)?;
        Ok(outcome(permit.submit(candidate).await?))
    }
}

fn outcome(submission: crate::persistence::facade::Submission) -> Outcome {
    match submission.result {
        SubmitResult::Decided(decision) => match &*decision {
            Decision::Applied(_) => Outcome::Applied,
            other => Outcome::Refused(format!("{other:?}")),
        },
        SubmitResult::NoEffect(_) => Outcome::NoEffect,
        SubmitResult::Reconcile => Outcome::Refused("reconcile".into()),
        SubmitResult::Uncertain | SubmitResult::Busy => Outcome::Retained,
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn applied_boundaries_use_the_boot_allocated_ring() {
        let mut state = CutState::ephemeral();
        let allocated = state.boundaries.capacity();
        assert!(
            allocated >= BOUNDARIES,
            "the full boundary ring is reserved at boot"
        );
        for index in 1..=(BOUNDARIES as u64 * 3) {
            let count = index * BOUNDARY_STRIDE;
            state.applied(
                Head {
                    count,
                    sequence: count,
                    hash: [1; 32],
                },
                [2; 32],
                None,
            );
            assert_eq!(
                state.boundaries.capacity(),
                allocated,
                "publishing a group performs no boundary-ring allocation"
            );
        }
        assert_eq!(state.boundaries.len(), BOUNDARIES);
    }
}
