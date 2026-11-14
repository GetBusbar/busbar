// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One host-owned original-frame reservation lane for a native node journal.
//! Staging is memory-only. Only confirm/flush returning Ok proves Applied under
//! the configured backend's declared durability; an ephemeral backend remains
//! explicitly ephemeral after Applied.

use super::*;
use busbar_kernel_wal::Entry;
use std::collections::VecDeque;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy)]
pub struct BufferBudget {
    pub records: usize,
    pub bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeError {
    Invalid,
    Budget,
    Authority,
    Corrupt,
    Pending,
    /// Native replay can no longer resolve the retained original automatically.
    Reconcile,
    Conflict,
    Closed,
    Backend(Failure),
}
impl From<Error> for RuntimeError {
    fn from(error: Error) -> Self {
        match error {
            Error::Budget | Error::Overflow => Self::Budget,
            Error::Authority => Self::Authority,
            Error::Invalid => Self::Invalid,
            Error::Backend(error) => Self::Backend(error),
            Error::Access(AccessError::Closed) => Self::Closed,
            Error::Access(AccessError::Overloaded) => Self::Budget,
            Error::Access(AccessError::Backend(error)) => Self::Backend(error),
            Error::Access(AccessError::Authority) => Self::Authority,
            _ => Self::Corrupt,
        }
    }
}

/// Exact originals retained before the first asynchronous crossing. The local
/// ticket is queue custody only, never a journal sequence or durable receipt.
pub struct StagedRun {
    owner: Arc<()>,
    ticket: u64,
    records: Arc<[Record]>,
    bytes: usize,
}
impl StagedRun {
    pub fn records(&self) -> &[Record] {
        &self.records
    }
}

/// A group submitted to the store: the proof it was appended under and how
/// many pending runs (from the front) it covers. Set only on the front entry
/// and kept until the group resolves, so a retry after an uncertain outcome
/// or a cancelled driver replays exactly the same records under the same
/// proof (the store's logical claim is keyed by node, digest over both).
struct Attempt {
    proof: Arc<VerifiedHead>,
    runs: usize,
}
struct PendingRun {
    run: Arc<StagedRun>,
    attempt: Option<Attempt>,
}
struct State {
    accepting: bool,
    verified: Arc<VerifiedHead>,
    reserved: Head,
    next_ticket: u64,
    completed: u64,
    pending: VecDeque<PendingRun>,
    records: usize,
    bytes: usize,
    failed: Option<RuntimeError>,
}

pub struct RuntimeJournal {
    owner: Arc<()>,
    store: Arc<CoreStore>,
    node: u64,
    budget: BufferBudget,
    state: Mutex<State>,
    driving: tokio::sync::Mutex<()>,
}
impl RuntimeJournal {
    /// Root constructs exactly one shared owner and passes this same Arc to
    /// audit, amendment, recovery and checkpoint services for this node.
    pub async fn open(
        store: Arc<CoreStore>,
        node: u64,
        budget: BufferBudget,
    ) -> std::result::Result<Arc<Self>, RuntimeError> {
        if budget.records == 0 || budget.bytes == 0 {
            return Err(RuntimeError::Invalid);
        }
        let journal = StoreJournal::new(&store, node).map_err(RuntimeError::from)?;
        let mut replay = journal
            .historical_replay()
            .await
            .map_err(RuntimeError::from)?;
        while replay.next().await.map_err(RuntimeError::from)?.is_some() {}
        let proof = replay.finish().map_err(RuntimeError::from)?;
        journal
            .confirm_owned(&proof)
            .await
            .map_err(RuntimeError::from)?;
        let reserved = proof.head;
        Ok(Arc::new(Self {
            owner: Arc::new(()),
            store,
            node,
            budget,
            state: Mutex::new(State {
                accepting: true,
                verified: Arc::new(proof),
                reserved,
                next_ticket: 1,
                completed: 0,
                pending: VecDeque::new(),
                records: 0,
                bytes: 0,
                failed: None,
            }),
            driving: tokio::sync::Mutex::new(()),
        }))
    }

    pub fn node(&self) -> u64 {
        self.node
    }
    /// The configured Store's acknowledgement guarantee, independent of this
    /// owner's temporary memory staging. Ephemeral Applied is not crash-durable.
    pub fn durability(&self) -> busbar_contract::persistence::Durability {
        self.store.info().durability
    }
    /// Display/cursor boundary, including memory-only reservations. It is never
    /// used as a durable receipt or as a replacement for a completed proof.
    pub fn next_seq(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .reserved
            .sequence
            .saturating_add(1)
    }
    pub(crate) fn store(&self) -> &Arc<CoreStore> {
        &self.store
    }
    /// Check attachment identity for a root-owned shutdown proof. This grants
    /// no writer authority and does not replace native admission verification.
    pub fn is_bound_to(&self, store: &Arc<CoreStore>) -> bool {
        Arc::ptr_eq(&self.store, store)
    }
    pub fn next_sequence(&self) -> std::result::Result<u64, RuntimeError> {
        self.state
            .lock()
            .map_err(|_| RuntimeError::Corrupt)?
            .reserved
            .sequence
            .checked_add(1)
            .ok_or(RuntimeError::Budget)
    }
    pub fn pending_records(&self) -> usize {
        self.state.lock().map_or(usize::MAX, |state| state.records)
    }
    /// Permanently stop new memory reservations before the final shutdown
    /// drain. Existing originals and exact native attempts remain confirmable.
    pub fn stop_staging(&self) -> std::result::Result<(), RuntimeError> {
        self.state
            .lock()
            .map_err(|_| RuntimeError::Corrupt)?
            .accepting = false;
        Ok(())
    }
    /// Inspect this owner's cached Applied confirmation for an opaque run.
    /// This is useful for releasing abandoned waiter custody after a later
    /// flush confirms its prefix; it never initiates or replans a write.
    pub fn is_confirmed(&self, run: &Arc<StagedRun>) -> std::result::Result<bool, RuntimeError> {
        if !Arc::ptr_eq(&self.owner, &run.owner) {
            return Err(RuntimeError::Authority);
        }
        let state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
        Ok(run.ticket <= state.completed)
    }
    /// Admission backpressure never discards a queued original or interprets a
    /// pending native attempt as durable acceptance.
    pub fn refuses_money(&self) -> Option<String> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !state.accepting {
            return Some("native journal staging is closed".into());
        }
        if let Some(error) = state.failed {
            return Some(format!("native journal custody failed: {error:?}"));
        }
        (state.records >= self.budget.records || state.bytes >= self.budget.bytes)
            .then(|| "native journal custody buffer is full".into())
    }

    /// Read a whole verified native selected history within an explicit host
    /// memory budget. Neither pending staged originals nor future appends can
    /// be mistaken for records in this selected immutable prefix.
    pub async fn read_records(
        &self,
        budget: BufferBudget,
    ) -> std::result::Result<Vec<JournalRecord>, RuntimeError> {
        self.read_node_records(self.node, budget).await
    }

    /// Enumerate the complete registered node inventory. This grants no writer
    /// ownership over another node and never opens a legacy Store reader.
    pub async fn registered_nodes(&self) -> std::result::Result<Vec<u64>, RuntimeError> {
        let registry = crate::persistence::boot_identity::BootIdentity::new(self.store.clone())
            .map_err(|_| RuntimeError::Corrupt)?;
        let mut nodes: Vec<_> = registry
            .registered()
            .await
            .map_err(|_| RuntimeError::Corrupt)?
            .into_iter()
            .map(|(_, node)| node)
            .collect();
        nodes.push(self.node);
        nodes.sort_unstable();
        nodes.dedup();
        Ok(nodes)
    }

    /// Historical read-only proof for any registered node. No confirm_owned or
    /// handover is issued; foreign writer custody remains unchanged.
    pub async fn read_node_records(
        &self,
        node: u64,
        budget: BufferBudget,
    ) -> std::result::Result<Vec<JournalRecord>, RuntimeError> {
        let journal = StoreJournal::new(&self.store, node).map_err(RuntimeError::from)?;
        let mut replay = journal
            .historical_replay()
            .await
            .map_err(RuntimeError::from)?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        while let Some(original) = replay.next().await.map_err(RuntimeError::from)? {
            bytes = bytes
                .checked_add(original.body.len())
                .ok_or(RuntimeError::Budget)?;
            if records.len() >= budget.records || bytes > budget.bytes {
                return Err(RuntimeError::Budget);
            }
            records.try_reserve(1).map_err(|_| RuntimeError::Budget)?;
            records.push(JournalRecord::decode(&original.body).map_err(|_| RuntimeError::Corrupt)?);
        }
        replay.finish().map_err(RuntimeError::from)?;
        Ok(records)
    }

    /// Synchronous hot sealing reserves one node's original sequence/hash chain.
    /// It neither submits nor acknowledges persistence. The caller must await
    /// confirm before publishing a dependent durable result.
    pub fn stage_run(
        &self,
        entries: &[Entry],
    ) -> std::result::Result<Arc<StagedRun>, RuntimeError> {
        if entries.is_empty() || entries.len() > self.store.limits().scan_items {
            return Err(RuntimeError::Budget);
        }
        let mut bytes = 0usize;
        for entry in entries {
            bytes = bytes
                .checked_add(entry.body.len())
                .and_then(|n| n.checked_add(busbar_kernel_wal::journal::JOURNAL_HEADER_BYTES))
                .ok_or(RuntimeError::Budget)?;
        }
        if bytes > self.store.limits().scan_bytes {
            return Err(RuntimeError::Budget);
        }
        let mut state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
        if !state.accepting {
            return Err(RuntimeError::Closed);
        }
        if let Some(error) = state.failed {
            return Err(error);
        }
        let next_records = state
            .records
            .checked_add(entries.len())
            .ok_or(RuntimeError::Budget)?;
        let next_bytes = state.bytes.checked_add(bytes).ok_or(RuntimeError::Budget)?;
        if next_records > self.budget.records || next_bytes > self.budget.bytes {
            return Err(RuntimeError::Budget);
        }
        let next_ticket = state
            .next_ticket
            .checked_add(1)
            .ok_or(RuntimeError::Budget)?;
        let mut head = state.reserved;
        let mut records = Vec::new();
        records
            .try_reserve_exact(entries.len())
            .map_err(|_| RuntimeError::Budget)?;
        for entry in entries {
            let record = super::recovery_hooks::seal_record(self.node, head, entry.clone())
                .map_err(RuntimeError::from)?;
            let decoded = decode_record(self.node, &record.body).map_err(RuntimeError::from)?;
            head = advance(head, &decoded).map_err(RuntimeError::from)?;
            records.push(record);
        }
        state
            .pending
            .try_reserve(1)
            .map_err(|_| RuntimeError::Budget)?;
        let run = Arc::new(StagedRun {
            owner: self.owner.clone(),
            ticket: state.next_ticket,
            records: records.into(),
            bytes,
        });
        state.pending.push_back(PendingRun {
            run: run.clone(),
            attempt: None,
        });
        state.reserved = head;
        state.next_ticket = next_ticket;
        state.records = next_records;
        state.bytes = next_bytes;
        Ok(run)
    }

    /// One node's serial publication driver. Cancellation drops a waiter and
    /// leaves originals, selected proof, and CoreStore's exact attempt retained.
    pub async fn confirm(&self, run: &Arc<StagedRun>) -> std::result::Result<(), RuntimeError> {
        if !Arc::ptr_eq(&self.owner, &run.owner) {
            return Err(RuntimeError::Authority);
        }
        // An equal local ticket from another owner is not an ownership proof.
        let target = {
            let state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
            if run.ticket <= state.completed {
                return self.confirm_completed(run);
            }
            if !state
                .pending
                .iter()
                .any(|pending| Arc::ptr_eq(&pending.run, run))
            {
                return Err(RuntimeError::Authority);
            }
            run.ticket
        };
        self.drive_through(target).await
    }

    fn confirm_completed(&self, run: &StagedRun) -> std::result::Result<(), RuntimeError> {
        // Completed evidence is validated from the original native journal by
        // callers after restart; in-process tickets additionally bind the owner.
        if run.records.iter().any(|record| record.node != self.node) {
            return Err(RuntimeError::Authority);
        }
        Ok(())
    }

    pub async fn flush(&self) -> std::result::Result<(), RuntimeError> {
        let target = self
            .state
            .lock()
            .map_err(|_| RuntimeError::Corrupt)?
            .next_ticket
            .saturating_sub(1);
        self.drive_through(target).await
    }

    /// Confirm live admission of this owner for a read-only observation.
    ///
    /// This owner is the only writer of the node's selected head, and every
    /// append is serialised by the publication driver. Holding that driver fixes
    /// the head, so the owner's current verified head is checked against native
    /// custody and execution admission in one authoritative read.
    ///
    /// A `prior` proof of this node taken earlier in the same observation must
    /// be a prefix of the current verified head: same dataset, node and owner,
    /// and no later sequence. Appends are guarded Absent-key writes by one
    /// admitted owner, so records already read against `prior` remain in the
    /// current history. A cold cutover, fence or epoch change fails admission.
    pub(crate) async fn confirm_live_owned(
        &self,
        prior: Option<&VerifiedHead>,
    ) -> std::result::Result<(), RuntimeError> {
        let _driver = self.driving.lock().await;
        let verified = {
            let state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
            if let Some(error) = state.failed {
                return Err(error);
            }
            state.verified.clone()
        };
        if let Some(prior) = prior {
            if prior.dataset != verified.dataset
                || prior.node != verified.node
                || prior.owner != verified.owner
                || prior.head.sequence > verified.head.sequence
            {
                return Err(RuntimeError::Authority);
            }
        }
        StoreJournal::new(&self.store, self.node)
            .map_err(RuntimeError::from)?
            .confirm_owned(&verified)
            .await
            .map_err(RuntimeError::from)
    }

    /// The group the next append carries. A group that was submitted is pinned
    /// on the front entry and returned unchanged until it resolves; otherwise
    /// every contiguous pending run from the front joins, up to the store's
    /// own per-append limits (a single run always fits: `stage_run` checks it).
    fn take_group(
        state: &mut State,
        limits: crate::persistence::facade::Limits,
    ) -> std::result::Result<(Arc<VerifiedHead>, Vec<Arc<StagedRun>>), RuntimeError> {
        let verified = state.verified.clone();
        let front = state.pending.front().ok_or(RuntimeError::Corrupt)?;
        let (proof, runs) = match &front.attempt {
            Some(attempt) => (attempt.proof.clone(), attempt.runs),
            None => {
                let (mut records, mut bytes, mut runs) = (0usize, 0usize, 0usize);
                for pending in &state.pending {
                    let next_records = records.saturating_add(pending.run.records.len());
                    let next_bytes = bytes.saturating_add(pending.run.bytes);
                    if runs > 0
                        && (next_records > limits.scan_items || next_bytes > limits.scan_bytes)
                    {
                        break;
                    }
                    (records, bytes, runs) = (next_records, next_bytes, runs + 1);
                }
                (verified, runs)
            }
        };
        if runs == 0 || runs > state.pending.len() {
            return Err(RuntimeError::Corrupt);
        }
        let group = state
            .pending
            .iter()
            .take(runs)
            .map(|pending| pending.run.clone())
            .collect();
        state
            .pending
            .front_mut()
            .ok_or(RuntimeError::Corrupt)?
            .attempt = Some(Attempt {
            proof: proof.clone(),
            runs,
        });
        Ok((proof, group))
    }

    /// Group commit: each pass appends every run already pending (bounded by the
    /// store limits) in one store append, so concurrent waiters share one round
    /// trip instead of queueing one append each behind the driver lock.
    async fn drive_through(&self, target: u64) -> std::result::Result<(), RuntimeError> {
        let _driver = self.driving.lock().await;
        let journal = StoreJournal::new(&self.store, self.node).map_err(RuntimeError::from)?;
        let limits = self.store.limits();
        loop {
            let (proof, group) = {
                let mut state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
                if let Some(error) = state.failed {
                    return Err(error);
                }
                if state.completed >= target {
                    return Ok(());
                }
                Self::take_group(&mut state, limits)?
            };
            // Runs chain from `state.reserved` in ticket order, so the group's
            // records are one contiguous chain; concatenating the same pinned
            // runs always yields the same bytes, hence the same claim digest.
            let joined: Vec<Record>;
            let records: &[Record] = match group.as_slice() {
                [run] => run.records(),
                runs => {
                    joined = runs
                        .iter()
                        .flat_map(|run| run.records().iter().cloned())
                        .collect();
                    &joined
                }
            };
            let submission = journal
                .append(&proof, records)
                .await
                .map_err(RuntimeError::from)?;
            let WriteResult::Submitted(submission) = submission else {
                return Err(RuntimeError::Pending);
            };
            match submission.result {
                super::super::commit::SubmitResult::Decided(decision)
                    if matches!(
                        &*decision,
                        busbar_contract::persistence::Decision::Applied(_)
                    ) =>
                {
                    // This is the precise head encoded in the Applied append,
                    // built from unchanged verified frame headers/digests. The
                    // old full proof and native H/O CAS establish its ancestry.
                    let mut head = proof.head;
                    let mut records_seal = proof.records_seal;
                    for original in records {
                        let record = checked_record(self.node, &original.body, head)
                            .map_err(RuntimeError::from)?;
                        head = advance(head, &record).map_err(RuntimeError::from)?;
                        records_seal = super::extend_records_seal(records_seal, &original.body);
                    }
                    let verified = Arc::new(VerifiedHead {
                        dataset: proof.dataset,
                        node: proof.node,
                        head,
                        records_seal,
                        selected: Some(head.encode()),
                        owner: Some(owner_bytes(
                            self.store
                                .authority()
                                .map_err(|error| RuntimeError::from(Error::Access(error)))?,
                        )),
                    });
                    let mut state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
                    for run in &group {
                        let pending = state.pending.pop_front().ok_or(RuntimeError::Corrupt)?;
                        if !Arc::ptr_eq(&pending.run, run) {
                            state.failed = Some(RuntimeError::Corrupt);
                            return Err(RuntimeError::Corrupt);
                        }
                        state.completed = run.ticket;
                        state.records -= run.records.len();
                        state.bytes -= run.bytes;
                    }
                    state.verified = verified;
                }
                super::super::commit::SubmitResult::Decided(_) => {
                    self.state.lock().map_err(|_| RuntimeError::Corrupt)?.failed =
                        Some(RuntimeError::Conflict);
                    return Err(RuntimeError::Conflict);
                }
                super::super::commit::SubmitResult::NoEffect(error) => {
                    return Err(RuntimeError::Backend(error));
                }
                super::super::commit::SubmitResult::Reconcile => {
                    self.state.lock().map_err(|_| RuntimeError::Corrupt)?.failed =
                        Some(RuntimeError::Reconcile);
                    return Err(RuntimeError::Reconcile);
                }
                super::super::commit::SubmitResult::Uncertain
                | super::super::commit::SubmitResult::Busy => return Err(RuntimeError::Pending),
            }
        }
    }
}
