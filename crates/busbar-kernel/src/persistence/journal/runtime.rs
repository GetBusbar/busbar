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

#[path = "conditional.rs"]
mod conditional;
pub use conditional::{ConditionalAppend, ConditionalOutcome};

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
    /// The chain hash this process sealed for each record, in order (SHUTDOWN-HANG F1).
    hashes: Arc<[[u8; 32]]>,
    bytes: usize,
}
impl StagedRun {
    pub fn records(&self) -> &[Record] {
        &self.records
    }
    /// The evidence this process holds for each original of the run: its sequence and the chain
    /// hash it sealed. It is evidence of a journal original only once `confirm` returned Ok.
    pub fn carried(&self) -> impl Iterator<Item = Carried> + '_ {
        self.records
            .iter()
            .zip(self.hashes.iter())
            .map(|(record, hash)| Carried {
                seq: record.node_seq,
                hash: *hash,
            })
    }
}

/// What this process holds for one of its own originals (SHUTDOWN-HANG F1): the sequence it sealed
/// and the chain hash of those exact bytes. A record read back against it is that original, or the
/// read is refused as `Corrupt`. RAM only; never persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Carried {
    pub seq: u64,
    pub hash: [u8; 32],
}

/// A group submitted to the store: the proof it was appended under and how
/// many pending runs (from the front) it covers. Set only on the front entry
/// and kept until the group resolves, so a retry after an uncertain outcome
/// or a cancelled driver replays exactly the same records under the same
/// proof (the store's logical claim is keyed by node, digest over both).
struct Attempt {
    proof: Arc<VerifiedHead>,
    runs: usize,
    /// The head and original-byte seal the group produces if it applies, computed once before
    /// its first submit (SHUTDOWN-HANG H3): a confirmation accepts this head while the group is
    /// in flight, and Applied publishes it without walking the group again.
    next: Head,
    records_seal: [u8; 32],
}

/// The head and original-byte seal after `group`'s records, appended in order to `head`/`seal`.
fn walk_group(
    node: u64,
    mut head: Head,
    mut seal: [u8; 32],
    group: &[Arc<StagedRun>],
) -> std::result::Result<(Head, [u8; 32]), RuntimeError> {
    for original in group.iter().flat_map(|run| run.records.iter()) {
        let record = checked_record(node, &original.body, head).map_err(RuntimeError::from)?;
        head = advance(head, &record).map_err(RuntimeError::from)?;
        seal = super::extend_records_seal(seal, &original.body);
    }
    Ok((head, seal))
}

/// The selected-row change a domain owner asks `change_live` to make (a guarded selection; a
/// delete, or several rows at once, go through `change_rows_live`).
pub(crate) enum LiveChange<'a> {
    Select {
        selection: Selection,
        guards: &'a [Predicate],
    },
}

/// `prior` must be a prefix of `current`: same dataset, node and owner, and
/// no later sequence.
fn prefix_of(
    prior: &VerifiedHead,
    current: &VerifiedHead,
) -> std::result::Result<(), RuntimeError> {
    if prior.dataset != current.dataset
        || prior.node != current.node
        || prior.owner != current.owner
        || prior.head.sequence > current.head.sequence
    {
        return Err(RuntimeError::Authority);
    }
    Ok(())
}

/// The group the next append carries: the verified head it extends (its proof), its runs, the head it
/// lands at and its records seal.
type Group = (Arc<VerifiedHead>, Vec<Arc<StagedRun>>, Head, [u8; 32]);

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
    conditional: Option<conditional::Slot>,
    /// Where each frame of this node's journal sits: `(first_ordinal, first_sequence)` per run of
    /// contiguous sequences, built by the open replay (one segment per custody bridge, usually
    /// one). Live appends are contiguous, so the last segment covers them (W1 step 2).
    seq_map: Vec<(u64, u64)>,
}

/// Publication progress mirrored from `State` for confirm waiters, so a
/// confirm whose own ticket is already applied never queues behind the driver
/// that is committing later tickets.
#[derive(Debug, Clone, Copy, Default)]
struct Progress {
    completed: u64,
    failed: Option<RuntimeError>,
}

pub struct RuntimeJournal {
    owner: Arc<()>,
    store: Arc<CoreStore>,
    node: u64,
    budget: BufferBudget,
    state: Mutex<State>,
    driving: tokio::sync::Mutex<()>,
    progress: tokio::sync::watch::Sender<Progress>,
    /// Confirmations that fell back to the publication driver (SHUTDOWN-HANG F1, counted).
    lane_fallbacks: std::sync::atomic::AtomicU64,
    /// Test probe: acquisitions of the publication driver, the journal lane (SHUTDOWN-HANG 8.3).
    #[cfg(test)]
    lane_holds: std::sync::atomic::AtomicU64,
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
        let mut seq_map: Vec<(u64, u64)> = Vec::new();
        let mut ordinal = 0u64;
        let mut previous: Option<u64> = None;
        while let Some(record) = replay.next().await.map_err(RuntimeError::from)? {
            ordinal = ordinal.checked_add(1).ok_or(RuntimeError::Budget)?;
            if previous.and_then(|seq| seq.checked_add(1)) != Some(record.node_seq) {
                seq_map.try_reserve(1).map_err(|_| RuntimeError::Budget)?;
                seq_map.push((ordinal, record.node_seq));
            }
            previous = Some(record.node_seq);
        }
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
                conditional: None,
                seq_map,
            }),
            driving: tokio::sync::Mutex::new(()),
            progress: tokio::sync::watch::Sender::new(Progress::default()),
            lane_fallbacks: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            lane_holds: std::sync::atomic::AtomicU64::new(0),
        }))
    }

    /// Mirror `completed` and `failed` to confirm waiters. Called with `state`
    /// still locked, so the watch is never behind `state` by more than one publish.
    fn publish(&self, state: &State) {
        let (completed, failed) = (state.completed, state.failed);
        self.progress.send_modify(|progress| {
            progress.completed = completed;
            progress.failed = failed;
        });
    }

    /// Record a sticky failure and publish it to every confirm waiter.
    fn fail(&self, state: &mut State, error: RuntimeError) -> RuntimeError {
        state.failed = Some(error);
        self.publish(state);
        error
    }

    /// The sticky custody failure, if any: exactly the error a drive would
    /// return first. O(1); never drives, waits for or retries a held run.
    pub fn failed(&self) -> Option<RuntimeError> {
        self.state
            .lock()
            .map_or(Some(RuntimeError::Corrupt), |state| state.failed)
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
    /// One settle tick of the store's slot queue: resubmit at most `SETTLE_PER_TICK`
    /// in-doubt attempts no waiter drives, then report the `busbar_store_slots` states.
    /// Independent of `flush`, so a stalled store never blocks the journal flush.
    pub async fn settle_store(
        &self,
    ) -> std::result::Result<crate::persistence::facade::SlotStates, AccessError> {
        self.store
            .settle_in_doubt(crate::persistence::facade::SETTLE_PER_TICK)
            .await?;
        self.store.slot_states()
    }

    pub fn refuses_money(&self) -> Option<String> {
        // One relaxed load: the store's slot queue is full (STORE_INFLIGHT_EXHAUSTED).
        if self.store.exhausted() {
            return Some("store in-flight queue exhausted".into());
        }
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
        if state.conditional.is_some() {
            return Some("native journal conditional publication is pending".into());
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
        nodes.sort();
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
        if state.conditional.is_some() {
            return Err(RuntimeError::Pending);
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
        let mut hashes = Vec::new();
        hashes
            .try_reserve_exact(entries.len())
            .map_err(|_| RuntimeError::Budget)?;
        for entry in entries {
            let record = super::recovery_hooks::seal_record(self.node, head, entry.clone())
                .map_err(RuntimeError::from)?;
            let decoded = decode_record(self.node, &record.body).map_err(RuntimeError::from)?;
            head = advance(head, &decoded).map_err(RuntimeError::from)?;
            hashes.push(decoded.hash);
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
            hashes: hashes.into(),
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
        let mut progress = self.progress.subscribe();
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
        // Lock order is not ticket order: a driver holding the lock for a later
        // ticket also applies this one. Return as soon as this ticket is applied
        // (or custody fails) instead of queueing for that driver's later commits.
        // A tokio Mutex waiter is cancel-safe, so the losing branch is dropped.
        tokio::select! {
            biased;
            failed = async {
                progress
                    .wait_for(|p| p.failed.is_some() || p.completed >= target)
                    .await
                    .map_or(Some(RuntimeError::Corrupt), |p| p.failed)
            } => {
                match failed {
                    Some(error) => Err(error),
                    None => self.confirm_completed(run),
                }
            }
            driver = self.lane() => self.drive_locked(&driver, target).await,
        }
    }

    fn confirm_completed(&self, run: &StagedRun) -> std::result::Result<(), RuntimeError> {
        // Completed evidence is validated from the original native journal by
        // callers after restart; in-process tickets additionally bind the owner.
        if run.records.iter().any(|record| record.node != self.node) {
            return Err(RuntimeError::Authority);
        }
        Ok(())
    }

    /// The ordinal of this node's frame `sequence` within a proof this owner verified, by
    /// arithmetic over the open replay's layout (W1 step 2). A proof of another dataset or node,
    /// or one longer than this owner's verified head, is refused; a sequence outside the proof or
    /// inside a bridged gap is invalid. A wrong ordinal can only fail closed: readers compare the
    /// frame's sequence and selections bind the exact frame body by predicate.
    pub(crate) fn locate(
        &self,
        proof: &VerifiedHead,
        sequence: u64,
    ) -> std::result::Result<u64, RuntimeError> {
        let state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
        if let Some(error) = state.failed {
            return Err(error);
        }
        let verified = &state.verified;
        if proof.dataset != verified.dataset
            || proof.node != verified.node
            || proof.head.count > verified.head.count
            || (proof.owner.is_some() && proof.owner != verified.owner)
        {
            return Err(RuntimeError::Authority);
        }
        if sequence == 0 || sequence > proof.head.sequence {
            return Err(RuntimeError::Invalid);
        }
        let segment = state
            .seq_map
            .partition_point(|&(_, first_sequence)| first_sequence <= sequence);
        let (first_ordinal, first_sequence) = *segment
            .checked_sub(1)
            .and_then(|index| state.seq_map.get(index))
            .ok_or(RuntimeError::Invalid)?;
        let ordinal = first_ordinal
            .checked_add(sequence - first_sequence)
            .ok_or(RuntimeError::Invalid)?;
        if state
            .seq_map
            .get(segment)
            .is_some_and(|&(next_ordinal, _)| ordinal >= next_ordinal)
            || ordinal == 0
            || ordinal > proof.head.count
        {
            return Err(RuntimeError::Invalid);
        }
        Ok(ordinal)
    }

    pub async fn flush(&self) -> std::result::Result<(), RuntimeError> {
        let target = {
            let state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
            if state.conditional.is_some() {
                // The root owner must install conditional canonical publication
                // before its barrier can be released; flush cannot invent it.
                return Err(RuntimeError::Pending);
            }
            state.next_ticket.saturating_sub(1)
        };
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
    /// and no later sequence. The originals appended after `prior` (only those)
    /// are then read and must link to it and reproduce this owner's verified
    /// head and original-byte seal exactly, so a forked, rewritten or damaged
    /// tail refuses. A cold cutover, fence or epoch change fails admission.
    pub(crate) async fn confirm_live_owned(
        &self,
        prior: Option<&VerifiedHead>,
    ) -> std::result::Result<(), RuntimeError> {
        let journal = StoreJournal::new(&self.store, self.node).map_err(RuntimeError::from)?;
        // The tail after `prior` is read outside the driver, so request-path
        // appends keep committing while it is checked (holding the driver here
        // would make every such append wait on this read, and an append the
        // read itself waits for would never land).
        let checked = match prior {
            Some(prior) => {
                let checked = self.live_head()?;
                prefix_of(prior, &checked)?;
                journal
                    .confirm_extends(prior, &checked)
                    .await
                    .map_err(RuntimeError::from)?;
                Some(checked)
            }
            None => None,
        };
        let _driver = self.lane().await;
        let verified = self.live_head()?;
        // Anything after `checked` is this owner's own Applied appends, each
        // verified as it was applied: the one writer vouches for them.
        if let Some(checked) = &checked {
            prefix_of(checked, &verified)?;
        }
        journal
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
        node: u64,
    ) -> std::result::Result<Group, RuntimeError> {
        let verified = state.verified.clone();
        let front = state.pending.front().ok_or(RuntimeError::Corrupt)?;
        let pinned = front
            .attempt
            .as_ref()
            .map(|attempt| (attempt.next, attempt.records_seal));
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
        let group: Vec<Arc<StagedRun>> = state
            .pending
            .iter()
            .take(runs)
            .map(|pending| pending.run.clone())
            .collect();
        let (next, records_seal) = match pinned {
            Some(pinned) => pinned,
            None => walk_group(node, proof.head, proof.records_seal, &group)?,
        };
        state
            .pending
            .front_mut()
            .ok_or(RuntimeError::Corrupt)?
            .attempt = Some(Attempt {
            proof: proof.clone(),
            runs,
            next,
            records_seal,
        });
        Ok((proof, group, next, records_seal))
    }

    /// Flush staged runs, then confirm this owner's live verified head against
    /// native custody and admission in one read while the driver is held. The
    /// head was built by the opening replay and extended only by this owner's
    /// Applied appends, so no history is replayed here.
    pub(crate) async fn live_proof(&self) -> std::result::Result<Arc<VerifiedHead>, RuntimeError> {
        let driver = self.lane().await;
        self.drive_locked(&driver, self.staged_target()?).await?;
        let verified = self.live_head()?;
        StoreJournal::new(&self.store, self.node)
            .map_err(RuntimeError::from)?
            .confirm_owned(&verified)
            .await
            .map_err(RuntimeError::from)?;
        Ok(verified)
    }

    /// Change a domain's selected row against originals of this node, built and
    /// submitted only while the publication driver is held, so no append can
    /// move the selected head between the proof and the CAS.
    ///
    /// `retained` is `Some` only when re-driving an earlier attempt: that exact
    /// proof is reused so the logical claim digest is unchanged. `None` uses
    /// the live head. `retain` is called exactly once, synchronously, under the
    /// driver, with the proof this call will CAS against, before any native
    /// claim; the caller stores it in its retained custody there. No journal
    /// replay runs: every original, before or after a chain discontinuity, is
    /// located by [`Self::locate`] over the open replay's segment map (W1).
    pub(crate) async fn change_live(
        &self,
        records: &[Record],
        change: LiveChange<'_>,
        retained: Option<Arc<VerifiedHead>>,
        retain: &(dyn Fn(&Arc<VerifiedHead>) + Send + Sync),
    ) -> std::result::Result<(Arc<VerifiedHead>, WriteResult), RuntimeError> {
        let journal = StoreJournal::new(&self.store, self.node).map_err(RuntimeError::from)?;
        let pre = self.live_head()?;
        let driver = self.lane().await;
        self.drive_locked(&driver, self.staged_target()?).await?;
        let proof = match retained {
            Some(proof) => proof,
            None => {
                let live = self.live_head()?;
                if !Arc::ptr_eq(&live, &pre) {
                    prefix_of(&pre, &live)?;
                }
                live
            }
        };
        let mut located = Vec::new();
        located
            .try_reserve_exact(records.len())
            .map_err(|_| RuntimeError::Budget)?;
        for record in records {
            located.push(self.locate(&proof, record.node_seq)?);
        }
        // Retain before any claim and before the first await below: every
        // later return or cancellation leaves the caller holding the exact
        // proof whose digest CoreStore may retain.
        retain(&proof);
        let LiveChange::Select { selection, guards } = change;
        let result = journal
            .change_selection_at(
                &proof,
                records,
                Some(located.as_slice()),
                selection,
                false,
                guards,
            )
            .await
            .map_err(RuntimeError::from)?;
        drop(driver);
        Ok((proof, result))
    }

    /// `change_live` for several rows of one namespace in one CAS (SHUTDOWN-HANG F3.1): the same
    /// driver, proof and `retain` rules, and every row's originals located in O(1) by
    /// [`Self::locate`]. One row is the same attempt as `change_live`'s selection or delete.
    pub(crate) async fn change_rows_live(
        &self,
        operation_id: [u8; 16],
        rows: &[RowChange<'_>],
        retained: Option<Arc<VerifiedHead>>,
        retain: &(dyn Fn(&Arc<VerifiedHead>) + Send + Sync),
    ) -> std::result::Result<(Arc<VerifiedHead>, WriteResult), RuntimeError> {
        let journal = StoreJournal::new(&self.store, self.node).map_err(RuntimeError::from)?;
        let pre = self.live_head()?;
        let driver = self.lane().await;
        self.drive_locked(&driver, self.staged_target()?).await?;
        let proof = match retained {
            Some(proof) => proof,
            None => {
                let live = self.live_head()?;
                if !Arc::ptr_eq(&live, &pre) {
                    prefix_of(&pre, &live)?;
                }
                live
            }
        };
        let mut located = Vec::new();
        located
            .try_reserve_exact(rows.iter().map(|row| row.records.len()).sum::<usize>())
            .map_err(|_| RuntimeError::Budget)?;
        for record in rows.iter().flat_map(|row| row.records) {
            located.push(self.locate(&proof, record.node_seq)?);
        }
        // Retain before any claim, as `change_live` does.
        retain(&proof);
        let result = journal
            .change_rows_at(&proof, operation_id, rows, &located)
            .await
            .map_err(RuntimeError::from)?;
        drop(driver);
        Ok((proof, result))
    }

    /// This owner's verified head right now, without the publication driver: a snapshot for
    /// locating its own originals, never a CAS predicate by itself.
    pub(crate) fn verified(&self) -> std::result::Result<Arc<VerifiedHead>, RuntimeError> {
        self.live_head()
    }

    /// Read-only view of ANOTHER node's journal (SHUTDOWN-HANG F1, R15). This node's own journal
    /// is refused: its proofs exist only under this owner.
    pub(crate) fn foreign(
        &self,
        node: u64,
    ) -> std::result::Result<super::ForeignJournal<'_>, RuntimeError> {
        if node == self.node {
            return Err(RuntimeError::Authority);
        }
        super::ForeignJournal::new(&self.store, node).map_err(RuntimeError::from)
    }

    /// This node's own journal, read cold: boot scans and hops with no carried evidence (R15).
    pub(crate) fn history(&self) -> std::result::Result<super::OwnHistory<'_>, RuntimeError> {
        super::OwnHistory::new(&self.store, self.node).map_err(RuntimeError::from)
    }

    /// Exact custody of `proof` of this node: H and O equal `proof`'s and our admission holds, in
    /// one read, without the driver. Cold paths only; the live path uses [`Self::confirm_with`].
    pub(crate) async fn confirm_exact(
        &self,
        proof: &VerifiedHead,
    ) -> std::result::Result<(), RuntimeError> {
        StoreJournal::new(&self.store, self.node)
            .map_err(RuntimeError::from)?
            .confirm_owned(proof)
            .await
            .map_err(RuntimeError::from)
    }

    /// The H and O predicates of `proof` of this node, refused unless it names this owner.
    pub(crate) fn owned_predicates(
        &self,
        proof: &VerifiedHead,
    ) -> std::result::Result<Vec<Predicate>, RuntimeError> {
        StoreJournal::new(&self.store, self.node)
            .map_err(RuntimeError::from)?
            .owned_predicates(proof)
            .map_err(RuntimeError::from)
    }

    /// Custody and admission of this owner plus `guards`, in one read, without the publication
    /// driver (SHUTDOWN-HANG F1). While O is ours and admission holds, only this owner's appends
    /// move H, serially, each from the verified head to its pinned group's `next` in one CAS. So
    /// the read is accepted iff O, admission and every guard match and H is one of the heads this
    /// owner knew just before or just after it. Accepting a later own head is sound: own appends
    /// only extend the prefix. Two own appends inside one read round trip leave H outside both
    /// windows; the read is retried once, then made exact under the driver (counted).
    pub(crate) async fn confirm_with(
        &self,
        guards: &[Predicate],
    ) -> std::result::Result<(), RuntimeError> {
        let journal = StoreJournal::new(&self.store, self.node).map_err(RuntimeError::from)?;
        for _ in 0..2 {
            let (verified, next) = self.head_window()?;
            if verified.owner.is_none() {
                // An unclaimed journal's first append also writes O: decide it under the driver.
                break;
            }
            let observed = journal
                .observe_owned_with(&verified, guards)
                .await
                .map_err(RuntimeError::from)?;
            if Self::knows(&journal, &verified, next, &observed)? {
                return Ok(());
            }
            let (after, next) = self.head_window()?;
            if Self::knows(&journal, &after, next, &observed)? {
                return Ok(());
            }
        }
        self.lane_fallbacks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _driver = self.lane().await;
        // Under the driver nothing moves H; a pinned group whose reply was lost may still have
        // applied, so its `next` stays a known own head.
        let (verified, next) = self.head_window()?;
        let observed = journal
            .observe_owned_with(&verified, guards)
            .await
            .map_err(RuntimeError::from)?;
        if Self::knows(&journal, &verified, next, &observed)? {
            Ok(())
        } else {
            Err(RuntimeError::Authority)
        }
    }

    /// Under the `state` lock: the verified head, and the head the pinned in-flight group produces
    /// if it applies.
    fn head_window(&self) -> std::result::Result<(Arc<VerifiedHead>, Option<Head>), RuntimeError> {
        let state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
        if let Some(error) = state.failed {
            return Err(error);
        }
        let next = state
            .pending
            .front()
            .and_then(|front| front.attempt.as_ref())
            .map(|attempt| attempt.next);
        Ok((state.verified.clone(), next))
    }

    fn knows(
        journal: &StoreJournal<'_>,
        verified: &VerifiedHead,
        next: Option<Head>,
        observed: &Option<Secret<Vec<u8>>>,
    ) -> std::result::Result<bool, RuntimeError> {
        if journal
            .names_head(verified, observed)
            .map_err(RuntimeError::from)?
        {
            return Ok(true);
        }
        Ok(next.zip(observed.as_ref()).is_some_and(|(next, observed)| {
            next.encode().expose(&crate::seal::lend()) == observed.expose(&crate::seal::lend())
        }))
    }

    /// This owner's original at `carried.seq`, read lane-free by its computed ordinal and checked
    /// against the evidence this process carried from its append (SHUTDOWN-HANG F1 `record`): the
    /// WAL verifier and canonical encoding (`decode_record`), the sequence, and the chain hash.
    /// A different original at that place is `Corrupt`; a sequence not yet applied is `Pending`.
    pub(crate) async fn record(
        &self,
        carried: Carried,
    ) -> std::result::Result<Record, RuntimeError> {
        let verified = self.live_head()?;
        if carried.seq == 0 {
            return Err(RuntimeError::Invalid);
        }
        if carried.seq > verified.head.sequence {
            return Err(RuntimeError::Pending);
        }
        let ordinal = self.locate(&verified, carried.seq)?;
        let original = StoreJournal::new(&self.store, self.node)
            .map_err(RuntimeError::from)?
            .read_verified_record_at(&verified, carried.seq, ordinal)
            .await
            .map_err(RuntimeError::from)?;
        let decoded = decode_record(self.node, &original.body).map_err(RuntimeError::from)?;
        if decoded.node_seq != carried.seq || decoded.hash != carried.hash {
            return Err(RuntimeError::Corrupt);
        }
        Ok(original)
    }

    /// Test probe: confirmations that fell back to the publication driver.
    #[cfg(test)]
    pub(crate) fn lane_fallbacks(&self) -> u64 {
        self.lane_fallbacks
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn live_head(&self) -> std::result::Result<Arc<VerifiedHead>, RuntimeError> {
        let state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
        if let Some(error) = state.failed {
            return Err(error);
        }
        Ok(state.verified.clone())
    }

    fn staged_target(&self) -> std::result::Result<u64, RuntimeError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RuntimeError::Corrupt)?
            .next_ticket
            .saturating_sub(1))
    }

    /// The publication driver: the journal lane. Every append, every selection CAS and every
    /// confirmation that falls back to the driver holds it once (counted in tests, 8.3).
    async fn lane(&self) -> tokio::sync::MutexGuard<'_, ()> {
        let driver = self.driving.lock().await;
        #[cfg(test)]
        self.lane_holds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        driver
    }

    /// Test probe: how many times the journal lane was held (SHUTDOWN-HANG 8.3).
    #[cfg(test)]
    pub(crate) fn lane_holds(&self) -> u64 {
        self.lane_holds.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Test probe: whether the publication driver is free right now.
    #[cfg(test)]
    pub(crate) fn driver_is_free(&self) -> bool {
        self.driving.try_lock().is_ok()
    }

    /// Group commit: each pass appends every run already pending (bounded by the
    /// store limits) in one store append, so concurrent waiters share one round
    /// trip instead of queueing one append each behind the driver lock.
    async fn drive_through(&self, target: u64) -> std::result::Result<(), RuntimeError> {
        let driver = self.lane().await;
        self.drive_locked(&driver, target).await
    }

    async fn drive_locked(
        &self,
        _driver: &tokio::sync::MutexGuard<'_, ()>,
        target: u64,
    ) -> std::result::Result<(), RuntimeError> {
        let journal = StoreJournal::new(&self.store, self.node).map_err(RuntimeError::from)?;
        let limits = self.store.limits();
        loop {
            let (proof, group, head, records_seal) = {
                let mut state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
                if let Some(error) = state.failed {
                    return Err(error);
                }
                if state.completed >= target {
                    return Ok(());
                }
                Self::take_group(&mut state, limits, self.node)?
            };
            // Runs chain from `state.reserved` in ticket order, so the group's
            // records are one contiguous chain; the same pinned runs in order
            // always yield the same bytes, hence the same claim digest. Borrow
            // them rather than deep-copying every body on each pass or retry.
            let runs: Vec<&[Record]> = group.iter().map(|run| run.records()).collect();
            let submission = journal
                .append_runs(&proof, &runs)
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
                    // built from unchanged verified frame headers/digests before
                    // the first submit (`take_group`). The old full proof and
                    // native H/O CAS establish its ancestry.
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
                    // Live appends continue the chain contiguously (`checked_record` above); only
                    // the first frame of an empty journal opens the layout's first segment.
                    if state.seq_map.is_empty() {
                        if let Some(first) = runs.iter().copied().flatten().next() {
                            let ordinal = proof
                                .head
                                .count
                                .checked_add(1)
                                .ok_or(RuntimeError::Corrupt)?;
                            state.seq_map.push((ordinal, first.node_seq));
                        }
                    }
                    for run in &group {
                        let pending = state.pending.pop_front().ok_or(RuntimeError::Corrupt)?;
                        if !Arc::ptr_eq(&pending.run, run) {
                            return Err(self.fail(&mut state, RuntimeError::Corrupt));
                        }
                        state.completed = run.ticket;
                        state.records -= run.records.len();
                        state.bytes -= run.bytes;
                    }
                    state.verified = verified;
                    self.publish(&state);
                }
                super::super::commit::SubmitResult::Decided(_) => {
                    let mut state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
                    return Err(self.fail(&mut state, RuntimeError::Conflict));
                }
                super::super::commit::SubmitResult::NoEffect(error) => {
                    return Err(RuntimeError::Backend(error));
                }
                super::super::commit::SubmitResult::Reconcile => {
                    let mut state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
                    return Err(self.fail(&mut state, RuntimeError::Reconcile));
                }
                super::super::commit::SubmitResult::Uncertain
                | super::super::commit::SubmitResult::Busy => return Err(RuntimeError::Pending),
            }
        }
    }
}
