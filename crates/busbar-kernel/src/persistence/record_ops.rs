// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Retention of CoreStore conditional-commit receipts (`busbar.recordop1`, DES-264).
//!
//! A receipt may be deleted only once no holder of its op id can submit that op again. Class-M
//! op ids are minted here in **generations**: `op = gen8 ‖ counter8`, where `gen8` is drawn per
//! generation and its owner row (`busbar.recopgen1`, Absent-guarded at open) names the one
//! control writer that minted it. Every mint is a [`HeldOp`] that holds its generation; the
//! request carrying it, CoreStore's logical entry and any retained attempt hold clones. A
//! generation that is no longer current and whose last hold has dropped is *drained*: its
//! receipts are swept by one range delete guarded by its owner row. Holds are released only by
//! dropping them with their request, never explicitly.
//!
//! A process that dies leaves owner rows behind. They are swept by whoever finds them owned by
//! a writer whose control row is closed (`retired_through == admitted_through`), with the closed
//! bytes and the owner row as `Exact` predicates. Close and sweep are separate candidates.
//!
//! Principal-transition receipts are class D ([`DerivedOp`]): re-derived from a persisted plan,
//! kept under their own partition label so no generation's range delete can reach them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::{
    persistence::{
        control, Address, Candidate, Decision, ExpectedValue, Mutation, NamespaceId, Predicate,
        PreparedCandidate, Read, ReadResult, Scan, CANDIDATE_VERSION,
    },
    records::OpId,
    Secret,
};

use super::{
    commit::SubmitResult,
    facade::{AccessError, CoreStore, PendingId},
    host_records::RECORD_OPERATIONS,
    keys, partition,
};

/// Mints per generation before it retires. A code constant, chosen so one range delete covers
/// at most `2 × GEN_OPS` receipts (the hard stop); not a config key.
pub const GEN_OPS: u64 = 1024;

/// Owner rows of receipt generations: key `framed(b'G', [gen8])`, value the minting writer.
/// Fixed ASCII, core-private and not a control namespace.
pub(crate) const OWNERS: NamespaceId = NamespaceId(*b"busbar.recopgen1");

/// `keys::framed(b'R', [RECORD_OPERATIONS, op])`: 1 + 4 + 16 + 4 + 16.
pub(crate) const RECEIPT_KEY_LENGTH: u64 = 41;

/// Draws of a fresh gen8 before an open gives up (each redraw is a proven collision).
const OPEN_DRAWS: usize = 8;

/// The partition label of class-D receipts, apart from every generation's `[gen8]`.
const DERIVED_LABEL: &[u8] = b"d";

/// Generations whose last hold dropped, waiting for their sweep.
#[derive(Debug, Default)]
struct Drained(Mutex<Vec<[u8; 8]>>);

impl Drained {
    fn lock(&self) -> MutexGuard<'_, Vec<[u8; 8]>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// One generation of receipt identities. Dropped when it is no longer current and no hold is
/// left: that drop is the drain.
#[derive(Debug)]
pub struct Generation {
    gen8: [u8; 8],
    drained: Arc<Drained>,
}

impl Drop for Generation {
    fn drop(&mut self) {
        self.drained.lock().push(self.gen8);
    }
}

/// A class-M receipt identity and the hold on its generation. Released only by dropping it,
/// with the request that carries it.
#[derive(Debug, Clone)]
pub struct HeldOp {
    op: [u8; 16],
    generation: Arc<Generation>,
}

impl HeldOp {
    #[must_use]
    pub fn bytes(&self) -> [u8; 16] {
        self.op
    }

    /// The contract identity carried by a plugin `conditional::Request`: derived from this
    /// hold, never built from raw bytes.
    #[must_use]
    pub fn op_id(&self) -> OpId {
        OpId(self.op)
    }

    /// An identity in this hold's generation with a caller-derived tail (overlay chunk stages:
    /// `gen8 ‖ digest[..8]`). A tail equal to a counter id answers `OpIdConflict` (fails closed).
    #[must_use]
    pub(crate) fn with_tail(&self, tail: [u8; 8]) -> Self {
        let mut op = self.op;
        op[8..].copy_from_slice(&tail);
        Self {
            op,
            generation: self.generation.clone(),
        }
    }

    #[must_use]
    pub(crate) fn gen8(&self) -> [u8; 8] {
        self.generation.gen8
    }
}

/// A class-D receipt identity: re-derivable from a persisted principal-transition plan.
/// Constructed only by `principal_transition::operation` (tools/ci-checks `record-op-source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedOp([u8; 16]);

impl DerivedOp {
    pub(crate) fn principal_transition(op: [u8; 16]) -> Self {
        Self(op)
    }

    #[must_use]
    pub fn bytes(self) -> [u8; 16] {
        self.0
    }

    #[must_use]
    pub fn op_id(self) -> OpId {
        OpId(self.0)
    }
}

/// The identity of one receipt-writing request. Every recordop1 entry point takes one.
#[derive(Debug, Clone)]
pub enum Op {
    Held(HeldOp),
    Derived(DerivedOp),
}

impl From<HeldOp> for Op {
    fn from(held: HeldOp) -> Self {
        Self::Held(held)
    }
}

impl Op {
    #[must_use]
    pub fn bytes(&self) -> [u8; 16] {
        match self {
            Self::Held(held) => held.op,
            Self::Derived(derived) => derived.0,
        }
    }

    pub(crate) fn held(&self) -> Option<&HeldOp> {
        match self {
            Self::Held(held) => Some(held),
            Self::Derived(_) => None,
        }
    }

    /// The receipt's partition: the generation's for class M, the class-D label otherwise.
    pub(crate) fn receipt_namespace(&self) -> NamespaceId {
        match self {
            Self::Held(held) => receipts_namespace(held.gen8()),
            Self::Derived(derived) => {
                partition::namespace(RECORD_OPERATIONS, &[DERIVED_LABEL, &derived.0[..8]])
            }
        }
    }
}

/// The partition holding every receipt of generation `gen8`.
pub(crate) fn receipts_namespace(gen8: [u8; 8]) -> NamespaceId {
    partition::namespace(RECORD_OPERATIONS, &[&gen8])
}

/// `52 ‖ 00000010 ‖ "busbar.recordop1" ‖ 00000010 ‖ gen8`: 33 bytes, the receipt key's first
/// 33 bytes for every op of the generation.
pub(crate) fn receipts_prefix(gen8: [u8; 8]) -> Result<Vec<u8>, AccessError> {
    let mut prefix =
        keys::framed(b'R', &[&RECORD_OPERATIONS.0]).map_err(|_| AccessError::Overloaded)?;
    prefix.extend_from_slice(&16u32.to_be_bytes());
    prefix.extend_from_slice(&gen8);
    Ok(prefix)
}

pub(crate) fn owner_address(gen8: [u8; 8]) -> Result<Address, AccessError> {
    Ok(Address {
        namespace: OWNERS.0,
        key: keys::framed(b'G', &[&gen8]).map_err(|_| AccessError::Overloaded)?,
    })
}

fn owner_gen8(key: &[u8]) -> Option<[u8; 8]> {
    match keys::components(key, b'G').ok()?.as_slice() {
        [gen8] => (*gen8).try_into().ok(),
        _ => None,
    }
}

/// The range delete of a generation's receipts and the delete of its owner row.
fn sweep_mutations(gen8: [u8; 8]) -> Result<Vec<Mutation>, AccessError> {
    Ok(vec![
        Mutation::DeleteRange {
            namespace: receipts_namespace(gen8),
            prefix: receipts_prefix(gen8)?,
            exact_key_length: RECEIPT_KEY_LENGTH,
        },
        Mutation::Delete(owner_address(gen8)?),
    ])
}

#[derive(Debug, Default)]
struct Minting {
    current: Option<Arc<Generation>>,
    /// Mints so far in `current`.
    minted: u64,
    next: Option<Arc<Generation>>,
}

impl Minting {
    fn needs_open(&self) -> bool {
        self.current.is_none() || (self.next.is_none() && self.minted >= GEN_OPS / 2)
    }
}

/// The open in flight: its drawn gen8 and its exact retained candidate.
type Retained = ([u8; 8], PreparedCandidate);

#[derive(Default)]
struct Sweeps {
    /// Sweeps whose outcome is not decided yet, retried with their exact candidate.
    retained: Vec<([u8; 8], PreparedCandidate, bool)>,
    /// Owner-row paging cursor (in memory; restarts from the beginning after a restart).
    cursor: Option<Vec<u8>>,
}

/// One CoreStore's receipt-identity minter and its sweep custody.
#[derive(Default)]
pub(crate) struct RecordOps {
    minting: Mutex<Minting>,
    drained: Arc<Drained>,
    opening: tokio::sync::Mutex<Option<Retained>>,
    sweeps: tokio::sync::Mutex<Sweeps>,
}

impl std::fmt::Debug for RecordOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordOps").finish_non_exhaustive()
    }
}

impl RecordOps {
    fn minting(&self) -> MutexGuard<'_, Minting> {
        self.minting.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// One mint, or `None` when no generation can take it (none open yet, or the hard stop).
    fn try_mint(&self) -> Option<HeldOp> {
        let mut minting = self.minting();
        if minting.minted >= GEN_OPS {
            if let Some(next) = minting.next.take() {
                // The retiring generation drains once its last hold drops.
                minting.current = Some(next);
                minting.minted = 0;
            }
        }
        let current = minting.current.clone()?;
        if minting.minted >= 2 * GEN_OPS {
            return None;
        }
        minting.minted += 1;
        let mut op = [0; 16];
        op[..8].copy_from_slice(&current.gen8);
        op[8..].copy_from_slice(&minting.minted.to_be_bytes());
        Some(HeldOp {
            op,
            generation: current,
        })
    }

    fn take_drained(&self) -> Vec<[u8; 8]> {
        std::mem::take(&mut *self.drained.lock())
    }

    fn requeue(&self, gen8: [u8; 8]) {
        self.drained.lock().push(gen8);
    }
}

/// What one maintenance pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RecordOpsPass {
    pub opened: bool,
    /// Generations swept (this writer's drained ones and closed writers' found by owner row).
    pub swept: usize,
    /// Sweeps still undecided and retained.
    pub retained: usize,
}

enum Settled {
    Done,
    Retain,
    Again,
}

fn settled(result: &SubmitResult) -> Settled {
    match result {
        SubmitResult::Decided(decision) => match decision.as_ref() {
            // ConditionConflict: another node swept it, or the owner row moved on.
            Decision::Applied(_) | Decision::ConditionConflict => Settled::Done,
            // This writer is fenced: the crash sweep of whoever closed it takes over.
            Decision::Fenced | Decision::Stale => Settled::Done,
            Decision::OpIdConflict | Decision::TimeGuardFailed { .. } => Settled::Done,
        },
        SubmitResult::NoEffect(_) => Settled::Again,
        SubmitResult::Uncertain | SubmitResult::Reconcile | SubmitResult::Busy => Settled::Retain,
    }
}

impl CoreStore {
    /// A class-M receipt identity. Waits for the next generation's open at the hard stop
    /// (`2 × GEN_OPS` mints in one generation); `Overloaded` if that open is not decided.
    pub async fn record_op(&self) -> Result<HeldOp, AccessError> {
        loop {
            if let Some(held) = self.record_ops.try_mint() {
                return Ok(held);
            }
            self.open_record_generation().await?;
        }
    }

    /// [`CoreStore::record_op`] for a synchronous admission path: `Overloaded` instead of
    /// waiting when no generation can take the mint.
    pub fn try_record_op(&self) -> Result<HeldOp, AccessError> {
        self.record_ops.try_mint().ok_or(AccessError::Overloaded)
    }

    /// Open the first generation (Startup, before it reports Admitted) or the next one (in the
    /// background once the current one is half used). One raw commit: `Absent` on the owner
    /// row, Put this writer. A ConditionConflict is a gen8 collision and draws again.
    pub async fn open_record_generation(&self) -> Result<bool, AccessError> {
        let mut opening = self.record_ops.opening.lock().await;
        if !self.record_ops.minting().needs_open() {
            return Ok(false);
        }
        let writer = self.authority()?.writer;
        for _ in 0..OPEN_DRAWS {
            let (gen8, submission) = match opening.clone() {
                Some((gen8, candidate)) => {
                    let id = PendingId(candidate.candidate().id.operation);
                    match self.retry(id).await {
                        Ok(submission) => (gen8, submission),
                        // Collected by another driver: draw again. An owner row it may have
                        // written names this writer and an empty partition; the crash sweep
                        // removes it once this writer is closed.
                        Err(AccessError::UnknownOperation) => {
                            *opening = None;
                            continue;
                        }
                        // Still retained: the next open retries it.
                        Err(error) => return Err(error),
                    }
                }
                None => {
                    let mut gen8 = [0; 8];
                    busbar_contract::crypto::fill(&mut gen8).map_err(|_| AccessError::Entropy)?;
                    let candidate = PreparedCandidate::new(Candidate {
                        id: self.next_id()?,
                        codec: CANDIDATE_VERSION,
                        predicates: vec![Predicate {
                            address: owner_address(gen8)?,
                            expected: ExpectedValue::Absent,
                        }],
                        mutations: vec![Mutation::Put {
                            address: owner_address(gen8)?,
                            value: Secret::new(writer.to_vec()),
                        }],
                        time: None,
                        result: Secret::new(vec![]),
                    })
                    .map_err(|_| AccessError::Corrupt)?;
                    *opening = Some((gen8, candidate.clone()));
                    match self.submit(candidate).await {
                        Ok(submission) => (gen8, submission),
                        Err(error) => {
                            // Nothing crossed: drop the draw.
                            *opening = None;
                            return Err(error);
                        }
                    }
                }
            };
            match submission.result {
                SubmitResult::Decided(decision) => {
                    *opening = None;
                    match decision.as_ref() {
                        Decision::Applied(_) => {
                            let generation = Arc::new(Generation {
                                gen8,
                                drained: self.record_ops.drained.clone(),
                            });
                            let mut minting = self.record_ops.minting();
                            if minting.current.is_none() {
                                minting.current = Some(generation);
                                minting.minted = 0;
                            } else {
                                minting.next = Some(generation);
                            }
                            return Ok(true);
                        }
                        Decision::ConditionConflict => continue,
                        Decision::Fenced | Decision::Stale => return Err(AccessError::Authority),
                        Decision::OpIdConflict | Decision::TimeGuardFailed { .. } => {
                            return Err(AccessError::Corrupt)
                        }
                    }
                }
                SubmitResult::NoEffect(failure) => {
                    *opening = None;
                    return Err(AccessError::Backend(failure));
                }
                SubmitResult::Uncertain | SubmitResult::Reconcile | SubmitResult::Busy => {
                    // Retained: the next open retries the exact candidate.
                    return Err(AccessError::Overloaded);
                }
            }
        }
        Err(AccessError::Entropy)
    }

    /// The background step (one settle tick): open the next generation when the current one is
    /// half used, sweep this writer's drained generations, and read one owner-row page for
    /// closed writers' generations.
    pub async fn maintain_record_ops(&self) -> Result<RecordOpsPass, AccessError> {
        let mut pass = RecordOpsPass::default();
        if self.record_ops.minting().needs_open() {
            pass.opened = self.open_record_generation().await?;
        }
        pass.swept += self.sweep_drained().await?;
        let page = self.limits().scan_items;
        let (swept, retained) = self.sweep_owner_rows(page).await?;
        pass.swept += swept;
        pass.retained = retained;
        Ok(pass)
    }

    /// Sweep every drained generation of this writer: `Exact(owner row = own writer)`, then
    /// the range delete and the owner-row delete. A generation not decided stays queued.
    async fn sweep_drained(&self) -> Result<usize, AccessError> {
        let mut drained = self.record_ops.take_drained().into_iter();
        let mut swept = 0;
        let mut sweeps = self.record_ops.sweeps.lock().await;
        let result = async {
            let writer = self.authority()?.writer;
            for gen8 in drained.by_ref() {
                let predicates = vec![Predicate {
                    address: owner_address(gen8)?,
                    expected: ExpectedValue::Exact(Secret::new(writer.to_vec())),
                }];
                swept += self
                    .submit_sweep(&mut sweeps, gen8, predicates, true)
                    .await?;
            }
            Ok::<(), AccessError>(())
        }
        .await;
        for gen8 in drained {
            self.record_ops.requeue(gen8);
        }
        result.map(|()| swept)
    }

    /// Submit one sweep. Returns 1 if it was decided. An undecided sweep is retained with its
    /// exact candidate; one with no effect is queued again if it is this writer's (`own`), and
    /// otherwise found again by the owner-row paging.
    async fn submit_sweep(
        &self,
        sweeps: &mut Sweeps,
        gen8: [u8; 8],
        predicates: Vec<Predicate>,
        own: bool,
    ) -> Result<usize, AccessError> {
        let requeue = |gen8| {
            if own {
                self.record_ops.requeue(gen8);
            }
        };
        let candidate = PreparedCandidate::new(Candidate {
            id: self.next_id()?,
            codec: CANDIDATE_VERSION,
            predicates,
            mutations: sweep_mutations(gen8)?,
            time: None,
            result: Secret::new(vec![]),
        })
        .map_err(|_| AccessError::Corrupt)?;
        let submission = match self.submit(candidate.clone()).await {
            Ok(submission) => submission,
            Err(error) => {
                requeue(gen8);
                return Err(error);
            }
        };
        Ok(match settled(&submission.result) {
            Settled::Done => 1,
            Settled::Retain => {
                sweeps.retained.push((gen8, candidate, own));
                0
            }
            Settled::Again => {
                requeue(gen8);
                0
            }
        })
    }

    async fn retry_sweeps(&self, sweeps: &mut Sweeps) -> usize {
        let mut swept = 0;
        for (gen8, candidate, own) in std::mem::take(&mut sweeps.retained) {
            match self
                .retry(PendingId(candidate.candidate().id.operation))
                .await
            {
                Ok(submission) => match settled(&submission.result) {
                    Settled::Done => swept += 1,
                    Settled::Retain => sweeps.retained.push((gen8, candidate, own)),
                    Settled::Again if own => self.record_ops.requeue(gen8),
                    Settled::Again => {}
                },
                // Collected by another driver: a fresh sweep is idempotent (owner row Exact).
                Err(AccessError::UnknownOperation) if own => self.record_ops.requeue(gen8),
                Err(AccessError::UnknownOperation) => {}
                Err(_) => sweeps.retained.push((gen8, candidate, own)),
            }
        }
        swept
    }

    /// The crash sweep, driven by owner rows: read at most `budget` owner rows from the
    /// in-memory cursor (wrapping at the end); for each owned by another writer whose control
    /// row is closed, sweep its generation under `Exact` on the closed bytes and on the owner
    /// row. Returns (generations swept, sweeps still retained).
    pub(crate) async fn sweep_owner_rows(
        &self,
        budget: usize,
    ) -> Result<(usize, usize), AccessError> {
        let own = self.authority()?.writer;
        let mut sweeps = self.record_ops.sweeps.lock().await;
        let mut swept = self.retry_sweeps(&mut sweeps).await;
        let mut read = 0;
        let mut closed: BTreeMap<[u8; 16], Option<Secret<Vec<u8>>>> = BTreeMap::new();
        while read < budget {
            let page = self
                .backend()
                .scan(Arc::new(Scan {
                    dataset: self.info().dataset,
                    namespace: OWNERS,
                    prefix: vec![b'G'],
                    after: sweeps.cursor.clone(),
                    generation: None,
                    allow_change: true,
                    max_items: (budget - read).min(self.limits().scan_items),
                    max_bytes: self.limits().scan_bytes,
                }))
                .await
                .map_err(AccessError::Backend)?;
            read += page.rows.len().max(1);
            sweeps.cursor = page.next.clone();
            // Decode the page first: no seal is held across a crossing.
            let foreign: Vec<_> = {
                let seal = crate::seal::lend();
                page.rows
                    .into_iter()
                    .filter_map(|(at, value)| {
                        let gen8 = owner_gen8(&at.key)?;
                        let writer = <[u8; 16]>::try_from(value.expose(&seal).as_slice()).ok()?;
                        (writer != own).then_some((gen8, writer, at, value))
                    })
                    .collect()
            };
            for (gen8, writer, at, value) in foreign {
                if !closed.contains_key(&writer) {
                    let row = self.closed_writer_row(writer).await?;
                    closed.insert(writer, row);
                }
                let Some(Some(control_row)) = closed.get(&writer) else {
                    continue;
                };
                let predicates = vec![
                    Predicate {
                        address: Address {
                            namespace: control::NAMESPACE.0,
                            key: control::writer_key(writer).to_vec(),
                        },
                        expected: ExpectedValue::Exact(control_row.clone()),
                    },
                    Predicate {
                        address: at.clone(),
                        expected: ExpectedValue::Exact(value.clone()),
                    },
                ];
                swept += self
                    .submit_sweep(&mut sweeps, gen8, predicates, false)
                    .await?;
            }
            if page.next.is_none() {
                break;
            }
        }
        Ok((swept, sweeps.retained.len()))
    }

    /// The writer's control row bytes if it decodes and is closed; `None` otherwise.
    async fn closed_writer_row(
        &self,
        writer: [u8; 16],
    ) -> Result<Option<Secret<Vec<u8>>>, AccessError> {
        let observed = self
            .backend()
            .read(Arc::new(Read {
                dataset: self.info().dataset,
                addresses: vec![Address {
                    namespace: control::NAMESPACE.0,
                    key: control::writer_key(writer).to_vec(),
                }],
                time: None,
            }))
            .await
            .map_err(AccessError::Backend)?;
        let ReadResult::Values {
            observed_at,
            mut values,
        } = observed
        else {
            return Err(AccessError::Corrupt);
        };
        if observed_at.authority != self.info().clock_authority || values.len() != 1 {
            return Err(AccessError::Corrupt);
        }
        let Some(row) = values.pop().flatten() else {
            return Ok(None);
        };
        let closed = control::Writer::decode(row.expose(&crate::seal::lend()))
            .is_some_and(|writer| writer.live().is_empty());
        Ok(closed.then_some(row))
    }

    /// Test seam: the current generation has already minted `minted` ids.
    #[cfg(test)]
    pub(crate) fn seed_record_ops(&self, minted: u64) {
        self.record_ops.minting().minted = minted;
    }

    /// Test seam: the gen8 of the current and next generations.
    #[cfg(test)]
    pub(crate) fn record_generations(&self) -> (Option<[u8; 8]>, Option<[u8; 8]>) {
        let minting = self.record_ops.minting();
        (
            minting.current.as_ref().map(|g| g.gen8),
            minting.next.as_ref().map(|g| g.gen8),
        )
    }
}
