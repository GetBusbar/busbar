// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conditional originals never enter the ordinary staged queue. The owner
//! retains the candidate and successor barrier until both native resolution
//! and the caller's canonical publication are complete.

use super::*;
use crate::persistence::{commit::SubmitResult, scoped};
use busbar_contract::persistence::Decision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalOutcome {
    Applied,
    Conflict,
    NoEffect(Failure),
}

struct Prepared {
    original: Arc<Record>,
    candidate: PreparedCandidate,
    proof: Arc<VerifiedHead>,
    next: Head,
    records_seal: [u8; 32],
    bytes: usize,
}

pub(super) struct Slot {
    token: Arc<()>,
    target: u64,
    prepared: Option<Arc<Prepared>>,
    outcome: Option<ConditionalOutcome>,
}

/// Root-owned conditional sealing capability. Before preparation, dropping it
/// abandons only an unsubmitted reservation. After preparation, dropping any
/// waiter leaves the original and barrier with RuntimeJournal. Root maintenance
/// reattaches with `retained_conditional`; this is not a restart intent log.
pub struct ConditionalAppend {
    owner: Arc<RuntimeJournal>,
    token: Arc<()>,
}

impl RuntimeJournal {
    /// Close successor sealing synchronously before any predecessor drain.
    /// Root must also exclude its own canonical linking/publication while this
    /// capability exists. No provisional StagedRun is exposed.
    pub fn reserve_conditional(
        self: &Arc<Self>,
    ) -> std::result::Result<ConditionalAppend, RuntimeError> {
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
        let token = Arc::new(());
        state.conditional = Some(Slot {
            token: token.clone(),
            target: state.next_ticket.saturating_sub(1),
            prepared: None,
            outcome: None,
        });
        self.mark(&state);
        Ok(ConditionalAppend {
            owner: self.clone(),
            token,
        })
    }

    /// Recover owner custody after a canceled waiter. A still-unprepared
    /// reservation belongs to its original caller and is never handed out.
    pub fn retained_conditional(
        self: &Arc<Self>,
    ) -> std::result::Result<Option<ConditionalAppend>, RuntimeError> {
        let state = self.state.lock().map_err(|_| RuntimeError::Corrupt)?;
        Ok(state.conditional.as_ref().and_then(|slot| {
            slot.prepared.as_ref().map(|_| ConditionalAppend {
                owner: self.clone(),
                token: slot.token.clone(),
            })
        }))
    }
}

impl ConditionalAppend {
    fn slot<'a>(&self, state: &'a State) -> std::result::Result<&'a Slot, RuntimeError> {
        state
            .conditional
            .as_ref()
            .filter(|slot| Arc::ptr_eq(&slot.token, &self.token))
            .ok_or(RuntimeError::Authority)
    }

    fn prepared(&self) -> std::result::Result<Arc<Prepared>, RuntimeError> {
        let state = self.owner.state.lock().map_err(|_| RuntimeError::Corrupt)?;
        self.slot(&state)?
            .prepared
            .clone()
            .ok_or(RuntimeError::Invalid)
    }

    /// Drain prior originals, then seal a private conditional original and its
    /// authorized participant. The closure can encode the selected original's
    /// node/sequence/hash into a receipt. Nothing is submitted by this method.
    pub async fn prepare(
        &self,
        entry: Entry,
        compose: impl FnOnce(&Record) -> std::result::Result<scoped::PreparedRows, scoped::Error>,
    ) -> std::result::Result<(), RuntimeError> {
        let original_bytes = entry
            .body
            .len()
            .checked_add(busbar_kernel_wal::journal::JOURNAL_HEADER_BYTES)
            .ok_or(RuntimeError::Budget)?;
        if original_bytes > self.owner.budget.bytes
            || original_bytes > self.owner.store.limits().scan_bytes
        {
            return Err(RuntimeError::Budget);
        }
        let driver = self.owner.lane().await;
        let target = {
            let state = self.owner.state.lock().map_err(|_| RuntimeError::Corrupt)?;
            let slot = self.slot(&state)?;
            if slot.prepared.is_some() {
                return Err(RuntimeError::Pending);
            }
            slot.target
        };
        self.owner.drive_locked(&driver, target).await?;
        let proof = self.owner.live_head()?;
        let journal =
            StoreJournal::new(&self.owner.store, self.owner.node).map_err(RuntimeError::from)?;
        journal
            .confirm_owned(&proof)
            .await
            .map_err(RuntimeError::from)?;
        let original = Arc::new(
            super::super::recovery_hooks::seal_record(self.owner.node, proof.head, entry)
                .map_err(RuntimeError::from)?,
        );
        let decoded = checked_record(self.owner.node, &original.body, proof.head)
            .map_err(RuntimeError::from)?;
        let next = advance(proof.head, &decoded).map_err(RuntimeError::from)?;
        let rows = compose(&original).map_err(|error| match error {
            scoped::Error::Unauthorized => RuntimeError::Authority,
            scoped::Error::Access(error) => RuntimeError::from(Error::Access(error)),
            _ => RuntimeError::Invalid,
        })?;
        let candidate = journal
            .prepare_append(
                &proof,
                &[std::slice::from_ref(original.as_ref())],
                Some(rows),
            )
            .map_err(RuntimeError::from)?;
        let bytes = retained_bytes(&candidate, original.body.len())?;
        if bytes > self.owner.budget.bytes
            || original.body.len() > self.owner.store.limits().scan_bytes
        {
            return Err(RuntimeError::Budget);
        }
        let prepared = Arc::new(Prepared {
            records_seal: super::super::extend_records_seal(proof.records_seal, &original.body),
            original,
            candidate,
            proof,
            next,
            bytes,
        });
        let mut state = self.owner.state.lock().map_err(|_| RuntimeError::Corrupt)?;
        self.slot(&state)?;
        let slot = state.conditional.as_mut().ok_or(RuntimeError::Corrupt)?;
        slot.prepared = Some(prepared);
        state.records += 1;
        state.bytes += bytes;
        self.owner.mark(&state);
        Ok(())
    }

    /// Exact private original for root's canonical publication/reconciliation.
    /// Its presence is not an Applied claim; call drive to resolve that fact.
    pub fn original(&self) -> std::result::Result<Arc<Record>, RuntimeError> {
        Ok(self.prepared()?.original.clone())
    }

    /// Resolve the retained original. The publication driver serializes callers;
    /// its logical claim retains the exact native attempt if this future drops.
    /// Neither a decided CAS loss nor a known no-effect poisons ordinary runs.
    pub async fn drive(&self) -> std::result::Result<ConditionalOutcome, RuntimeError> {
        let _driver = self.owner.lane().await;
        let prepared = self.prepared()?;
        {
            let state = self.owner.state.lock().map_err(|_| RuntimeError::Corrupt)?;
            if let Some(error) = state.failed {
                return Err(error);
            }
            if let Some(outcome) = self.slot(&state)?.outcome {
                return Ok(outcome);
            }
        }
        let journal =
            StoreJournal::new(&self.owner.store, self.owner.node).map_err(RuntimeError::from)?;
        let mut operation = [0; 16];
        operation[..8].copy_from_slice(&self.owner.node.to_be_bytes());
        let claim = self
            .owner
            .store
            .claim_logical(
                LogicalId {
                    namespace: journal.namespace.0,
                    operation,
                },
                prepared.candidate.fingerprint(),
            )
            .map_err(|error| RuntimeError::from(Error::Access(error)))?;
        let submission = match claim {
            LogicalClaim::Prepare(permit) => permit.submit(prepared.candidate.clone()).await,
            LogicalClaim::Retained(id) => self.owner.store.retry(id).await,
            LogicalClaim::Busy => return Err(RuntimeError::Pending),
        }
        .map_err(|error| RuntimeError::from(Error::Access(error)))?;
        let outcome = match submission.result {
            SubmitResult::Decided(decision) => match &*decision {
                Decision::Applied(_) => ConditionalOutcome::Applied,
                Decision::ConditionConflict => ConditionalOutcome::Conflict,
                Decision::Fenced | Decision::Stale => {
                    let mut state = self.owner.state.lock().map_err(|_| RuntimeError::Corrupt)?;
                    return Err(self.owner.fail(&mut state, RuntimeError::Authority));
                }
                _ => {
                    let mut state = self.owner.state.lock().map_err(|_| RuntimeError::Corrupt)?;
                    return Err(self.owner.fail(&mut state, RuntimeError::Corrupt));
                }
            },
            SubmitResult::NoEffect(error) => ConditionalOutcome::NoEffect(error),
            SubmitResult::Uncertain | SubmitResult::Busy => return Err(RuntimeError::Pending),
            SubmitResult::Reconcile => return Err(RuntimeError::Reconcile),
        };
        let mut state = self.owner.state.lock().map_err(|_| RuntimeError::Corrupt)?;
        self.slot(&state)?;
        if outcome == ConditionalOutcome::Applied {
            let id = prepared.candidate.candidate().id;
            if state.seq_map.is_empty() {
                state
                    .seq_map
                    .push((prepared.proof.head.count + 1, prepared.original.node_seq));
            }
            state.verified = Arc::new(VerifiedHead {
                dataset: prepared.proof.dataset,
                node: prepared.proof.node,
                head: prepared.next,
                records_seal: prepared.records_seal,
                selected: Some(prepared.next.encode()),
                owner: Some(owner_bytes(WriterAuthority {
                    writer_epoch: id.writer_epoch,
                    writer: id.writer,
                    execution_epoch: id.execution_epoch,
                })),
            });
            state.reserved = prepared.next;
        }
        state
            .conditional
            .as_mut()
            .ok_or(RuntimeError::Corrupt)?
            .outcome = Some(outcome);
        self.owner.publish(&state);
        Ok(outcome)
    }

    /// Root calls only after installing an Applied canonical result, or after
    /// validating the receipt/head for a known loser. Recheck local native head
    /// custody before admitting successors. Unknown cannot release the barrier.
    pub async fn finish(self) -> std::result::Result<(), RuntimeError> {
        let _driver = self.owner.lane().await;
        let prepared = self.prepared()?;
        {
            let state = self.owner.state.lock().map_err(|_| RuntimeError::Corrupt)?;
            if self.slot(&state)?.outcome.is_none() {
                return Err(RuntimeError::Pending);
            }
        }
        let proof = self.owner.live_head()?;
        StoreJournal::new(&self.owner.store, self.owner.node)
            .map_err(RuntimeError::from)?
            .confirm_owned(&proof)
            .await
            .map_err(RuntimeError::from)?;
        let mut state = self.owner.state.lock().map_err(|_| RuntimeError::Corrupt)?;
        self.slot(&state)?;
        state.conditional = None;
        state.records -= 1;
        state.bytes -= prepared.bytes;
        self.owner.publish(&state);
        Ok(())
    }
}

impl Drop for ConditionalAppend {
    fn drop(&mut self) {
        if let Ok(mut state) = self.owner.state.lock() {
            if self.slot(&state).is_ok_and(|slot| slot.prepared.is_none()) {
                state.conditional = None;
                self.owner.publish(&state);
            }
        }
    }
}

fn retained_bytes(
    candidate: &PreparedCandidate,
    mut bytes: usize,
) -> std::result::Result<usize, RuntimeError> {
    let seal = crate::seal::lend();
    let mut charge = |amount: usize| -> std::result::Result<(), RuntimeError> {
        bytes = bytes.checked_add(amount).ok_or(RuntimeError::Budget)?;
        Ok(())
    };
    for row in &candidate.candidate().predicates {
        charge(std::mem::size_of::<Predicate>())?;
        charge(row.address.key.len())?;
        if let ExpectedValue::Exact(value) = &row.expected {
            charge(value.expose(&seal).len())?;
        }
    }
    for row in &candidate.candidate().mutations {
        charge(std::mem::size_of::<Mutation>())?;
        match row {
            Mutation::Put { address, value } => {
                charge(address.key.len())?;
                charge(value.expose(&seal).len())?;
            }
            Mutation::Delete(address) => charge(address.key.len())?,
            Mutation::DeleteRange { prefix, .. } => charge(prefix.len())?,
        }
    }
    Ok(bytes)
}
