// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::super::boot_identity::WriterRetirement;
use super::*;
use std::collections::VecDeque;

#[derive(Default)]
pub(super) struct ScanState {
    cursor: Option<scoped::Cursor>,
    intents: bool,
    keys: VecDeque<Vec<u8>>,
    page_end: bool,
    pending: Option<Recovery>,
}
struct Recovery {
    key: Vec<u8>,
    header: codec::Header,
    pending: Secret<Vec<u8>>,
    intent: Secret<Vec<u8>>,
    candidate: Option<PreparedCandidate>,
}

impl CallerIntents {
    fn cancellation(
        &self,
        key: &[u8],
        header: &codec::Header,
        pending: &Secret<Vec<u8>>,
        intent: &Secret<Vec<u8>>,
        guards: Vec<Predicate>,
    ) -> Result<PreparedCandidate, Error> {
        let terminal = codec::seal_guard(self, key, header, codec::Phase::NoEffect)?;
        let no_effect = codec::seal_terminal(self, key, header, codec::Phase::NoEffect)?;
        let rows = self
            .scoped
            .prepare_participant(
                &scoped::Request {
                    op_id: header.origin.operation,
                    predicates: vec![
                        predicate(GUARD, key, Some(pending)),
                        predicate(INTENT, key, Some(intent)),
                    ],
                    mutations: vec![put(GUARD, key, &terminal), put(INTENT, key, &no_effect)],
                },
                self.store.limits().scan_bytes,
            )
            .map_err(|_| Error::Budget)?;
        let (mut predicates, mutations) =
            rows.into_parts(&self.store).map_err(|_| Error::Authority)?;
        predicates.extend(guards);
        PreparedCandidate::new(Candidate {
            id: self.store.next_id().map_err(|_| Error::Authority)?,
            codec: CANDIDATE_VERSION,
            predicates,
            mutations,
            time: None,
            result: Secret::default(),
        })
        .map_err(|_| Error::Invalid)
    }

    pub(super) async fn cancel_local(
        &self,
        operation: &Operation,
        prepared: &Prepared,
    ) -> Result<Outcome, Error> {
        let current = self.classify(prepared).await?;
        if current != Outcome::Pending {
            return self.finish(operation, current);
        }
        let candidate = {
            let mut held = operation.state.lock().map_err(|_| Error::Corrupt)?;
            if held.cancel.is_none() {
                held.cancel = Some(self.cancellation(
                    &prepared.key,
                    &prepared.header,
                    &prepared.pending,
                    &prepared.intent,
                    vec![],
                )?);
            }
            held.cancel.clone().ok_or(Error::Corrupt)?
        };
        match self.submit(&candidate).await? {
            SubmitResult::Decided(decision)
                if matches!(
                    *decision,
                    Decision::Applied(_) | Decision::ConditionConflict
                ) =>
            {
                self.finish(operation, self.classify(prepared).await?)
            }
            SubmitResult::NoEffect(_) | SubmitResult::Uncertain | SubmitResult::Busy => {
                Ok(Outcome::Pending)
            }
            _ => Ok(Outcome::Reconcile),
        }
    }

    /// One page, under the same retained cursor across cancellation. Every
    /// serving lookup still checks its key; a completed scan is not a global
    /// lock over healthy replicas. Both schemas are enumerated, including
    /// terminal NoEffect slots with no grant row.
    pub(crate) async fn recover_page(&self) -> Result<bool, Error> {
        let result = self.recover_inner().await;
        if result.is_err() {
            self.state.lock().map_err(|_| Error::Corrupt)?.ready = false;
        }
        result
    }

    async fn recover_inner(&self) -> Result<bool, Error> {
        let mut scan = self.recovery.lock().await;
        if scan.pending.is_none() && scan.keys.is_empty() && !scan.page_end {
            let schema = if scan.intents { INTENT } else { GUARD };
            let page = match self.scoped.scan(schema, b"", scan.cursor.as_ref()).await {
                Ok(page) => page,
                Err(scoped::Error::Backend(busbar_contract::persistence::Failure::StaleScan)) => {
                    scan.cursor = None;
                    scan.intents = false;
                    return Ok(false);
                }
                Err(_) => return Err(Error::Unavailable),
            };
            scan.keys = page.rows.into_iter().map(|(key, _)| key).collect();
            scan.page_end = page.next.is_none();
            scan.cursor = page.next;
        }
        for _ in 0..self.store.limits().scan_items {
            if scan.pending.is_none() {
                let Some(key) = scan.keys.front() else { break };
                let observed = self.observe(key).await?;
                match observed.slot {
                    Some((header, codec::Phase::Pending)) => {
                        if header.origin.writer
                            == self.store.authority().map_err(|_| Error::Authority)?.writer
                        {
                            // This attachment's local map owns any active work.
                            scan.keys.pop_front();
                            continue;
                        }
                        scan.pending = Some(Recovery {
                            key: key.clone(),
                            header,
                            pending: observed.guard.ok_or(Error::Corrupt)?,
                            intent: observed.intent.ok_or(Error::Corrupt)?,
                            candidate: None,
                        });
                    }
                    Some(_) => {
                        scan.keys.pop_front();
                        continue;
                    }
                    None => return Err(Error::Corrupt),
                }
            }
            let pending = scan.pending.as_mut().ok_or(Error::Corrupt)?;
            if !self.recover_one(pending).await? {
                return Ok(false);
            }
            scan.pending = None;
            scan.keys.pop_front();
        }
        if scan.pending.is_some() || !scan.keys.is_empty() || !scan.page_end {
            return Ok(false);
        }
        scan.cursor = None;
        scan.page_end = false;
        if !scan.intents {
            scan.intents = true;
            return Ok(false);
        }
        scan.intents = false;
        self.state.lock().map_err(|_| Error::Corrupt)?.ready = true;
        Ok(true)
    }

    // true permits scanning the next key, including a live foreign writer. Its
    // Pending row still denies this key; readiness never manufactures a lease.
    async fn recover_one(&self, recovery: &mut Recovery) -> Result<bool, Error> {
        let observed = self.observe(&recovery.key).await?;
        let Some((header, phase)) = observed.slot else {
            return Err(Error::Corrupt);
        };
        if header != recovery.header || phase != codec::Phase::Pending {
            return Ok(true);
        }
        if observed.guard.as_ref() != Some(&recovery.pending)
            || observed.intent.as_ref() != Some(&recovery.intent)
        {
            return Err(Error::Corrupt);
        }
        if recovery.candidate.is_none() {
            let retired = self
                .retirements
                .retire_after(
                    &self.store,
                    header.origin.writer_epoch,
                    header.origin.writer,
                    0,
                    None,
                )
                .await
                .map_err(|_| Error::Unavailable)?;
            let guards = match retired {
                WriterRetirement::Live { .. } => return Ok(true),
                WriterRetirement::Pending => return Ok(false),
                WriterRetirement::Retired(guards) => guards,
            };
            recovery.candidate = Some(self.cancellation(
                &recovery.key,
                &header,
                &recovery.pending,
                &recovery.intent,
                guards,
            )?);
        }
        let candidate = recovery.candidate.as_ref().ok_or(Error::Corrupt)?;
        match self.submit(candidate).await? {
            SubmitResult::Decided(decision)
                if matches!(
                    *decision,
                    Decision::Applied(_) | Decision::ConditionConflict
                ) =>
            {
                let current = self.observe(&recovery.key).await?;
                let settled = current
                    .slot
                    .is_some_and(|(h, p)| h != recovery.header || p != codec::Phase::Pending);
                if !settled && matches!(*decision, Decision::ConditionConflict) {
                    // Only a definite failed R may obtain a new retirement
                    // observation. Unknown R always retains its exact bytes.
                    recovery.candidate = None;
                }
                Ok(settled)
            }
            SubmitResult::NoEffect(_) | SubmitResult::Uncertain | SubmitResult::Busy => Ok(false),
            _ => Err(Error::Authority),
        }
    }

    /// Root supervises this bounded pass. It returns remaining local custody,
    /// not grants/permits. No spawned task or caller is required for progress.
    pub(crate) async fn maintain(&self, limit: usize) -> Result<usize, Error> {
        self.domain
            .settle(limit.min(self.store.limits().pending_operations))
            .await
            .map_err(|_| Error::Unavailable)?;
        let operations = {
            let state = self.state.lock().map_err(|_| Error::Corrupt)?;
            state
                .operations
                .values()
                .filter(|op| op.foreground.strong_count() == 0)
                .take(limit.min(self.store.limits().pending_operations))
                .cloned()
                .collect::<Vec<_>>()
        };
        for operation in operations {
            let outcome = self.drive(&operation, true).await?;
            if !matches!(outcome, Outcome::Pending | Outcome::Reconcile) {
                self.state
                    .lock()
                    .map_err(|_| Error::Corrupt)?
                    .operations
                    .remove(&operation.origin.operation);
            }
        }
        self.recover_page().await?;
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Corrupt)?
            .operations
            .len())
    }
}
