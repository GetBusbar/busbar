// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORE'S RECORDS STEP OVER THE OPENED STORE (MIGRATE-ON-BOOT r42 §3 4a, §6 (1)): the three store
//! calls `busbar_migrate::records::RecordStore` needs (one page of a scan, one atomic commit, the
//! writer authority), over the admitted [`CoreStore`] and under the FST owner authority admission
//! registered. The gateway's seam implements the trait by delegating here; the native records it
//! commits are encoded by this facade's own migration encoders ([`super::records`]), so the
//! migrator links no kernel and no store driver.
//!
//! Cold code: a boot whose IMPORT namespace is empty makes one one-row scan here and nothing else.

use std::sync::Arc;

use busbar_contract::persistence::{
    Address, Candidate, Decision, ExpectedValue, Failure, Mutation, NamespaceId, Predicate,
    PreparedCandidate, Read, ReadResult, Scan, CANDIDATE_VERSION,
};
use busbar_contract::secure::SecureVec;
use busbar_contract::Secret;

use crate::persistence::commit::{NoEffectCause, SubmitResult};
use crate::persistence::facade::CoreStore;

/// How many times an in-doubt commit is driven again before the step reports the store's fault
/// (the next boot resumes: every page is exact on what it consumes).
const IN_DOUBT_RETRIES: usize = 4;

/// How one commit ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every predicate held; every effect applied, atomically.
    Applied,
    /// A predicate failed; nothing applied.
    Conflict,
    /// The store fenced this writer: another owner holds the dataset. Nothing applied.
    Fenced,
    /// The store refused this send, with no earlier uncertainty: nothing applied, and a smaller
    /// candidate may pass (#319 r4 §7.2).
    Refused,
}

/// One commit: `(address, None)` must be absent, `(address, Some(bytes))` must hold exactly those
/// bytes; then every put and delete applies, or nothing does.
#[derive(Debug, Default)]
pub struct Commit {
    /// The predicates.
    pub expect: Vec<(Address, Option<SecureVec>)>,
    /// The records put.
    pub put: Vec<(Address, SecureVec)>,
    /// The records deleted.
    pub delete: Vec<Address>,
}

impl Commit {
    /// The native predicates and mutations, in this commit's order.
    pub(crate) fn parts(self) -> (Vec<Predicate>, Vec<Mutation>) {
        let predicates = self
            .expect
            .into_iter()
            .map(|(address, expected)| Predicate {
                address,
                expected: match expected {
                    None => ExpectedValue::Absent,
                    Some(bytes) => ExpectedValue::Exact(Secret::new(bytes.to_vec())),
                },
            })
            .collect();
        let mutations = self
            .put
            .into_iter()
            .map(|(address, value)| Mutation::Put {
                address,
                value: Secret::new(value.to_vec()),
            })
            .chain(self.delete.into_iter().map(Mutation::Delete))
            .collect();
        (predicates, mutations)
    }
}

/// One native page: its records in key order and the store's continuation (`None`: no record of
/// the namespace follows).
#[derive(Debug, Default)]
pub struct ScanPage {
    /// The records, in key order.
    pub rows: Vec<(Vec<u8>, SecureVec)>,
    /// The last row's key while more may follow; `None` at the namespace's end.
    pub next: Option<Vec<u8>>,
}

/// The records step's access to the admitted store.
#[derive(Clone)]
pub struct Access {
    store: Arc<CoreStore>,
}

fn secure(value: &Secret<Vec<u8>>) -> SecureVec {
    SecureVec::from(value.expose(&crate::seal::lend()).clone())
}

impl Access {
    /// Over the store FST admission handed the boot (`Startup::store`).
    #[must_use]
    pub fn new(store: Arc<CoreStore>) -> Self {
        Self { store }
    }

    /// Up to `limit` records of `namespace` whose keys sort after `after` (`None`: from the first;
    /// `Some` may name the empty key), in key order: one native page, never more than the store's
    /// own scan bounds, with the store's continuation. A page shorter than asked (a byte bound)
    /// may still have one; only an absent continuation is the namespace's end (#319 r4 §7.3).
    ///
    /// # Errors
    /// The store's failure, or a page that is not in order, not of `namespace`, or whose
    /// continuation is not its last row.
    pub async fn scan(
        &self,
        namespace: NamespaceId,
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<ScanPage, String> {
        let limits = self.store.limits();
        let max_items = usize::try_from(limit)
            .unwrap_or(usize::MAX)
            .clamp(1, limits.scan_items);
        let after = after.map(<[u8]>::to_vec);
        let page = self
            .store
            .backend()
            .scan(Arc::new(Scan {
                dataset: self.store.info().dataset,
                namespace,
                prefix: Vec::new(),
                after: after.clone(),
                generation: None,
                allow_change: after.is_some(),
                max_items,
                max_bytes: limits.scan_bytes,
            }))
            .await
            .map_err(|failure| format!("the store did not answer a scan: {failure:?}"))?;
        if page.rows.len() > max_items {
            return Err("the store answered a scan with more rows than asked".to_owned());
        }
        let mut previous = after;
        let mut rows = Vec::with_capacity(page.rows.len());
        for (address, value) in &page.rows {
            if address.namespace != namespace.0
                || previous.as_ref().is_some_and(|key| *key >= address.key)
            {
                return Err(
                    "the store answered a scan out of order or outside its namespace".into(),
                );
            }
            previous = Some(address.key.clone());
            rows.push((address.key.clone(), secure(value)));
        }
        if page
            .next
            .as_ref()
            .is_some_and(|next| previous.as_ref() != Some(next))
        {
            return Err(
                "the store answered a scan whose continuation is not its last row".to_owned(),
            );
        }
        Ok(ScanPage {
            rows,
            next: page.next,
        })
    }

    /// The record at `address`, `None` when absent.
    ///
    /// # Errors
    /// The store's failure.
    pub async fn read(&self, address: Address) -> Result<Option<SecureVec>, String> {
        let answer = self
            .store
            .backend()
            .read(Arc::new(Read {
                dataset: self.store.info().dataset,
                addresses: vec![address],
                time: None,
            }))
            .await
            .map_err(|failure| format!("the store did not answer a read: {failure:?}"))?;
        match answer {
            ReadResult::Values { values, .. } if values.len() == 1 => {
                Ok(values.into_iter().next().flatten().map(|v| secure(&v)))
            }
            _ => Err("the store answered a read with the wrong shape".to_owned()),
        }
    }

    /// Apply `commit` atomically under this process's writer authority.
    ///
    /// # Errors
    /// The store's failure, or an outcome still in doubt after the retries (the next boot
    /// resumes).
    pub async fn commit(&self, commit: Commit) -> Result<Outcome, String> {
        if commit.put.is_empty() && commit.delete.is_empty() {
            return Ok(Outcome::Applied);
        }
        let (predicates, mutations) = commit.parts();
        let candidate = PreparedCandidate::new(Candidate {
            id: self
                .store
                .next_id()
                .map_err(|error| format!("the store admits no commit: {error:?}"))?,
            codec: CANDIDATE_VERSION,
            predicates,
            mutations,
            time: None,
            result: Secret::new(Vec::new()),
        })
        .map_err(|error| format!("a records-step commit is not a valid candidate: {error:?}"))?;
        let (mut submission, cause) = self
            .store
            .submit_traced(candidate)
            .await
            .map_err(|error| format!("the store refused a records-step commit: {error:?}"))?;
        for _ in 0..IN_DOUBT_RETRIES {
            match submission.result {
                SubmitResult::Uncertain | SubmitResult::Busy => {
                    submission = self.store.retry(submission.id).await.map_err(|error| {
                        format!("a records-step commit stayed in doubt: {error:?}")
                    })?;
                }
                _ => break,
            }
        }
        match submission.result {
            SubmitResult::Decided(decision) => match decision.as_ref() {
                Decision::Applied(_) => Ok(Outcome::Applied),
                Decision::ConditionConflict => Ok(Outcome::Conflict),
                Decision::Fenced => Ok(Outcome::Fenced),
                other => Err(format!(
                    "the store did not apply a records-step commit: {other:?}"
                )),
            },
            // Only the first send can answer NoEffect, so each is a send with no earlier
            // uncertainty: a backend refusal may be retried smaller, a fence ends this owner.
            SubmitResult::NoEffect(failure) => match cause {
                Some(NoEffectCause::Backend(Failure::Refused)) => Ok(Outcome::Refused),
                Some(NoEffectCause::Fenced) => Ok(Outcome::Fenced),
                _ => Err(format!(
                    "the store applied nothing of a records-step commit: {failure:?} ({cause:?})"
                )),
            },
            SubmitResult::Uncertain | SubmitResult::Busy | SubmitResult::Reconcile => {
                Err("a records-step commit is still in doubt; the next boot resumes it".to_owned())
            }
        }
    }

    /// The writer authority: admission registered this process's writer, so this only proves the
    /// admission still holds. An ordinary registration keeps the dataset epoch and fences no other
    /// writer; only a record-format opening or claim advances it (#319 r4 §2, §6).
    ///
    /// # Errors
    /// When the store no longer admits this writer.
    pub fn register(&self) -> Result<(), String> {
        self.store
            .authority()
            .map(drop)
            .map_err(|error| format!("the store no longer admits this writer: {error:?}"))
    }
}
