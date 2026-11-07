// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Staged asynchronous opaque record owner. Construction requires host-authorized
//! schemas and an instance; this is not a plugin-facing authorization entry point.
//! Applied logical receipts survive reconnect. Unresolved work remains in CoreStore
//! and does not by itself establish durable intent or crash recovery.
//! Physical generations belong to one schema/instance. Keys retain the base owner,
//! schema and exact legacy instance-scoped suffix; unrelated owners do not share
//! scan guards, and namespace hash collisions cannot alias complete record keys.

use std::{collections::BTreeSet, sync::Arc};

use busbar_contract::{
    host_records::conditional,
    persistence::{
        Address, Candidate, Decision, ExpectedValue, Failure, Mutation, NamespaceId, Predicate,
        PreparedCandidate, Read, ReadResult, Scan, TimeGuard, CANDIDATE_VERSION,
    },
    Secret,
};
use sha2::{Digest, Sha256};

use super::{
    commit::SubmitResult,
    facade::{AccessError, CoreStore, LogicalClaim, PendingId, Submission},
    keys, partition,
};

pub(crate) const RECORDS: NamespaceId = NamespaceId(*b"busbar.records1\0");
pub(crate) const HOST_RECORDS: NamespaceId = NamespaceId(*b"busbar.hostrec1\0");
pub(crate) const RECORD_OPERATIONS: NamespaceId = NamespaceId(*b"busbar.recordop1");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unauthorized,
    Invalid,
    Corrupt,
    Access(AccessError),
    Backend(Failure),
}
impl From<AccessError> for Error {
    fn from(error: AccessError) -> Self {
        Self::Access(error)
    }
}
impl From<Failure> for Error {
    fn from(error: Failure) -> Self {
        Self::Backend(error)
    }
}
impl From<keys::KeyError> for Error {
    fn from(error: keys::KeyError) -> Self {
        match error {
            keys::KeyError::Allocation => Self::Access(AccessError::Overloaded),
            _ => Self::Invalid,
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    ConditionConflict,
    OpIdConflict,
    Pending(PendingId),
    Reconcile(PendingId),
    Busy(Option<PendingId>),
    NoEffect(Failure),
}

/// A cursor's raw key includes the original instance prefix, but no schema frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cursor {
    pub key: Vec<u8>,
    pub generation: u64,
}

#[derive(Debug)]
pub(crate) struct Page {
    pub generation: u64,
    pub rows: Vec<(Vec<u8>, Secret<Vec<u8>>)>,
    pub next: Option<Cursor>,
}

pub(crate) struct HostRecords<'a> {
    store: &'a CoreStore,
    namespace: NamespaceId,
    scope: Vec<u8>,
    schemas: BTreeSet<&'a str>,
}

impl<'a> HostRecords<'a> {
    /// Caller has already authenticated the instance and authorized these schemas.
    pub(crate) fn authorized(
        store: &'a CoreStore,
        instance: &str,
        schemas: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self> {
        Self::new(store, RECORDS, instance, schemas)
    }

    /// Host-generated records occupy a separate namespace, never a magic plugin schema.
    pub(crate) fn host_private(
        store: &'a CoreStore,
        instance: &str,
        schemas: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self> {
        Self::new(store, HOST_RECORDS, instance, schemas)
    }

    fn new(
        store: &'a CoreStore,
        namespace: NamespaceId,
        instance: &str,
        schemas: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self> {
        u16::try_from(instance.len()).map_err(|_| Error::Invalid)?;
        Ok(Self {
            store,
            namespace,
            scope: crate::host_records::record_key(instance, &[]),
            schemas: schemas.into_iter().collect(),
        })
    }

    fn frame(&self, schema: &str) -> Result<Vec<u8>> {
        if !self.schemas.contains(schema) {
            return Err(Error::Unauthorized);
        }
        Ok(keys::framed(b'R', &[&self.namespace.0, schema.as_bytes()])?)
    }

    pub(super) fn address(&self, schema: &str, scoped_key: &[u8]) -> Result<Address> {
        if !self.schemas.contains(schema) {
            return Err(Error::Unauthorized);
        }
        scoped_address(self.namespace, &self.scope, schema, scoped_key)
    }

    /// One coherent observation in input order, with missing distinct from empty.
    pub(crate) async fn read(
        &self,
        keys: &[(&str, &[u8])],
    ) -> Result<Vec<Option<Secret<Vec<u8>>>>> {
        let addresses = keys
            .iter()
            .map(|(schema, key)| self.address(schema, key))
            .collect::<Result<_>>()?;
        self.read_addresses(addresses).await
    }

    async fn read_addresses(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Secret<Vec<u8>>>>> {
        let count = addresses.len();
        match self
            .store
            .backend()
            .read(Arc::new(Read {
                dataset: self.store.info().dataset,
                addresses,
                time: None,
            }))
            .await?
        {
            ReadResult::Values {
                observed_at,
                values,
            } if observed_at.authority == self.store.info().clock_authority
                && values.len() == count =>
            {
                Ok(values)
            }
            _ => Err(Error::Corrupt),
        }
    }

    pub(crate) async fn get(&self, schema: &str, key: &[u8]) -> Result<Option<Secret<Vec<u8>>>> {
        self.read(&[(schema, key)])
            .await?
            .pop()
            .ok_or(Error::Corrupt)
    }

    /// Each crossing is bounded by the attachment's explicit page resource limits.
    /// A continuation pins its observed generation; stale pages are never combined.
    pub(crate) async fn scan(
        &self,
        schema: &str,
        prefix: &[u8],
        after: Option<&Cursor>,
    ) -> Result<Page> {
        let address = self.address(schema, prefix)?;
        let namespace = NamespaceId(address.namespace);
        let prefix = address.key;
        let frame_len = self.frame(schema)?.len();
        let after_key = after
            .map(|cursor| self.address(schema, &cursor.key).map(|at| at.key))
            .transpose()?;
        if after_key
            .as_ref()
            .is_some_and(|key| !key.starts_with(&prefix))
        {
            return Err(Error::Invalid);
        }
        let limits = self.store.limits();
        let page = self
            .store
            .backend()
            .scan(Arc::new(Scan {
                dataset: self.store.info().dataset,
                namespace,
                prefix: prefix.clone(),
                after: after_key.clone(),
                generation: after.map(|cursor| cursor.generation),
                allow_change: false,
                max_items: limits.scan_items,
                max_bytes: limits.scan_bytes,
            }))
            .await?;
        if after.is_some_and(|cursor| cursor.generation != page.generation) {
            return Err(Error::Backend(Failure::StaleScan));
        }
        if page.rows.len() > limits.scan_items {
            return Err(Error::Corrupt);
        }
        let seal = crate::seal::lend();
        let mut bytes = 0usize;
        let mut previous = after_key.as_ref();
        for (at, value) in &page.rows {
            if at.namespace != namespace.0
                || !at.key.starts_with(&prefix)
                || previous.is_some_and(|key| key >= &at.key)
            {
                return Err(Error::Corrupt);
            }
            bytes = bytes
                .checked_add(at.key.len())
                .and_then(|n| n.checked_add(value.expose(&seal).len()))
                .ok_or(Error::Corrupt)?;
            previous = Some(&at.key);
        }
        if bytes > limits.scan_bytes
            || page
                .next
                .as_ref()
                .is_some_and(|key| page.rows.last().map(|(at, _)| &at.key) != Some(key))
        {
            return Err(Error::Corrupt);
        }
        Ok(Page {
            generation: page.generation,
            rows: page
                .rows
                .into_iter()
                .map(|(at, value)| (at.key[frame_len..].to_vec(), value))
                .collect(),
            next: page.next.map(|key| Cursor {
                key: key[frame_len..].to_vec(),
                generation: page.generation,
            }),
        })
    }

    /// Opaque storage values have storage bounds, not the plane's 512-byte bound.
    /// Empty values remain present; callers mapping legacy empty-put deletion use delete.
    pub(crate) async fn put(
        &self,
        schema: &str,
        key: &[u8],
        value: Secret<Vec<u8>>,
    ) -> Result<Outcome> {
        self.write(Mutation::Put {
            address: self.address(schema, key)?,
            value,
        })
        .await
    }

    pub(crate) async fn delete(&self, schema: &str, key: &[u8]) -> Result<Outcome> {
        self.write(Mutation::Delete(self.address(schema, key)?))
            .await
    }

    async fn write(&self, mutation: Mutation) -> Result<Outcome> {
        let candidate = self.candidate(vec![], vec![mutation])?;
        outcome(self.store.submit(candidate).await?)
    }

    fn candidate(
        &self,
        predicates: Vec<Predicate>,
        mutations: Vec<Mutation>,
    ) -> Result<PreparedCandidate> {
        self.candidate_at(predicates, mutations, None)
    }
    fn candidate_at(
        &self,
        predicates: Vec<Predicate>,
        mutations: Vec<Mutation>,
        time: Option<TimeGuard>,
    ) -> Result<PreparedCandidate> {
        PreparedCandidate::new(Candidate {
            id: self.store.next_id()?,
            codec: CANDIDATE_VERSION,
            predicates,
            mutations,
            time,
            result: Secret::new(vec![]),
        })
        .map_err(|_| Error::Invalid)
    }

    /// Preserve the old already-authorized conditional vocabulary and its bounds.
    /// The durable receipt binds the original fingerprint and selected namespace.
    /// A failed predicate writes no logical receipt; unknown never triggers replanning.
    pub(crate) async fn conditional(&self, request: &conditional::Request) -> Result<Outcome> {
        request.encode_held().map_err(|_| Error::Invalid)?;
        let mut predicates = Vec::new();
        for predicate in &request.predicates {
            predicates.push(Predicate {
                address: self.address(&predicate.schema, &predicate.key)?,
                expected: match &predicate.expected {
                    conditional::Expected::Absent => ExpectedValue::Absent,
                    conditional::Expected::Bytes(bytes) => {
                        ExpectedValue::Exact(Secret::new(bytes.clone()))
                    }
                },
            });
        }
        let mut mutations = Vec::new();
        for mutation in &request.mutations {
            let (schema, key) = mutation.address();
            let address = self.address(schema, key)?;
            mutations.push(match mutation {
                conditional::Mutation::Put { value, .. } => Mutation::Put {
                    address,
                    value: Secret::new(value.clone()),
                },
                conditional::Mutation::Delete { .. } => Mutation::Delete(address),
                conditional::Mutation::DeleteRange {
                    exact_key_length, ..
                } => Mutation::DeleteRange {
                    namespace: NamespaceId(address.namespace),
                    prefix: address.key,
                    exact_key_length: exact_key_length
                        .checked_add(
                            u64::try_from(self.frame(schema)?.len()).map_err(|_| Error::Invalid)?,
                        )
                        .ok_or(Error::Invalid)?,
                },
            });
        }
        self.conditional_prepared(
            request.op_id.0,
            request.fingerprint(),
            predicates,
            mutations,
            None,
        )
        .await
    }

    /// Trusted host owners bypass the plane carrier's value/transport bounds.
    /// Candidate validation still rejects duplicate/overlapping selectors before
    /// a durable logical claim or a backend crossing.
    pub(crate) async fn conditional_native(
        &self,
        operation: [u8; 16],
        predicates: Vec<Predicate>,
        mutations: Vec<Mutation>,
    ) -> Result<Outcome> {
        self.conditional_native_timed(operation, predicates, mutations, None)
            .await
    }
    pub(crate) async fn conditional_native_timed(
        &self,
        operation: [u8; 16],
        predicates: Vec<Predicate>,
        mutations: Vec<Mutation>,
        time: Option<TimeGuard>,
    ) -> Result<Outcome> {
        // Use a fixed validation identity only for the semantic body digest.
        // Native submission receives a fresh independently allocated attempt id.
        let canonical = PreparedCandidate::new(Candidate {
            id: busbar_contract::persistence::AttemptId {
                dataset: self.store.info().dataset,
                writer_epoch: 1,
                writer: [1; 16],
                execution_epoch: 1,
                operation,
            },
            codec: CANDIDATE_VERSION,
            predicates,
            mutations,
            time,
            result: Secret::new(vec![]),
        })
        .map_err(|_| Error::Invalid)?;
        self.conditional_prepared(
            operation,
            canonical.fingerprint(),
            canonical
                .candidate()
                .predicates
                .iter()
                .map(|predicate| Predicate {
                    address: predicate.address.clone(),
                    expected: match &predicate.expected {
                        ExpectedValue::Absent => ExpectedValue::Absent,
                        ExpectedValue::Exact(value) => ExpectedValue::Exact(value.clone()),
                    },
                })
                .collect(),
            canonical
                .candidate()
                .mutations
                .iter()
                .map(|mutation| match mutation {
                    Mutation::Put { address, value } => Mutation::Put {
                        address: address.clone(),
                        value: value.clone(),
                    },
                    Mutation::Delete(address) => Mutation::Delete(address.clone()),
                    Mutation::DeleteRange {
                        namespace,
                        prefix,
                        exact_key_length,
                    } => Mutation::DeleteRange {
                        namespace: *namespace,
                        prefix: prefix.clone(),
                        exact_key_length: *exact_key_length,
                    },
                })
                .collect(),
            time,
        )
        .await
    }

    async fn conditional_prepared(
        &self,
        operation: [u8; 16],
        fingerprint: [u8; 32],
        mut predicates: Vec<Predicate>,
        mut mutations: Vec<Mutation>,
        time: Option<TimeGuard>,
    ) -> Result<Outcome> {
        let mut receipt = vec![1];
        receipt.extend_from_slice(&self.namespace.0);
        receipt.extend_from_slice(&fingerprint);
        let digest = Sha256::digest(&receipt).into();
        let claim = self.store.claim_logical(
            super::facade::LogicalId {
                namespace: RECORD_OPERATIONS.0,
                operation,
            },
            digest,
        );
        let permit = match claim {
            Err(AccessError::OperationConflict) => return Ok(Outcome::OpIdConflict),
            Err(error) => return Err(error.into()),
            Ok(LogicalClaim::Retained(id)) => return self.retry_timed(id, time).await,
            Ok(LogicalClaim::Busy) => return Ok(Outcome::Busy(None)),
            Ok(LogicalClaim::Prepare(permit)) => permit,
        };
        let receipt_at = Address {
            // OpId is node8 + counter8. Keep one generation owner per logical
            // writer rather than leaving a permanent namespace per operation.
            namespace: partition::namespace(RECORD_OPERATIONS, &[&operation[..8]]).0,
            key: keys::framed(b'R', &[&RECORD_OPERATIONS.0, &operation])?,
        };
        if let Some(found) = self
            .read_addresses(vec![receipt_at.clone()])
            .await?
            .pop()
            .ok_or(Error::Corrupt)?
        {
            let seal = crate::seal::lend();
            let found = found.expose(&seal);
            if found.len() != 49 || found[0] != 1 {
                return Err(Error::Corrupt);
            }
            return Ok(if found == &receipt {
                Outcome::Applied
            } else {
                Outcome::OpIdConflict
            });
        }
        predicates.push(Predicate {
            address: receipt_at.clone(),
            expected: ExpectedValue::Absent,
        });
        mutations.push(Mutation::Put {
            address: receipt_at.clone(),
            value: Secret::new(receipt.clone()),
        });
        let candidate = self.candidate_at(predicates, mutations, time)?;
        let result = self.timed_outcome(permit.submit(candidate).await?, time)?;
        // Another attachment may have committed this logical operation after our
        // receipt read. Resolve its receipt without rebuilding or reapplying effects.
        if result == Outcome::ConditionConflict {
            if let Some(found) = self
                .read_addresses(vec![receipt_at])
                .await?
                .pop()
                .ok_or(Error::Corrupt)?
            {
                let seal = crate::seal::lend();
                let found = found.expose(&seal);
                if found.len() != 49 || found[0] != 1 {
                    return Err(Error::Corrupt);
                }
                return Ok(if found == &receipt {
                    Outcome::Applied
                } else {
                    Outcome::OpIdConflict
                });
            }
        }
        Ok(result)
    }

    fn timed_outcome(&self, submission: Submission, time: Option<TimeGuard>) -> Result<Outcome> {
        if let SubmitResult::Decided(decision) = &submission.result {
            if let Decision::TimeGuardFailed { observed_at } = decision.as_ref() {
                if time.is_none_or(|guard| guard.permits(observed_at.unix_seconds))
                    || observed_at.authority != self.store.info().clock_authority
                {
                    return Err(Error::Corrupt);
                }
                return Ok(Outcome::NoEffect(Failure::Refused));
            }
        }
        outcome(submission)
    }
    async fn retry_timed(&self, id: PendingId, time: Option<TimeGuard>) -> Result<Outcome> {
        self.timed_outcome(self.store.retry(id).await?, time)
    }

    /// Uses CoreStore's original candidate and original backend, including after close.
    pub(crate) async fn retry(&self, id: PendingId) -> Result<Outcome> {
        outcome(self.store.retry(id).await?)
    }
}

/// Pure owner framing shared by live reads/writes and fenced migration imports.
pub(super) fn scoped_address(
    namespace: NamespaceId,
    scope: &[u8],
    schema: &str,
    scoped_key: &[u8],
) -> Result<Address> {
    if !scoped_key.starts_with(scope) {
        return Err(Error::Unauthorized);
    }
    let mut key = keys::framed(b'R', &[&namespace.0, schema.as_bytes()])?;
    key.try_reserve(scoped_key.len())
        .map_err(|_| Error::Access(AccessError::Overloaded))?;
    key.extend_from_slice(scoped_key);
    Ok(Address {
        namespace: partition::namespace(namespace, &[schema.as_bytes(), scope]).0,
        key,
    })
}

fn outcome(submission: Submission) -> Result<Outcome> {
    Ok(match submission.result {
        SubmitResult::Decided(decision) => match decision.as_ref() {
            Decision::Applied(_) => Outcome::Applied,
            Decision::ConditionConflict => Outcome::ConditionConflict,
            Decision::OpIdConflict => Outcome::OpIdConflict,
            Decision::ExpiredUnknown => Outcome::Reconcile(submission.id),
            Decision::TimeGuardFailed { .. } => return Err(Error::Corrupt),
        },
        SubmitResult::NoEffect(failure) => Outcome::NoEffect(failure),
        SubmitResult::Uncertain => Outcome::Pending(submission.id),
        SubmitResult::Reconcile => Outcome::Reconcile(submission.id),
        SubmitResult::Busy => Outcome::Busy(Some(submission.id)),
    })
}

#[cfg(test)]
#[path = "host_records_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "host_records_timed_tests.rs"]
pub(crate) mod timed_tests;
