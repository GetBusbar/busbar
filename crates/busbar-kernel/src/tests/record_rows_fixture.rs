// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Record rows held behind a real native [`PersistenceBackend`], so the host's production record
//! path (CoreStore, HostRecords, AsyncRecords, the write-behind's native flush) reads and commits
//! them, while a test still addresses them as `(kind, instance-scoped record key)`.
//!
//! `calls` holds every crossing that touches a transaction-guarded kind (every kind here but
//! `cache`), in the plane's conditional vocabulary; the store's own operation receipt rows are kept
//! apart from `rows`. `lose_reply` commits and then answers UNKNOWN; `fail_before_commit` answers
//! UNKNOWN without committing; `refuse` refuses; `refuse_scan` fails a scan of a plane kind and
//! `scans` counts them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use busbar_contract::host_records::conditional::{self, Decision, Expected, Request};
use busbar_contract::host_records::RecordFailure;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};
use busbar_contract::persistence::{
    control, Address, BackendInfo, Call, Candidate, ClockObservation, DatasetId,
    Decision as NativeDecision, Durability, ExpectedValue, Failure, Mutation, Page,
    PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_contract::Secret;
use futures::FutureExt;

use crate::host_records_async::AsyncRecords;
use crate::persistence::facade::{CoreStore, Limits, WriterAuthority};
use crate::persistence::host_records::Outcome;

/// Writes to this kind are ordinary, not record transactions.
const UNGUARDED: &str = "cache";

fn kinds() -> [&'static str; 5] {
    [
        "state",
        "events",
        UNGUARDED,
        "ev",
        crate::host_chains::CHAIN_LIFE_SCHEMA.as_str(),
    ]
}

#[derive(Default)]
pub(crate) struct State {
    pub(crate) rows: BTreeMap<(String, Vec<u8>), Vec<u8>>,
    pub(crate) receipts: HashMap<[u8; 16], [u8; 32]>,
    pub(crate) calls: Vec<Request>,
    pub(crate) lose_reply: bool,
    pub(crate) fail_before_commit: bool,
    pub(crate) refuse: bool,
    pub(crate) scans: usize,
    pub(crate) refuse_scan: bool,
    host: BTreeMap<Address, Vec<u8>>,
    generations: HashMap<[u8; 16], u64>,
}

/// The rows, and the one CoreStore attached over them.
#[derive(Default)]
pub(crate) struct Rows(pub(crate) Arc<Mutex<State>>, OnceLock<Arc<CoreStore>>);

fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    future
        .now_or_never()
        .expect("the native in-memory fixture finishes in one poll")
}

fn instance_of(key: &[u8]) -> Option<&str> {
    let len = usize::from(u16::from_be_bytes(key.get(..2)?.try_into().ok()?));
    std::str::from_utf8(key.get(2..2 + len)?).ok()
}

/// The native address of a plane kind's instance-scoped key (or key prefix).
fn plane_address(kind: &str, key: &[u8]) -> Option<Address> {
    let instance = instance_of(key)?;
    crate::persistence::scoped::migration_address(false, instance, kind, &key[2 + instance.len()..])
        .ok()
}

fn frame(kind: &str) -> Vec<u8> {
    crate::persistence::keys::framed(
        b'R',
        &[
            &crate::persistence::host_records::RECORDS.0,
            kind.as_bytes(),
        ],
    )
    .expect("a fixture kind frames")
}

/// A plane kind's prefix (scan or range) as `(kind, instance-scoped prefix, frame length)`.
fn plane_range(namespace: [u8; 16], prefix: &[u8]) -> Option<(String, Vec<u8>, usize)> {
    kinds().into_iter().find_map(|kind| {
        let frame = frame(kind);
        let rest = prefix.strip_prefix(frame.as_slice())?;
        (plane_address(kind, rest)?.namespace == namespace)
            .then(|| (kind.to_string(), rest.to_vec(), frame.len()))
    })
}

fn plane_row(at: &Address) -> Option<(String, Vec<u8>)> {
    kinds().into_iter().find_map(|kind| {
        let key = at.key.strip_prefix(frame(kind).as_slice())?;
        (plane_address(kind, key).as_ref() == Some(at)).then(|| (kind.to_string(), key.to_vec()))
    })
}

fn plane_call(candidate: &Candidate) -> Option<Request> {
    let seal = crate::seal::lend();
    let mut guarded = false;
    let mut predicates = Vec::new();
    for predicate in &candidate.predicates {
        let Some((schema, key)) = plane_row(&predicate.address) else {
            continue;
        };
        guarded |= schema != UNGUARDED;
        predicates.push(conditional::Predicate {
            schema,
            key,
            expected: match &predicate.expected {
                ExpectedValue::Absent => Expected::Absent,
                ExpectedValue::Exact(value) => Expected::Bytes(value.expose(&seal).clone()),
            },
        });
    }
    let mut mutations = Vec::new();
    for mutation in &candidate.mutations {
        let mutation = match mutation {
            Mutation::Put { address, value } => {
                let Some((schema, key)) = plane_row(address) else {
                    continue;
                };
                conditional::Mutation::Put {
                    schema,
                    key,
                    value: value.expose(&seal).clone(),
                }
            }
            Mutation::Delete(address) => {
                let Some((schema, key)) = plane_row(address) else {
                    continue;
                };
                conditional::Mutation::Delete { schema, key }
            }
            Mutation::DeleteRange {
                namespace,
                prefix,
                exact_key_length,
            } => {
                let Some((schema, prefix, frame)) = plane_range(namespace.0, prefix) else {
                    continue;
                };
                conditional::Mutation::DeleteRange {
                    schema,
                    prefix,
                    exact_key_length: exact_key_length.saturating_sub(frame as u64),
                }
            }
        };
        guarded |= mutation.address().0 != UNGUARDED;
        mutations.push(mutation);
    }
    guarded.then(|| Request {
        version: conditional::VERSION,
        op_id: busbar_contract::records::OpId(candidate.id.operation),
        predicates,
        mutations,
    })
}

impl State {
    fn value(&self, at: &Address) -> Option<Vec<u8>> {
        if at.namespace == control::GENERATION_NAMESPACE.0 {
            let namespace: [u8; 16] = at.key.as_slice().try_into().ok()?;
            return self
                .generations
                .get(&namespace)
                .filter(|generation| **generation != 0)
                .map(|generation| generation.to_le_bytes().to_vec());
        }
        match plane_row(at) {
            Some(row) => self.rows.get(&row).cloned(),
            None => self.host.get(at).cloned(),
        }
    }
}

struct Native(Arc<Mutex<State>>);

impl PersistenceBackend for Native {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 1,
            durability: Durability::Local,
        }
    }

    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let state = self.0.lock().unwrap();
            let values = request
                .addresses
                .iter()
                .map(|at| {
                    if at.namespace == control::NAMESPACE.0 {
                        let bytes = if at.key == control::DATASET_KEY {
                            control::Dataset {
                                id: DatasetId([1; 16]),
                                writer_epoch: 2,
                            }
                            .encode()
                            .unwrap()
                            .to_vec()
                        } else {
                            control::Writer {
                                retired_through: 2,
                                admitted_through: 3,
                            }
                            .encode()
                            .unwrap()
                            .to_vec()
                        };
                        Some(Secret::new(bytes))
                    } else {
                        state.value(at).map(Secret::new)
                    }
                })
                .collect();
            Ok(ReadResult::Values {
                observed_at: ClockObservation {
                    authority: [3; 16],
                    unix_seconds: 10,
                },
                values,
            })
        })
    }

    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            let mut guard = self.0.lock().unwrap();
            let state = &mut *guard;
            let generation = state
                .generations
                .get(&request.namespace.0)
                .copied()
                .unwrap_or(0);
            if request
                .generation
                .is_some_and(|expected| expected != generation)
            {
                return Err(Failure::StaleScan);
            }
            let found: Vec<(Address, Vec<u8>)> =
                match plane_range(request.namespace.0, &request.prefix) {
                    Some((kind, prefix, _)) => {
                        state.scans += 1;
                        if state.refuse_scan {
                            return Err(Failure::Unavailable);
                        }
                        state
                            .rows
                            .iter()
                            .filter(|((held, key), _)| *held == kind && key.starts_with(&prefix))
                            .filter_map(|((held, key), value)| {
                                Some((plane_address(held, key)?, value.clone()))
                            })
                            .collect()
                    }
                    None => state
                        .host
                        .iter()
                        .filter(|(at, _)| {
                            at.namespace == request.namespace.0
                                && at.key.starts_with(&request.prefix)
                        })
                        .map(|(at, value)| (at.clone(), value.clone()))
                        .collect(),
                };
            let mut rows = Vec::new();
            let mut bytes = 0;
            let mut more = false;
            for (at, value) in found {
                if request.after.as_ref().is_some_and(|after| *after >= at.key) {
                    continue;
                }
                bytes += at.key.len() + value.len();
                if rows.len() == request.max_items || bytes > request.max_bytes {
                    more = true;
                    break;
                }
                rows.push((at, Secret::new(value)));
            }
            Ok(Page {
                generation,
                next: if more {
                    rows.last().map(|(at, _)| at.key.clone())
                } else {
                    None
                },
                rows,
            })
        })
    }

    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async move {
            Ok(ClockObservation {
                authority: [3; 16],
                unix_seconds: 10,
            })
        })
    }

    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, NativeDecision> {
        Box::pin(async move {
            let seal = crate::seal::lend();
            let mut guard = self.0.lock().unwrap();
            let state = &mut *guard;
            let candidate = prepared.candidate();
            if let Some(call) = plane_call(candidate) {
                state.calls.push(call);
            }
            if state.refuse {
                return Err(Failure::Refused);
            }
            if let Some(held) = state.receipts.get(&candidate.id.operation) {
                return Ok(if *held == prepared.fingerprint() {
                    NativeDecision::Applied(candidate.result.clone())
                } else {
                    NativeDecision::OpIdConflict
                });
            }
            for predicate in &candidate.predicates {
                let found = state.value(&predicate.address);
                let matches = match &predicate.expected {
                    ExpectedValue::Absent => found.is_none(),
                    ExpectedValue::Exact(bytes) => found.as_ref() == Some(bytes.expose(&seal)),
                };
                if !matches {
                    return Ok(NativeDecision::ConditionConflict);
                }
            }
            if state.fail_before_commit {
                state.fail_before_commit = false;
                return Err(Failure::Unknown);
            }
            let mut touched = BTreeSet::new();
            for mutation in &candidate.mutations {
                match mutation {
                    Mutation::Put { address, value } => {
                        touched.insert(address.namespace);
                        let value = value.expose(&seal).clone();
                        match plane_row(address) {
                            Some(row) => state.rows.insert(row, value),
                            None => state.host.insert(address.clone(), value),
                        };
                    }
                    Mutation::Delete(address) => {
                        touched.insert(address.namespace);
                        match plane_row(address) {
                            Some(row) => state.rows.remove(&row),
                            None => state.host.remove(address),
                        };
                    }
                    Mutation::DeleteRange {
                        namespace,
                        prefix,
                        exact_key_length,
                    } => {
                        touched.insert(namespace.0);
                        match plane_range(namespace.0, prefix) {
                            Some((kind, prefix, frame)) => {
                                let exact = exact_key_length.saturating_sub(frame as u64);
                                state.rows.retain(|(held, key), _| {
                                    *held != kind
                                        || !key.starts_with(&prefix)
                                        || key.len() as u64 != exact
                                });
                            }
                            None => state.host.retain(|at, _| {
                                at.namespace != namespace.0
                                    || !at.key.starts_with(prefix)
                                    || at.key.len() as u64 != *exact_key_length
                            }),
                        }
                    }
                }
            }
            for namespace in touched {
                *state.generations.entry(namespace).or_default() += 1;
            }
            state
                .receipts
                .insert(candidate.id.operation, prepared.fingerprint());
            if state.lose_reply {
                state.lose_reply = false;
                return Err(Failure::Unknown);
            }
            Ok(NativeDecision::Applied(candidate.result.clone()))
        })
    }
}

impl Rows {
    /// The CoreStore attached over these rows; one per fixture, so retained work survives.
    pub(crate) fn store(&self) -> Arc<CoreStore> {
        Arc::clone(self.1.get_or_init(|| {
            Arc::new(
                ready(CoreStore::attach(
                    Arc::new(Native(Arc::clone(&self.0))),
                    WriterAuthority {
                        writer_epoch: 2,
                        writer: [4; 16],
                        execution_epoch: 3,
                    },
                    Limits {
                        pending_operations: 64,
                        conflict_retries: 2,
                        scan_items: 128,
                        scan_bytes: 1024 * 1024,
                    },
                ))
                .expect("the fixture store attaches"),
            )
        }))
    }

    /// The production async record owner of `instance`, authorized for every fixture kind.
    pub(crate) fn records(&self, instance: &str) -> AsyncRecords {
        AsyncRecords::authorized(
            self.store(),
            instance,
            kinds().into_iter().map(str::to_string),
        )
        .expect("fixture kinds are authorized")
    }

    /// One record transaction through the production native conditional path.
    pub(crate) fn record_transaction(&self, request: &Request) -> Result<Decision, RecordFailure> {
        let key = request
            .predicates
            .first()
            .map(|predicate| predicate.key.as_slice())
            .or_else(|| {
                request
                    .mutations
                    .first()
                    .map(|mutation| mutation.address().1)
            })
            .unwrap_or_default();
        let instance = instance_of(key).ok_or(RecordFailure::Refused("unscoped key".into()))?;
        match ready(self.records(instance).conditional(request)) {
            Ok(Outcome::Applied) => Ok(Decision::Applied),
            Ok(Outcome::ConditionConflict) => Ok(Decision::ConditionConflict),
            Ok(Outcome::OpIdConflict) => Err(RecordFailure::Conflict),
            Ok(Outcome::Busy(_)) => Err(RecordFailure::Overloaded),
            Ok(Outcome::NoEffect(failure)) => Err(RecordFailure::Refused(format!("{failure:?}"))),
            Ok(Outcome::Pending(_) | Outcome::Reconcile(_)) => {
                Err(RecordFailure::Failed("unresolved".into()))
            }
            Err(error) => Err(RecordFailure::Failed(format!("{error:?}"))),
        }
    }

    pub(crate) fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError> {
        let mut state = self.0.lock().unwrap();
        if let Some(at) = plane_address(schema.as_str(), key) {
            *state.generations.entry(at.namespace).or_default() += 1;
        }
        state.rows.insert(
            (schema.as_str().into(), key.to_vec()),
            value.as_slice().to_vec(),
        );
        Ok(())
    }

    pub(crate) fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .rows
            .get(&(schema.as_str().into(), key.to_vec()))
            .map(|bytes| RecordBytes::new(bytes.clone()).unwrap()))
    }

    pub(crate) fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .rows
            .iter()
            .filter(|((held, key), _)| held == schema.as_str() && key.starts_with(prefix))
            .take(limit as usize)
            .map(|((_, key), value)| (key.clone(), RecordBytes::new(value.clone()).unwrap()))
            .collect())
    }
}
