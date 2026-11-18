// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE IN-MEMORY TEST STORE BACKEND, with switches that lose a reply, hang a commit, or make a
//! submission provably never apply. Test support only: absent from production builds
//! (TRUST-ADMIN-PRODUCER-DESIGN r3 §14 A-C3; moved out of `host_records_tests.rs` unchanged
//! apart from the `never_applies` switch).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use busbar_contract::{
    persistence::{
        control, BackendInfo, Call, ClockObservation, DatasetId, Decision, Durability,
        ExpectedValue, Failure, Mutation, PersistenceBackend, PreparedCandidate, Read, ReadResult,
        Scan,
    },
    Secret,
};

use super::facade::{CoreStore, Limits, WriterAuthority};
use busbar_contract::persistence::Address;

#[derive(Default)]
pub struct State {
    pub rows: BTreeMap<Address, Secret<Vec<u8>>>,
    pub receipts: HashMap<[u8; 16], [u8; 32]>,
    pub sent: Vec<PreparedCandidate>,
    pub generations: HashMap<[u8; 16], u64>,
}
pub struct Backend {
    pub state: Mutex<State>,
    pub lose_reply: AtomicBool,
    pub hang: AtomicBool,
    /// The next commit is answered as unknown *without* applying, and its operation is bound to
    /// other bytes, so a retry of that exact attempt is decided `OpIdConflict`: provably never
    /// applied (r3 §4.6, test G20).
    pub never_applies: AtomicBool,
    pub now: AtomicU64,
}
impl Default for Backend {
    fn default() -> Self {
        Self {
            state: Mutex::default(),
            lose_reply: AtomicBool::new(false),
            hang: AtomicBool::new(false),
            never_applies: AtomicBool::new(false),
            now: AtomicU64::new(10),
        }
    }
}

impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: busbar_contract::persistence::PHYSICAL_VERSION,
            durability: Durability::Local,
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let state = self.state.lock().unwrap();
            let observed_at = ClockObservation {
                authority: [3; 16],
                unix_seconds: self.now.load(Ordering::SeqCst),
            };
            if request
                .time
                .is_some_and(|guard| !guard.permits(observed_at.unix_seconds))
            {
                return Ok(ReadResult::TimeGuardFailed { observed_at });
            }
            Ok(ReadResult::Values {
                observed_at,
                values: request
                    .addresses
                    .iter()
                    .map(|at| {
                        if at.namespace == control::NAMESPACE.0 && at.key == control::RESTORE_KEY {
                            // The declared-restore row (DES-331 §B2, 3bdc74edd2): absent until a
                            // restore path writes it, never the synthetic writer row below.
                            state.rows.get(at).cloned()
                        } else if at.namespace == control::NAMESPACE.0 {
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
                        } else if at.namespace == control::GENERATION_NAMESPACE.0 {
                            let namespace: [u8; 16] = at.key.as_slice().try_into().unwrap();
                            state
                                .generations
                                .get(&namespace)
                                .filter(|generation| **generation != 0)
                                .map(|generation| Secret::new(generation.to_le_bytes().to_vec()))
                        } else {
                            state.rows.get(at).cloned()
                        }
                    })
                    .collect(),
            })
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, busbar_contract::persistence::Page> {
        Box::pin(async move {
            let state = self.state.lock().unwrap();
            let generation = state
                .generations
                .get(&request.namespace.0)
                .copied()
                .unwrap_or(0);
            if request.generation.is_some_and(|n| n != generation) {
                return Err(Failure::StaleScan);
            }
            let seal = crate::seal::lend();
            let mut bytes = 0;
            let mut rows = Vec::new();
            let mut more = false;
            for (at, value) in &state.rows {
                if at.namespace != request.namespace.0
                    || !at.key.starts_with(&request.prefix)
                    || request.after.as_ref().is_some_and(|key| key >= &at.key)
                {
                    continue;
                }
                bytes += at.key.len() + value.expose(&seal).len();
                if rows.len() == request.max_items || bytes > request.max_bytes {
                    more = true;
                    break;
                }
                rows.push((at.clone(), value.clone()));
            }
            Ok(busbar_contract::persistence::Page {
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
                unix_seconds: self.now.load(Ordering::SeqCst),
            })
        })
    }
    fn commit(
        &self,
        prepared: PreparedCandidate,
        _key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        self.state.lock().unwrap().sent.push(prepared.clone());
        Box::pin(async move {
            if self.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let mut state = self.state.lock().unwrap();
            let candidate = prepared.candidate();
            if self.never_applies.swap(false, Ordering::SeqCst) {
                state.receipts.insert(candidate.id.operation, [0; 32]);
                return Err(Failure::Unknown);
            }
            if let Some(digest) = state.receipts.get(&candidate.id.operation) {
                return Ok(if *digest == prepared.fingerprint() {
                    Decision::Applied(candidate.result.clone())
                } else {
                    Decision::OpIdConflict
                });
            }
            let observed_at = ClockObservation {
                authority: [3; 16],
                unix_seconds: self.now.load(Ordering::SeqCst),
            };
            if candidate
                .time
                .is_some_and(|guard| !guard.permits(observed_at.unix_seconds))
            {
                return Ok(Decision::TimeGuardFailed { observed_at });
            }
            for predicate in &candidate.predicates {
                let found = if predicate.address.namespace == control::GENERATION_NAMESPACE.0 {
                    let namespace: [u8; 16] = predicate.address.key.as_slice().try_into().unwrap();
                    state
                        .generations
                        .get(&namespace)
                        .filter(|generation| **generation != 0)
                        .map(|generation| Secret::new(generation.to_le_bytes().to_vec()))
                } else {
                    state.rows.get(&predicate.address).cloned()
                };
                let matches = match &predicate.expected {
                    ExpectedValue::Absent => found.is_none(),
                    ExpectedValue::Exact(bytes) => found.as_ref() == Some(bytes),
                };
                if !matches {
                    return Ok(Decision::ConditionConflict);
                }
            }
            let mut changed = BTreeSet::new();
            for mutation in &candidate.mutations {
                match mutation {
                    Mutation::Put { address, value } => {
                        changed.insert(address.namespace);
                        state.rows.insert(address.clone(), value.clone());
                    }
                    Mutation::Delete(at) => {
                        changed.insert(at.namespace);
                        state.rows.remove(at);
                    }
                    Mutation::DeleteRange {
                        namespace,
                        prefix,
                        exact_key_length,
                    } => {
                        changed.insert(namespace.0);
                        state.rows.retain(|at, _| {
                            !(at.namespace == namespace.0
                                && at.key.starts_with(prefix)
                                && at.key.len() as u64 == *exact_key_length)
                        });
                    }
                }
            }
            for namespace in changed {
                *state.generations.entry(namespace).or_default() += 1;
            }
            state
                .receipts
                .insert(candidate.id.operation, prepared.fingerprint());
            if self.lose_reply.swap(false, Ordering::SeqCst) {
                return Err(Failure::Unknown);
            }
            Ok(Decision::Applied(candidate.result.clone()))
        })
    }
}
/// A CoreStore as Startup hands it over: attached, with its first receipt generation open
/// (DES-264 §3.2). `sent` then lists only the commits made through the returned store.
pub async fn attach(backend: Arc<Backend>) -> CoreStore {
    let store = CoreStore::attach(
        backend.clone(),
        WriterAuthority {
            writer_epoch: 2,
            writer: [4; 16],
            execution_epoch: 3,
        },
        Limits {
            pending_operations: 16,
            conflict_retries: 2,
            scan_items: 2,
            scan_bytes: 8192,
        },
    )
    .await
    .unwrap();
    store.open_record_generation().await.unwrap();
    backend.state.lock().unwrap().sent.clear();
    store
}
