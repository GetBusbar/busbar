// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::{persistence::*, Secret};
use busbar_kernel::persistence::{
    facade::{CoreStore, Limits},
    startup::{Progress, Startup},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Default)]
struct State {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    receipts: HashMap<[u8; 16], [u8; 32]>,
    sent: Vec<PreparedCandidate>,
    generations: HashMap<[u8; 16], u64>,
}
#[derive(Default)]
pub(crate) struct MemoryBackend {
    state: Mutex<State>,
    pub(crate) fail_client_read: AtomicBool,
    lose_reply: AtomicBool,
    pub(crate) hang: AtomicBool,
}
impl PersistenceBackend for MemoryBackend {
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
            if request.addresses.iter().any(|at| {
                at.key
                    .windows(b"bucket.atomic.v1".len())
                    .any(|w| w == b"bucket.atomic.v1")
            }) && self.fail_client_read.swap(false, Ordering::SeqCst)
            {
                return Err(Failure::Unavailable);
            }
            let state = self.state.lock().unwrap();
            let observed_at = ClockObservation {
                authority: [3; 16],
                unix_seconds: now(),
            };
            if request.time.is_some_and(|guard| !guard.permits(now())) {
                return Ok(ReadResult::TimeGuardFailed { observed_at });
            }
            Ok(ReadResult::Values {
                observed_at: ClockObservation {
                    authority: [3; 16],
                    unix_seconds: now(),
                },
                values: request
                    .addresses
                    .iter()
                    .map(|at| state.rows.get(at).cloned())
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
            let seal = busbar_kernel::seal::lend();
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
        Box::pin(async {
            Ok(ClockObservation {
                authority: [3; 16],
                unix_seconds: now(),
            })
        })
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        self.state.lock().unwrap().sent.push(prepared.clone());
        Box::pin(async move {
            if self.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let mut state = self.state.lock().unwrap();
            let candidate = prepared.candidate();
            if let Some(digest) = state.receipts.get(&candidate.id.operation) {
                return Ok(if *digest == prepared.fingerprint() {
                    Decision::Applied(candidate.result.clone())
                } else {
                    Decision::OpIdConflict
                });
            }
            if candidate.time.is_some_and(|guard| !guard.permits(now())) {
                return Ok(Decision::TimeGuardFailed {
                    observed_at: ClockObservation {
                        authority: [3; 16],
                        unix_seconds: now(),
                    },
                });
            }
            for predicate in &candidate.predicates {
                let found = state.rows.get(&predicate.address);
                let matches = match &predicate.expected {
                    ExpectedValue::Absent => found.is_none(),
                    ExpectedValue::Exact(bytes) => found == Some(bytes),
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

pub(crate) async fn memory_store() -> Arc<CoreStore> {
    memory_store_on(Arc::new(MemoryBackend::default())).await
}

pub(crate) async fn memory_store_on(backend: Arc<MemoryBackend>) -> Arc<CoreStore> {
    let mut startup = Startup::new(
        backend,
        Limits {
            pending_operations: 128,
            conflict_retries: 64,
            scan_items: 16,
            scan_bytes: 32 * 1024 * 1024,
        },
        true,
    )
    .unwrap();
    for _ in 0..16 {
        match startup.advance().await.unwrap() {
            Progress::Admitted => return startup.store().unwrap(),
            Progress::Advanced => {}
            other => panic!("unexpected startup: {other:?}"),
        }
    }
    panic!("startup did not finish")
}

pub(crate) fn lose_next_reply(backend: &MemoryBackend) {
    backend.lose_reply.store(true, Ordering::SeqCst);
}
