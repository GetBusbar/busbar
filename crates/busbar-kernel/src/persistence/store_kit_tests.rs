// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kit over the actual memory product store, over a correct mock store, and its two negative
//! controls: a store that applies Initialize blindly and a store that misreports reads must
//! both fail it.

use super::*;
use crate::persistence::startup;
use busbar_contract::persistence::{
    control, Address, AttemptId, BackendInfo, Call, ClockObservation, CommitKey, DatasetId,
    Decision, Durability, ExpectedValue, Failure, Mutation, NamespaceId, Page, PreparedCandidate,
    Read, ReadResult, Scan,
};
use busbar_contract::Secret;
use futures::FutureExt;
use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::Mutex;

/// The memory product store through its actual ABI: each opened instance is one dataset, so a
/// second "process" on it shares the instance.
struct Memory;

#[async_trait::async_trait]
impl Fixture for Memory {
    type Dataset = Arc<dyn PersistenceBackend>;
    async fn fresh(&self) -> Self::Dataset {
        crate::real_store::native_backend().await
    }
    async fn open(&self, dataset: &Self::Dataset) -> Arc<dyn PersistenceBackend> {
        dataset.clone()
    }
}

#[derive(Default)]
struct Rows {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    receipts: Vec<(AttemptId, [u8; 32])>,
}

/// A minimal store with the reference store's commit rules: receipt replay, the fresh-dataset
/// rule (no records, no receipts, an initialization candidate), the writer fence, predicates.
/// `blind_initialize` is the one defect: any initialization candidate applies with no fence and
/// no predicate check.
#[derive(Default)]
struct Mock {
    state: Mutex<Rows>,
    blind_initialize: bool,
}

const DATASET: DatasetId = DatasetId([1; 16]);
const CLOCK: [u8; 16] = [3; 16];

fn observed() -> ClockObservation {
    ClockObservation {
        authority: CLOCK,
        unix_seconds: 1,
    }
}

impl PersistenceBackend for Mock {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DATASET,
            atomic_domain: [2; 16],
            clock_authority: CLOCK,
            physical_version: busbar_contract::persistence::PHYSICAL_VERSION,
            durability: Durability::Local,
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            if request.dataset != DATASET {
                return Err(Failure::Refused);
            }
            if request.time.is_some_and(|guard| !guard.permits(1)) {
                return Ok(ReadResult::TimeGuardFailed {
                    observed_at: observed(),
                });
            }
            let state = self.state.lock().unwrap();
            Ok(ReadResult::Values {
                observed_at: observed(),
                values: request
                    .addresses
                    .iter()
                    .map(|address| state.rows.get(address).cloned())
                    .collect(),
            })
        })
    }
    fn scan(&self, _: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async { Err(Failure::Refused) })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { Ok(observed()) })
    }
    fn commit(&self, prepared: PreparedCandidate, key: CommitKey) -> Call<'_, Decision> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let digest = prepared.fingerprint();
            let candidate = prepared.candidate();
            // Slotted sends replay their recorded verdict; self-fenced sends record none.
            if let Some((_, prior)) = (!key.is_self_fenced())
                .then(|| state.receipts.iter().find(|(id, _)| id == &candidate.id))
                .flatten()
            {
                return Ok(if *prior == digest {
                    Decision::Applied(candidate.result.clone())
                } else {
                    Decision::OpIdConflict
                });
            }
            if candidate.id.dataset != DATASET {
                return Err(Failure::Refused);
            }
            let initialization = control::initialization(&prepared, DATASET);
            let blind = self.blind_initialize && initialization;
            // Initialize's emptiness proof ignores the import namespace (FIRST-START-TAKEOVER
            // §2.9 (b)).
            let fresh = !state
                .rows
                .keys()
                .any(|a| control::counts_toward_empty(NamespaceId(a.namespace)))
                && state.receipts.is_empty()
                && initialization;
            if !fresh && !blind {
                let seal = crate::seal::lend();
                let Some(root) = state
                    .rows
                    .get(&startup::root_address())
                    .and_then(|v| control::Dataset::decode(v.expose(&seal)))
                else {
                    return Ok(Decision::Fenced);
                };
                let writer = state
                    .rows
                    .get(&startup::writer_address(candidate.id.writer))
                    .and_then(|v| control::Writer::decode(v.expose(&seal)));
                if root.writer_epoch != candidate.id.writer_epoch
                    || !writer.is_some_and(|w| w.admits(candidate.id.execution_epoch))
                {
                    return Ok(Decision::Fenced);
                }
            }
            if !blind && candidate.time.is_some_and(|guard| !guard.permits(1)) {
                return Ok(Decision::TimeGuardFailed {
                    observed_at: observed(),
                });
            }
            if !blind {
                for predicate in &candidate.predicates {
                    let value = state.rows.get(&predicate.address);
                    let matches = match &predicate.expected {
                        ExpectedValue::Absent => value.is_none(),
                        ExpectedValue::Exact(expected) => value == Some(expected),
                    };
                    if !matches {
                        return Ok(Decision::ConditionConflict);
                    }
                }
            }
            for mutation in &candidate.mutations {
                match mutation {
                    Mutation::Put { address, value } => {
                        state.rows.insert(address.clone(), value.clone());
                    }
                    Mutation::Delete(address) => {
                        state.rows.remove(address);
                    }
                    Mutation::DeleteRange { .. } => return Err(Failure::Refused),
                }
            }
            if !key.is_self_fenced() {
                state.receipts.push((candidate.id, digest));
            }
            Ok(Decision::Applied(candidate.result.clone()))
        })
    }
}

struct Mocks {
    blind_initialize: bool,
}

#[async_trait::async_trait]
impl Fixture for Mocks {
    type Dataset = Arc<Mock>;
    async fn fresh(&self) -> Self::Dataset {
        Arc::new(Mock {
            state: Mutex::default(),
            blind_initialize: self.blind_initialize,
        })
    }
    async fn open(&self, dataset: &Self::Dataset) -> Arc<dyn PersistenceBackend> {
        dataset.clone()
    }
}

#[async_trait::async_trait]
impl DurableFixture for Mocks {
    async fn seed(
        &self,
        dataset: &Self::Dataset,
        namespace: NamespaceId,
        key: &[u8],
        value: &[u8],
    ) {
        dataset.state.lock().unwrap().rows.insert(
            Address {
                namespace: namespace.0,
                key: key.to_vec(),
            },
            Secret::new(value.to_vec()),
        );
    }
}

/// The memory product store, but every read answers "absent": a store that misreports reads.
struct EmptyReads(Arc<dyn PersistenceBackend>);

impl PersistenceBackend for EmptyReads {
    fn info(&self) -> BackendInfo {
        self.0.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            match self.0.read(request).await? {
                ReadResult::Values {
                    observed_at,
                    values,
                } => Ok(ReadResult::Values {
                    observed_at,
                    values: values.iter().map(|_| None).collect(),
                }),
                other => Ok(other),
            }
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.0.scan(request)
    }
    fn commit(&self, candidate: PreparedCandidate, key: CommitKey) -> Call<'_, Decision> {
        self.0.commit(candidate, key)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.0.clock(dataset)
    }
}

struct MisreportingMemory;

#[async_trait::async_trait]
impl Fixture for MisreportingMemory {
    type Dataset = Arc<dyn PersistenceBackend>;
    async fn fresh(&self) -> Self::Dataset {
        Arc::new(EmptyReads(crate::real_store::native_backend().await))
    }
    async fn open(&self, dataset: &Self::Dataset) -> Arc<dyn PersistenceBackend> {
        dataset.clone()
    }
}

async fn fails<T>(case: impl std::future::Future<Output = T>) -> bool {
    AssertUnwindSafe(case).catch_unwind().await.is_err()
}

#[tokio::test]
async fn the_memory_product_store_passes_the_kit() {
    run(&Memory).await;
}

#[tokio::test]
async fn a_correct_store_passes_the_kit() {
    run(&Mocks {
        blind_initialize: false,
    })
    .await;
    run_durable(&Mocks {
        blind_initialize: false,
    })
    .await;
}

/// T11 alone over the correct mock store, so its red-before-green proof names one test.
#[tokio::test]
async fn a_correct_store_hands_over_at_once_after_abandon() {
    t11_abandon_hands_over(&Mocks {
        blind_initialize: false,
    })
    .await;
}

#[tokio::test]
async fn the_kit_fails_a_store_that_applies_initialize_blindly() {
    let blind = Mocks {
        blind_initialize: true,
    };
    assert!(
        fails(k3_racing_initialize(&blind)).await,
        "K3 must fail a store whose second Initialize overwrites the first"
    );
}

#[tokio::test]
async fn the_kit_fails_a_store_that_misreports_reads() {
    assert!(
        fails(k1_first_start_publication(&MisreportingMemory)).await,
        "K1 must fail a store that answers every read with absent values"
    );
}
