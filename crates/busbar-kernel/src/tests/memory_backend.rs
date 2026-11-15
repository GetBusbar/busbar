// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN IN-TREE PRIMITIVE STORE for core's own tests (owner ruling: "core is built and tested solo").
//!
//! Core's store-backed tests used to load the busbar-store-memory product cdylib
//! (`BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN`, settings `{}`), which core no longer builds. This is the
//! same contract behind [`PersistenceBackend`], in memory, keeping that product's observable rules:
//! an ephemeral dataset with a fresh identity per backend; reads and commits judged against the
//! dataset and their time guard; the execution fence (dataset root and writer records in
//! [`control::NAMESPACE`]) checked before anything else on every commit but the proven-empty
//! initialization; control records only conditionally replaced, never deleted; generation records
//! adapter-owned; one generation step per mutated namespace per commit; scans that refuse empty
//! limits, report a changed namespace as [`Failure::StaleScan`] unless the scan allows change, and
//! refuse a first row larger than the page; an operation id replayed by fingerprint.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::persistence::{
    control, Address, BackendInfo, Call, ClockObservation, CommitKey, DatasetId, Decision,
    Durability, ExpectedValue, Failure, Mutation, Page, PersistenceBackend, PreparedCandidate,
    Read, ReadResult, Scan,
};
use busbar_contract::Secret;

/// The product's physical layout version (the store SDK's slot layout).
const PHYSICAL_VERSION: u32 = busbar_contract::abi::sdk::store::v4::slot::PHYSICAL_VERSION;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A nonzero identity no other backend in this process holds.
fn identity(role: u8) -> [u8; 16] {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut id = [0; 16];
    id[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    id[8..12].copy_from_slice(&std::process::id().to_le_bytes());
    id[12] = role;
    id[15] = 0xb5;
    id
}

#[derive(Default)]
struct State {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    generations: HashMap<[u8; 16], u64>,
    receipts: HashMap<[u8; 16], [u8; 32]>,
}

impl State {
    /// The record at `at` as a reader or a predicate sees it: a generation record is the
    /// adapter-owned count of commits that mutated the namespace its key names (absent while none
    /// has), every other record is the row itself.
    fn value(&self, at: &Address) -> Option<Secret<Vec<u8>>> {
        if at.namespace != control::GENERATION_NAMESPACE.0 {
            return self.rows.get(at).cloned();
        }
        let namespace: [u8; 16] = at.key.as_slice().try_into().ok()?;
        self.generations
            .get(&namespace)
            .copied()
            .filter(|n| *n > 0)
            .map(|n| Secret::new(n.to_le_bytes().to_vec()))
    }
}

/// One ephemeral dataset.
pub(crate) struct MemoryBackend {
    info: BackendInfo,
    state: Mutex<State>,
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self {
            info: BackendInfo {
                dataset: DatasetId(identity(1)),
                atomic_domain: identity(2),
                clock_authority: identity(3),
                physical_version: PHYSICAL_VERSION,
                durability: Durability::Ephemeral,
            },
            state: Mutex::new(State::default()),
        }
    }
}

impl MemoryBackend {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn observed(&self) -> ClockObservation {
        ClockObservation {
            authority: self.info.clock_authority,
            unix_seconds: now(),
        }
    }

    fn dataset(&self, dataset: DatasetId) -> Result<(), Failure> {
        if dataset == self.info.dataset {
            Ok(())
        } else {
            Err(Failure::Refused)
        }
    }

    fn commit_now(&self, prepared: &PreparedCandidate) -> Result<Decision, Failure> {
        let seal = busbar_kernel::seal::lend();
        let candidate = prepared.candidate();
        self.dataset(candidate.id.dataset)?;
        let mut state = self.state();
        let observed_at = self.observed();
        if let Some(digest) = state.receipts.get(&candidate.id.operation) {
            return Ok(if *digest == prepared.fingerprint() {
                Decision::Applied(candidate.result.clone())
            } else {
                Decision::OpIdConflict
            });
        }
        let get = |state: &State, namespace: [u8; 16], key: &[u8]| {
            state
                .rows
                .get(&Address {
                    namespace,
                    key: key.to_vec(),
                })
                .map(|value| value.expose(&seal).clone())
        };
        let fresh = state.rows.is_empty()
            && state.receipts.is_empty()
            && control::initialization(prepared, self.info.dataset);
        if !fresh {
            let Some(root) = get(&state, control::NAMESPACE.0, control::DATASET_KEY) else {
                return Ok(Decision::Fenced);
            };
            let root = control::Dataset::decode(&root).ok_or(Failure::Corrupt)?;
            if root.id != self.info.dataset {
                return Err(Failure::Corrupt);
            }
            let Some(writer) = get(
                &state,
                control::NAMESPACE.0,
                &control::writer_key(candidate.id.writer),
            ) else {
                return Ok(Decision::Fenced);
            };
            let writer = control::Writer::decode(&writer).ok_or(Failure::Corrupt)?;
            if root.writer_epoch != candidate.id.writer_epoch
                || !writer.admits(candidate.id.execution_epoch)
            {
                return Ok(Decision::Fenced);
            }
        }
        if candidate
            .time
            .is_some_and(|guard| !guard.permits(observed_at.unix_seconds))
        {
            return Ok(Decision::TimeGuardFailed { observed_at });
        }
        for predicate in &candidate.predicates {
            let found = state.value(&predicate.address);
            let matches = match &predicate.expected {
                ExpectedValue::Absent => found.is_none(),
                ExpectedValue::Exact(bytes) => found.as_ref() == Some(bytes),
            };
            if !matches {
                return Ok(Decision::ConditionConflict);
            }
        }
        for mutation in &candidate.mutations {
            let (namespace, key, value) = match mutation {
                Mutation::Put { address, value } => {
                    (address.namespace, Some(&address.key), Some(value))
                }
                Mutation::Delete(at) => (at.namespace, Some(&at.key), None),
                Mutation::DeleteRange { namespace, .. } => (namespace.0, None, None),
            };
            if namespace == control::GENERATION_NAMESPACE.0 {
                return Err(Failure::Refused);
            }
            if namespace == control::NAMESPACE.0 && !fresh {
                let key = key.ok_or(Failure::Refused)?;
                let value = value.ok_or(Failure::Refused)?;
                let known = control::Key::decode(key).ok_or(Failure::Refused)?;
                let old = get(&state, namespace, key);
                let explicit = candidate.predicates.iter().any(|predicate| {
                    predicate.address.namespace == namespace
                        && predicate.address.key == *key
                        && match (&predicate.expected, &old) {
                            (ExpectedValue::Absent, None) => true,
                            (ExpectedValue::Exact(expected), Some(old)) => {
                                expected.expose(&seal) == old
                            }
                            _ => false,
                        }
                });
                if !explicit {
                    return Err(Failure::Refused);
                }
                control::replacement(
                    known,
                    self.info.dataset,
                    old.as_deref(),
                    value.expose(&seal),
                )?;
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
                            && u64::try_from(at.key.len()).is_ok_and(|n| n == *exact_key_length))
                    });
                }
            }
        }
        for namespace in changed {
            let generation = state.generations.entry(namespace).or_default();
            *generation = generation.checked_add(1).ok_or(Failure::Refused)?;
        }
        state
            .receipts
            .insert(candidate.id.operation, prepared.fingerprint());
        Ok(Decision::Applied(candidate.result.clone()))
    }
}

impl PersistenceBackend for MemoryBackend {
    fn info(&self) -> BackendInfo {
        self.info
    }

    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            self.dataset(request.dataset)?;
            let observed_at = self.observed();
            if request
                .time
                .is_some_and(|guard| !guard.permits(observed_at.unix_seconds))
            {
                return Ok(ReadResult::TimeGuardFailed { observed_at });
            }
            let state = self.state();
            Ok(ReadResult::Values {
                observed_at,
                values: request.addresses.iter().map(|at| state.value(at)).collect(),
            })
        })
    }

    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            self.dataset(request.dataset)?;
            if request.max_items == 0
                || request.max_bytes == 0
                || (!request.allow_change
                    && request.after.is_some()
                    && request.generation.is_none())
            {
                return Err(Failure::Refused);
            }
            let seal = busbar_kernel::seal::lend();
            let state = self.state();
            let generation = state
                .generations
                .get(&request.namespace.0)
                .copied()
                .unwrap_or(0);
            if !request.allow_change && request.generation.is_some_and(|n| n != generation) {
                return Err(Failure::StaleScan);
            }
            let mut used = 0usize;
            let mut rows = Vec::new();
            let mut more = false;
            for (at, value) in &state.rows {
                if at.namespace != request.namespace.0
                    || !at.key.starts_with(&request.prefix)
                    || request.after.as_ref().is_some_and(|after| &at.key <= after)
                {
                    continue;
                }
                let size = at.key.len() + value.expose(&seal).len();
                if rows.len() == request.max_items || size > request.max_bytes - used {
                    more = true;
                    break;
                }
                used += size;
                rows.push((at.clone(), value.clone()));
            }
            if more && rows.is_empty() {
                return Err(Failure::Refused);
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

    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async move {
            self.dataset(dataset)?;
            Ok(self.observed())
        })
    }

    fn commit(&self, prepared: PreparedCandidate, _: CommitKey) -> Call<'_, Decision> {
        Box::pin(async move { self.commit_now(&prepared) })
    }
}
