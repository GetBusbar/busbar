// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Native control/conditional/slot fixture; all state survives dropping owners.

use super::*;
use crate::persistence::facade::{Limits, WriterAuthority};
use busbar_contract::persistence::{
    control, BackendInfo, Call, ClockObservation, CommitKey, DatasetId, Failure, Page,
    PersistenceBackend, Read, ReadResult, Scan,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};

/// The fixture's slot rows, keyed as the native store keys them.
type SlotKey = ([u8; 16], u64, u32);
type SlotRow = (u64, [u8; 32], bool);

#[derive(Default)]
struct Native {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    generations: BTreeMap<[u8; 16], u64>,
    slots: BTreeMap<SlotKey, SlotRow>,
    sent: Vec<[u8; 32]>,
}
pub(crate) struct Backend {
    state: Mutex<Native>,
    pub(super) hang: AtomicBool,
    pub(super) hang_read: AtomicBool,
    pub(super) lose_reply: AtomicBool,
}
fn control_at(key: Vec<u8>) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key,
    }
}
impl Backend {
    pub(crate) fn new() -> Self {
        let mut state = Native::default();
        state.rows.insert(
            control_at(control::DATASET_KEY.to_vec()),
            Secret::new(
                control::Dataset {
                    id: DatasetId([1; 16]),
                    writer_epoch: 1,
                }
                .encode()
                .unwrap()
                .to_vec(),
            ),
        );
        Self {
            state: Mutex::new(state),
            hang: AtomicBool::new(false),
            hang_read: AtomicBool::new(false),
            lose_reply: AtomicBool::new(false),
        }
    }
    pub(crate) async fn attach(self: &Arc<Self>, writer: u8) -> Arc<CoreStore> {
        self.state.lock().unwrap().rows.insert(
            control_at(control::writer_key([writer; 16]).to_vec()),
            Secret::new(
                control::Writer {
                    retired_through: 0,
                    admitted_through: 1,
                }
                .encode()
                .unwrap()
                .to_vec(),
            ),
        );
        self.lease(writer, 0);
        Arc::new(
            CoreStore::attach(
                self.clone(),
                WriterAuthority {
                    writer_epoch: 1,
                    writer: [writer; 16],
                    execution_epoch: 1,
                },
                Limits {
                    pending_operations: 8,
                    conflict_retries: 2,
                    scan_items: 4,
                    scan_bytes: 262144,
                },
            )
            .await
            .unwrap(),
        )
    }
    pub(super) fn lease(&self, writer: u8, expires: u64) {
        let key = [b"writer:".as_slice(), &1u64.to_be_bytes(), &[writer; 16]].concat();
        let address = scoped::migration_address(
            true,
            crate::persistence::boot_identity::INSTANCE,
            crate::persistence::boot_identity::NODE_SCHEMA,
            &key,
        )
        .unwrap();
        self.state.lock().unwrap().rows.insert(
            address,
            Secret::new([&[writer; 16][..], &expires.to_be_bytes()].concat()),
        );
    }
    pub(super) fn closed(&self, writer: u8) -> bool {
        let state = self.state.lock().unwrap();
        let bytes = state
            .rows
            .get(&control_at(control::writer_key([writer; 16]).to_vec()))
            .unwrap();
        !control::Writer::decode(bytes.expose(&crate::seal::lend()))
            .unwrap()
            .admits(1)
    }
    pub(super) fn calls(&self) -> usize {
        self.state.lock().unwrap().sent.len()
    }
    pub(super) fn sent(&self) -> Vec<[u8; 32]> {
        self.state.lock().unwrap().sent.clone()
    }
    pub(super) fn contains_plaintext(&self, needle: &[u8]) -> bool {
        self.state.lock().unwrap().rows.values().any(|v| {
            v.expose(&crate::seal::lend())
                .windows(needle.len())
                .any(|w| w == needle)
        })
    }
}
fn clock() -> ClockObservation {
    ClockObservation {
        authority: [3; 16],
        unix_seconds: 10,
    }
}
fn value(state: &Native, address: &Address) -> Option<Secret<Vec<u8>>> {
    if address.namespace == control::GENERATION_NAMESPACE.0 {
        let namespace: [u8; 16] = address.key.as_slice().try_into().ok()?;
        return state
            .generations
            .get(&namespace)
            .map(|g| Secret::new(g.to_le_bytes().to_vec()));
    }
    state.rows.get(address).cloned()
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
            if self.hang_read.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let state = self.state.lock().unwrap();
            Ok(ReadResult::Values {
                observed_at: clock(),
                values: request.addresses.iter().map(|a| value(&state, a)).collect(),
            })
        })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { Ok(clock()) })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            let state = self.state.lock().unwrap();
            let generation = *state.generations.get(&request.namespace.0).unwrap_or(&0);
            if request.generation.is_some_and(|g| g != generation) {
                return Err(Failure::StaleScan);
            }
            let mut rows = Vec::new();
            let mut bytes = 0;
            let mut more = false;
            for (at, v) in &state.rows {
                if at.namespace != request.namespace.0
                    || !at.key.starts_with(&request.prefix)
                    || request.after.as_ref().is_some_and(|a| a >= &at.key)
                {
                    continue;
                }
                bytes += at.key.len() + v.expose(&crate::seal::lend()).len();
                if rows.len() == request.max_items || bytes > request.max_bytes {
                    more = true;
                    break;
                }
                rows.push((at.clone(), v.clone()));
            }
            let next = if more {
                rows.last().map(|(a, _)| a.key.clone())
            } else {
                None
            };
            Ok(Page {
                generation,
                rows,
                next,
            })
        })
    }
    fn commit(&self, prepared: PreparedCandidate, key: CommitKey) -> Call<'_, Decision> {
        self.state.lock().unwrap().sent.push(prepared.fingerprint());
        Box::pin(async move {
            if self.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let mut state = self.state.lock().unwrap();
            let body = prepared.candidate();
            let writer = state
                .rows
                .get(&control_at(control::writer_key(body.id.writer).to_vec()))
                .and_then(|v| control::Writer::decode(v.expose(&crate::seal::lend())));
            if body.id.dataset != self.info().dataset
                || body.id.writer_epoch != 1
                || !writer.is_some_and(|w| w.admits(body.id.execution_epoch))
            {
                return Ok(Decision::Fenced);
            }
            let (slot, sequence) = key.wire();
            let at = (body.id.writer, body.id.execution_epoch, slot);
            if let Some((prior, digest, applied)) = state.slots.get(&at) {
                if *prior > sequence {
                    return Ok(Decision::Stale);
                }
                if *prior == sequence {
                    return Ok(if *digest != prepared.fingerprint() {
                        Decision::OpIdConflict
                    } else if *applied {
                        Decision::Applied(Secret::default())
                    } else {
                        Decision::ConditionConflict
                    });
                }
            }
            if body.time.is_some_and(|g| !g.permits(clock().unix_seconds)) {
                return Ok(Decision::TimeGuardFailed {
                    observed_at: clock(),
                });
            }
            let matches = body.predicates.iter().all(|p| match &p.expected {
                ExpectedValue::Absent => value(&state, &p.address).is_none(),
                ExpectedValue::Exact(v) => value(&state, &p.address).as_ref() == Some(v),
            });
            state
                .slots
                .insert(at, (sequence, prepared.fingerprint(), matches));
            if !matches {
                return Ok(Decision::ConditionConflict);
            }
            let mut changed = BTreeSet::new();
            for mutation in &body.mutations {
                match mutation {
                    Mutation::Put { address, value } => {
                        changed.insert(address.namespace);
                        state.rows.insert(address.clone(), value.clone());
                    }
                    Mutation::Delete(address) => {
                        changed.insert(address.namespace);
                        state.rows.remove(address);
                    }
                    // The one range delete here is a closed writer's slot cleanup, part of the
                    // shared writer transition a fence carries (D299 3853418ae9, retained in the
                    // retirement candidate since d01322db5f). Caller intents use none.
                    Mutation::DeleteRange {
                        namespace,
                        prefix,
                        exact_key_length,
                    } => {
                        assert_eq!(
                            *namespace,
                            control::SLOT_NS,
                            "caller intent uses no range deletion"
                        );
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
            if self.lose_reply.swap(false, Ordering::SeqCst) {
                return Err(Failure::Unknown);
            }
            Ok(Decision::Applied(Secret::default()))
        })
    }
}
