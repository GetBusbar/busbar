// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::facade::{Limits, WriterAuthority};
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Durability, Page, PersistenceBackend, Scan,
    control,
};
use busbar_contract::records::ModelTokensDelta;
use std::sync::Mutex;

// Atomic in-memory fixture for this owner's predicates, generations and immutable attempts.
// It is deliberately not a production Store or a carrier implementation.
struct AttemptReceipt {
    digest: [u8; 32],
    result: Secret<Vec<u8>>,
}
#[derive(Default)]
struct State {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    generations: BTreeMap<[u8; 16], u64>,
    receipts: BTreeMap<[u8; 16], AttemptReceipt>,
    attempts: Vec<[u8; 16]>,
    reads: Vec<usize>,
    last_predicates: Vec<Address>,
    unknown: bool,
    conflict: bool,
    race_meter: bool,
    race_usage_index: bool,
}
#[derive(Default)]
struct Backend(Mutex<State>);
impl Backend {
    fn now(&self) -> ClockObservation {
        ClockObservation {
            authority: [3; 16],
            unix_seconds: 1234,
        }
    }
}
impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 1,
            durability: Durability::Ephemeral,
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let mut state = self.0.lock().unwrap();
            state.reads.push(request.addresses.len());
            let values = request
                .addresses
                .iter()
                .map(|at| {
                    if at.namespace == control::NAMESPACE.0 {
                        Some(Secret::new(if at.key == control::DATASET_KEY {
                            control::Dataset {
                                id: self.info().dataset,
                                writer_epoch: 1,
                            }
                            .encode()
                            .unwrap()
                            .to_vec()
                        } else {
                            control::Writer {
                                retired_through: 0,
                                admitted_through: 1,
                            }
                            .encode()
                            .unwrap()
                            .to_vec()
                        }))
                    } else if at.namespace == control::GENERATION_NAMESPACE.0 {
                        let ns: [u8; 16] = at.key.as_slice().try_into().unwrap();
                        state
                            .generations
                            .get(&ns)
                            .filter(|g| **g != 0)
                            .map(|g| Secret::new(g.to_le_bytes().to_vec()))
                    } else {
                        state.rows.get(at).cloned()
                    }
                })
                .collect();
            Ok(ReadResult::Values {
                observed_at: self.now(),
                values,
            })
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            let state = self.0.lock().unwrap();
            let generation = *state.generations.get(&request.namespace.0).unwrap_or(&0);
            if request.generation.is_some_and(|g| g != generation) {
                return Err(Failure::StaleScan);
            }
            let mut eligible = state.rows.iter().filter(|(at, _)| {
                at.namespace == request.namespace.0
                    && at.key.starts_with(&request.prefix)
                    && request.after.as_ref().is_none_or(|p| &at.key > p)
            });
            let rows: Vec<_> = eligible
                .by_ref()
                .take(request.max_items)
                .map(|(at, v)| (at.clone(), v.clone()))
                .collect();
            let next = eligible
                .next()
                .and_then(|_| rows.last().map(|(at, _)| at.key.clone()));
            Ok(Page {
                generation,
                rows,
                next,
            })
        })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { Ok(self.now()) })
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let mut state = self.0.lock().unwrap();
            let c = prepared.candidate();
            let digest = prepared.fingerprint();
            state.attempts.push(c.id.operation);
            state.last_predicates = c.predicates.iter().map(|p| p.address.clone()).collect();
            if let Some(found) = state.receipts.get(&c.id.operation) {
                return Ok(if found.digest == digest {
                    Decision::Applied(found.result.clone())
                } else {
                    Decision::OpIdConflict
                });
            }
            if state.conflict {
                state.conflict = false;
                return Ok(Decision::ConditionConflict);
            }
            if state.race_meter {
                state.race_meter = false;
                let d = meter("key", 1);
                let mut row = empty_meter(&d);
                row.checked_add_delta(&d).unwrap();
                state.rows.insert(
                    meter_address(1, &row).unwrap(),
                    Secret::new(encode(&row).unwrap()),
                );
                *state
                    .generations
                    .entry(time_namespace(METERING, 1).0)
                    .or_default() += 1;
                if state
                    .rows
                    .insert(
                        index_address(METERING, 1).unwrap(),
                        Secret::new(index_bytes(1)),
                    )
                    .is_none()
                {
                    *state.generations.entry(METERING.0).or_default() += 1;
                }
            }
            if state.race_usage_index {
                state.race_usage_index = false;
                let mut row = UsageLedger::default();
                row.checked_apply_delta(&delta(1)).unwrap();
                state.rows.insert(
                    usage_address("raced", 2).unwrap(),
                    Secret::new(encode(&row).unwrap()),
                );
                state.rows.insert(
                    index_address(USAGE, 2).unwrap(),
                    Secret::new(index_bytes(2)),
                );
                *state.generations.entry(USAGE.0).or_default() += 1;
                *state
                    .generations
                    .entry(time_namespace(USAGE, 2).0)
                    .or_default() += 1;
            }
            let seal = crate::seal::lend();
            for p in &c.predicates {
                let generation;
                let actual = if p.address.namespace == control::GENERATION_NAMESPACE.0 {
                    let ns: [u8; 16] = p.address.key.as_slice().try_into().unwrap();
                    generation = state
                        .generations
                        .get(&ns)
                        .filter(|g| **g != 0)
                        .map(|g| g.to_le_bytes().to_vec());
                    generation.as_ref()
                } else {
                    state.rows.get(&p.address).map(|v| v.expose(&seal))
                };
                let expected = match &p.expected {
                    ExpectedValue::Absent => None,
                    ExpectedValue::Exact(v) => Some(v.expose(&seal)),
                };
                if actual != expected {
                    return Ok(Decision::ConditionConflict);
                }
            }
            let mut touched = std::collections::BTreeSet::new();
            for m in &c.mutations {
                match m {
                    Mutation::Put { address, value } => {
                        touched.insert(address.namespace);
                        state.rows.insert(address.clone(), value.clone());
                    }
                    Mutation::Delete(at) => {
                        touched.insert(at.namespace);
                        state.rows.remove(at);
                    }
                    _ => panic!("ledger uses point writes"),
                }
            }
            for ns in touched {
                *state.generations.entry(ns).or_default() += 1;
            }
            state.receipts.insert(
                c.id.operation,
                AttemptReceipt {
                    digest,
                    result: c.result.clone(),
                },
            );
            if state.unknown {
                state.unknown = false;
                return Err(Failure::Unknown);
            }
            Ok(Decision::Applied(c.result.clone()))
        })
    }
}
async fn attach(backend: Arc<Backend>) -> CoreStore {
    CoreStore::attach(
        backend,
        WriterAuthority {
            writer_epoch: 1,
            writer: [4; 16],
            execution_epoch: 1,
        },
        Limits {
            pending_operations: 16,
            conflict_retries: 2,
            scan_items: 2,
            scan_bytes: 100_000,
        },
    )
    .await
    .unwrap()
}
fn delta(amount: i128) -> UsageDelta {
    UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            scale: 6,
            model: "model".into(),
            usage_units: BTreeMap::from([("input".into(), amount)]),
        }],
    }
}
fn meter(key: &str, bucket: u64) -> MeteringDelta {
    MeteringDelta {
        scale: 6,
        key_id: key.into(),
        bucket,
        model: "model".into(),
        provider: "provider".into(),
        tokens_input: 1,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "group".into(),
        pricing_version: "version".into(),
        priced_from_ms: 123,
        usage_units: BTreeMap::new(),
    }
}
#[tokio::test]
async fn overflow_is_atomic_and_rejected_batch_has_no_receipt() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    store
        .ledger()
        .add_usage("b", 1, &delta(i128::MAX))
        .await
        .unwrap();
    let before = store.ledger().get_usage("b", 1).await.unwrap();
    let cells = [("a", 1, delta(5)), ("b", 1, delta(1))];
    assert!(
        store
            .ledger()
            .add_usage_batch_deduped(OpId([8; 16]), &cells)
            .await
            .is_err()
    );
    assert_eq!(store.ledger().get_usage("b", 1).await.unwrap(), before);
    assert_eq!(
        store.ledger().get_usage("a", 1).await.unwrap(),
        UsageLedger::default()
    );
    assert_eq!(backend.0.lock().unwrap().receipts.len(), 1);
}
#[tokio::test]
async fn logical_receipt_survives_attachment_and_preserves_original_body() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let op = OpId([8; 16]);
    let cells = [("b", 1, delta(5))];
    backend.0.lock().unwrap().conflict = true;
    store
        .ledger()
        .add_usage_batch_deduped(op, &cells)
        .await
        .unwrap();
    {
        let state = backend.0.lock().unwrap();
        assert_eq!(state.attempts.len(), 2);
        assert_ne!(state.attempts[0], state.attempts[1]);
    }
    let replacement = attach(backend.clone()).await;
    replacement
        .ledger()
        .add_usage_batch_deduped(op, &cells)
        .await
        .unwrap();
    assert_eq!(
        replacement
            .ledger()
            .get_usage("b", 1)
            .await
            .unwrap()
            .requests,
        1
    );
    let mut changed = cells.clone();
    changed[0].2.models[0].scale = 0;
    assert!(
        replacement
            .ledger()
            .add_usage_batch_deduped(op, &changed)
            .await
            .is_err()
    );
    assert_eq!(backend.0.lock().unwrap().attempts.len(), 2);
}
#[tokio::test]
async fn unknown_replays_exact_attempt_before_planning() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    backend.0.lock().unwrap().unknown = true;
    let op = OpId([8; 16]);
    let cells = [("b", 1, delta(5))];
    let err = store
        .ledger()
        .add_usage_batch_deduped(op, &cells)
        .await
        .unwrap_err();
    assert!(err.0.contains("retained operation"));
    assert!(
        store
            .ledger()
            .add_usage_batch_deduped(op, &[("b", 1, delta(6))])
            .await
            .is_err()
    );
    store
        .ledger()
        .add_usage_batch_deduped(op, &cells)
        .await
        .unwrap();
    assert_eq!(store.ledger().get_usage("b", 1).await.unwrap().requests, 1);
    let state = backend.0.lock().unwrap();
    assert_eq!(state.attempts.len(), 2);
    assert_eq!(state.attempts[0], state.attempts[1]);
}
#[tokio::test]
async fn scans_all_pages_and_prunes_dated_usage_without_receipt_gc() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    for key in ["a", "long-name", "z", "xy", "third"] {
        store.ledger().add_metering(&meter(key, 1)).await.unwrap();
    }
    let rows = store.ledger().list_metering(1).await.unwrap();
    assert_eq!(
        rows.iter().map(|r| r.key_id.as_str()).collect::<Vec<_>>(),
        vec!["a", "long-name", "third", "xy", "z"]
    );
    for window in 0..5 {
        store
            .ledger()
            .add_usage_batch_deduped(OpId::from_parts(9, window), &[("b", window, delta(1))])
            .await
            .unwrap();
    }
    assert_eq!(store.ledger().prune_usage_before(4).await.unwrap(), 3);
    assert_eq!(store.ledger().get_usage("b", 0).await.unwrap().requests, 1);
    assert_eq!(store.ledger().get_usage("b", 4).await.unwrap().requests, 1);
    assert_eq!(store.ledger().prune_metering_before(2).await.unwrap(), 5);
    assert_eq!(store.ledger().prune_metering_before(2).await.unwrap(), 0);
    assert_eq!(store.ledger().prune_usage_before(4).await.unwrap(), 0);
    let receipt_count = backend
        .0
        .lock()
        .unwrap()
        .rows
        .keys()
        .filter(|at| at.key.first() == Some(&b'R'))
        .count();
    assert_eq!(receipt_count, 5);
}
#[test]
fn canonical_records_reject_unknown_versions_nested_fields_and_retain_i128() {
    let mut row = UsageLedger::default();
    row.checked_apply_delta(&delta(i128::MAX)).unwrap();
    let bytes = encode(&row).unwrap();
    assert_eq!(
        decode::<UsageLedger>(&Secret::new(bytes.clone())).unwrap(),
        row
    );
    let text = String::from_utf8(bytes).unwrap();
    let reordered = text.replacen("{\"version\":1,\"record\":", "{ \"record\" : ", 1);
    let reordered = format!("{}, \"version\":1 }}", &reordered[..reordered.len() - 1]);
    assert_eq!(
        decode::<UsageLedger>(&Secret::new(reordered.into_bytes())).unwrap(),
        row
    );
    assert!(
        decode::<UsageLedger>(&Secret::new(
            text.replace("\"version\":1", "\"version\":2").into_bytes()
        ))
        .is_err()
    );
    assert!(
        decode::<UsageLedger>(&Secret::new(
            text.replace("\"requests\":1", "\"unknown\":1,\"requests\":1")
                .into_bytes()
        ))
        .is_err()
    );
}

#[tokio::test]
async fn correction_guards_complete_selection_and_usage_prestate() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let key = busbar_contract::records::VirtualKey {
        id: "key".into(),
        enabled: true,
        ..Default::default()
    };
    backend.0.lock().unwrap().rows.insert(
        super::super::identity::key_address("key").unwrap(),
        Secret::new(encode(&key).unwrap()),
    );
    let mut replacement = UsageLedger::default();
    replacement.checked_apply_delta(&delta(50)).unwrap();
    let request = correction::Request {
        version: 1,
        op_id: OpId([7; 16]),
        key_id: "key".into(),
        day_start: 1,
        metering: vec![],
        usage: vec![correction::UsageChange {
            address: correction::UsageAddress {
                bucket_id: "b".into(),
                window_start: 1,
            },
            expected: UsageLedger::default(),
            replacement,
        }],
    };
    backend.0.lock().unwrap().race_meter = true;
    backend.0.lock().unwrap().reads.clear();
    assert_eq!(
        store
            .ledger()
            .apply_usage_correction(&request)
            .await
            .unwrap(),
        correction::Decision::ConditionConflict
    );
    assert_eq!(backend.0.lock().unwrap().reads, vec![4, 4]);
    assert_eq!(
        store.ledger().get_usage("b", 1).await.unwrap(),
        UsageLedger::default()
    );
    assert_eq!(backend.0.lock().unwrap().attempts.len(), 1);
    let mut current = request.clone();
    current.metering = store.ledger().list_metering(1).await.unwrap();
    current.op_id = OpId([6; 16]);
    assert_eq!(
        store
            .ledger()
            .apply_usage_correction(&current)
            .await
            .unwrap(),
        correction::Decision::Applied
    );
    assert_eq!(
        store
            .ledger()
            .apply_usage_correction(&current)
            .await
            .unwrap(),
        correction::Decision::Applied
    );
    assert_eq!(store.ledger().get_usage("b", 1).await.unwrap().requests, 1);
    let mut mismatch = current.clone();
    mismatch.op_id = OpId([5; 16]);
    assert_eq!(
        store
            .ledger()
            .apply_usage_correction(&mismatch)
            .await
            .unwrap(),
        correction::Decision::ConditionConflict
    );
}
#[tokio::test]
async fn sequential_refund_floor_and_metering_overflow_remain_atomic() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let mut refund = delta(-5);
    refund.requests = -5;
    refund.billable_requests = -5;
    store
        .ledger()
        .add_usage_batch_deduped(OpId([7; 16]), &[("b", 1, refund), ("b", 1, delta(3))])
        .await
        .unwrap();
    let row = store.ledger().get_usage("b", 1).await.unwrap();
    assert_eq!(row.requests, 1);
    assert_eq!(row.models[0].usage_units["input"], 3);
    let mut max = meter("max", 1);
    max.tokens_input = i128::MAX;
    store.ledger().add_metering(&max).await.unwrap();
    let mut one = max.clone();
    one.tokens_input = 1;
    assert!(
        store
            .ledger()
            .add_metering_batch_deduped(OpId([6; 16]), &[meter("new", 1), one])
            .await
            .is_err()
    );
    let rows = store.ledger().list_metering(1).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tokens_input, i128::MAX);
}

#[tokio::test]
async fn batches_prefetch_distinct_rows_once_and_keep_sequential_floor_order() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let names: Vec<_> = (0..40).map(|n| format!("key-{n}")).collect();
    let mut cells = Vec::new();
    for name in &names {
        let mut refund = delta(-10);
        refund.requests = -4;
        refund.billable_requests = -4;
        cells.extend([
            (name.as_str(), 1, delta(7)),
            (name.as_str(), 1, refund),
            (name.as_str(), 1, delta(3)),
        ]);
    }
    backend.0.lock().unwrap().reads.clear();
    store
        .ledger()
        .add_usage_batch_deduped(OpId([11; 16]), &cells)
        .await
        .unwrap();
    assert_eq!(backend.0.lock().unwrap().reads, vec![42]);
    for name in &names {
        let row = store.ledger().get_usage(name, 1).await.unwrap();
        assert_eq!(row.requests, 1);
        assert_eq!(row.billable_requests, 1);
        assert_eq!(row.models[0].usage_units["input"], 3);
    }
    let deltas: Vec<_> = names
        .iter()
        .flat_map(|name| [meter(name, 1), meter(name, 1)])
        .collect();
    backend.0.lock().unwrap().reads.clear();
    store
        .ledger()
        .add_metering_batch_deduped(OpId([12; 16]), &deltas)
        .await
        .unwrap();
    assert_eq!(backend.0.lock().unwrap().reads, vec![42]);
    let rows = store.ledger().list_metering(1).await.unwrap();
    assert_eq!(rows.len(), 40);
    assert!(
        rows.iter()
            .all(|row| row.tokens_input == 2 && row.requests == 2)
    );
    // A warm transaction must not issue additional reads for cached/changed rows.
    let mut tx = Tx::new(&store);
    let at = usage_address(&names[0], 1).unwrap();
    backend.0.lock().unwrap().reads.clear();
    tx.prefetch(vec![at.clone(), at.clone()]).await.unwrap();
    tx.put(at.clone(), &UsageLedger::default()).unwrap();
    tx.prefetch(vec![at]).await.unwrap();
    assert_eq!(backend.0.lock().unwrap().reads, vec![1]);
}

#[tokio::test]
async fn partitions_isolate_bucket_writes_and_keep_index_metadata_stable() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    store.ledger().add_usage("b", 1, &delta(1)).await.unwrap();
    store.ledger().add_usage("b", 2, &delta(1)).await.unwrap();
    assert_ne!(
        usage_address("b", 1).unwrap().namespace,
        usage_address("b", 2).unwrap().namespace
    );
    assert_ne!(usage_address("b", 1).unwrap().namespace, USAGE.0);
    let original_index_generation = backend.0.lock().unwrap().generations[&USAGE.0];
    store.ledger().add_usage("b", 1, &delta(1)).await.unwrap();
    {
        let state = backend.0.lock().unwrap();
        assert_eq!(state.generations[&USAGE.0], original_index_generation);
        assert!(
            state
                .last_predicates
                .iter()
                .all(|at| at.namespace != USAGE.0)
        );
        for time in [1, 2] {
            let at = index_address(USAGE, time).unwrap();
            assert_eq!(index_time(&at, &state.rows[&at], USAGE).unwrap(), time);
        }
    }
    for name in ["a", "b", "c", "d"] {
        store.ledger().add_metering(&meter(name, 1)).await.unwrap();
    }
    let namespace = time_namespace(METERING, 1);
    let prefix = keys::framed(b'M', &[&METERING.0, &1u64.to_be_bytes()]).unwrap();
    let first = backend
        .scan(Arc::new(Scan {
            dataset: store.info().dataset,
            namespace,
            prefix: prefix.clone(),
            after: None,
            generation: None,
            allow_change: false,
            max_items: 2,
            max_bytes: 100_000,
        }))
        .await
        .unwrap();
    assert!(first.next.is_some());
    // Creating another bucket changes the family index, but not this day scan.
    store
        .ledger()
        .add_metering(&meter("elsewhere", 2))
        .await
        .unwrap();
    let second = backend
        .scan(Arc::new(Scan {
            dataset: store.info().dataset,
            namespace,
            prefix,
            after: first.next,
            generation: Some(first.generation),
            allow_change: false,
            max_items: 2,
            max_bytes: 100_000,
        }))
        .await
        .unwrap();
    assert_eq!(second.rows.len(), 2);
    assert_eq!(second.generation, first.generation);
    let a = OpId::from_parts(77, 1);
    let b = OpId::from_parts(77, 2);
    let c = OpId::from_parts(78, 1);
    assert_eq!(
        receipt_address(a).unwrap().namespace,
        receipt_address(b).unwrap().namespace
    );
    assert_ne!(
        receipt_address(a).unwrap().key,
        receipt_address(b).unwrap().key
    );
    assert_ne!(
        receipt_address(a).unwrap().namespace,
        receipt_address(c).unwrap().namespace
    );
    assert_eq!(store.ledger().prune_usage_before(3).await.unwrap(), 2);
    let state = backend.0.lock().unwrap();
    assert!(state.rows.contains_key(&index_address(USAGE, 1).unwrap()));
    assert!(state.rows.contains_key(&index_address(USAGE, 2).unwrap()));
}

#[tokio::test]
async fn prune_replans_when_a_partition_is_created_after_index_scan() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    store
        .ledger()
        .add_usage("original", 1, &delta(1))
        .await
        .unwrap();
    backend.0.lock().unwrap().race_usage_index = true;
    assert_eq!(store.ledger().prune_usage_before(3).await.unwrap(), 2);
    assert_eq!(
        store.ledger().get_usage("original", 1).await.unwrap(),
        UsageLedger::default()
    );
    assert_eq!(
        store.ledger().get_usage("raced", 2).await.unwrap(),
        UsageLedger::default()
    );
    let state = backend.0.lock().unwrap();
    assert_eq!(state.attempts.len(), 3); // initial write, refused stale plan, atomic replacement plan
    assert!(state.rows.contains_key(&index_address(USAGE, 1).unwrap()));
    assert!(state.rows.contains_key(&index_address(USAGE, 2).unwrap()));
}
