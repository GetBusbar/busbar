// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::{commit::SubmitResult, facade::Limits};
use busbar_contract::persistence::{
    control, BackendInfo, Call, ClockObservation, Decision, Durability, Page, PersistenceBackend,
    Scan,
};
use busbar_kernel_wal::{journal::body_digest, RecordClass};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

#[derive(Default)]
struct State {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    receipts: HashMap<[u8; 16], [u8; 32]>,
    sent: Vec<PreparedCandidate>,
}
fn control_address(key: Vec<u8>) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key,
    }
}
fn row(state: &State, address: &Address) -> Option<Secret<Vec<u8>>> {
    if let Some(value) = state.rows.get(address) {
        return Some(value.clone());
    }
    if address.namespace != control::NAMESPACE.0 {
        return None;
    }
    let value = if address.key == control::DATASET_KEY {
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
    Some(Secret::new(value))
}
fn set_root_epoch(backend: &Backend, epoch: u64) {
    backend.state.lock().unwrap().rows.insert(
        control_address(control::DATASET_KEY.to_vec()),
        Secret::new(
            control::Dataset {
                id: DatasetId([1; 16]),
                writer_epoch: epoch,
            }
            .encode()
            .unwrap()
            .to_vec(),
        ),
    );
}
#[derive(Default)]
struct Backend {
    state: Mutex<State>,
    lose_reply: AtomicBool,
    expire_receipt: AtomicBool,
    hang: AtomicBool,
}
impl PersistenceBackend for Backend {
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
            let state = self.state.lock().unwrap();
            Ok(ReadResult::Values {
                observed_at: ClockObservation {
                    authority: [3; 16],
                    unix_seconds: 10,
                },
                values: request
                    .addresses
                    .iter()
                    .map(|address| row(&state, address))
                    .collect(),
            })
        })
    }
    fn scan(&self, _: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async { panic!("replay must walk the selected immutable prefix") })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        self.state.lock().unwrap().sent.push(prepared.clone());
        Box::pin(async move {
            if self.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let mut state = self.state.lock().unwrap();
            let candidate = prepared.candidate();
            if self.expire_receipt.swap(false, Ordering::SeqCst) {
                return Ok(Decision::ExpiredUnknown);
            }
            if let Some(digest) = state.receipts.get(&candidate.id.operation) {
                return Ok(if *digest == prepared.fingerprint() {
                    Decision::Applied(candidate.result.clone())
                } else {
                    Decision::OpIdConflict
                });
            }
            for predicate in &candidate.predicates {
                let found = row(&state, &predicate.address);
                if !match &predicate.expected {
                    ExpectedValue::Absent => found.is_none(),
                    ExpectedValue::Exact(value) => found.as_ref() == Some(value),
                } {
                    return Ok(Decision::ConditionConflict);
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
                    Mutation::DeleteRange { .. } => panic!("journal never uses range deletion"),
                }
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
async fn attach(backend: Arc<Backend>, writer: u8) -> CoreStore {
    attach_at(backend, writer, 2).await
}
async fn attach_at(backend: Arc<Backend>, writer: u8, writer_epoch: u64) -> CoreStore {
    CoreStore::attach(
        backend,
        WriterAuthority {
            writer_epoch,
            writer: [writer; 16],
            execution_epoch: 3,
        },
        Limits {
            pending_operations: 8,
            conflict_retries: 1,
            scan_items: 4,
            scan_bytes: 128 * 1024,
        },
    )
    .await
    .unwrap()
}
fn record(seq: u64, previous: [u8; 32], body: Vec<u8>) -> Record {
    let mut record = JournalRecord {
        class: RecordClass::Transaction,
        node: 7,
        node_seq: seq,
        lease_epoch: 9,
        policy_epoch: 11,
        wall: 13,
        mono: 17,
        body_hash: body_digest(&body),
        body,
        prev_hash: previous,
        hash: [0; 32],
    };
    record.hash = record.digest_of_chain();
    Record::new(7, seq, record.encode())
}
fn hash(record: &Record) -> [u8; 32] {
    JournalRecord::decode(&record.body).unwrap().hash
}

fn chain_break(seq: u64, previous: [u8; 32], before: u64, after: u64) -> Record {
    let note = busbar_kernel_wal::Quarantine {
        segment: 0,
        segment_file: None,
        offset: 0,
        damage_at: 0,
        bytes: 1,
        why: None,
        identities: vec![(7, before + 1)],
        unverified: Vec::new(),
        damaged: Vec::new(),
        at_unix_ms: 0,
        kept: busbar_kernel_wal::QuarantineKept::Memory,
        before: Some((7, before)),
        after: Some((7, after)),
    };
    let mut frame = JournalRecord::decode(&record(seq, previous, note.body()).body).unwrap();
    frame.class = RecordClass::ChainBreak;
    frame.hash = frame.digest_of_chain();
    Record::new(7, seq, frame.encode())
}

#[test]
fn historical_snapshot_preserves_original_prefix_and_quarantine_bridge() {
    use historical::{HistoricalSnapshot, SnapshotBudget};
    let first = record(8, [19; 32], vec![1]);
    let omitted = record(9, hash(&first), vec![2]);
    let after = record(10, hash(&omitted), vec![3]);
    let note = chain_break(11, hash(&after), 8, 10);
    let records = vec![first, after, note];
    let snapshot = HistoricalSnapshot::verify(
        7,
        records.clone(),
        SnapshotBudget {
            records: 3,
            bytes: 4096,
        },
    )
    .unwrap();
    assert_eq!(snapshot.node(), 7);
    assert_eq!(snapshot.first_previous(), [19; 32]);
    assert_eq!(snapshot.tail(), (11, hash(&records[2])));
    for (verified, original) in snapshot.records().iter().zip(&records) {
        assert_eq!(verified.body, original.body);
    }
    assert!(matches!(
        HistoricalSnapshot::verify(
            7,
            records[..2].to_vec(),
            SnapshotBudget {
                records: 3,
                bytes: 4096,
            }
        ),
        Err(Error::Verification(_))
    ));
}

#[test]
fn historical_snapshot_refuses_changed_frame_or_unverified_bridge_anchor() {
    use historical::{HistoricalSnapshot, SnapshotBudget};
    let budget = SnapshotBudget {
        records: 3,
        bytes: 4096,
    };
    let first = record(8, [19; 32], vec![1]);
    let after = record(10, [20; 32], vec![3]);
    let note = chain_break(11, hash(&after), 7, 10);
    assert!(matches!(
        HistoricalSnapshot::verify(7, vec![first.clone(), after, note], budget),
        Err(Error::Verification(_))
    ));
    let mut corrupt = first.clone();
    *corrupt.body.last_mut().unwrap() ^= 1;
    assert!(matches!(
        HistoricalSnapshot::verify(7, vec![corrupt], budget),
        Err(Error::Verification(_))
    ));
    assert!(matches!(
        HistoricalSnapshot::verify(
            7,
            vec![first],
            SnapshotBudget {
                records: 1,
                bytes: 1,
            }
        ),
        Err(Error::Budget)
    ));
}

#[tokio::test]
async fn store_snapshot_binds_historical_frames_to_exact_selected_head() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone(), 4).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let first = record(8, [19; 32], vec![1]);
    let after = record(10, [20; 32], vec![3]);
    let note = chain_break(11, hash(&after), 8, 10);
    let records = vec![first, after, note];
    // Fixture represents already imported original historical frames. This
    // deliberately does not claim that a normal append may create such a gap.
    {
        let mut state = backend.state.lock().unwrap();
        for (index, record) in records.iter().enumerate() {
            state.rows.insert(
                journal.address(b'R', index as u64 + 1),
                Secret::new(record.body.clone()),
            );
        }
        state.rows.insert(
            journal.address(b'O', 0),
            owner_bytes(store.authority().unwrap()),
        );
        state.rows.insert(
            journal.address(b'H', 0),
            Head {
                count: 3,
                sequence: 11,
                hash: hash(&records[2]),
            }
            .encode(),
        );
    }
    let budget = historical::SnapshotBudget {
        records: 3,
        bytes: 4096,
    };
    let snapshot = journal.snapshot(budget).await.unwrap();
    let mut streamed = journal.historical_replay().await.unwrap();
    for original in &records {
        assert_eq!(streamed.next().await.unwrap().unwrap().body, original.body);
    }
    let streamed_head = streamed.finish().unwrap();
    assert_eq!(streamed_head.sequence(), 11);
    assert_eq!(
        journal
            .read_verified_record(&streamed_head, 10)
            .await
            .unwrap()
            .body,
        records[1].body
    );
    assert!(matches!(
        journal.read_verified_record(&streamed_head, 9).await,
        Err(Error::Corrupt)
    ));
    assert_eq!(snapshot.head().sequence(), 11);
    assert_eq!(snapshot.records()[0].body, records[0].body);
    assert_eq!(
        journal
            .read_verified_record(snapshot.head(), 8)
            .await
            .unwrap()
            .body,
        records[0].body
    );
    // A resealed frame covered by the original quarantine bridge can retain
    // the same selected tail. It cannot replace bytes in an existing proof.
    backend.state.lock().unwrap().rows.insert(
        journal.address(b'R', 1),
        Secret::new(record(8, [19; 32], vec![9]).body),
    );
    let mut changed = journal.historical_replay().await.unwrap();
    while changed.next().await.unwrap().is_some() {}
    assert!(changed.finish().is_ok());
    assert!(matches!(
        journal.read_verified_record(&streamed_head, 8).await,
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        journal.read_verified_record(snapshot.head(), 8).await,
        Err(Error::Corrupt)
    ));
    backend.state.lock().unwrap().rows.insert(
        journal.address(b'R', 1),
        Secret::new(records[0].body.clone()),
    );
    assert!(matches!(
        journal
            .selected_head_predicate(snapshot.head())
            .unwrap()
            .expected,
        ExpectedValue::Exact(_)
    ));
    set_root_epoch(&backend, 3);
    let new_store = attach_at(backend.clone(), 5, 3).await;
    let resumed = StoreJournal::new(&new_store, 7).unwrap();
    applied(
        resumed
            .cold_transfer(snapshot.head(), handover())
            .await
            .unwrap(),
    );
    let after_transfer = resumed.snapshot(budget).await.unwrap();
    let next = record(12, hash(&records[2]), vec![4]);
    applied(
        resumed
            .append(after_transfer.head(), std::slice::from_ref(&next))
            .await
            .unwrap(),
    );
    let resumed_budget = historical::SnapshotBudget {
        records: 4,
        bytes: 4096,
    };
    let complete = resumed.snapshot(resumed_budget).await.unwrap();
    assert_eq!(complete.head().sequence(), 12);
    for (verified, original) in complete.records().iter().zip(&records) {
        assert_eq!(verified.body, original.body);
    }
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .remove(&journal.address(b'R', 4));
    assert!(matches!(
        resumed.snapshot(resumed_budget).await,
        Err(Error::Corrupt)
    ));
}

fn selection(value: u8) -> Selection {
    Selection {
        operation_id: [51; 16],
        address: Address {
            namespace: *b"busbar.recover1\0",
            key: vec![51; 16],
        },
        expected: ExpectedValue::Absent,
        value: Secret::new(vec![value]),
    }
}

#[tokio::test]
async fn presealed_run_preserves_wal_recipe_and_selects_only_exact_durable_originals() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone(), 4).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let empty = verified(&journal).await;
    assert_eq!(journal.owned_predicates(&empty).unwrap().len(), 2);
    journal.confirm_owned(&empty).await.unwrap();
    let entries = [
        busbar_kernel_wal::Entry::new(RecordClass::Transaction, vec![1])
            .under(9, 11)
            .at(13, 17),
        busbar_kernel_wal::Entry::new(RecordClass::Transaction, vec![2])
            .under(9, 11)
            .at(13, 17),
    ];
    let records = journal.seal_run(&empty, &entries).unwrap();
    assert_eq!(records[0].body, record(1, [0; 32], vec![1]).body);
    assert_eq!(records[1].body, record(2, hash(&records[0]), vec![2]).body);
    assert_eq!(
        journal.seal(&empty, entries[0].clone()).unwrap().body,
        records[0].body
    );
    assert!(backend.state.lock().unwrap().sent.is_empty());
    applied(journal.append(&empty, &records).await.unwrap());
    let proof = verified(&journal).await;
    applied(
        journal
            .select_verified(&proof, &records, selection(1))
            .await
            .unwrap(),
    );
    let state = backend.state.lock().unwrap();
    let candidate = state.sent[1].candidate();
    assert_eq!(candidate.predicates.len(), 5);
    for (ordinal, record) in records.iter().enumerate() {
        assert!(candidate.predicates.iter().any(|predicate| predicate.address == journal.address(b'R', ordinal as u64+1)
            && matches!(&predicate.expected, ExpectedValue::Exact(value) if value.expose(&crate::seal::lend()) == &record.body)));
    }
    assert_eq!(candidate.mutations.len(), 1);
    assert_eq!(
        state.rows[&selection(1).address].expose(&crate::seal::lend()),
        &[1]
    );
}

#[tokio::test]
async fn recovery_selection_unknown_retains_exact_candidate_and_rejects_changed_intent() {
    let backend = Arc::new(Backend::default());
    let (store, first) = old_journal(&backend).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let proof = verified(&journal).await;
    backend.lose_reply.store(true, Ordering::SeqCst);
    let WriteResult::Submitted(reply) = journal
        .select_verified(&proof, std::slice::from_ref(&first), selection(1))
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(matches!(reply.result, SubmitResult::Uncertain));
    assert!(matches!(
        journal
            .select_verified(&proof, std::slice::from_ref(&first), selection(2))
            .await,
        Err(Error::Access(AccessError::OperationConflict))
    ));
    applied(
        journal
            .select_verified(&proof, std::slice::from_ref(&first), selection(1))
            .await
            .unwrap(),
    );
    let state = backend.state.lock().unwrap();
    assert_eq!(state.sent[1].candidate().id, state.sent[2].candidate().id);
    assert_eq!(state.sent[1].fingerprint(), state.sent[2].fingerprint());
}

#[tokio::test]
async fn recovery_selection_cancelled_candidate_cannot_select_a_changed_original_or_owner() {
    for tag in *b"ROH" {
        let backend = Arc::new(Backend::default());
        let (store, first) = old_journal(&backend).await;
        let journal = StoreJournal::new(&store, 7).unwrap();
        let proof = verified(&journal).await;
        backend.hang.store(true, Ordering::SeqCst);
        let mut future =
            Box::pin(journal.select_verified(&proof, std::slice::from_ref(&first), selection(1)));
        assert!(futures::poll!(future.as_mut()).is_pending());
        drop(future);
        backend.hang.store(false, Ordering::SeqCst);
        backend.state.lock().unwrap().rows.insert(
            journal.address(tag, if tag == b'R' { 1 } else { 0 }),
            Secret::new(vec![99]),
        );
        let WriteResult::Submitted(reply) = journal
            .select_verified(&proof, std::slice::from_ref(&first), selection(1))
            .await
            .unwrap()
        else {
            panic!()
        };
        // Cancellation leaves a possible prior effect. A later native
        // predicate conflict cannot resolve that earlier uncertainty.
        assert!(matches!(reply.result, SubmitResult::Reconcile));
        let state = backend.state.lock().unwrap();
        assert_eq!(state.sent[1].candidate().id, state.sent[2].candidate().id);
        assert_eq!(state.sent[1].fingerprint(), state.sent[2].fingerprint());
        assert!(!state.rows.contains_key(&selection(1).address));
    }
}

#[tokio::test]
async fn readonly_owned_confirmation_checks_native_cold_fence_and_current_writer() {
    let backend = Arc::new(Backend::default());
    let (store, _) = old_journal(&backend).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let proof = verified(&journal).await;
    journal.confirm_owned(&proof).await.unwrap();
    set_root_epoch(&backend, 3);
    journal.confirm_selected(&proof).await.unwrap();
    assert!(matches!(
        journal.confirm_owned(&proof).await,
        Err(Error::Authority)
    ));
    let new_store = attach_at(backend.clone(), 5, 3).await;
    let resumed = StoreJournal::new(&new_store, 7).unwrap();
    assert!(matches!(
        resumed.confirm_owned(&proof).await,
        Err(Error::Authority)
    ));
    applied(resumed.cold_transfer(&proof, handover()).await.unwrap());
    assert!(matches!(
        journal.confirm_selected(&proof).await,
        Err(Error::Authority)
    ));
    resumed
        .confirm_owned(&verified(&resumed).await)
        .await
        .unwrap();
    backend.state.lock().unwrap().rows.insert(
        control_address(control::writer_key([5; 16]).to_vec()),
        Secret::new(
            control::Writer {
                retired_through: 3,
                admitted_through: 3,
            }
            .encode()
            .unwrap()
            .to_vec(),
        ),
    );
    assert!(matches!(
        resumed.confirm_owned(&verified(&resumed).await).await,
        Err(Error::Authority)
    ));
}

#[tokio::test]
async fn audited_selection_delete_is_atomic_and_unknown_replays_original_delete() {
    let backend = Arc::new(Backend::default());
    let (store, first) = old_journal(&backend).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let proof = verified(&journal).await;
    applied(
        journal
            .select_verified(&proof, std::slice::from_ref(&first), selection(1))
            .await
            .unwrap(),
    );
    backend.lose_reply.store(true, Ordering::SeqCst);
    let delete = || {
        journal.delete_verified(
            &proof,
            std::slice::from_ref(&first),
            [51; 16],
            selection(1).address,
            ExpectedValue::Exact(Secret::new(vec![1])),
        )
    };
    let WriteResult::Submitted(reply) = delete().await.unwrap() else {
        panic!()
    };
    assert!(matches!(reply.result, SubmitResult::Uncertain));
    assert!(!backend
        .state
        .lock()
        .unwrap()
        .rows
        .contains_key(&selection(1).address));
    applied(delete().await.unwrap());
    let state = backend.state.lock().unwrap();
    assert_eq!(state.sent[2].candidate().id, state.sent[3].candidate().id);
    assert_eq!(state.sent[2].fingerprint(), state.sent[3].fingerprint());
    assert!(state.rows.contains_key(&journal.address(b'R', 1)));
}

#[tokio::test]
async fn runtime_reconcile_retains_original_and_refuses_new_staging_without_retrying_forever() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let owner = RuntimeJournal::open(
        store,
        7,
        BufferBudget {
            records: 4,
            bytes: 4096,
        },
    )
    .await
    .unwrap();
    let run = owner
        .stage_run(&[busbar_kernel_wal::Entry::new(
            RecordClass::Transaction,
            vec![1],
        )])
        .unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(owner.confirm(&run).await, Err(RuntimeError::Pending));
    backend.state.lock().unwrap().receipts.clear();
    backend.expire_receipt.store(true, Ordering::SeqCst);
    assert_eq!(owner.confirm(&run).await, Err(RuntimeError::Reconcile));
    assert_eq!(owner.pending_records(), 1);
    assert_eq!(owner.confirm(&run).await, Err(RuntimeError::Reconcile));
    assert!(matches!(
        owner.stage_run(&[busbar_kernel_wal::Entry::new(
            RecordClass::Transaction,
            vec![2]
        )]),
        Err(RuntimeError::Reconcile)
    ));
    let state = backend.state.lock().unwrap();
    assert_eq!(
        state.sent.len(),
        2,
        "permanent reconciliation never sends a replacement"
    );
    assert_eq!(state.sent[0].candidate().id, state.sent[1].candidate().id);
    assert_eq!(state.sent[0].fingerprint(), state.sent[1].fingerprint());
    assert!(state
        .rows
        .values()
        .any(|value| value.expose(&crate::seal::lend()) == &run.records()[0].body));
}

#[tokio::test]
async fn shared_runtime_reserves_one_original_chain_and_unknown_keeps_exact_prefix() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let owner = RuntimeJournal::open(
        store.clone(),
        7,
        BufferBudget {
            records: 4,
            bytes: 4096,
        },
    )
    .await
    .unwrap();
    let first = owner
        .stage_run(&[busbar_kernel_wal::Entry::new(
            RecordClass::Transaction,
            vec![1],
        )])
        .unwrap();
    let second = owner
        .stage_run(&[busbar_kernel_wal::Entry::new(
            RecordClass::Reconciliation,
            vec![2],
        )])
        .unwrap();
    assert_eq!(first.records()[0].node_seq, 1);
    assert_eq!(second.records()[0].node_seq, 2);
    assert_eq!(
        JournalRecord::decode(&second.records()[0].body)
            .unwrap()
            .prev_hash,
        hash(&first.records()[0])
    );
    assert!(
        backend.state.lock().unwrap().sent.is_empty(),
        "staging is memory-only"
    );
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(owner.confirm(&second).await, Err(RuntimeError::Pending));
    assert_eq!(owner.pending_records(), 2);
    owner.confirm(&second).await.unwrap();
    owner.confirm(&first).await.unwrap();
    assert_eq!(owner.pending_records(), 0);
    {
        let state = backend.state.lock().unwrap();
        assert_eq!(state.sent[0].candidate().id, state.sent[1].candidate().id);
        assert_eq!(state.sent[0].fingerprint(), state.sent[1].fingerprint());
        assert_eq!(state.sent.len(), 3);
    }
    let other = RuntimeJournal::open(
        store,
        7,
        BufferBudget {
            records: 4,
            bytes: 4096,
        },
    )
    .await
    .unwrap();
    let foreign = other
        .stage_run(&[busbar_kernel_wal::Entry::new(
            RecordClass::Transaction,
            vec![3],
        )])
        .unwrap();
    assert_eq!(owner.confirm(&foreign).await, Err(RuntimeError::Authority));
}

#[tokio::test]
async fn runtime_cancelled_waiter_keeps_originals_and_refused_stage_keeps_sequence() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let owner = RuntimeJournal::open(
        store,
        7,
        BufferBudget {
            records: 1,
            bytes: 4096,
        },
    )
    .await
    .unwrap();
    let run = owner
        .stage_run(&[busbar_kernel_wal::Entry::new(
            RecordClass::Transaction,
            vec![1],
        )])
        .unwrap();
    assert!(matches!(
        owner.stage_run(&[busbar_kernel_wal::Entry::new(
            RecordClass::Transaction,
            vec![2]
        )]),
        Err(RuntimeError::Budget)
    ));
    assert_eq!(owner.next_seq(), 2);
    backend.hang.store(true, Ordering::SeqCst);
    let mut future = Box::pin(owner.confirm(&run));
    assert!(futures::poll!(future.as_mut()).is_pending());
    drop(future);
    backend.hang.store(false, Ordering::SeqCst);
    owner.confirm(&run).await.unwrap();
    let second = owner
        .stage_run(&[busbar_kernel_wal::Entry::new(
            RecordClass::Transaction,
            vec![2],
        )])
        .unwrap();
    assert_eq!(second.records()[0].node_seq, 2);
    let state = backend.state.lock().unwrap();
    assert_eq!(state.sent[0].candidate().id, state.sent[1].candidate().id);
    assert_eq!(state.sent[0].fingerprint(), state.sent[1].fingerprint());
}
fn applied(result: WriteResult) {
    let WriteResult::Submitted(submission) = result else {
        panic!("busy")
    };
    assert!(
        matches!(submission.result, SubmitResult::Decided(d) if matches!(*d, Decision::Applied(_)))
    );
}
async fn verified(journal: &StoreJournal<'_>) -> VerifiedHead {
    let mut replay = journal.replay().await.unwrap();
    while replay.next().await.unwrap().is_some() {}
    replay.finish().unwrap()
}

fn handover() -> Handover<'static> {
    Handover {
        actor: [31; 16],
        reason: "explicit cold-cutover custody handover",
        evidence_digest: [41; 32],
    }
}

async fn old_journal(backend: &Arc<Backend>) -> (CoreStore, Record) {
    let store = attach(backend.clone(), 4).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let first = record(1, [0; 32], vec![1]);
    applied(
        journal
            .append(&verified(&journal).await, std::slice::from_ref(&first))
            .await
            .unwrap(),
    );
    (store, first)
}

#[tokio::test]
async fn cold_transfer_atomically_binds_old_owner_native_fence_head_and_handover() {
    let backend = Arc::new(Backend::default());
    let (_old_store, first) = old_journal(&backend).await;
    set_root_epoch(&backend, 3);
    let store = attach_at(backend.clone(), 5, 3).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let previous = verified(&journal).await;
    applied(journal.cold_transfer(&previous, handover()).await.unwrap());
    {
        let state = backend.state.lock().unwrap();
        let candidate = state.sent[1].candidate();
        assert_eq!(candidate.predicates.len(), 5);
        for address in [
            journal.address(b'H', 0),
            journal.address(b'O', 0),
            control_address(control::DATASET_KEY.to_vec()),
            control_address(control::writer_key([5; 16]).to_vec()),
        ] {
            assert!(candidate
                .predicates
                .iter()
                .any(|predicate| predicate.address == address
                    && matches!(predicate.expected, ExpectedValue::Exact(_))));
        }
        assert_eq!(
            state.rows[&journal.address(b'R', 1)].expose(&crate::seal::lend()),
            &first.body
        );
        let metadata = state.rows[&journal.address(b'T', 3)].expose(&crate::seal::lend());
        assert_eq!(&metadata[..8], b"BBJXFER1");
        assert_eq!(
            &metadata[32..88],
            previous.head.encode().expose(&crate::seal::lend())
        );
        assert_eq!(
            &metadata[88..120],
            previous
                .owner
                .as_ref()
                .unwrap()
                .expose(&crate::seal::lend())
        );
        assert_eq!(
            &metadata[120..152],
            owner_bytes(store.authority().unwrap()).expose(&crate::seal::lend())
        );
        assert_eq!(&metadata[152..168], &[31; 16]);
        assert_eq!(
            &metadata[176..metadata.len() - 32],
            handover().reason.as_bytes()
        );
        assert_eq!(&metadata[metadata.len() - 32..], &[41; 32]);
    }
    let second = record(2, hash(&first), vec![2]);
    applied(
        journal
            .append(&verified(&journal).await, std::slice::from_ref(&second))
            .await
            .unwrap(),
    );
    assert_eq!(verified(&journal).await.hash(), hash(&second));
}

#[tokio::test]
async fn same_dataset_epoch_refuses_transfer_even_when_old_execution_is_retired() {
    let backend = Arc::new(Backend::default());
    let (_old_store, _) = old_journal(&backend).await;
    backend.state.lock().unwrap().rows.insert(
        control_address(control::writer_key([4; 16]).to_vec()),
        Secret::new(
            control::Writer {
                retired_through: 3,
                admitted_through: 3,
            }
            .encode()
            .unwrap()
            .to_vec(),
        ),
    );
    let store = attach(backend.clone(), 5).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    assert!(matches!(
        journal
            .cold_transfer(&verified(&journal).await, handover())
            .await,
        Err(Error::Authority)
    ));
    assert_eq!(backend.state.lock().unwrap().sent.len(), 1);
}

#[tokio::test]
async fn cold_transfer_requires_native_current_root_and_open_current_writer() {
    for stale_root in [false, true] {
        let backend = Arc::new(Backend::default());
        let (_old_store, _) = old_journal(&backend).await;
        set_root_epoch(&backend, 3);
        let store = attach_at(backend.clone(), 5, 3).await;
        let journal = StoreJournal::new(&store, 7).unwrap();
        let previous = verified(&journal).await;
        if stale_root {
            set_root_epoch(&backend, 2);
        } else {
            backend.state.lock().unwrap().rows.insert(
                control_address(control::writer_key([5; 16]).to_vec()),
                Secret::new(
                    control::Writer {
                        retired_through: 3,
                        admitted_through: 3,
                    }
                    .encode()
                    .unwrap()
                    .to_vec(),
                ),
            );
        }
        assert!(matches!(
            journal.cold_transfer(&previous, handover()).await,
            Err(Error::Authority)
        ));
        assert_eq!(backend.state.lock().unwrap().sent.len(), 1);
    }
}

#[tokio::test]
async fn cold_transfer_unknown_replays_identical_candidate_before_native_reread() {
    let backend = Arc::new(Backend::default());
    let (_old_store, _) = old_journal(&backend).await;
    set_root_epoch(&backend, 3);
    let store = attach_at(backend.clone(), 5, 3).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let previous = verified(&journal).await;
    backend.lose_reply.store(true, Ordering::SeqCst);
    let WriteResult::Submitted(reply) = journal.cold_transfer(&previous, handover()).await.unwrap()
    else {
        panic!()
    };
    assert!(matches!(reply.result, SubmitResult::Uncertain));
    let mut changed = handover();
    changed.evidence_digest = [42; 32];
    assert!(matches!(
        journal.cold_transfer(&previous, changed).await,
        Err(Error::Access(AccessError::OperationConflict))
    ));
    set_root_epoch(&backend, 4);
    applied(journal.cold_transfer(&previous, handover()).await.unwrap());
    let state = backend.state.lock().unwrap();
    assert_eq!(state.sent.len(), 3);
    assert_eq!(state.sent[1].candidate().id, state.sent[2].candidate().id);
    assert_eq!(state.sent[1].fingerprint(), state.sent[2].fingerprint());
}

#[tokio::test]
async fn cancelled_cold_transfer_keeps_exact_proof_and_cannot_overwrite_changed_custody() {
    for changed in *b"HODW" {
        let backend = Arc::new(Backend::default());
        let (_old_store, first) = old_journal(&backend).await;
        set_root_epoch(&backend, 3);
        let store = attach_at(backend.clone(), 5, 3).await;
        let journal = StoreJournal::new(&store, 7).unwrap();
        let previous = verified(&journal).await;
        backend.hang.store(true, Ordering::SeqCst);
        let mut future = Box::pin(journal.cold_transfer(&previous, handover()));
        assert!(futures::poll!(future.as_mut()).is_pending());
        drop(future);
        backend.hang.store(false, Ordering::SeqCst);
        let address = match changed {
            b'D' => control_address(control::DATASET_KEY.to_vec()),
            b'W' => control_address(control::writer_key([5; 16]).to_vec()),
            tag => journal.address(tag, 0),
        };
        backend
            .state
            .lock()
            .unwrap()
            .rows
            .insert(address, Secret::new(vec![99]));
        let WriteResult::Submitted(reply) =
            journal.cold_transfer(&previous, handover()).await.unwrap()
        else {
            panic!()
        };
        // Cancellation leaves a possible prior effect. A later native
        // predicate conflict cannot resolve that earlier uncertainty.
        assert!(matches!(reply.result, SubmitResult::Reconcile));
        let state = backend.state.lock().unwrap();
        assert_eq!(state.sent[1].candidate().id, state.sent[2].candidate().id);
        assert_eq!(state.sent[1].fingerprint(), state.sent[2].fingerprint());
        assert!(!state.rows.contains_key(&journal.address(b'T', 3)));
        assert_eq!(
            state.rows[&journal.address(b'R', 1)].expose(&crate::seal::lend()),
            &first.body
        );
    }
}

#[tokio::test]
async fn original_large_frames_and_selected_head_publish_atomically() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone(), 4).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let old = verified(&journal).await;
    let first = record(1, [0; 32], vec![42; 70_000]);
    let second = record(2, hash(&first), b"original signed preimage".to_vec());
    applied(
        journal
            .append(&old, &[first.clone(), second.clone()])
            .await
            .unwrap(),
    );
    assert_eq!(backend.state.lock().unwrap().sent.len(), 1);
    let mut replay = journal.replay().await.unwrap();
    assert_eq!(replay.next().await.unwrap().unwrap().body, first.body);
    assert_eq!(replay.next().await.unwrap().unwrap().body, second.body);
    let proof = replay.finish().unwrap();
    assert_eq!(proof.sequence(), 2);
    assert_eq!(proof.hash(), hash(&second));

    let stale = record(1, [0; 32], b"competing genesis".to_vec());
    let WriteResult::Submitted(reply) = journal.append(&old, &[stale]).await.unwrap() else {
        panic!()
    };
    assert!(
        matches!(reply.result, SubmitResult::Decided(d) if matches!(*d, Decision::ConditionConflict))
    );
    assert_eq!(verified(&journal).await.hash(), hash(&second));
}

#[tokio::test]
async fn different_writer_can_inspect_but_cannot_adopt_old_node() {
    let backend = Arc::new(Backend::default());
    let first_store = attach(backend.clone(), 4).await;
    let journal = StoreJournal::new(&first_store, 7).unwrap();
    let first = record(1, [0; 32], vec![1]);
    applied(
        journal
            .append(&verified(&journal).await, std::slice::from_ref(&first))
            .await
            .unwrap(),
    );
    let other_store = attach(backend.clone(), 5).await;
    let other = StoreJournal::new(&other_store, 7).unwrap();
    let proof = verified(&other).await;
    assert!(matches!(
        other
            .append(&proof, &[record(2, hash(&first), vec![2])])
            .await,
        Err(Error::Authority)
    ));
    assert_eq!(backend.state.lock().unwrap().sent.len(), 1);
}

#[tokio::test]
async fn live_execution_epoch_promotion_preserves_the_node_writer() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone(), 4).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let first = record(1, [0; 32], vec![1]);
    applied(
        journal
            .append(&verified(&journal).await, std::slice::from_ref(&first))
            .await
            .unwrap(),
    );
    let proof = verified(&journal).await;
    let mut authority = store.authority().unwrap();
    authority.execution_epoch += 1;
    // Startup invokes this only after the native registration grant is Applied.
    store.promote_authority(authority).unwrap();
    let second = record(2, hash(&first), vec![2]);
    applied(
        journal
            .append(&proof, std::slice::from_ref(&second))
            .await
            .unwrap(),
    );
    assert_eq!(verified(&journal).await.hash(), hash(&second));
    assert_eq!(
        backend.state.lock().unwrap().sent[1]
            .candidate()
            .id
            .execution_epoch,
        4
    );
}

#[tokio::test]
async fn uncertainty_and_cancellation_retain_exact_original_candidate() {
    for cancel in [false, true] {
        let backend = Arc::new(Backend::default());
        let store = attach(backend.clone(), 4).await;
        let journal = StoreJournal::new(&store, 7).unwrap();
        let proof = verified(&journal).await;
        let records = [record(1, [0; 32], vec![7; 2048])];
        if cancel {
            backend.hang.store(true, Ordering::SeqCst);
            let mut future = Box::pin(journal.append(&proof, &records));
            assert!(futures::poll!(future.as_mut()).is_pending());
            drop(future);
            backend.hang.store(false, Ordering::SeqCst);
        } else {
            backend.lose_reply.store(true, Ordering::SeqCst);
            let WriteResult::Submitted(reply) = journal.append(&proof, &records).await.unwrap()
            else {
                panic!()
            };
            assert!(matches!(reply.result, SubmitResult::Uncertain));
        }
        assert!(matches!(
            journal.append(&proof, &[record(1, [0; 32], vec![8])]).await,
            Err(Error::Access(AccessError::OperationConflict))
        ));
        applied(journal.append(&proof, &records).await.unwrap());
        {
            let state = backend.state.lock().unwrap();
            assert_eq!(state.sent.len(), 2);
            assert_eq!(state.sent[0].candidate().id, state.sent[1].candidate().id);
            assert_eq!(state.sent[0].fingerprint(), state.sent[1].fingerprint());
        }
        assert_eq!(verified(&journal).await.hash(), hash(&records[0]));
    }
}

#[tokio::test]
async fn replay_checks_middle_records_and_requires_completion() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone(), 4).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let first = record(1, [0; 32], vec![1]);
    let second = record(2, hash(&first), vec![2]);
    let third = record(3, hash(&second), vec![3]);
    applied(
        journal
            .append(&verified(&journal).await, &[first, second.clone(), third])
            .await
            .unwrap(),
    );
    let mut incomplete = journal.replay().await.unwrap();
    incomplete.next().await.unwrap();
    assert!(matches!(incomplete.finish(), Err(Error::IncompleteReplay)));
    let mut bad = second.body;
    *bad.last_mut().unwrap() ^= 1;
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .insert(journal.address(b'R', 2), Secret::new(bad));
    let mut replay = journal.replay().await.unwrap();
    replay.next().await.unwrap();
    assert!(matches!(replay.next().await, Err(Error::Verification(_))));
    assert!(matches!(replay.finish(), Err(Error::IncompleteReplay)));
}

#[tokio::test]
async fn replay_pins_old_prefix_across_append_and_detects_missing_tail() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone(), 4).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let first = record(1, [0; 32], vec![1]);
    applied(
        journal
            .append(&verified(&journal).await, std::slice::from_ref(&first))
            .await
            .unwrap(),
    );
    let mut old_cursor = journal.replay().await.unwrap();
    let second = record(2, hash(&first), vec![2]);
    applied(
        journal
            .append(&verified(&journal).await, &[second])
            .await
            .unwrap(),
    );
    assert_eq!(old_cursor.next().await.unwrap().unwrap().body, first.body);
    assert!(old_cursor.next().await.unwrap().is_none());
    assert_eq!(old_cursor.finish().unwrap().sequence(), 1);
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .remove(&journal.address(b'R', 2));
    let mut cursor = journal.replay().await.unwrap();
    cursor.next().await.unwrap();
    assert!(matches!(cursor.next().await, Err(Error::Corrupt)));
}

#[tokio::test]
async fn bounds_and_unported_bridge_histories_refuse_before_commit() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone(), 4).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let proof = verified(&journal).await;
    assert!(matches!(
        journal
            .append(&proof, &[record(1, [0; 32], vec![0; 128 * 1024])])
            .await,
        Err(Error::Budget)
    ));
    assert!(matches!(
        journal.append(&proof, &[record(5, [9; 32], vec![1])]).await,
        Err(Error::UnsupportedHistory)
    ));
    let first = record(1, [0; 32], vec![1]);
    let gap = record(3, hash(&first), vec![2]);
    assert!(matches!(
        journal.append(&proof, &[first, gap]).await,
        Err(Error::UnsupportedHistory)
    ));
    assert!(backend.state.lock().unwrap().sent.is_empty());
}

#[tokio::test]
async fn verified_original_prefix_survives_append_without_granting_stale_selection() {
    let backend = Arc::new(Backend::default());
    let (store, first) = old_journal(&backend).await;
    let journal = StoreJournal::new(&store, 7).unwrap();
    let proof = verified(&journal).await;
    let unrelated = record(2, hash(&first), vec![2]);
    applied(
        journal
            .append(&proof, std::slice::from_ref(&unrelated))
            .await
            .unwrap(),
    );
    assert_eq!(
        journal.read_verified_record(&proof, 1).await.unwrap().body,
        first.body,
        "a newer selected tip does not corrupt the verified immutable prefix"
    );
    assert!(matches!(
        journal.confirm_owned(&proof).await,
        Err(Error::Authority)
    ));
    let stale = journal
        .select_verified(&proof, std::slice::from_ref(&first), selection(1))
        .await
        .unwrap();
    let WriteResult::Submitted(stale) = stale else {
        panic!("the stale candidate must receive a definitive native decision")
    };
    assert!(matches!(
        stale.result,
        SubmitResult::Decided(ref result) if matches!(**result, Decision::ConditionConflict)
    ));
    let fresh = verified(&journal).await;
    let mut retry = selection(1);
    retry.operation_id = [52; 16];
    applied(
        journal
            .select_verified(&fresh, std::slice::from_ref(&first), retry)
            .await
            .unwrap(),
    );
    {
        let state = backend.state.lock().unwrap();
        let stale = &state.sent[state.sent.len() - 2];
        let fresh = &state.sent[state.sent.len() - 1];
        assert_ne!(stale.candidate().id, fresh.candidate().id);
        assert_ne!(stale.fingerprint(), fresh.fingerprint());
    }
    backend.state.lock().unwrap().rows.insert(
        journal.address(b'R', 1),
        Secret::new(record(1, [0; 32], vec![9]).body),
    );
    assert!(matches!(
        journal.read_verified_record(&proof, 1).await,
        Err(Error::Corrupt)
    ));
}
