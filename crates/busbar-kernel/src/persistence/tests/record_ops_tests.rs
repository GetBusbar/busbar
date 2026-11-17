// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-264 R1-R11: retention of CoreStore conditional-commit receipts (`busbar.recordop1`).
//! Crash-sweep cases run on the F5 store double (real fence semantics: control rows, `Exact`
//! predicates, per-writer epoch admission); in-boot cases on the in-memory test backend.
//!
//! R9's real-database case belongs to the store fixtures (W40/W41) on Postgres, MySQL, SQLite
//! and Memory. Its Valkey case waits on store-valkey V-RANGE (DES-264 §3.8): today a Valkey
//! range delete scans the whole keyspace and leaves tombstones, so the bound does not hold
//! there and no Valkey case is claimed here.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use busbar_contract::persistence::{Address, Mutation};
use busbar_contract::Secret;
use futures::FutureExt;

use super::expired_writers_tests::{attach, control_address, writer_id, Store, CLOSED, OWN};
use super::{BootIdentity, PredecessorFence, TestHold, LEASE_TTL_MS};
use crate::persistence::facade::CoreStore;
use crate::persistence::host_records::{Outcome, RECORD_OPERATIONS};
use crate::persistence::keys;
use crate::persistence::record_ops::{
    owner_address, receipts_namespace, receipts_prefix, DerivedOp, HeldOp, Op, GEN_OPS, OWNERS,
    RECEIPT_KEY_LENGTH,
};
use crate::persistence::scoped::{self, ScopedStore};
use crate::persistence::test_backend;

const SCHEMA: &str = "rows";

fn stop() -> tokio::sync::watch::Receiver<bool> {
    let (tx, rx) = tokio::sync::watch::channel(false);
    // The pass reads the flag only; a dropped sender leaves it false.
    drop(tx);
    rx
}

fn records(core: &Arc<CoreStore>, instance: &str) -> ScopedStore {
    ScopedStore::host_private(core.clone(), instance, [SCHEMA.to_string()]).unwrap()
}

fn put(op: Op, key: &[u8], value: u8) -> scoped::Request {
    scoped::Request {
        op,
        predicates: vec![],
        mutations: vec![scoped::Mutation::Put {
            schema: SCHEMA.into(),
            key: key.to_vec(),
            value: Secret::new(vec![value]),
        }],
    }
}

fn receipt_address(op: &Op) -> Address {
    Address {
        namespace: op.receipt_namespace().0,
        key: keys::framed(b'R', &[&RECORD_OPERATIONS.0, &op.bytes()]).unwrap(),
    }
}

/// Commits `n` puts on `records`, each under a fresh held identity released at its outcome.
async fn commit_ops(records: &ScopedStore, prefix: &str, n: usize) {
    for i in 0..n {
        let op = records.record_op().await.unwrap();
        let request = put(op, format!("{prefix}{i}").as_bytes(), 1);
        assert_eq!(
            records.conditional_native(&request).await.unwrap(),
            Outcome::Applied
        );
    }
}

/// A writer `a` registered on `store` with an expired lease, attached as its own process.
async fn expired_process(store: &Arc<Store>, host: &str, node: u64) -> ([u8; 16], Arc<CoreStore>) {
    let writer = writer_id();
    store.open_writer(writer, 1_000, host, node);
    (writer, attach(store, writer).await)
}

/// R1: A's generations are found by their owner rows once F5 has closed A's writer, and swept;
/// B's receipts and owner rows survive. Red before DES-264: A's receipts remain for ever.
#[tokio::test]
async fn r1_a_closed_writers_generations_are_swept_and_b_keeps_its_own() {
    let store = Store::new();
    let (a_writer, a) = expired_process(&store, "host-a", 31).await;
    let b = attach(&store, OWN).await;
    commit_ops(&records(&a, "r1"), "a", 5).await;
    commit_ops(&records(&b, "r1"), "b", 3).await;
    let a_gen = a.record_generations().0.unwrap();
    let b_gen = b.record_generations().0.unwrap();
    assert_ne!(a_gen, b_gen, "each CoreStore draws its own gen8");
    assert_eq!(store.rows_in(receipts_namespace(a_gen).0), 5);
    assert_eq!(store.rows_in(receipts_namespace(b_gen).0), 3);
    assert_eq!(store.rows_in(OWNERS.0), 2);

    store.now.store(100, Ordering::SeqCst);
    let pass = PredecessorFence::new(b.clone(), "host-b")
        .unwrap()
        .run(stop())
        .await;
    assert_eq!((pass.closed, pass.swept), (1, 1), "{pass:?}");
    assert_eq!(store.control(a_writer), Some(CLOSED));
    assert_eq!(store.rows_in(receipts_namespace(a_gen).0), 0);
    assert!(store.row(&owner_address(a_gen).unwrap()).is_none());
    assert_eq!(store.rows_in(receipts_namespace(b_gen).0), 3);
    assert_eq!(
        store.row(&owner_address(b_gen).unwrap()),
        Some(OWN.to_vec())
    );
}

/// R2: while A is live the crash sweep deletes nothing, and resubmitting an A op answers Applied.
#[tokio::test]
async fn r2_a_live_writers_generations_are_never_swept() {
    let store = Store::new();
    let a_writer = writer_id();
    store.admit(a_writer);
    let a = attach(&store, a_writer).await;
    let b = attach(&store, OWN).await;
    let rows = records(&a, "r2");
    let op = rows.record_op().await.unwrap();
    let request = put(op, b"kept", 7);
    assert_eq!(
        rows.conditional_native(&request).await.unwrap(),
        Outcome::Applied
    );
    let gen8 = a.record_generations().0.unwrap();
    assert_eq!(b.sweep_owner_rows(1_000).await.unwrap(), (0, 0));
    assert_eq!(store.rows_in(receipts_namespace(gen8).0), 1);
    assert!(store.row(&owner_address(gen8).unwrap()).is_some());
    assert_eq!(
        rows.conditional_native(&request).await.unwrap(),
        Outcome::Applied
    );
}

/// R3: a principal-transition (class D) receipt survives its writer's crash sweep and a restart,
/// and still answers its re-derived operation as Applied.
#[tokio::test]
async fn r3_a_class_d_receipt_survives_the_crash_sweep_and_a_restart() {
    let store = Store::new();
    let (_, a) = expired_process(&store, "host-a", 41).await;
    let b = attach(&store, OWN).await;
    let derived = Op::Derived(DerivedOp::principal_transition([0x5d; 16]));
    let request = put(derived.clone(), b"plan", 1);
    assert_eq!(
        records(&a, "r3")
            .conditional_native(&request)
            .await
            .unwrap(),
        Outcome::Applied
    );
    commit_ops(&records(&a, "r3"), "m", 2).await;
    let a_gen = a.record_generations().0.unwrap();
    store.now.store(100, Ordering::SeqCst);
    let pass = PredecessorFence::new(b.clone(), "host-b")
        .unwrap()
        .run(stop())
        .await;
    assert_eq!(pass.swept, 1, "{pass:?}");
    assert_eq!(store.rows_in(receipts_namespace(a_gen).0), 0);
    assert!(store.row(&receipt_address(&derived)).is_some());
    let restarted = attach(&store, OWN).await;
    assert_eq!(
        records(&restarted, "r3")
            .conditional_native(&request)
            .await
            .unwrap(),
        Outcome::Applied
    );
}

/// R4: a second attachment that commits the same operation between our receipt read and our
/// commit makes our commit a ConditionConflict, which still resolves to Applied.
#[tokio::test]
async fn r4_a_concurrent_second_attachment_conflict_resolves_to_applied() {
    let store = Store::new();
    let first = attach(&store, OWN).await;
    let rows = records(&first, "r4");
    let op = rows.record_op().await.unwrap();
    let request = put(op.clone(), b"once", 3);
    assert_eq!(
        rows.conditional_native(&request).await.unwrap(),
        Outcome::Applied
    );
    // Rewind to "the other attachment has not committed yet", then let it commit inside ours.
    let receipt_at = receipt_address(&op);
    let receipt = store.remove_row(&receipt_at).unwrap();
    let effect_at = scoped::migration_address(true, "r4", SCHEMA, b"once").unwrap();
    let effect = store.remove_row(&effect_at).unwrap();
    let second = attach(&store, OWN).await;
    store.before_next_commit(Box::new(move |_, rows| {
        rows.insert(receipt_at, Secret::new(receipt));
        rows.insert(effect_at, Secret::new(effect));
    }));
    assert_eq!(
        records(&second, "r4")
            .conditional_native(&request)
            .await
            .unwrap(),
        Outcome::Applied
    );
}

/// R5: the process dies with its sweep sent but undecided; the next F5 pass sweeps A's partition.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r5_a_sweep_lost_to_a_crash_is_redone_by_the_next_pass() {
    let store = Store::new();
    let (a_writer, a) = expired_process(&store, "host-a", 51).await;
    commit_ops(&records(&a, "r5"), "a", 4).await;
    let a_gen = a.record_generations().0.unwrap();
    store.now.store(100, Ordering::SeqCst);
    let hold = Arc::new(TestHold::default());
    store.hold_next_sweep(hold.clone());
    let fence = PredecessorFence::new(attach(&store, OWN).await, "host-b").unwrap();
    let running = tokio::spawn(async move { fence.run(stop()).await });
    hold.reached.notified().await;
    // The close is decided; the sweep never answers: this process dies here.
    assert_eq!(store.control(a_writer), Some(CLOSED));
    running.abort();
    let _ = running.await;
    assert_eq!(store.rows_in(receipts_namespace(a_gen).0), 4);
    assert!(store.row(&owner_address(a_gen).unwrap()).is_some());

    let pass = PredecessorFence::new(attach(&store, OWN).await, "host-c")
        .unwrap()
        .run(stop())
        .await;
    assert_eq!(pass.swept, 1, "{pass:?}");
    assert_eq!(store.rows_in(receipts_namespace(a_gen).0), 0);
    assert!(store.row(&owner_address(a_gen).unwrap()).is_none());
}

/// R6: the sweep's prefix is the receipt key's first 33 bytes, and its exact key length 41.
#[tokio::test]
async fn r6_the_sweep_prefix_and_length_match_every_receipt_key_of_the_generation() {
    let backend = Arc::new(test_backend::Backend::default());
    let core = test_backend::attach(backend).await;
    let held = core.record_op().await.unwrap();
    let key = keys::framed(b'R', &[&RECORD_OPERATIONS.0, &held.bytes()]).unwrap();
    let prefix = receipts_prefix(held.gen8()).unwrap();
    assert_eq!(prefix.len(), 33);
    assert_eq!(prefix, key[..33]);
    assert_eq!(key.len() as u64, RECEIPT_KEY_LENGTH);
    assert_eq!(RECEIPT_KEY_LENGTH, 41);
    let mut expected = vec![b'R', 0, 0, 0, 16];
    expected.extend_from_slice(b"busbar.recordop1");
    expected.extend_from_slice(&[0, 0, 0, 16]);
    expected.extend_from_slice(&held.gen8());
    assert_eq!(prefix, expected);
}

/// R7: with `busbar.recopgen1` populated, a 40-byte Assignment row still parses and the F5 scan
/// counts no row as invalid.
#[tokio::test]
async fn r7_owner_rows_leave_the_assignment_row_and_the_scan_untouched() {
    let store = Store::new();
    let (_, a) = expired_process(&store, "host-a", 71).await;
    commit_ops(&records(&a, "r7"), "a", 2).await;
    assert_eq!(store.rows_in(OWNERS.0), 1);
    let assignment = store.node_row(&super::host_key("host-a")).unwrap();
    assert_eq!(assignment.len(), 40);
    assert!(super::Assignment::parse(&assignment).is_ok());
    let identity = BootIdentity::new(attach(&store, OWN).await).unwrap();
    store.now.store(100, Ordering::SeqCst);
    let scan = identity
        .expired_writers(LEASE_TTL_MS, super::EXPIRED_PASS_MAX)
        .await
        .unwrap();
    assert_eq!((scan.invalid, scan.rows.len()), (0, 1));
}

/// R8: a gen8 that already has an owner row is a ConditionConflict and a redraw; a crash sweep
/// of an owner row naming a live writer deletes nothing.
#[tokio::test]
async fn r8_one_writer_per_gen8() {
    let store = Store::new();
    let other = writer_id();
    store.admit(other);
    let core = attach(&store, OWN).await;
    let taken = std::sync::Arc::new(std::sync::Mutex::new(None));
    let seen = taken.clone();
    store.before_next_commit(Box::new(move |candidate, rows| {
        let Some(Mutation::Put { address, .. }) = candidate.mutations.first() else {
            panic!("the first commit is the generation open");
        };
        assert_eq!(address.namespace, OWNERS.0);
        rows.insert(address.clone(), Secret::new(other.to_vec()));
        *seen.lock().unwrap() = Some(address.clone());
    }));
    let held = core.record_op().await.unwrap();
    let collided = taken.lock().unwrap().clone().unwrap();
    assert_ne!(owner_address(held.gen8()).unwrap(), collided);
    assert_eq!(store.row(&collided), Some(other.to_vec()));
    assert_eq!(
        store.row(&owner_address(held.gen8()).unwrap()),
        Some(OWN.to_vec())
    );
    // `other` is live: its owner row is never swept.
    assert_eq!(core.sweep_owner_rows(1_000).await.unwrap(), (0, 0));
    assert_eq!(store.row(&collided), Some(other.to_vec()));
    assert!(store.row(&control_address(other)).is_some());
}

fn receipt_rows(backend: &test_backend::Backend) -> (usize, usize) {
    let frame = keys::framed(b'R', &[&RECORD_OPERATIONS.0]).unwrap();
    let state = backend.state.lock().unwrap();
    let receipts = state
        .rows
        .keys()
        .filter(|at| at.key.len() as u64 == RECEIPT_KEY_LENGTH && at.key.starts_with(&frame))
        .count();
    let owners = state
        .rows
        .keys()
        .filter(|at| at.namespace == OWNERS.0)
        .count();
    (receipts, owners)
}

/// R9 (in memory): 64 × GEN_OPS conditional ops in one boot, holds released at each outcome.
/// After every GEN_OPS the receipt rows stay ≤ (P + 2) × 2 × GEN_OPS and the owner rows ≤ P + 2,
/// with P = 0 pinned generations: the bound does not grow with uptime.
#[tokio::test]
async fn r9_receipts_stay_bounded_over_a_long_boot() {
    let backend = Arc::new(test_backend::Backend::default());
    let core = Arc::new(test_backend::attach(backend.clone()).await);
    let rows = records(&core, "r9");
    let mut gens = std::collections::BTreeSet::new();
    for cycle in 0..64u64 {
        for i in 0..GEN_OPS {
            let op = rows.record_op().await.unwrap();
            gens.insert(op.held().unwrap().gen8());
            let request = put(op, &(cycle * GEN_OPS + i).to_be_bytes(), 1);
            assert_eq!(
                rows.conditional_native(&request).await.unwrap(),
                Outcome::Applied
            );
            if i % 256 == 255 {
                core.maintain_record_ops().await.unwrap();
            }
        }
        let (receipts, owners) = receipt_rows(&backend);
        assert!(
            receipts as u64 <= 2 * 2 * GEN_OPS,
            "cycle {cycle}: {receipts}"
        );
        assert!(owners <= 2, "cycle {cycle}: {owners}");
    }
    assert!(gens.len() >= 60, "generations rotate: {}", gens.len());
}

/// R9 (counter): a generation seeded at GEN_OPS - 1 rotates without reusing an id; a generation
/// whose next open is held reaches 2 × GEN_OPS and the next mint waits for that open.
#[tokio::test]
async fn r9_the_counter_rotates_without_reuse_and_waits_at_the_hard_stop() {
    let backend = Arc::new(test_backend::Backend::default());
    let core = test_backend::attach(backend.clone()).await;
    core.seed_record_ops(GEN_OPS - 1);
    assert!(core.maintain_record_ops().await.unwrap().opened);
    let (first, next) = core.record_generations();
    let last = core.record_op().await.unwrap();
    assert_eq!(last.gen8(), first.unwrap());
    assert_eq!(last.bytes()[8..], GEN_OPS.to_be_bytes());
    let rotated = core.record_op().await.unwrap();
    assert_eq!(rotated.gen8(), next.unwrap());
    assert_eq!(rotated.bytes()[8..], 1u64.to_be_bytes());
    assert_ne!(last.bytes(), rotated.bytes());

    core.seed_record_ops(2 * GEN_OPS);
    assert!(
        core.try_record_op().is_err(),
        "the hard stop refuses a mint"
    );
    backend.hang.store(true, Ordering::SeqCst);
    assert!(
        core.record_op().now_or_never().is_none(),
        "the mint waits for the next generation's open"
    );
    backend.hang.store(false, Ordering::SeqCst);
    let after = core.record_op().await.unwrap();
    assert_ne!(after.gen8(), rotated.gen8());
    assert_eq!(after.bytes()[8..], 1u64.to_be_bytes());
}

/// R10: a held write answered Pending, retried after its generation stopped being current and
/// after CoreStore's logical entry popped, answers Applied without re-applying; its generation
/// is not swept while the write is held, and is swept once the write is dropped.
#[tokio::test]
async fn r10_a_held_identity_pins_its_generation_across_retries() {
    let backend = Arc::new(test_backend::Backend::default());
    let core = Arc::new(test_backend::attach(backend.clone()).await);
    let rows = records(&core, "r10");
    let op = rows.record_op().await.unwrap();
    let gen8 = op.held().unwrap().gen8();
    let request = put(op.clone(), b"held", 9);
    backend.lose_reply.store(true, Ordering::SeqCst);
    let Outcome::Pending(id) = rows.conditional_native(&request).await.unwrap() else {
        panic!("a lost reply leaves the write pending");
    };
    // Someone else collects the decision: the attempt and the logical entry pop.
    assert_eq!(rows.retry(id).await.unwrap(), Outcome::Applied);
    // The generation stops being current.
    core.seed_record_ops(GEN_OPS);
    core.maintain_record_ops().await.unwrap();
    let _rotated = core.record_op().await.unwrap();
    assert_ne!(core.record_generations().0, Some(gen8));
    let sent = backend.state.lock().unwrap().sent.len();
    assert_eq!(
        rows.conditional_native(&request).await.unwrap(),
        Outcome::Applied
    );
    assert_eq!(
        backend.state.lock().unwrap().sent.len(),
        sent,
        "not re-applied"
    );
    core.maintain_record_ops().await.unwrap();
    assert!(backend
        .state
        .lock()
        .unwrap()
        .rows
        .contains_key(&receipt_address(&op)));
    drop(request);
    drop(op);
    let pass = core.maintain_record_ops().await.unwrap();
    assert_eq!(pass.swept, 1, "{pass:?}");
    assert!(!backend
        .state
        .lock()
        .unwrap()
        .rows
        .keys()
        .any(|at| at.namespace == receipts_namespace(gen8).0));
}

/// R11: a class-D receipt whose op[..8] equals a live gen8 survives that generation's sweep.
#[tokio::test]
async fn r11_the_class_d_label_keeps_derived_receipts_out_of_every_generation() {
    let backend = Arc::new(test_backend::Backend::default());
    let core = Arc::new(test_backend::attach(backend.clone()).await);
    let rows = records(&core, "r11");
    let gen8 = core.record_generations().0.unwrap();
    let mut colliding = [0x11; 16];
    colliding[..8].copy_from_slice(&gen8);
    let derived = Op::Derived(DerivedOp::principal_transition(colliding));
    assert_ne!(derived.receipt_namespace(), receipts_namespace(gen8));
    assert_eq!(
        rows.conditional_native(&put(derived.clone(), b"plan", 1))
            .await
            .unwrap(),
        Outcome::Applied
    );
    let held: HeldOp = core.record_op().await.unwrap();
    assert_eq!(held.gen8(), gen8);
    assert_eq!(
        rows.conditional_native(&put(held.into(), b"m", 1))
            .await
            .unwrap(),
        Outcome::Applied
    );
    core.seed_record_ops(GEN_OPS);
    core.maintain_record_ops().await.unwrap();
    let _rotated = core.record_op().await.unwrap();
    let pass = core.maintain_record_ops().await.unwrap();
    assert_eq!(pass.swept, 1, "{pass:?}");
    let state = backend.state.lock().unwrap();
    assert!(!state
        .rows
        .keys()
        .any(|at| at.namespace == receipts_namespace(gen8).0));
    assert!(state.rows.contains_key(&receipt_address(&derived)));
}
