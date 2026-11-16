// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 §9 test 30, kernel parts (`ephemeral_journal_is_bounded_after_n_requests`):
//! the Ephemeral journal cut (§3.9). A base row `B@0`, a cut in two steps, floors and pins, kept
//! rows, and every reader starting at the base with `Truncated` (never `Corrupt`) below it and a
//! restart when a cut passes a walk.

use super::*;
use busbar_kernel_wal::Entry;

const OPEN: BufferBudget = BufferBudget {
    records: 64,
    bytes: 64 * 1024,
};
const READ: BufferBudget = BufferBudget {
    records: 1 << 16,
    bytes: 1 << 26,
};

fn ephemeral() -> Arc<Backend> {
    let backend = Arc::new(Backend::default());
    backend.ephemeral.store(true, Ordering::SeqCst);
    backend
}

async fn owner_on(backend: &Arc<Backend>) -> (Arc<CoreStore>, Arc<RuntimeJournal>) {
    let store = Arc::new(attach(backend.clone(), 4).await);
    let owner = RuntimeJournal::open(store.clone(), 7, OPEN).await.unwrap();
    (store, owner)
}

/// Append `n` one-record runs, four to a group (the double's scan limit).
async fn append(owner: &RuntimeJournal, n: u64) {
    let mut left = n;
    while left > 0 {
        let take = left.min(4);
        let mut last = None;
        for _ in 0..take {
            last = Some(
                owner
                    .stage_run(&[Entry::new(RecordClass::Transaction, vec![7; 8])])
                    .unwrap(),
            );
        }
        owner.confirm(&last.unwrap()).await.unwrap();
        left -= take;
    }
}

/// Journal rows (`R@*`) the store holds.
fn rows(backend: &Backend) -> u64 {
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .keys()
        .filter(|address| address.key.get(24) == Some(&b'R'))
        .count() as u64
}

fn base_row(backend: &Backend) -> Option<Secret<Vec<u8>>> {
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .iter()
        .find(|(address, _)| address.key.get(24) == Some(&b'B'))
        .map(|(_, value)| value.clone())
}

/// The double commits a cut (`after`: base moved, rows deleted) on the first read of any journal
/// row, i.e. between a walker's `B@0` read and its next `read_next`.
fn cut_during_next_walk(backend: &Arc<Backend>, after: BTreeMap<Address, Secret<Vec<u8>>>) {
    let weak = Arc::downgrade(backend);
    let after = Mutex::new(Some(after));
    *backend.on_read.lock().unwrap() = Some(Arc::new(move |read: &Read| {
        if !read
            .addresses
            .iter()
            .any(|address| address.key.get(24) == Some(&b'R'))
        {
            return;
        }
        let Some(rows) = after.lock().unwrap().take() else {
            return;
        };
        if let Some(backend) = weak.upgrade() {
            backend.state.lock().unwrap().rows = rows;
        }
    }));
}

#[test]
fn base_row_round_trips_and_refuses_damage() {
    let kept = record(2, [0; 32], b"boot".to_vec());
    let base = Base {
        head: Head {
            count: 3,
            sequence: 3,
            hash: [5; 32],
        },
        records_seal: [6; 32],
        tail: AuditTail {
            chain_seq: 1,
            node_seq: 3,
            fp: [8; 32],
        },
        keep: vec![kept],
    };
    let raw = base.encode().unwrap();
    assert!(Base::decode(7, &raw).unwrap() == base);
    let bytes = raw.expose(&crate::seal::lend()).clone();
    let mut damaged = bytes.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    assert!(
        Base::decode(7, &Secret::new(damaged)).is_err(),
        "a damaged kept copy fails its WAL digest"
    );
    assert!(
        Base::decode(8, &raw).is_err(),
        "a kept copy is this node's original"
    );
    let mut magic = bytes;
    magic[0] ^= 1;
    assert!(matches!(
        Base::decode(7, &Secret::new(magic)),
        Err(Error::Corrupt)
    ));
    let above = Base {
        keep: vec![record(4, [0; 32], b"late".to_vec())],
        ..base
    };
    assert!(
        Base::decode(7, &above.encode().unwrap()).is_err(),
        "a kept copy lies at or below the base"
    );
}

/// (a) `B@0` exists after a cut and a fresh `replay()` from it yields the same `VerifiedHead`
/// (`head`, `records_seal`) as the owner's own, reading only head − base rows.
#[tokio::test]
async fn cut_moves_the_base_and_replay_from_it_proves_the_same_head() {
    let backend = ephemeral();
    let (store, owner) = owner_on(&backend).await;
    append(&owner, RETAIN_TAIL + 3 * CUT_BATCH).await;
    let mut cut = owner.cutter().expect("an Ephemeral journal has one cut");
    assert!(owner.cutter().is_none(), "the cut is handed out once");
    let progress = cut.truncate_through(u64::MAX).await;
    let CutProgress::Cut { base } = progress else {
        panic!("expected a cut, got {progress:?}");
    };
    let live = owner.verified().unwrap();
    assert!(base >= CUT_BATCH && base <= live.head.count - RETAIN_TAIL);
    assert_eq!(owner.base_count(), base);
    assert!(base_row(&backend).is_some(), "the base row exists");
    assert_eq!(
        rows(&backend),
        live.head.count - base,
        "every row at or below the base is deleted, none above it"
    );
    let journal = StoreJournal::new(&store, 7).unwrap();
    let mut replay = journal.replay().await.unwrap();
    let mut read = 0u64;
    while replay.next().await.unwrap().is_some() {
        read += 1;
    }
    let proof = replay.finish().unwrap();
    assert_eq!(
        read,
        live.head.count - base,
        "a replay reads head − base rows"
    );
    assert!(proof.head == live.head, "the same head as a full replay");
    assert_eq!(
        proof.records_seal, live.records_seal,
        "the same original-byte seal"
    );
}

/// (a) The store holds at most `RETAIN_TAIL + 2 × CUT_BATCH` journal rows at every sample.
#[tokio::test]
async fn ephemeral_journal_is_bounded_after_n_requests() {
    let backend = ephemeral();
    let (_store, owner) = owner_on(&backend).await;
    let mut cut = owner.cutter().unwrap();
    let mut total = 0;
    for _ in 0..8 {
        append(&owner, 2 * CUT_BATCH).await;
        total += 2 * CUT_BATCH;
        cut.truncate_through(u64::MAX).await;
        let held = rows(&backend);
        assert!(
            held <= RETAIN_TAIL + 2 * CUT_BATCH,
            "{held} rows held after {total} records"
        );
        assert_eq!(held, total - owner.base_count());
    }
    assert!(owner.base_count() >= total - RETAIN_TAIL - 2 * CUT_BATCH);
}

/// (a) On a `Durability::Local` double nothing is cut and nothing is pinned.
#[tokio::test]
async fn local_journal_is_never_cut() {
    let backend = Arc::new(Backend::default());
    let (_store, owner) = owner_on(&backend).await;
    append(&owner, RETAIN_TAIL + 2 * CUT_BATCH).await;
    assert!(owner.cutter().is_none());
    assert!(!owner.is_cut_capable());
    let run = owner
        .stage_run(&[Entry::new(RecordClass::Transaction, vec![1])])
        .unwrap();
    assert!(run.pin().is_none() && owner.pin(1).is_none());
    owner.confirm(&run).await.unwrap();
    assert_eq!(rows(&backend), RETAIN_TAIL + 2 * CUT_BATCH + 1);
    assert!(base_row(&backend).is_none());
}

/// (c)/(d) A carried row's pin holds the floor after its run is gone; the floor argument is
/// honoured; once released, the row is cut and reads `Truncated`, never `Corrupt`.
#[tokio::test]
async fn pins_hold_the_floor_and_a_released_row_reads_truncated() {
    let backend = ephemeral();
    let (_store, owner) = owner_on(&backend).await;
    append(&owner, 10).await;
    let persist = owner
        .stage_run(&[Entry::new(RecordClass::Checkpoint, b"persist".to_vec())])
        .unwrap();
    owner.confirm(&persist).await.unwrap();
    let carried = persist.carried().next().unwrap();
    let pin = owner.pin(carried.seq).expect("an Ephemeral journal pins");
    drop(persist);
    append(&owner, RETAIN_TAIL + 3 * CUT_BATCH).await;
    let mut cut = owner.cutter().unwrap();
    assert_eq!(
        cut.truncate_through(u64::MAX).await,
        CutProgress::Idle,
        "a pinned row holds the floor"
    );
    assert_eq!(owner.record(carried).await.unwrap().node_seq, carried.seq);
    drop(pin);
    assert_eq!(
        cut.truncate_through(CUT_BATCH - 1).await,
        CutProgress::Idle,
        "nothing is cut beyond the floor"
    );
    let progress = cut.truncate_through(u64::MAX).await;
    let CutProgress::Cut { base } = progress else {
        panic!("expected a cut, got {progress:?}");
    };
    assert!(base >= owner.ordinal_of(carried.seq));
    assert_eq!(
        owner.record(carried).await.map(|_| ()),
        Err(RuntimeError::Truncated)
    );
    assert_eq!(owner.locate_truncated(), 1);
}

/// Test 30(c): another caller publishes both runs before either owner's confirm is polled.
/// Their staging pins must survive more than two retention windows and an attempted cut.
#[tokio::test]
async fn delayed_confirm_keeps_checkpoint_and_reconciliation_originals() {
    let backend = ephemeral();
    let (_store, owner) = owner_on(&backend).await;
    let checkpoint = owner
        .stage_run(&[Entry::new(RecordClass::Checkpoint, vec![1])])
        .unwrap();
    let reconciliation = owner
        .stage_run(&[Entry::new(RecordClass::Reconciliation, vec![2])])
        .unwrap();
    let driver = owner
        .stage_run(&[Entry::new(RecordClass::Transaction, vec![3])])
        .unwrap();
    owner.confirm(&driver).await.unwrap();
    drop(driver);
    append(&owner, 2 * RETAIN_TAIL + CUT_BATCH).await;
    let mut cut = owner.cutter().unwrap();
    assert_eq!(cut.truncate_through(u64::MAX).await, CutProgress::Idle);
    for run in [&checkpoint, &reconciliation] {
        owner.confirm(run).await.unwrap();
        for original in run.carried() {
            assert_eq!(owner.record(original).await.unwrap().node_seq, original.seq);
        }
    }
    drop(checkpoint);
    drop(reconciliation);
    assert_eq!(owner.locate_truncated(), 0);
    assert!(matches!(
        cut.truncate_through(u64::MAX).await,
        CutProgress::Cut { .. }
    ));
}

/// Test 30(f): a cut waiting at the Store never owns the append driver.
#[tokio::test]
async fn a_blocked_cut_does_not_block_request_confirmations() {
    let backend = ephemeral();
    let (_store, owner) = owner_on(&backend).await;
    append(&owner, RETAIN_TAIL + 2 * CUT_BATCH).await;
    let mut cut = owner.cutter().unwrap();
    backend.hold_cut.store(true, Ordering::SeqCst);
    let cutting = tokio::spawn(async move { cut.truncate_through(u64::MAX).await });
    backend.cut_entered.notified().await;
    tokio::time::timeout(std::time::Duration::from_secs(1), append(&owner, 1000))
        .await
        .expect("confirms complete while the cut remains blocked at the store");
    assert!(!cutting.is_finished());
    backend.hold_cut.store(false, Ordering::SeqCst);
    backend.release_cut.notify_one();
    assert!(matches!(cutting.await.unwrap(), CutProgress::Cut { .. }));
}

/// (d) Cut versus readers: a walker whose base read preceded a cut is `Rebased`, never `Corrupt`;
/// `read_node_records` and `read_verified_record` restart and return what a walk started after
/// the cut returns; `snapshot` and reads below the base are `Truncated`; a same-holder re-take of
/// a cut journal is refused with `Truncated`.
#[tokio::test]
async fn cut_versus_readers_restarts_and_never_reads_corrupt() {
    let backend = ephemeral();
    let (store, owner) = owner_on(&backend).await;
    append(&owner, RETAIN_TAIL + 3 * CUT_BATCH).await;
    let before = backend.state.lock().unwrap().rows.clone();
    let journal = StoreJournal::new(&store, 7).unwrap();
    let mut early = journal.replay().await.unwrap();
    let proof = owner.verified().unwrap();
    let mut cut = owner.cutter().unwrap();
    let progress = cut.truncate_through(u64::MAX).await;
    let CutProgress::Cut { base } = progress else {
        panic!("expected a cut, got {progress:?}");
    };
    assert!(
        matches!(early.next().await, Err(Error::Rebased)),
        "a row cut after the cursor began is Rebased, never Corrupt"
    );
    let after = backend.state.lock().unwrap().rows.clone();
    let fresh = owner.read_node_records(7, READ).await.unwrap();
    assert_eq!(fresh.len() as u64, proof.head.count - base);

    backend.state.lock().unwrap().rows.clone_from(&before);
    cut_during_next_walk(&backend, after.clone());
    let restarts = journal_walk_restarts();
    assert_eq!(owner.read_node_records(7, READ).await.unwrap(), fresh);
    assert!(journal_walk_restarts() > restarts, "the walk restarted");

    backend.state.lock().unwrap().rows = before;
    cut_during_next_walk(&backend, after);
    let restarts = journal_walk_restarts();
    let newest = proof.head.sequence;
    let record = journal.read_verified_record(&proof, newest).await.unwrap();
    assert_eq!(record.node_seq, newest);
    assert!(journal_walk_restarts() > restarts, "the lookup restarted");

    assert!(matches!(
        journal.read_verified_record(&proof, 1).await,
        Err(Error::Truncated)
    ));
    assert!(matches!(
        owner.locate(&proof, 1),
        Err(RuntimeError::Truncated)
    ));
    assert!(matches!(
        journal
            .snapshot(crate::persistence::journal::historical::SnapshotBudget {
                records: 1 << 16,
                bytes: 1 << 26,
            })
            .await,
        Err(Error::Truncated)
    ));
    drop(early);
    drop(cut);
    drop(owner);
    assert!(matches!(
        RuntimeJournal::open(store.clone(), 7, OPEN).await,
        Err(RuntimeError::Truncated)
    ));
}

/// (e) In-doubt cut: an `Uncertain` base move is re-driven with the same digest, no new cut is
/// computed until it is decided, and group appends keep applying meanwhile (the cut's logical id
/// is never the append's).
#[tokio::test]
async fn in_doubt_cut_is_re_driven_exactly_while_appends_apply() {
    let backend = ephemeral();
    let (_store, owner) = owner_on(&backend).await;
    append(&owner, RETAIN_TAIL + 2 * CUT_BATCH).await;
    let mut cut = owner.cutter().unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(cut.truncate_through(u64::MAX).await, CutProgress::Retained);
    assert!(cut.retained());
    assert_eq!(owner.base_count(), 0, "an undecided move is not a base");
    let moved = Base::decode(
        7,
        &base_row(&backend).expect("the lost reply's move applied"),
    )
    .unwrap()
    .count();
    append(&owner, 1000).await;
    assert_eq!(
        cut.truncate_through(u64::MAX).await,
        CutProgress::Cut { base: moved },
        "the retained attempt is re-driven; no new cut is computed until it is decided"
    );
    assert!(!cut.retained());
    let moves: Vec<_> = appended(&backend)
        .into_iter()
        .filter(|candidate| {
            candidate.candidate().mutations.iter().any(|mutation| {
                matches!(mutation, Mutation::Put { address, .. } if address.key.get(24) == Some(&b'B'))
            })
        })
        .collect();
    assert_eq!(moves.len(), 2, "the move and its exact re-drive");
    assert_eq!(moves[0].fingerprint(), moves[1].fingerprint());
    assert_eq!(moves[0].candidate().id, moves[1].candidate().id);
}

/// (h) and the audit tail: the boot's `Bootstrap` original rides in the base's `keep` once the
/// cut passes it and is walked first; `keep.tail` is the newest audit line at or below the base,
/// by its WAL `node_seq` (chain seq and `node_seq` drift apart with interleaved rows, (g)).
#[tokio::test]
async fn kept_rows_and_the_audit_tail_enter_the_base() {
    let backend = ephemeral();
    let (_store, owner) = owner_on(&backend).await;
    let boot = owner
        .stage_run(&[Entry::new(RecordClass::Bootstrap, b"boot".to_vec())])
        .unwrap();
    owner.confirm(&boot).await.unwrap();
    let boot_seq = boot.records()[0].node_seq;
    drop(boot);
    let mut lines = BTreeMap::new();
    let mut chain_seq = 0u64;
    while owner.next_seq() <= RETAIN_TAIL + 3 * CUT_BATCH {
        chain_seq += 1;
        let fp = [chain_seq as u8; 32];
        let line = owner
            .stage_audit_run(
                &[Entry::new(
                    RecordClass::Transaction,
                    chain_seq.to_le_bytes().to_vec(),
                )],
                chain_seq,
                fp,
            )
            .unwrap();
        let other = owner
            .stage_run(&[Entry::new(RecordClass::Checkpoint, vec![1])])
            .unwrap();
        owner.confirm(&other).await.unwrap();
        let node_seq = line.records()[0].node_seq;
        lines.insert(
            node_seq,
            AuditTail {
                chain_seq,
                node_seq,
                fp,
            },
        );
    }
    let mut cut = owner.cutter().unwrap();
    let progress = cut.truncate_through(u64::MAX).await;
    let CutProgress::Cut { base } = progress else {
        panic!("expected a cut, got {progress:?}");
    };
    // The journal started empty, so a row's ordinal is its seq.
    assert_eq!(owner.ordinal_of(base), base);
    let expected = *lines.range(..=base).next_back().unwrap().1;
    assert_ne!(
        expected.chain_seq, expected.node_seq,
        "the two seqs drift apart"
    );
    assert_eq!(owner.base_tail(), Some(expected));
    let stored = Base::decode(7, &base_row(&backend).unwrap()).unwrap();
    assert_eq!(stored.tail(), expected);
    assert_eq!(stored.keep.len(), 1);
    assert_eq!(stored.keep[0].node_seq, boot_seq);
    let walked = owner.read_node_walk(7, READ).await.unwrap();
    assert_eq!(
        walked.base_tail,
        Some(expected),
        "audit readers receive the tail from the same base as their retained rows"
    );
    assert_eq!(walked.kept.len(), 1, "the kept copy is walked first");
    assert_eq!(walked.kept[0].class, RecordClass::Bootstrap);
    assert_eq!(walked.kept[0].node_seq, boot_seq);
    assert_eq!(walked.rows.first().map(|row| row.node_seq), Some(base + 1));
}
