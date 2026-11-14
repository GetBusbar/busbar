// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Group commit in the node journal driver: every run already pending when the
//! driver takes its lock goes to the store in one append, and a group that was
//! submitted is replayed unchanged until it resolves (exact-retry rule).

use crate::root::durability::tests::{audit_inputs, audit_pass, NativeFixture, BUDGET};
use crate::root::durability::{audit_entry, decode_audit};
use busbar_contract::persistence::{Mutation, PreparedCandidate};
use busbar_kernel::persistence::journal::StagedRun;
use busbar_kernel_audit::{Audit, AuditChain, AuditRecord, AuditSigningKey};
use busbar_kernel_wal::Entry;
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;

/// The store's scan limit in the test `CoreStore` (`native_store_startup.rs`).
const SCAN_ITEMS: usize = 128;

fn entries(node: u64, count: usize) -> (Vec<Entry>, Vec<AuditRecord>) {
    let mut chain = AuditChain::new()
        .sealing_as(node)
        .signing_with(AuditSigningKey::from_seed(&[0x65; 32]));
    let records: Vec<_> = (1..=count)
        .map(|seq| chain.seal(audit_inputs(seq as u64), &audit_pass()))
        .collect();
    let entries = records
        .iter()
        .map(|record| audit_entry(record).unwrap())
        .collect();
    (entries, records)
}

fn stage_each(fixture: &NativeFixture, entries: &[Entry]) -> Vec<Arc<StagedRun>> {
    entries
        .iter()
        .map(|entry| {
            fixture
                .journal
                .stage_run(std::slice::from_ref(entry))
                .unwrap()
        })
        .collect()
}

fn is_head_put(mutation: &Mutation) -> bool {
    matches!(mutation, Mutation::Put { address, .. } if address.key.get(24) == Some(&b'H'))
}
fn is_record_put(mutation: &Mutation) -> bool {
    matches!(mutation, Mutation::Put { address, .. } if address.key.get(24) == Some(&b'R'))
}

/// Every journal append the store saw (one head select per append).
fn appends(fixture: &NativeFixture) -> Vec<PreparedCandidate> {
    fixture
        .faults
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.candidate().mutations.iter().any(is_head_put))
        .cloned()
        .collect()
}
fn record_puts(candidate: &PreparedCandidate) -> usize {
    candidate
        .candidate()
        .mutations
        .iter()
        .filter(|m| is_record_put(m))
        .count()
}

async fn assert_stored(fixture: &NativeFixture, expected: &[AuditRecord]) {
    let stored = fixture.journal.read_records(BUDGET).await.unwrap();
    busbar_kernel_wal::verify_journal(&stored).unwrap();
    let decoded: Vec<_> = stored
        .iter()
        .map(|record| decode_audit(record).unwrap().unwrap())
        .collect();
    assert_eq!(decoded, expected);
    AuditChain::verify_chain(&decoded).unwrap();
}

#[tokio::test]
async fn drive_through_groups_pending_runs() {
    let fixture = NativeFixture::new(141).await;
    let (entries, expected) = entries(141, 5);
    let runs = stage_each(&fixture, &entries);
    fixture.faults.clear_observations();
    fixture.journal.confirm(runs.last().unwrap()).await.unwrap();
    let appends = appends(&fixture);
    assert_eq!(appends.len(), 1, "5 pending runs need one store append");
    assert_eq!(record_puts(&appends[0]), 5);
    for run in &runs {
        assert!(fixture.journal.is_confirmed(run).unwrap());
    }
    assert_eq!(fixture.journal.pending_records(), 0);
    assert_stored(&fixture, &expected).await;
}

#[tokio::test]
async fn group_is_cut_at_the_store_scan_limit() {
    let fixture = NativeFixture::new(142).await;
    let (entries, expected) = entries(142, 2 * SCAN_ITEMS);
    let runs = stage_each(&fixture, &entries);
    fixture.faults.clear_observations();
    fixture.journal.flush().await.unwrap();
    let appends = appends(&fixture);
    assert_eq!(
        appends.len(),
        2,
        "2x scan_items pending runs need two appends"
    );
    for append in &appends {
        assert_eq!(record_puts(append), SCAN_ITEMS);
    }
    for run in &runs {
        assert!(fixture.journal.is_confirmed(run).unwrap());
    }
    assert_stored(&fixture, &expected).await;
}

#[tokio::test]
async fn group_retry_after_uncertain_is_exact() {
    let fixture = NativeFixture::new(143).await;
    let (entries, expected) = entries(143, 5);
    let first = stage_each(&fixture, &entries[..3]);
    fixture.faults.clear_observations();
    fixture.faults.lose_acks.store(true, Ordering::Release);
    assert!(fixture
        .journal
        .confirm(first.last().unwrap())
        .await
        .is_err());
    fixture.faults.lose_acks.store(false, Ordering::Release);
    for run in &first {
        assert!(!fixture.journal.is_confirmed(run).unwrap());
    }
    let later = stage_each(&fixture, &entries[3..]);
    fixture
        .journal
        .confirm(later.last().unwrap())
        .await
        .unwrap();
    let appends = appends(&fixture);
    assert_eq!(
        appends.len(),
        3,
        "first group, its exact retry, the new group"
    );
    assert_eq!(appends[0].candidate().id, appends[1].candidate().id);
    assert_eq!(appends[0].fingerprint(), appends[1].fingerprint());
    assert_eq!(record_puts(&appends[1]), 3);
    assert_eq!(record_puts(&appends[2]), 2);
    for run in first.iter().chain(&later) {
        assert!(fixture.journal.is_confirmed(run).unwrap());
    }
    assert_stored(&fixture, &expected).await;
}

#[tokio::test]
async fn group_retry_after_cancel_is_exact() {
    let fixture = NativeFixture::new(144).await;
    let (entries, expected) = entries(144, 5);
    let first = stage_each(&fixture, &entries[..3]);
    fixture.faults.clear_observations();
    let entered = Arc::new(tokio::sync::Notify::new());
    let gate = entered.clone();
    *fixture.faults.on_commit.lock().unwrap() = Some(Arc::new(move |request| {
        let gate = gate.clone();
        Box::pin(async move {
            if request.candidate().mutations.iter().any(is_head_put) {
                gate.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(())
        })
    }));
    let writer = fixture.journal.clone();
    let target = first.last().unwrap().clone();
    let driving = tokio::spawn(async move { writer.confirm(&target).await });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    driving.abort();
    let _ = driving.await;
    *fixture.faults.on_commit.lock().unwrap() = None;
    let later = stage_each(&fixture, &entries[3..]);
    tokio::time::timeout(
        Duration::from_secs(10),
        fixture.journal.confirm(later.last().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let appends = appends(&fixture);
    assert!(appends.len() >= 2);
    // The cancelled group is replayed unchanged before any new group forms.
    assert_eq!(record_puts(&appends[0]), 3);
    let replayed: Vec<_> = appends[1..]
        .iter()
        .filter(|append| append.candidate().id == appends[0].candidate().id)
        .collect();
    for append in &replayed {
        assert_eq!(append.fingerprint(), appends[0].fingerprint());
    }
    let fresh: Vec<_> = appends[1..]
        .iter()
        .filter(|append| append.candidate().id != appends[0].candidate().id)
        .collect();
    assert_eq!(
        fresh.len(),
        1,
        "the 2 runs staged after the cancel form one group"
    );
    assert_eq!(record_puts(fresh[0]), 2);
    for run in first.iter().chain(&later) {
        assert!(fixture.journal.is_confirmed(run).unwrap());
    }
    assert_stored(&fixture, &expected).await;
}
