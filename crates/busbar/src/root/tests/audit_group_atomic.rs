// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::durability::tests::{audit_inputs, audit_pass, NativeFixture, BUDGET};
use crate::root::durability::{audit_entry, decode_audit};
use busbar_contract::persistence::{Failure, Mutation};
use busbar_kernel::persistence::journal::{RuntimeError, RuntimeJournal};
use busbar_kernel_audit::{Audit, AuditChain, AuditRecord, AuditSigningKey};
use busbar_kernel_wal::Entry;
use std::sync::{atomic::Ordering, Arc};

fn signed_entries(node: u64, count: usize) -> (Vec<Entry>, Vec<AuditRecord>) {
    let mut chain = AuditChain::new()
        .sealing_as(node)
        .signing_with(AuditSigningKey::from_seed(&[0x63; 32]));
    let records: Vec<_> = (1..=count)
        .map(|seq| {
            let mut inputs = audit_inputs(seq as u64);
            inputs.what.destination = Some("actual-group-destination".repeat(100));
            chain.seal(inputs, &audit_pass())
        })
        .collect();
    let entries = records
        .iter()
        .map(|record| audit_entry(record).unwrap())
        .collect();
    (entries, records)
}

fn assert_signed(actual: &[busbar_kernel_wal::JournalRecord], expected: &[AuditRecord]) {
    busbar_kernel_wal::verify_journal(actual).unwrap();
    let decoded: Vec<_> = actual
        .iter()
        .map(|record| decode_audit(record).unwrap().unwrap())
        .collect();
    assert_eq!(decoded, expected);
    AuditChain::verify_chain(&decoded).unwrap();
    let public = busbar_kernel_audit::AuditVerifyingKey::from_hex(
        &AuditSigningKey::from_seed(&[0x63; 32]).public_key_hex(),
    )
    .unwrap();
    for record in &decoded {
        AuditChain::verify_signature(record, &public).unwrap();
    }
}

#[tokio::test]
async fn group_publishes_every_signed_original_and_head_in_one_native_commit() {
    let fixture = NativeFixture::new(81).await;
    let (entries, expected) = signed_entries(81, 3);
    fixture.faults.clear_observations();
    let run = fixture.journal.stage_run(&entries).unwrap();
    assert_eq!(fixture.journal.pending_records(), 3);
    assert!(fixture
        .journal
        .read_records(BUDGET)
        .await
        .unwrap()
        .is_empty());
    fixture.journal.confirm(&run).await.unwrap();
    assert!(fixture.journal.is_confirmed(&run).unwrap());
    assert_eq!(fixture.journal.pending_records(), 0);
    assert_signed(
        &fixture.journal.read_records(BUDGET).await.unwrap(),
        &expected,
    );
    let requests = fixture.faults.requests.lock().unwrap();
    let finals: Vec<_> = requests
        .iter()
        .filter(|request| {
            request.candidate().mutations.iter().any(|mutation|
        matches!(mutation, Mutation::Put { address, .. } if address.key.get(24) == Some(&b'H')))
        })
        .collect();
    assert_eq!(finals.len(), 1);
    let candidate = finals[0].candidate();
    assert!(!candidate
        .mutations
        .iter()
        .any(|m| matches!(m, Mutation::DeleteRange { .. } | Mutation::Delete(_))));
    assert_eq!(
        candidate
            .mutations
            .iter()
            .filter(
                |m| matches!(m, Mutation::Put { address, .. } if address.key.get(24) == Some(&b'R'))
            )
            .count(),
        3
    );
    assert_eq!(
        candidate
            .mutations
            .iter()
            .filter(
                |m| matches!(m, Mutation::Put { address, .. } if address.key.get(24) == Some(&b'H'))
            )
            .count(),
        1
    );
}

#[tokio::test]
async fn refused_group_publishes_no_member_and_retries_the_retained_originals() {
    let fixture = NativeFixture::new(82).await;
    let (entries, expected) = signed_entries(82, 3);
    let run = fixture.journal.stage_run(&entries).unwrap();
    fixture.faults.refusing.store(true, Ordering::Release);
    assert!(fixture.journal.confirm(&run).await.is_err());
    assert!(!fixture.journal.is_confirmed(&run).unwrap());
    assert_eq!(fixture.journal.pending_records(), 3);
    assert!(fixture
        .journal
        .read_records(BUDGET)
        .await
        .unwrap()
        .is_empty());
    fixture.faults.refusing.store(false, Ordering::Release);
    fixture.journal.confirm(&run).await.unwrap();
    assert_signed(
        &fixture.journal.read_records(BUDGET).await.unwrap(),
        &expected,
    );
}

#[tokio::test]
async fn lost_group_reply_retains_exact_candidate_and_restart_reads_the_signed_prefix() {
    let fixture = NativeFixture::new(83).await;
    let (entries, expected) = signed_entries(83, 3);
    let run = fixture.journal.stage_run(&entries).unwrap();
    fixture.faults.clear_observations();
    fixture.faults.lose_acks.store(true, Ordering::Release);
    assert!(fixture.journal.confirm(&run).await.is_err());
    assert_eq!(fixture.journal.pending_records(), 3);
    assert!(!fixture.journal.is_confirmed(&run).unwrap());
    fixture.faults.lose_acks.store(false, Ordering::Release);
    fixture.journal.confirm(&run).await.unwrap();
    let requests = fixture.faults.requests.lock().unwrap().clone();
    // Include every repeated operation, including core custody frames: no replay
    // may change a candidate body while retaining its original attempt identity.
    let mut repeated = false;
    for (index, request) in requests.iter().enumerate() {
        for earlier in &requests[..index] {
            if earlier.candidate().id == request.candidate().id {
                repeated = true;
                assert_eq!(earlier.fingerprint(), request.fingerprint());
            }
        }
    }
    assert!(
        repeated,
        "a lost acknowledgement must retry its exact native attempt"
    );
    assert_signed(
        &fixture.journal.read_records(BUDGET).await.unwrap(),
        &expected,
    );
    let restarted = RuntimeJournal::open(fixture.core.clone(), 83, BUDGET)
        .await
        .unwrap();
    assert_signed(&restarted.read_records(BUDGET).await.unwrap(), &expected);
    assert_eq!(restarted.next_seq(), 4);
    assert_eq!(restarted.pending_records(), 0);
}

#[tokio::test]
async fn staged_run_cannot_be_acknowledged_by_another_node_owner() {
    let fixture = NativeFixture::new(84).await;
    let other = RuntimeJournal::open(fixture.core.clone(), 85, BUDGET)
        .await
        .unwrap();
    let (entries, _) = signed_entries(84, 3);
    let run = fixture.journal.stage_run(&entries).unwrap();
    fixture.faults.clear_observations();
    assert_eq!(other.confirm(&run).await, Err(RuntimeError::Authority));
    assert_eq!(other.is_confirmed(&run), Err(RuntimeError::Authority));
    assert!(fixture.faults.requests.lock().unwrap().is_empty());
    assert!(other.read_records(BUDGET).await.unwrap().is_empty());
}

#[tokio::test]
async fn group_bounds_refuse_before_any_backend_call_or_sequence_reservation() {
    let fixture = NativeFixture::new(86).await;
    fixture.faults.clear_observations();
    let initial = fixture.journal.next_seq();
    let (one, _) = signed_entries(86, 1);
    let entries = vec![one[0].clone(); BUDGET.records + 1];
    assert!(matches!(
        fixture.journal.stage_run(&entries),
        Err(RuntimeError::Budget)
    ));
    let huge = Entry::new(
        busbar_kernel_wal::RecordClass::Transaction,
        vec![0; BUDGET.bytes],
    );
    assert!(matches!(
        fixture.journal.stage_run(&[huge]),
        Err(RuntimeError::Budget)
    ));
    assert_eq!(fixture.journal.next_seq(), initial);
    assert_eq!(fixture.journal.pending_records(), 0);
    assert!(fixture.faults.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn backend_refusal_in_publication_keeps_the_whole_group_unacknowledged() {
    let fixture = NativeFixture::new(87).await;
    let (entries, expected) = signed_entries(87, 3);
    let run = fixture.journal.stage_run(&entries).unwrap();
    *fixture.faults.on_commit.lock().unwrap() = Some(Arc::new(|request| {
        Box::pin(async move {
            if request.candidate().mutations.iter().any(|mutation|
            matches!(mutation, Mutation::Put { address, .. } if address.key.get(24) == Some(&b'H'))) {
            return Err(Failure::Refused);
        }
            Ok(())
        })
    }));
    assert!(fixture.journal.confirm(&run).await.is_err());
    assert_eq!(fixture.journal.pending_records(), 3);
    assert!(!fixture.journal.is_confirmed(&run).unwrap());
    assert!(fixture
        .journal
        .read_records(BUDGET)
        .await
        .unwrap()
        .is_empty());
    *fixture.faults.on_commit.lock().unwrap() = None;
    fixture.journal.confirm(&run).await.unwrap();
    assert_signed(
        &fixture.journal.read_records(BUDGET).await.unwrap(),
        &expected,
    );
}

#[tokio::test]
async fn reconstructed_group_proof_rejects_corrupt_members_and_earlier_history_without_writes() {
    for ordinal in [1, 3] {
        let fixture = NativeFixture::new(88 + ordinal).await;
        let (entries, _) = signed_entries(88 + ordinal, 4);
        let run = fixture.journal.stage_run(&entries).unwrap();
        fixture.journal.confirm(&run).await.unwrap();
        fixture.corrupt_original(ordinal).await;
        fixture.faults.clear_observations();
        assert!(
            fixture.journal.read_records(BUDGET).await.is_err(),
            "a matching tail cannot excuse a corrupt earlier signed original"
        );
        assert!(
            RuntimeJournal::open(fixture.core.clone(), 88 + ordinal, BUDGET)
                .await
                .is_err()
        );
        assert!(
            fixture.faults.requests.lock().unwrap().is_empty(),
            "corrupt reconstructed history must not trigger destructive cleanup or publication"
        );
    }
}

#[tokio::test]
async fn prepared_group_head_conflict_cannot_overwrite_a_newly_published_member() {
    let fixture = NativeFixture::new(93).await;
    let (entries, _) = signed_entries(93, 3);
    let staged = fixture.journal.stage_run(&entries).unwrap();
    let competing = RuntimeJournal::open(fixture.core.clone(), 93, BUDGET)
        .await
        .unwrap();
    let one = competing.stage_run(&entries[..1]).unwrap();
    competing.confirm(&one).await.unwrap();
    let before = competing.read_records(BUDGET).await.unwrap();
    assert_eq!(before.len(), 1);
    assert!(fixture.journal.confirm(&staged).await.is_err());
    assert!(!fixture.journal.is_confirmed(&staged).unwrap());
    assert_eq!(fixture.journal.pending_records(), 3);
    let after = competing.read_records(BUDGET).await.unwrap();
    assert_eq!(
        after, before,
        "a stale group cannot publish a suffix or remove the independently committed prefix"
    );
    busbar_kernel_wal::verify_journal(&after).unwrap();
}
