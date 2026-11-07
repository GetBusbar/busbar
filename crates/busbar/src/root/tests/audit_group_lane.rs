// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::durability::audit_entry;
use crate::root::durability::tests::{audit_inputs, audit_pass, NativeFixture, BUDGET};
use busbar_contract::persistence::Mutation;
use busbar_kernel::persistence::journal::RuntimeJournal;
use busbar_kernel_audit::{Audit, AuditChain, AuditSigningKey};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn actual_lane_acknowledges_only_the_whole_published_prefix_and_restarts() {
    let fixture = NativeFixture::new(91).await;
    let mut chain = AuditChain::new()
        .sealing_as(91)
        .signing_with(AuditSigningKey::from_seed(&[0x64; 32]));
    let audits: Vec<_> = (1..=3)
        .map(|seq| chain.seal(audit_inputs(seq), &audit_pass()))
        .collect();
    let entries: Vec<_> = audits
        .iter()
        .map(|record| audit_entry(record).unwrap())
        .collect();
    let run = fixture.journal.stage_run(&entries).unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (gate, resume) = (entered.clone(), release.clone());
    *fixture.faults.on_commit.lock().unwrap() = Some(Arc::new(move |request| {
        let (gate, resume) = (gate.clone(), resume.clone());
        Box::pin(async move {
            if request.candidate().mutations.iter().any(|mutation|
                matches!(mutation, Mutation::Put { address, .. } if address.key.get(24) == Some(&b'H'))) {
                gate.notify_one();
                resume.notified().await;
            }
            Ok(())
        })
    }));
    let writer = fixture.journal.clone();
    let pending = run.clone();
    let confirm = tokio::spawn(async move { writer.confirm(&pending).await });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    assert_eq!(fixture.journal.pending_records(), 3);
    assert!(!fixture.journal.is_confirmed(&run).unwrap());
    assert!(fixture
        .journal
        .read_records(BUDGET)
        .await
        .unwrap()
        .is_empty());
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), confirm)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(fixture.journal.pending_records(), 0);
    assert!(fixture.journal.is_confirmed(&run).unwrap());
    *fixture.faults.on_commit.lock().unwrap() = None;
    let stored = fixture.journal.read_records(BUDGET).await.unwrap();
    assert_eq!(stored.len(), 3);
    busbar_kernel_wal::verify_journal(&stored).unwrap();
    let reopened = RuntimeJournal::open(fixture.core.clone(), 91, BUDGET)
        .await
        .unwrap();
    fixture.faults.clear_observations();
    let replay = reopened.read_records(BUDGET).await.unwrap();
    assert_eq!(replay, stored);
    assert_eq!(reopened.pending_records(), 0);
    assert_eq!(reopened.next_seq(), 4);
    assert!(
        fixture.faults.requests.lock().unwrap().is_empty(),
        "reconstructed proof requires no cleanup or publication"
    );
    let decoded: Vec<_> = replay
        .iter()
        .map(|r| crate::root::durability::decode_audit(r).unwrap().unwrap())
        .collect();
    assert_eq!(decoded, audits);
    AuditChain::verify_chain(&decoded).unwrap();
}
