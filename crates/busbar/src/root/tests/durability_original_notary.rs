// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::durability::audit::{tests::inputs, FrozenNativeAudit};
use crate::root::durability::tests::{audit_pass, token, NativeFixture, BUDGET};
use crate::root::durability::Durability;
use busbar_contract::storage::{StorageAccount, StorageDenied, StorageSource};
use busbar_kernel_audit::{AuditSigningKey, LiveSigner, Notary};
use busbar_kernel_wal::{Entry, RecordClass};
use std::sync::atomic::AtomicUsize;

#[derive(Default)]
struct Account(AtomicUsize);
impl StorageAccount for Account {
    fn try_reserve(&self, bytes: usize) -> Result<(), StorageDenied> {
        self.0.fetch_add(bytes, Ordering::AcqRel);
        Ok(())
    }
    fn release(&self, bytes: usize) {
        self.0.fetch_sub(bytes, Ordering::AcqRel);
    }
}

fn signing() -> (Notary, AuditVerifyingKey) {
    let key = AuditSigningKey::from_seed(&[41; 32]);
    let public = AuditVerifyingKey::from_hex(&key.public_key_hex()).unwrap();
    let (grant, _) = key.into_grants(LiveSigner::SameAsBootstrap).unwrap();
    (Notary::new(grant), public)
}

fn signed(notary: &Notary, target: &OriginalPageTarget) -> Stamp {
    notary
        .sign_stamp(Stamp {
            node: 7,
            from: target.from,
            to: target.to.seq,
            fingerprint: Fingerprint(target.to.fp),
            kind: StampKind::Live,
            sealer: 7,
            host: "receipt-test".into(),
            every: 10,
            stamped_ms: 123_000,
            down_from_ms: 0,
            down_to_ms: 0,
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            key_cert: 0,
            signature: Vec::new(),
        })
        .unwrap()
}

#[tokio::test]
async fn original_receipt_requires_exact_signed_run_applied_and_retains_credit() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let feed = book.lock().unwrap().head.clone();
    let (notary, public) = signing();
    feed.bind_original(fixture.journal.clone(), public).unwrap();
    let frozen = FrozenNativeAudit::new(inputs(1), &book);
    let mut slot = None;
    Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).unwrap();
    let original = slot.unwrap();
    let target = feed.original.page(1, feed.head()).unwrap();
    assert!(target.covers(&original));
    let stamp = signed(&notary, &target);
    assert!(feed.original.verify(&target, &stamp));
    let foreign_key = AuditSigningKey::from_seed(&[42; 32]);
    let (foreign_grant, _) = foreign_key
        .into_grants(LiveSigner::SameAsBootstrap)
        .unwrap();
    let foreign_stamp = Notary::new(foreign_grant)
        .sign_stamp(stamp.clone())
        .unwrap();
    assert!(!feed.original.verify(&target, &foreign_stamp));
    let mut final_page = stamp.clone();
    final_page.kind = StampKind::Final;
    let final_page = notary.sign_stamp(final_page).unwrap();
    assert!(!feed.original.verify(&target, &final_page));
    let mut delegated = stamp.clone();
    delegated.key_cert = 1;
    let delegated = notary.sign_stamp(delegated).unwrap();
    assert!(!feed.original.verify(&target, &delegated));
    let restart_key = AuditSigningKey::from_seed(&[41; 32]);
    let (_, restart_grant) = restart_key
        .into_grants(LiveSigner::SameAsBootstrap)
        .unwrap();
    let mut restarted = stamp.clone();
    restarted.kind = StampKind::AfterRestart;
    let restarted = busbar_kernel_audit::BootstrapSigner::new(restart_grant)
        .sign_restart_page(restarted)
        .unwrap();
    assert!(!feed.original.verify(&target, &restarted));
    feed.original.configure(&stamp).unwrap();
    let account = Arc::new(Account::default());
    let bytes = feed.original.bytes().unwrap();
    let mut credit = StorageSource::new(account.clone())
        .try_reserve(bytes)
        .unwrap();
    let run = fixture
        .journal
        .stage_run(&[Entry::new(
            RecordClass::Transaction,
            busbar_kernel_audit::stamp_body(&stamp).unwrap(),
        )])
        .unwrap();
    credit = feed
        .original
        .applied(target.clone(), run.clone(), credit)
        .err()
        .unwrap();
    assert_eq!(account.0.load(Ordering::Acquire), bytes);
    fixture.faults.lose_acks.store(true, Ordering::Release);
    assert!(fixture.journal.confirm(&run).await.is_err());
    credit = feed
        .original
        .applied(target.clone(), run.clone(), credit)
        .err()
        .unwrap();
    fixture.faults.lose_acks.store(false, Ordering::Release);
    fixture.journal.confirm(&run).await.unwrap();
    let receipt = feed
        .original
        .applied(target, run.clone(), credit)
        .ok()
        .unwrap();
    let line = receipt.bind(&original).unwrap();
    assert!(line.confirms(&original));
    assert_eq!(account.0.load(Ordering::Acquire), bytes);
    let other = NativeFixture::new(7).await;
    let foreign = Arc::new(Mutex::new(other.book().await));
    let frozen = FrozenNativeAudit::new(inputs(1), &foreign);
    let mut slot = None;
    Durability::stage_native(&foreign, &frozen, &audit_pass(), &token(), &mut slot).unwrap();
    assert!(receipt.bind(&slot.unwrap()).is_none());
    let mut altered = original.clone();
    altered.line.fp = Fingerprint::ZERO;
    assert!(receipt.bind(&altered).is_none());
    assert!(!line.confirms(&altered));
    drop(receipt);
    assert_eq!(account.0.load(Ordering::Acquire), bytes);
    drop(line);
    assert_eq!(account.0.load(Ordering::Acquire), 0);
    {
        let requests = fixture.faults.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].candidate().id, requests[1].candidate().id);
        assert_eq!(requests[0].fingerprint(), requests[1].fingerprint());
    }
    let reopened = RuntimeJournal::open(fixture.core.clone(), 7, BUDGET)
        .await
        .unwrap();
    let stored = reopened.read_records(BUDGET).await.unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(
        stored[1],
        busbar_kernel_wal::JournalRecord::decode(&run.records()[0].body).unwrap()
    );
    assert_eq!(
        reopened.is_confirmed(&run),
        Err(busbar_kernel::persistence::journal::runtime::RuntimeError::Authority),
        "persisted bytes do not reconstruct the previous live owner's capability"
    );
}

#[tokio::test]
async fn original_baseline_excludes_old_lines_and_recovery_publication_invalidates() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let first = FrozenNativeAudit::new(inputs(1), &book);
    let mut old = None;
    Durability::stage_native(&book, &first, &audit_pass(), &token(), &mut old).unwrap();
    old.as_ref().unwrap().confirm_journal().await.unwrap();
    let feed = book.lock().unwrap().head.clone();
    let (_, public) = signing();
    feed.bind_original(fixture.journal.clone(), public).unwrap();
    assert!(feed.original.page(1, feed.head()).is_none());
    let second = FrozenNativeAudit::new(inputs(2), &book);
    let mut current = None;
    Durability::stage_native(&book, &second, &audit_pass(), &token(), &mut current).unwrap();
    let page = feed.original.page(2, feed.head()).unwrap();
    assert!(!page.covers(old.as_ref().unwrap()));
    assert!(page.covers(current.as_ref().unwrap()));
    feed.publish_max(&feed.head());
    assert!(feed.original.page(2, feed.head()).is_none());
    assert!(feed.original.ready().is_none());
    let third = FrozenNativeAudit::new(inputs(3), &book);
    let mut refused = None;
    assert!(
        Durability::stage_native(&book, &third, &audit_pass(), &token(), &mut refused).is_err()
    );
    assert!(refused.is_none());
}
