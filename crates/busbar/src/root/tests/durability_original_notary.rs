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

#[test]
fn original_scan_rejects_changed_horizon_and_nonprogress() {
    let first = OriginalPageCursor {
        last: Some(64),
        upper: 130,
    };
    assert!(first.advances(None, None));
    assert!(!first.advances(Some(first), Some(130)));
    assert!(first.preserves(Some(first), Some(130)));
    assert!(!OriginalPageCursor {
        last: Some(65),
        upper: 131
    }
    .advances(Some(first), Some(130)));
    assert!(!OriginalPageCursor {
        last: Some(131),
        upper: 130
    }
    .advances(Some(first), Some(130)));
    let page = super::super::Page {
        to: 2,
        to_node_seq: 2,
        first_ms: None,
        original: None,
        upper: Some(130),
    };
    let retry = super::super::Funding::retry(page, None);
    assert_eq!(retry.page.upper, Some(130));
    assert_eq!(retry.cursor, Some(OriginalPageCursor::start(130)));
}

struct TwoOriginals {
    entries: [NativeStagedAudit; 2],
    credit: Mutex<Option<StorageCredit>>,
    receipts: Mutex<[Option<OriginalLineReceipt>; 2]>,
    stamp_pointer: Mutex<Option<usize>>,
    deliveries: AtomicUsize,
    done: tokio::sync::Notify,
}

impl OriginalPageReceiver for TwoOriginals {
    fn fund_original_page(
        &self,
        target: &OriginalPageTarget,
        bytes: usize,
        cursor: Option<OriginalPageCursor>,
    ) -> PageFunding {
        let upper = cursor.map_or(2, |cursor| cursor.upper);
        assert_eq!(upper, 2);
        assert!(target.covers(&self.entries[0]));
        assert!(target.covers(&self.entries[1]));
        let credit = self.credit.lock().unwrap().take().unwrap();
        assert!(credit.len() >= bytes);
        PageFunding::Reserved(credit, upper)
    }

    fn deliver_original_page(
        &self,
        page: &OriginalPageReceipt,
        cursor: Option<OriginalPageCursor>,
    ) -> PageDelivery {
        let cursor = cursor.expect("delivery inherits funding's finite horizon");
        assert_eq!(cursor.upper, 2);
        let index = match cursor.last {
            None => 0,
            Some(1) => 1,
            _ => panic!("delivery repeated or escaped its original scan"),
        };
        let pointer = Arc::as_ptr(&page.backing.run) as usize;
        let mut original = self.stamp_pointer.lock().unwrap();
        if let Some(original) = *original {
            assert_eq!(original, pointer);
        }
        *original = Some(pointer);
        self.receipts.lock().unwrap()[index] = Some(page.bind(&self.entries[index]).unwrap());
        self.deliveries.fetch_add(1, Ordering::AcqRel);
        if index == 0 {
            PageDelivery::Pending(OriginalPageCursor {
                last: Some(1),
                upper: 2,
            })
        } else {
            self.done.notify_waiters();
            PageDelivery::Complete
        }
    }
}

#[tokio::test]
async fn running_notary_keeps_actual_signed_run_through_unknown_ack_and_delivery_slices() {
    use crate::root::durability::{notary, signer};
    use std::sync::OnceLock;
    use std::time::Duration;

    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let feed = book.lock().unwrap().head.clone();
    let key = AuditSigningKey::from_seed(&[41; 32]);
    let public = AuditVerifyingKey::from_hex(&key.public_key_hex()).unwrap();
    let (grant, bootstrap) = key.into_grants(LiveSigner::SameAsBootstrap).unwrap();
    let cap = Notary::new(grant);
    feed.bind_original(fixture.journal.clone(), public).unwrap();
    let start = book.lock().unwrap().notary_start();
    let mut entries = Vec::new();
    for unit in 1..=2 {
        let frozen = FrozenNativeAudit::new(inputs(unit), &book);
        let mut slot = None;
        Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).unwrap();
        entries.push(slot.unwrap());
    }
    let target = feed.original.page(1, feed.head()).unwrap();
    feed.original.configure(&signed(&cap, &target)).unwrap();
    let account = Arc::new(Account::default());
    let bytes = feed.original.bytes().unwrap();
    let credit = StorageSource::new(account.clone())
        .try_reserve(bytes)
        .unwrap();
    let receiver = Arc::new(TwoOriginals {
        entries: entries.try_into().ok().unwrap(),
        credit: Mutex::new(Some(credit)),
        receipts: Mutex::new([None, None]),
        stamp_pointer: Mutex::new(None),
        deliveries: AtomicUsize::new(0),
        done: tokio::sync::Notify::new(),
    });
    let erased: Arc<dyn OriginalPageReceiver> = receiver.clone();
    feed.register_original_receiver(Arc::downgrade(&erased))
        .unwrap();
    assert!(feed.original_ready().is_none(), "notary has not started");
    let signers = signer::spawn(
        cap,
        busbar_kernel_audit::BootstrapSigner::new(bootstrap),
        Arc::new(OnceLock::new()),
    )
    .unwrap();
    fixture.faults.clear_observations();
    fixture.faults.lose_acks.store(true, Ordering::Release);
    let task = notary::spawn_with_floor(
        notary::NotaryConfig {
            node: 7,
            host: "receipt-test".into(),
            every_ms: 10,
            key_cert: 0,
        },
        start,
        fixture.journal.clone(),
        feed.clone(),
        signers.live,
        None,
        None,
    );
    assert_eq!(feed.original_ready().unwrap().retention_bytes(), bytes);
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.faults.applied() == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(receiver.deliveries.load(Ordering::Acquire), 0);
    assert!(receiver
        .receipts
        .lock()
        .unwrap()
        .iter()
        .all(Option::is_none));
    assert_eq!(account.0.load(Ordering::Acquire), bytes);
    fixture.faults.lose_acks.store(false, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let notified = receiver.done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if receiver.deliveries.load(Ordering::Acquire) == 2 {
                break;
            }
            notified.await;
        }
    })
    .await
    .unwrap();
    for (entry, receipt) in receiver
        .entries
        .iter()
        .zip(receiver.receipts.lock().unwrap().iter())
    {
        assert!(receipt.as_ref().unwrap().confirms(entry));
    }
    let end = task.stop().await.unwrap();
    assert!(end.halted.is_none());
    assert_eq!(end.stamped_through, 2);
    let sent = fixture.faults.requests.lock().unwrap().clone();
    assert!(sent.len() >= 2);
    assert!(sent
        .iter()
        .all(|request| request.candidate().id == sent[0].candidate().id
            && request.fingerprint() == sent[0].fingerprint()));
    drop(erased);
    drop(receiver);
    assert_eq!(account.0.load(Ordering::Acquire), 0);
    drop((
        signers.boot,
        signers.sealer,
        signers.checkpoint,
        signers.response_intent,
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !signers.threads.live_finished() || !signers.threads.bootstrap_finished() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn original_bootstrap_binding_rejects_foreign_owners_and_starts_after_recovery() {
    use crate::root::durability::audit_services::AuditServices;
    use busbar_kernel_audit::BootstrapSigner;
    use std::time::Duration;

    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let feed = book.lock().unwrap().head.clone();
    let key = AuditSigningKey::from_seed(&[41; 32]);
    let public = AuditVerifyingKey::from_hex(&key.public_key_hex()).unwrap();
    let (live, boot) = key.into_grants(LiveSigner::SameAsBootstrap).unwrap();
    let (services, checkpoint) = AuditServices::spawn(
        Notary::new(live),
        BootstrapSigner::new(boot),
        7,
        fixture.journal.clone(),
        feed.clone(),
        book.lock().unwrap().notary_start(),
    )
    .unwrap();
    // The services existed before recovery's final canonical publication.
    Durability::seal_unit(&book, inputs(1), audit_pass(), &token())
        .await
        .unwrap();
    let foreign = NativeFixture::new(7).await;
    let foreign_book = foreign.book().await;
    assert!(services
        .bind_original_bootstrap(&foreign_book, public.clone())
        .is_err());
    let wrong = AuditSigningKey::from_seed(&[42; 32]);
    let wrong = AuditVerifyingKey::from_hex(&wrong.public_key_hex()).unwrap();
    assert!(services
        .bind_original_bootstrap(&book.lock().unwrap(), wrong)
        .is_err());
    services
        .bind_original_bootstrap(&book.lock().unwrap(), public.clone())
        .unwrap();
    assert!(services
        .bind_original_bootstrap(&book.lock().unwrap(), public)
        .is_err());
    assert!(feed.original.page(1, feed.head()).is_none());
    let clock = busbar_kernel::governance::drain::DrainClock::new(Duration::from_secs(5));
    assert!(services.start_notary(10, clock));
    assert!(
        feed.original_ready().is_none(),
        "no Node receiver was registered"
    );
    let end = services.take_notary().unwrap().stop().await.unwrap();
    assert_eq!(end.committed_through, 1);
    assert_eq!(end.stamped_through, 1);
    assert_eq!(end.final_staged, None);
    assert_eq!(fixture.journal.read_records(BUDGET).await.unwrap().len(), 1);
    drop(checkpoint);
}
