// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::tests::{bind, seal, token, NativeFixture, BUDGET};
use super::*;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
const NOW: u64 = 1_700_000_000;

#[tokio::test]
async fn amendment_rebuild_refuses_unreadable_store_without_advancing() {
    let fixture = NativeFixture::new(47).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    seal(&book, 1).await;
    let mut reopened = fixture.reopen().await;
    fixture.faults.unreadable.store(true, Ordering::Release);
    let amendments = busbar_kernel_audit::amend::NodeAmendments::new();
    let failure = reopened
        .restore_amendments(&amendments, &token())
        .await
        .unwrap_err();
    assert!(failure.contains("could not be read back"), "{failure}");
    assert_eq!(reopened.amendments_through, None);
}

#[tokio::test]
async fn keyset_binding_refuses_unreadable_store_without_second_bootstrap() {
    let fixture = NativeFixture::new(47).await;
    let mut first = fixture.book().await;
    bind(&mut first, &fixture).await;
    let mut reopened = fixture.reopen().await;
    let next = reopened.journal.next_seq();
    fixture.faults.unreadable.store(true, Ordering::Release);
    assert!(crate::root::keyset::bind(
        &mut reopened,
        &fixture.identity().await,
        &token(),
        StepName::Meter,
        NOW
    )
    .await
    .is_err());
    assert_eq!(reopened.journal.next_seq(), next);
    assert!(reopened.record.signing_key_id().is_none());
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn an_unreadable_old_audit_window_is_never_answered_empty() {
    use crate::root::units_admin::{AuditView, NodeAudit};
    let fixture = NativeFixture::new(47).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    for unit in 1..=(AUDIT_RING + 5) as u64 {
        seal(&book, unit).await;
    }
    assert!(book.lock().unwrap().audit_records[0].seq > 1);
    fixture.faults.unreadable.store(true, Ordering::Release);
    let mut answered = None;
    NodeAudit::new(book)
        .read_window(1, 3, &mut |_, records| {
            answered = Some(records.map_or(0, <[_]>::len));
        })
        .await;
    assert_eq!(
        answered, None,
        "unreadable is never an empty successful window"
    );
}

#[tokio::test]
async fn corrupt_original_refuses_boot_amendments_and_keyset_without_second_bootstrap() {
    let fixture = NativeFixture::new(47).await;
    let mut first = fixture.book().await;
    bind(&mut first, &fixture).await;
    let book = Arc::new(Mutex::new(first));
    seal(&book, 1).await;
    seal(&book, 2).await;
    let mut reopened = fixture.reopen().await;
    assert_eq!(reopened.audit_records.len(), 2);
    let next = reopened.journal.next_seq();
    fixture.corrupt_original(1).await;
    assert!(RuntimeJournal::open(fixture.core.clone(), 47, BUDGET)
        .await
        .is_err());
    assert!(fixture.build(&DurabilityConfig::default()).await.is_err());
    let amendments = busbar_kernel_audit::amend::NodeAmendments::new();
    assert!(reopened
        .restore_amendments(&amendments, &token())
        .await
        .is_err());
    assert_eq!(reopened.amendments_through, None);
    assert!(crate::root::keyset::bind(
        &mut reopened,
        &fixture.identity().await,
        &token(),
        StepName::Meter,
        NOW
    )
    .await
    .is_err());
    assert_eq!(reopened.journal.next_seq(), next);
    assert!(reopened.record.signing_key_id().is_none());
}
