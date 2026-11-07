// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::tests::{audit_inputs, audit_pass, seal, token, NativeFixture};
use super::*;
use crate::root::units_admin::{AuditView, NodeAudit};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

#[derive(Default)]
struct Reads {
    all: AtomicUsize,
    locked: AtomicUsize,
}
impl Reads {
    fn assert_unlocked(&self) {
        assert!(
            self.all.load(Ordering::Acquire) > 0,
            "the native journal was actually read"
        );
        assert_eq!(
            self.locked.load(Ordering::Acquire),
            0,
            "backend reads must release the book lock"
        );
    }
}
fn probe(fixture: &NativeFixture, book: &Arc<Mutex<Durability>>) -> Arc<Reads> {
    let reads = Arc::new(Reads::default());
    let (observed, held) = (reads.clone(), Arc::downgrade(book));
    *fixture.faults.on_read.lock().unwrap() = Some(Arc::new(move |_| {
        observed.all.fetch_add(1, Ordering::AcqRel);
        if let Some(book) = held.upgrade() {
            if matches!(book.try_lock(), Err(TryLockError::WouldBlock)) {
                observed.locked.fetch_add(1, Ordering::AcqRel);
            }
        }
        Box::pin(async { Ok(()) })
    }));
    reads
}

#[tokio::test]
async fn verify_walk_reads_native_store_without_book_lock() {
    let fixture = NativeFixture::new(47).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    seal(&book, 1).await;
    let reads = probe(&fixture, &book);
    let findings = NodeAudit::new(book).stored_chain_findings().await;
    assert!(findings.is_empty(), "{findings:?}");
    reads.assert_unlocked();
}

#[tokio::test]
async fn audit_window_older_than_cache_reads_native_store_without_book_lock() {
    let fixture = NativeFixture::new(47).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    for unit in 1..=(AUDIT_RING + 5) as u64 {
        seal(&book, unit).await;
    }
    let reads = probe(&fixture, &book);
    let mut answered = None;
    NodeAudit::new(book)
        .read_window(1, 3, &mut |_, records| {
            answered = records.map(|records| records.iter().map(|r| r.seq).collect::<Vec<_>>());
        })
        .await;
    assert_eq!(answered, Some(vec![1, 2, 3]));
    reads.assert_unlocked();
}

#[tokio::test]
async fn unit_sealed_during_native_window_read_is_in_window_and_head() {
    let fixture = NativeFixture::new(47).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    for unit in 1..=3 {
        seal(&book, unit).await;
    }
    let flag = Arc::new(AtomicBool::new(false));
    let (observed, held) = (flag.clone(), Arc::downgrade(&book));
    *fixture.faults.on_read.lock().unwrap() = Some(Arc::new(move |_| {
        let (observed, held) = (observed.clone(), held.clone());
        Box::pin(async move {
            if observed.swap(true, Ordering::AcqRel) {
                return Ok(());
            }
            let book = held.upgrade().expect("reader retains the book");
            assert!(book.try_lock().is_ok(), "the native read released the book");
            Durability::seal_unit(&book, audit_inputs(4), audit_pass(), &token())
                .await
                .unwrap();
            Ok(())
        })
    }));
    let mut answered = None;
    NodeAudit::new(book)
        .read_window(0, u64::MAX, &mut |chain, records| {
            answered = Some((
                records.map(|records| records.iter().map(|r| r.seq).collect::<Vec<_>>()),
                chain.heads().anchor_at(u64::MAX).map(|head| head.seq),
            ));
        })
        .await;
    assert!(flag.load(Ordering::Acquire));
    assert_eq!(answered, Some((Some(vec![1, 2, 3, 4]), Some(4))));
}
