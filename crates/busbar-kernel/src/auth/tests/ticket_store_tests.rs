// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[tokio::test(flavor = "current_thread")]
async fn cancelling_ticket_waits_keeps_the_started_worker_permit_and_starts_no_waiter() {
    static PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let (started, entered) = tokio::sync::oneshot::channel();
    let (release, hold) = std::sync::mpsc::channel();
    let ran = Arc::new(AtomicUsize::new(0));
    let mut first = Box::pin(ticket_store_on(&PERMITS, move || {
        let _ = started.send(());
        hold.recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        Some(1)
    }));
    assert!(futures::poll!(&mut first).is_pending());
    entered.await.unwrap();
    drop(first);
    assert_eq!(PERMITS.available_permits(), 0);
    let mut waiting = Box::pin(ticket_store_on(&PERMITS, {
        let ran = Arc::clone(&ran);
        move || {
            ran.fetch_add(1, Ordering::SeqCst);
            Some(2)
        }
    }));
    assert!(futures::poll!(&mut waiting).is_pending());
    drop(waiting);
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    assert_eq!(PERMITS.available_permits(), 0);
    release.send(()).unwrap();
    let permit = tokio::time::timeout(std::time::Duration::from_secs(5), PERMITS.acquire())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    drop(permit);
    assert_eq!(ticket_store_on(&PERMITS, || Some(3)).await, Some(3));
    assert!(ticket_store_on::<()>(&PERMITS, || panic!("store panic"))
        .await
        .is_none());
    assert_eq!(PERMITS.available_permits(), 1);
}

#[test]
fn cancelling_a_ticket_queued_on_the_blocking_pool_never_starts_its_store_call() {
    static PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    rt.block_on(async {
        let (release, hold) = std::sync::mpsc::channel();
        let (entered, started) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            hold.recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        });
        started.await.unwrap();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut queued = Box::pin(ticket_store_on(&PERMITS, {
            let ran = Arc::clone(&ran);
            move || {
                ran.fetch_add(1, Ordering::SeqCst);
                Some(())
            }
        }));
        assert!(futures::poll!(&mut queued).is_pending());
        drop(queued);
        release.send(()).unwrap();
        blocker.await.unwrap();
        let permit = tokio::time::timeout(std::time::Duration::from_secs(5), PERMITS.acquire())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        drop(permit);
    });
}
