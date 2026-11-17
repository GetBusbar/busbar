// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::workers::PreparedWorkers;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[tokio::test]
async fn discarded_candidate_never_runs_prepared_work() {
    let entered = Arc::new(AtomicUsize::new(0));
    let mut candidate = PreparedWorkers::new();
    candidate.push({
        let entered = entered.clone();
        async move {
            entered.fetch_add(1, Ordering::SeqCst);
        }
    });
    drop(candidate);
    tokio::task::yield_now().await;
    assert_eq!(entered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stop_joins_every_started_worker_and_releases_its_custody() {
    struct Custody(Arc<AtomicUsize>);
    impl Drop for Custody {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let released = Arc::new(AtomicUsize::new(0));
    let mut candidate = PreparedWorkers::new();
    let mut entered = Vec::new();
    for _ in 0..3 {
        let (send, recv) = tokio::sync::oneshot::channel();
        entered.push(recv);
        let custody = Custody(released.clone());
        candidate.push(async move {
            let _custody = custody;
            let _ = send.send(());
            core::future::pending::<()>().await;
        });
    }
    let running = candidate.start();
    for entered in entered {
        entered.await.expect("worker starts only after publication");
    }
    assert_eq!(released.load(Ordering::SeqCst), 0);
    assert!(running.stop().await.is_ok());
    assert_eq!(released.load(Ordering::SeqCst), 3);
}
