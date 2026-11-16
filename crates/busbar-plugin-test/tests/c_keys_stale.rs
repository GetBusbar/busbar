// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-KEYS-STALE (ABI-MIN3-INTERFACE §14): Unknown kid: one refresh, one re-verify; 100 concurrent requests share
//! it; a second within the interval is declined.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! The port side (W1-L5): the auth adapter's `KeyRefresh` is the one single-flight, rate-limited refresh gate a
//! KEYS_STALE verify passes (IF §8.3, §12.11). The one re-verify after it is the adapter's `settle` loop, which
//! needs a fixture auth image through the proxy (W1-H1); until then this arm pins the gate itself.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_plugin_loader::adapters::auth::{verify_refusal, KeyRefresh};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_kid_refreshes_once() {
    use busbar_plugin_abi::auth::KEYS_STALE;
    use busbar_plugin_abi::host_side::scrub::Scrub;

    // KEYS_STALE is no verdict: the adapter refreshes, then verifies again.
    assert!(matches!(
        verify_refusal(KEYS_STALE, "kid k9", &Scrub::new()),
        Ok(None)
    ));

    let keys = Arc::new(KeyRefresh::new(Duration::from_secs(30)));
    let runs = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let mut burst = tokio::task::JoinSet::new();
    for _ in 0..100 {
        let round = keys.begin().expect("joins the refresh in flight");
        let (runs, gate) = (Arc::clone(&runs), Arc::clone(&gate));
        burst.spawn(async move {
            round
                .get_or_init(|| async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                    let _open = gate.acquire().await.expect("gate");
                    Ok(())
                })
                .await
                .clone()
        });
    }
    gate.add_permits(1);
    while let Some(done) = burst.join_next().await {
        assert_eq!(done.expect("verify task"), Ok(()));
    }
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "100 KEYS_STALE share one refresh"
    );

    // A second refresh inside `auth.unknown_key_refresh_s` is declined (the adapter then answers BAD_CREDENTIAL).
    assert!(keys.begin().is_none());
}
