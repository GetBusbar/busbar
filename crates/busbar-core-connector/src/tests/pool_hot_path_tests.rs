// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLIENT-LEG POOL ON THE REQUEST PATH (TRANSPORT-TLS T9a/T9b): releasing a kept line makes no
//! heap allocation, a key's fields are hashed once, and a pooled line is lent only to its own key.

use std::time::Duration;

use super::*;

/// A pooled connector whose one finished exchange left its line idle: the line, its shard and key.
async fn one_idle_line(c: &Connector, far: &str) -> (usize, crate::pool::PoolKey, Arc<Line>) {
    c.declare_over(OWNER, NeedId(0), "messages")
        .expect("a served scheme declares");
    assert_eq!(
        pooled_exchange(c, (OWNER, 0), far, b"ask", true).await,
        (b"x".to_vec(), true, None),
        "the first exchange finishes whole, and its line is kept"
    );
    let mut idle = c.pools.idle_lines();
    assert_eq!(idle.len(), 1, "the finished exchange's line is kept idle");
    let kept = idle.pop().expect("one idle line");
    assert_eq!(kept.2.users(), 0, "nobody holds the idle line");
    kept
}

/// T9a: a release that keeps a line idle, within the per-host budget, allocates nothing (no
/// collect of the idle entries unless there are more than the shard keeps).
#[test]
fn pool_release_allocates_nothing() {
    worker().block_on(async {
        let (far, accepted, _) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60));
        let (shard, key, line) = one_idle_line(&c, &far).await;
        let ((), allocated) =
            crate::support::allocations_during(|| c.pools.release(shard, &key, &line));
        assert_eq!(
            allocated, 0,
            "a release within the idle budget makes no heap allocation"
        );
        assert_eq!(
            c.pools.idle_lines().len(),
            1,
            "the released line is still kept idle"
        );
        let again = pooled_exchange(&c, (OWNER, 0), &far, b"ask", false).await;
        assert_eq!(again.0, b"x".to_vec(), "the next open is answered");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the next open rides the kept line"
        );
    });
}
