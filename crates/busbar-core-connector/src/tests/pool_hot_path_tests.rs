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

/// T9b: a key's fields are hashed once, when it is built; every lookup after that (two in a lend,
/// one in a release) hashes only the one `u64`: under one fixed hasher the key hashes exactly as
/// its `hash` alone does, so nothing but that `u64` is written.
#[test]
fn pool_key_hashed_once() {
    use std::hash::BuildHasher as _;
    worker().block_on(async {
        let (far, _, _) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60));
        let (_, key, _) = one_idle_line(&c, &far).await;
        let fixed = foldhash::fast::FixedState::with_seed(0);
        assert_eq!(
            fixed.hash_one(&key),
            fixed.hash_one(key.hash),
            "a pool lookup hashes the key's one u64, never its fields again"
        );
        assert_eq!(
            fixed.hash_one(key.clone()),
            fixed.hash_one(key.hash),
            "a copy of the key carries its hash"
        );
    });
}

/// T9b: two keys whose hashes collide are still two keys: a line is never lent across them.
#[test]
fn pool_key_collision_never_lends() {
    worker().block_on(async {
        let (far, _, _) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60));
        let (shard, key, line) = one_idle_line(&c, &far).await;
        let mut elsewhere = key.clone();
        elsewhere.authority = "elsewhere.invalid:443".to_owned();
        let mut other_owner = key.clone();
        other_owner.owner = OTHER;
        for (what, colliding) in [("authority", elsewhere), ("owner", other_owner)] {
            assert_eq!(colliding.hash, key.hash, "{what}: a forced collision");
            assert_ne!(
                colliding, key,
                "{what}: the same hash with another field is another key"
            );
            assert!(
                c.pools
                    .take(shard, &colliding, false, false)
                    .lent()
                    .is_none(),
                "{what}: the line is never lent to a key whose hash collides with its own"
            );
        }
        let lent = c
            .pools
            .take(shard, &key, false, false)
            .lent()
            .expect("control: the line is lent to its own key");
        assert!(Arc::ptr_eq(&lent, &line), "control: the kept line itself");
    });
}

/// A far end that answers one ask on each connection and then closes it.
async fn answering_once_far_end() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    let (l, far) = far_end().await;
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0_u8; 3];
                if s.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(b"xe").await;
                }
            });
        }
    });
    (far, accepted)
}

/// A kept line whose far end went away meanwhile is never handed back as live: the next open is
/// answered on a fresh dial, or refused, never left hanging and never answered from the dead line.
#[test]
fn pool_stale_line_is_retried_or_refused() {
    worker().block_on(async {
        let (far, accepted) = answering_once_far_end().await;
        let c = pooled_messages(Duration::from_secs(60));
        c.declare_over(OWNER, NeedId(0), "messages")
            .expect("a served scheme declares");
        assert_eq!(
            pooled_exchange(&c, (OWNER, 0), &far, b"ask", true).await,
            (b"x".to_vec(), true, None),
            "the first exchange finishes whole"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (got, whole, failed) = pooled_exchange(&c, (OWNER, 0), &far, b"ask", true).await;
        match failed {
            None => {
                assert_eq!(
                    (got, whole),
                    (b"x".to_vec(), true),
                    "retried: the next open is answered whole, not left to its deadline"
                );
                assert_eq!(
                    accepted.load(Ordering::SeqCst),
                    2,
                    "retried: on a fresh dial, not the closed line"
                );
            }
            Some(e) => assert!(
                got.is_empty(),
                "refused ({e:?}): nothing is read from the closed line"
            ),
        }
    });
}
