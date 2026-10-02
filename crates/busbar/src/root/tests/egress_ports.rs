// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS WALK'S PRODUCTION PORTS (ARCHITECT Q-SW8, 2026-10-02): the clock reads the wall and
//! a monotonic origin and sleeps on the runtime's timer; a member's `max_concurrent` slots are held
//! until dropped and handed to the longest waiter; the counters label a member by its name and keep
//! each pool's wait depth balanced.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busbar_kernel_egress::ports::{Capacity, Clock, DestinationId, Telemetry};

use super::{MemberPermits, NodeClock, WalkTelemetry};

const A: DestinationId = DestinationId::new(0);
const B: DestinationId = DestinationId::new(1);
const FREE: DestinationId = DestinationId::new(2);

#[tokio::test]
async fn the_clock_reads_the_wall_a_monotonic_origin_and_sleeps_on_the_timer() {
    let clock = NodeClock::new();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    assert!(clock.now_secs().abs_diff(wall) <= 1, "whole wall seconds");
    let before = clock.now_millis();
    let started = std::time::Instant::now();
    clock.sleep(20).await;
    assert!(started.elapsed() >= Duration::from_millis(20), "slept");
    assert!(
        clock.now_millis() >= before + 20,
        "monotonic, in milliseconds"
    );
}

#[test]
fn a_limited_member_holds_its_slots_until_they_drop_and_an_unlimited_one_never_fills() {
    let permits = MemberPermits::new([(A, 1)]);
    let held = permits.try_acquire(A).expect("one slot");
    assert_eq!(held.destination(), A);
    assert!(permits.try_acquire(A).is_none(), "at capacity");
    drop(held);
    assert!(permits.try_acquire(A).is_some(), "freed on drop");
    let many: Vec<_> = (0..64).map(|_| permits.try_acquire(FREE)).collect();
    assert!(
        many.iter().all(Option::is_some),
        "no limit, never at capacity"
    );
}

#[tokio::test]
async fn a_waiter_takes_the_first_slot_freed_on_any_of_its_members() {
    let permits = std::sync::Arc::new(MemberPermits::new([(A, 1), (B, 1)]));
    let a = permits.try_acquire(A).expect("a's slot");
    let b = permits.try_acquire(B).expect("b's slot");
    let waiter = {
        let permits = std::sync::Arc::clone(&permits);
        tokio::spawn(async move {
            permits
                .acquire_any(&[A, B])
                .await
                .map(|(d, p)| (d, p.destination()))
        })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiter.is_finished(), "both members are full");
    drop(b);
    let got = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("woken")
        .expect("joined");
    assert_eq!(got, Some((B, B)), "the freed member's slot");
    drop(a);
}

#[tokio::test]
async fn a_wait_over_an_unlimited_member_answers_at_once() {
    let permits = MemberPermits::new([(A, 0)]);
    let got = permits.acquire_any(&[A, FREE]).await.map(|(d, _)| d);
    assert_eq!(got, Some(FREE));
}

#[test]
fn the_counters_label_a_member_by_name_and_keep_each_pools_depth() {
    let t = WalkTelemetry::new([(A, "first".to_string())]);
    assert_eq!(t.lane(A), "first");
    assert_eq!(t.lane(B), "", "a member the seal did not name");
    t.queued("p", 1);
    t.queued("p", 1);
    t.queued("q", 1);
    t.queued("p", -1);
    assert_eq!((t.depth("p"), t.depth("q")), (1, 1));
    t.queued("p", -5);
    assert_eq!(t.depth("p"), 0, "a depth never reads below empty");
}
