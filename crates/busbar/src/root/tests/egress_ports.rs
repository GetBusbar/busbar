// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busbar_contract::clock::{Deadline, HostClock};
use busbar_kernel_egress::ports::{Capacity, DestinationId, Telemetry};

use super::{tokio_sleep, MemberPermits, WalkTelemetry};

const A: DestinationId = DestinationId::new(0);
const B: DestinationId = DestinationId::new(1);
const FREE: DestinationId = DestinationId::new(2);

/// Permits as the plane seats build them: one semaphore of `n` slots per limited member.
fn permits<const N: usize>(limits: [(DestinationId, usize); N]) -> MemberPermits {
    MemberPermits {
        limits: limits
            .into_iter()
            .map(|(d, n)| (d, Arc::new(tokio::sync::Semaphore::new(n))))
            .collect(),
    }
}

#[tokio::test]
async fn the_clock_reads_the_wall_a_monotonic_origin_and_sleeps_on_the_timer() {
    let clock = HostClock::system(tokio_sleep);
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    let before = clock.now();
    assert!(
        (before.wall_ns / 1_000_000_000).abs_diff(wall) <= 1,
        "whole wall seconds"
    );
    let started = std::time::Instant::now();
    clock
        .sleep_until(Deadline::after(before, Duration::from_millis(20)))
        .await;
    assert!(started.elapsed() >= Duration::from_millis(20), "slept");
    assert!(
        clock.now().mono_ns >= before.mono_ns + 20_000_000,
        "monotonic, past the deadline it slept until"
    );
}

#[test]
fn a_limited_member_holds_its_slots_until_they_drop_and_an_unlimited_one_never_fills() {
    let permits = permits([(A, 1)]);
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
    let permits = std::sync::Arc::new(permits([(A, 1), (B, 1)]));
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
    let permits = permits([(A, 0)]);
    let got = permits.acquire_any(&[A, FREE]).await.map(|(d, _)| d);
    assert_eq!(got, Some(FREE));
}

/// Each pool's depth is the pool's own count now (`busbar_kernel_egress::pool::QueueDepth`, tested there).
#[test]
fn the_counters_label_a_member_by_name() {
    let t = WalkTelemetry::new([(A, "first".to_string())]);
    assert_eq!(t.lane(A), "first");
    assert_eq!(t.lane(B), "", "a member the seal did not name");
}

#[tokio::test]
async fn the_queue_frees_one_permit_to_exactly_one_of_two_waiters() {
    let permits = std::sync::Arc::new(permits([(A, 1)]));
    let held = permits.try_acquire(A).expect("the one slot");
    let (woke, mut wakes) = tokio::sync::mpsc::unbounded_channel();
    let waiters: Vec<_> = (0..2)
        .map(|_| {
            let (permits, woke) = (std::sync::Arc::clone(&permits), woke.clone());
            tokio::spawn(async move {
                let got = permits.acquire_any(&[A]).await;
                let _ = woke.send(got);
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        wakes.try_recv().is_err(),
        "both waiters park on the full member"
    );

    drop(held);
    let first = tokio::time::timeout(Duration::from_secs(5), wakes.recv())
        .await
        .expect("exactly one waiter must win the freed slot")
        .expect("a waiter answered")
        .expect("the slot was handed over");
    assert_eq!(first.0, A);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        wakes.try_recv().is_err(),
        "while the winner holds the only slot, the surviving waiter must still be parked (no herd)"
    );
    assert!(
        permits.try_acquire(A).is_none(),
        "the single freed slot is held by the one winner — none left for a second dispatcher"
    );

    drop(first);
    let second = tokio::time::timeout(Duration::from_secs(5), wakes.recv())
        .await
        .expect("the survivor wins the slot the winner freed")
        .expect("a waiter answered")
        .expect("the slot was handed over");
    assert_eq!(second.0, A);
    for waiter in waiters {
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("both waiters resolve")
            .expect("joined");
    }
}

#[tokio::test]
async fn a_slot_freed_as_its_waiter_parks_is_not_lost() {
    for _ in 0..50 {
        let permits = std::sync::Arc::new(permits([(A, 1)]));
        let held = permits.try_acquire(A).expect("the one slot");
        let waiter = {
            let permits = std::sync::Arc::clone(&permits);
            tokio::spawn(async move { permits.acquire_any(&[A]).await })
        };
        tokio::task::yield_now().await;
        drop(held);
        let got = tokio::time::timeout(Duration::from_millis(400), waiter)
            .await
            .expect("the freed slot reaches the waiter inside the short wait")
            .expect("joined")
            .expect("the slot was handed over");
        assert_eq!(got.0, A);
    }
}

fn scraped(family: &str, labels: &[(&str, &str)]) -> f64 {
    busbar_kernel::snapshot::snapshot()
        .expect("the actual host recorder is installed")
        .iter()
        .flat_map(|f| &f.samples)
        .filter(|sample| sample.name == family)
        .filter(|sample| {
            labels
                .iter()
                .all(|(name, value)| sample.labels.iter().any(|(n, v)| n == name && v == value))
        })
        .filter_map(|sample| sample.value.parse::<f64>().ok())
        .sum()
}

#[test]
fn a_label_outside_the_bound_falls_back_and_counts_its_refusal() {
    use busbar_kernel_egress::ports::StatedLabels;
    busbar_kernel::snapshot::init_for_test(Duration::from_secs(60));
    let attempts = busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL;
    let refused = busbar_kernel::snapshot::PLUGIN_LABEL_REFUSED_TOTAL;
    let bound = super::LabelBound {
        reach: [(
            "walked-red-arm".to_string(),
            // (pool words: the walk's entry names, as no pool label is configured; entries)
            (
                std::collections::BTreeSet::from(["entry-red-arm".to_string()]),
                std::collections::BTreeSet::from(["entry-red-arm".to_string()]),
            ),
        )]
        .into_iter()
        .collect(),
        vocabulary: std::collections::BTreeSet::from(["declared-word".to_string()]),
    };
    let t = WalkTelemetry {
        bound,
        ..WalkTelemetry::new([(A, "own-red-arm".to_string())])
    };
    let stated = |pool: &str, lane: &str| StatedLabels {
        pool: Some(pool.to_string()),
        lane: Some(lane.to_string()),
    };

    let before = scraped(refused, &[]);
    t.upstream_attempt_stated(
        "walked-red-arm",
        A,
        Some(&stated("entry-red-arm", "undeclared-word")),
    );
    assert!(
        scraped(refused, &[]) > before,
        "an undeclared lane word is counted refused"
    );
    assert!(
        scraped(
            attempts,
            &[("pool", "entry-red-arm"), ("lane", "own-red-arm")]
        ) >= 1.0,
        "its lane fell back to the walk's own, its reachable pool was taken: {:?}",
        busbar_kernel::snapshot::snapshot()
    );
    assert_eq!(
        scraped(attempts, &[("lane", "undeclared-word")]),
        0.0,
        "the undeclared word was never emitted"
    );

    let before = scraped(refused, &[]);
    t.upstream_failure_stated(
        "walked-red-arm",
        A,
        "transient_upstream",
        Some(&stated("unreachable-pool", "declared-word")),
    );
    assert!(
        scraped(refused, &[]) > before,
        "an unreachable pool is refused"
    );
    assert!(
        scraped(
            busbar_kernel::telemetry::UPSTREAM_FAILURES_TOTAL,
            &[("pool", "walked-red-arm"), ("lane", "declared-word")]
        ) >= 1.0,
        "its pool fell back to the walk's own, its declared lane word was taken"
    );

    let before = scraped(refused, &[]);
    t.upstream_attempt_stated(
        "walked-red-arm",
        A,
        Some(&stated("entry-red-arm", "declared-word")),
    );
    assert_eq!(
        scraped(refused, &[]),
        before,
        "words within the bound refuse nothing"
    );
}
