// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The cache's own mechanics: atomic swap under concurrency, and the rug-pull defence's
//! refresh-trigger gate.

use crate::mcp::client::catalogue::{CatalogueCache, RefreshGate, ServerCatalogue};
use crate::mcp::client::support::{approved_server, sid, simple_tool};

#[test]
fn a_reader_never_observes_a_torn_snapshot_under_concurrent_swaps() {
    use std::sync::Arc;
    let cache = Arc::new(CatalogueCache::new());
    cache.apply(|s| {
        s.insert(
            "a".into(),
            approved_server("a", vec![simple_tool("t", "d")]),
        );
        s.insert(
            "b".into(),
            approved_server("b", vec![simple_tool("t", "d")]),
        );
    });

    let writer = {
        let cache = cache.clone();
        std::thread::spawn(move || {
            for i in 0..200 {
                cache.apply(move |s| {
                    // Both servers are replaced together. A torn read would see one replaced and one
                    // not, which is exactly what a snapshot swap must make impossible.
                    let n = format!("gen{i}");
                    s.insert("a".into(), approved_server("a", vec![simple_tool("t", &n)]));
                    s.insert("b".into(), approved_server("b", vec![simple_tool("t", &n)]));
                });
            }
        })
    };
    let reader = {
        let cache = cache.clone();
        std::thread::spawn(move || {
            let mut reads = 0usize;
            for _ in 0..2000 {
                let snap = cache.load();
                let a = snap.server(&sid("a")).unwrap().bound_identity("t").unwrap();
                let b = snap.server(&sid("b")).unwrap().bound_identity("t").unwrap();
                assert_eq!(a.digest, b.digest, "a torn snapshot was observed");
                reads += 1;
            }
            reads
        })
    };
    writer.join().unwrap();
    let reads = reader.join().unwrap();
    // A FLOOR: a reader that did no reads would have asserted nothing.
    assert_eq!(reads, 2000);
    assert!(cache.generation() >= 200);
}

#[test]
fn the_snapshot_carries_the_generation_it_was_published_under() {
    let cache = CatalogueCache::new();
    assert_eq!(cache.load().generation(), 0);
    cache.apply(|_| {});
    assert_eq!(cache.load().generation(), 1);
    assert_eq!(cache.load().generation(), cache.generation());
}

#[test]
fn a_registered_server_serves_nothing_until_it_is_approved() {
    let sc = ServerCatalogue::registered(sid("new"));
    assert!(sc.served_tools().is_empty());
    assert_eq!(sc.state(), crate::trust::TrustState::Pending);
}

#[test]
fn a_failed_contact_is_never_reported_as_trust() {
    let mut sc = approved_server("s", vec![simple_tool("t", "d")]);
    assert_eq!(sc.state(), crate::trust::TrustState::Approved);
    sc.observe_failure("connection refused");
    assert_eq!(sc.state(), crate::trust::TrustState::Error);
    assert!(sc.served_tools().is_empty());
}

/// A refresh must never be driven solely by the upstream's own `notifications/tools/list_changed`:
/// that trigger is attacker-controlled in TIMING. The gate rations it.
#[test]
fn the_refresh_trigger_is_rate_limited_and_counts_what_it_rejected() {
    let gate = RefreshGate::new(5_000);
    // The first trigger is always accepted: there has been no recent re-pull.
    assert!(gate.allow(1_000_000));
    // A burst inside the window is refused, and counted.
    for t in 1..=50 {
        assert!(
            !gate.allow(1_000_000 + t),
            "trigger at +{t}ms must be refused"
        );
    }
    assert_eq!(gate.rejected(), 50);
    // Just before the floor: still refused.
    assert!(!gate.allow(1_004_999));
    // At the floor: accepted.
    assert!(gate.allow(1_005_000));
    assert_eq!(gate.rejected(), 51);
}

/// The gate is a HARD FLOOR, not a bucket: a quiet period does not accrue credit that a later burst
/// can spend. Two re-pulls a millisecond apart return the same list, so a burst has no value.
#[test]
fn a_quiet_period_does_not_accrue_burst_credit() {
    let gate = RefreshGate::new(1_000);
    assert!(gate.allow(1_000_000));
    // An hour of silence.
    assert!(gate.allow(1_000_000 + 3_600_000));
    // The very next trigger is still refused; the floor applies from the last ACCEPTED one.
    assert!(!gate.allow(1_000_000 + 3_600_001));
}

/// A1 REGRESSION: two or more `apply()` calls targeting DISTINCT server keys must each survive.
///
/// The lost-update bug cloned the pre-edit map from a lock-free `load()` and only took the write
/// lock for the final swap, so concurrent applies copied the SAME base and the last swap dropped the
/// others' edits — a just-detected drift or refresh silently lost. Each thread inserts one unique
/// key, all released together on a barrier to hit the read-modify-write window, repeated so the
/// buggy version drops keys reliably. The atomic apply keeps every key.
#[test]
fn concurrent_applies_to_distinct_keys_all_survive() {
    use crate::mcp::client::support::simple_tool;
    use std::sync::{Arc, Barrier};
    const THREADS: usize = 8;
    for _ in 0..100 {
        let cache = Arc::new(CatalogueCache::new());
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let cache = cache.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let key = format!("srv{i}");
                    // Line every thread up on the barrier so their read-copy-update windows overlap.
                    barrier.wait();
                    cache.apply(move |s| {
                        s.insert(
                            key.clone(),
                            approved_server(&key, vec![simple_tool("t", "d")]),
                        );
                    });
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let snap = cache.load();
        assert_eq!(
            snap.servers.len(),
            THREADS,
            "every concurrent apply on a distinct key must survive; a dropped key is the lost-update bug"
        );
        for i in 0..THREADS {
            assert!(
                snap.servers.contains_key(&format!("srv{i}")),
                "srv{i} was dropped by a racing apply"
            );
        }
    }
}
