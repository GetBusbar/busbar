// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::idempotency::{IdempotencyCache, Probe, IDEMPOTENCY_TTL_SECS};

fn key(actor: &str, header: &str) -> (String, String) {
    (actor.to_string(), header.to_string())
}

#[test]
fn a_leaked_sentinel_still_refuses_a_retry_long_after_the_replay_window_has_passed() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let k = key("alice", "idem-stuck");

    match cache.probe(k.clone(), 1_000) {
        Probe::Reserved(r) => r.leak(),
        _ => panic!("the first sighting must reserve"),
    }

    for elapsed in [
        IDEMPOTENCY_TTL_SECS,
        IDEMPOTENCY_TTL_SECS + 1,
        IDEMPOTENCY_TTL_SECS * 10,
        IDEMPOTENCY_TTL_SECS * 1_000,
    ] {
        assert!(
            matches!(cache.probe(k.clone(), 1_000 + elapsed), Probe::InFlight),
            "{elapsed}s after the reservation the sentinel was swept and a second mint admitted"
        );
    }
}

#[test]
fn a_committed_value_is_swept_at_the_window_boundary_and_not_before_it() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();

    let inside = key("alice", "idem-inside");
    match cache.probe(inside.clone(), 1_000) {
        Probe::Reserved(r) => r.commit("first-response".to_string(), 1_000),
        _ => panic!("the first sighting must reserve"),
    }
    match cache.probe(inside.clone(), 1_000 + IDEMPOTENCY_TTL_SECS - 1) {
        Probe::Replay(v) => assert_eq!(v, "first-response"),
        _ => panic!("a retry inside the replay window must replay the first response"),
    }

    let boundary = key("alice", "idem-boundary");
    match cache.probe(boundary.clone(), 1_000) {
        Probe::Reserved(r) => r.commit("first-response".to_string(), 1_000),
        _ => panic!("the first sighting must reserve"),
    }
    assert!(
        matches!(
            cache.probe(boundary.clone(), 1_000 + IDEMPOTENCY_TTL_SECS),
            Probe::Reserved(_)
        ),
        "a committed value survived its own replay window"
    );
}

#[test]
fn one_slot_ageing_out_does_not_take_a_younger_slot_with_it() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let old = key("alice", "idem-old");
    let young = key("alice", "idem-young");

    match cache.probe(old.clone(), 1_000) {
        Probe::Reserved(r) => r.commit("old-response".to_string(), 1_000),
        _ => panic!("reserve"),
    }
    match cache.probe(young.clone(), 1_000 + IDEMPOTENCY_TTL_SECS - 1) {
        Probe::Reserved(r) => r.commit(
            "young-response".to_string(),
            1_000 + IDEMPOTENCY_TTL_SECS - 1,
        ),
        _ => panic!("reserve"),
    }

    let now = 1_000 + IDEMPOTENCY_TTL_SECS + 1;
    assert!(
        matches!(cache.probe(old.clone(), now), Probe::Reserved(_)),
        "the aged slot was not swept"
    );
    match cache.probe(young.clone(), now) {
        Probe::Replay(v) => assert_eq!(v, "young-response"),
        _ => panic!("a slot still inside its own window was swept with an older one"),
    };
}

#[test]
fn commit_clear_and_drop_each_resolve_a_sentinel() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();

    let committed = key("alice", "idem-commit");
    match cache.probe(committed.clone(), 1_000) {
        Probe::Reserved(r) => r.commit("v".to_string(), 1_000),
        _ => panic!("reserve"),
    }
    assert!(matches!(cache.probe(committed, 1_001), Probe::Replay(_)));

    let cleared = key("alice", "idem-clear");
    match cache.probe(cleared.clone(), 1_000) {
        Probe::Reserved(r) => r.clear(),
        _ => panic!("reserve"),
    }
    assert!(
        matches!(cache.probe(cleared, 1_001), Probe::Reserved(_)),
        "a cleared reservation went on refusing a retry it had already declared safe"
    );

    let dropped = key("alice", "idem-drop");
    match cache.probe(dropped.clone(), 1_000) {
        Probe::Reserved(r) => drop(r),
        _ => panic!("reserve"),
    }
    assert!(
        matches!(cache.probe(dropped, 1_001), Probe::Reserved(_)),
        "a dropped reservation left its sentinel standing"
    );
}

#[test]
fn two_actors_using_one_header_value_never_replay_each_other() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    match cache.probe(key("alice", "shared"), 1_000) {
        Probe::Reserved(r) => r.commit("alices-response".to_string(), 1_000),
        _ => panic!("reserve"),
    }
    assert!(
        matches!(cache.probe(key("bob", "shared"), 1_001), Probe::Reserved(_)),
        "bob replayed alice's response"
    );
}
