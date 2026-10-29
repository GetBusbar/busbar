// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ported assertions from `busbar-core::admin::tests` for the idempotency cache: a same-node
//! replay returns the committed value verbatim, a concurrent in-flight call is refused rather than
//! double-run, a cleared/expired reservation frees the key for a fresh mint, and the 600 s TTL is
//! honoured exactly.

use crate::idempotency::durable::{self, Refused, Settled};
use crate::idempotency::{IdempotencyCache, Probe, IDEMPOTENCY_TTL_SECS};
use busbar_kernel::governance::MemoryStore;

fn key(actor: &str, header: &str) -> (String, String) {
    (actor.to_string(), header.to_string())
}

#[test]
fn first_sighting_reserves_and_replay_returns_committed_value_verbatim() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let k = key("alice", "idem-1");

    let reservation = match cache.probe(k.clone(), 1_000) {
        Probe::Reserved(r) => r,
        _ => panic!("first sighting must reserve"),
    };
    reservation.commit("first-response".to_string(), 1_000);

    // A same-node retry, any time inside the window, replays the exact committed value.
    match cache.probe(k, 1_100) {
        Probe::Replay(v) => assert_eq!(v, "first-response"),
        _ => panic!("expected a replay, got a different probe outcome"),
    };
}

#[test]
fn concurrent_retry_while_in_flight_is_refused_not_double_run() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let k = key("alice", "idem-2");

    let _first = match cache.probe(k.clone(), 1_000) {
        Probe::Reserved(r) => r,
        _ => panic!("first sighting must reserve"),
    };
    // The reservation is still live (not committed, not dropped): a concurrent retry must see
    // in-flight, never a second reservation and never a replay of nothing.
    match cache.probe(k, 1_005) {
        Probe::InFlight => {}
        _ => panic!("a concurrent retry against a live reservation must be InFlight"),
    };
}

#[test]
fn a_dropped_reservation_frees_the_key_for_retry() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let k = key("alice", "idem-3");

    {
        let _reservation = match cache.probe(k.clone(), 1_000) {
            Probe::Reserved(r) => r,
            _ => panic!("first sighting must reserve"),
        };
        // Dropped here without commit/clear/leak — mirrors a parse/validation failure before
        // anything irreversible happened.
    }
    match cache.probe(k, 1_001) {
        Probe::Reserved(_) => {}
        _ => panic!("a dropped (uncommitted) reservation must free the key"),
    };
}

#[test]
fn a_leaked_reservation_survives_drop_so_a_disconnect_cannot_double_mint() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let k = key("alice", "idem-4");

    {
        let reservation = match cache.probe(k.clone(), 1_000) {
            Probe::Reserved(r) => r,
            _ => panic!("first sighting must reserve"),
        };
        reservation.leak(); // handed to an uncancellable execution path
    }
    // The handler future was "dropped" (client disconnect) after `leak`; the sentinel must still
    // be there, refusing a retry as in-flight rather than admitting a double mint.
    match cache.probe(k, 1_001) {
        Probe::InFlight => {}
        _ => panic!("a leaked reservation must survive drop"),
    };
}

#[test]
fn replay_expires_after_the_ttl_and_a_fresh_mint_is_then_allowed() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let k = key("alice", "idem-5");

    let reservation = match cache.probe(k.clone(), 1_000) {
        Probe::Reserved(r) => r,
        _ => panic!("first sighting must reserve"),
    };
    reservation.commit("first-response".to_string(), 1_000);

    // Just inside the window: still a replay.
    match cache.probe(k.clone(), 1_000 + IDEMPOTENCY_TTL_SECS - 1) {
        Probe::Replay(v) => assert_eq!(v, "first-response"),
        _ => panic!("expected a replay just inside the TTL window"),
    }
    // At/after the window: the entry is swept, so this is a fresh reservation, not a replay.
    match cache.probe(k, 1_000 + IDEMPOTENCY_TTL_SECS) {
        Probe::Reserved(_) => {}
        _ => panic!("expected the expired entry to be swept and a fresh reservation returned"),
    };
}

#[test]
fn create_and_rotate_scoped_keys_never_replay_each_other() {
    // A create's cache key is (actor, header); a rotate's is (actor, "rotate:{id}:{k}"). The same
    // header value presented to both verbs must never collide, or one verb replays the other's
    // cached response — and a rotate's response carries secret material.
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let create_key = key("alice", "shared-header");
    let rotate_key = key("alice", "rotate:key-42:shared-header");

    let r = match cache.probe(create_key, 1_000) {
        Probe::Reserved(r) => r,
        _ => panic!("first sighting must reserve"),
    };
    r.commit("created".to_string(), 1_000);

    // The rotate-scoped key, despite sharing the header string, must be a fresh reservation.
    match cache.probe(rotate_key, 1_000) {
        Probe::Reserved(_) => {}
        _ => panic!("a rotate's scoped key must not see the create's committed slot"),
    };
}

/// The sentinel's own bound -- what the replay window is, and is not, a bound on.
#[path = "sentinel_tests.rs"]
mod sentinel_tests;

/// Two rotates whose id and header would join to one string on a separator get two slots, and a
/// create and a rotate sharing a header value never share one.
#[test]
fn the_rotate_replay_key_is_framed_so_no_two_pairs_share_a_slot() {
    use crate::idempotency::rotate_replay_key;
    assert_eq!(rotate_replay_key("a:b", "c"), "rotate:3:a:b:1:c");
    assert_eq!(rotate_replay_key("a", "b:c"), "rotate:1:a:3:b:c");
    assert_ne!(rotate_replay_key("a:b", "c"), rotate_replay_key("a", "b:c"));
    assert_ne!(rotate_replay_key("x", "shared"), "shared");
    // The length is of BYTES, so a multi-byte id puts its boundary where the reader finds it.
    assert_eq!(rotate_replay_key("é", "h"), "rotate:2:é:1:h");
}

/// A reservation handed to an uncancellable path stays finishable: after `in_flight` a drop leaves
/// the sentinel, and `commit` still replaces it with the value a retry then replays.
#[test]
fn a_reservation_marked_in_flight_survives_a_drop_and_still_commits() {
    let cache: IdempotencyCache<&'static str> = IdempotencyCache::new();
    let key = ("alice".to_string(), "k".to_string());
    let Probe::Reserved(mut r) = cache.probe(key.clone(), 10) else {
        panic!("first sighting reserves");
    };
    r.in_flight();
    r.commit("done", 11);
    assert!(matches!(cache.probe(key, 12), Probe::Replay("done")));

    let key = ("alice".to_string(), "dropped".to_string());
    let Probe::Reserved(mut r) = cache.probe(key.clone(), 20) else {
        panic!("first sighting reserves");
    };
    r.in_flight();
    drop(r);
    assert!(matches!(cache.probe(key, 21), Probe::InFlight));
}

/// THE CLAIM OUTLIVES THE PROCESS. A key claimed and settled as applied by one process is refused
/// to the next process on the same store, naming what was made: never run a second time.
#[test]
fn an_applied_claim_is_refused_after_a_restart_not_run_again() {
    let store = MemoryStore::new();
    let k = key("alice", "restart-1");
    let claim = durable::claim(&store, &k, 1_000).expect("the first claim is granted");
    durable::settle(&store, &claim, 1_001, &Settled::Applied("key:vk_1".into())).unwrap();
    // A fresh process: a fresh cache, the same store.
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    assert!(matches!(cache.probe(k.clone(), 1_002), Probe::Reserved(_)));
    assert_eq!(
        durable::claim(&store, &k, 1_002),
        Err(Refused::Applied("key:vk_1".into())),
    );
}

/// An answer settled in the store replays to the next claimer, byte for byte.
#[test]
fn a_settled_answer_is_handed_to_the_next_claimer() {
    let store = MemoryStore::new();
    let k = key("alice", "answer-1");
    let claim = durable::claim(&store, &k, 1_000).unwrap();
    durable::settle(&store, &claim, 1_000, &Settled::Answer(b"first".to_vec())).unwrap();
    assert_eq!(
        durable::claim(&store, &k, 1_010),
        Err(Refused::Answer(b"first".to_vec()))
    );
}

/// A claim released with nothing done opens the next generation, once.
#[test]
fn a_released_claim_frees_the_key_for_exactly_one_retry() {
    let store = MemoryStore::new();
    let k = key("alice", "released-1");
    let first = durable::claim(&store, &k, 1_000).unwrap();
    durable::settle(&store, &first, 1_001, &Settled::Released).unwrap();
    let second = durable::claim(&store, &k, 1_002).expect("a released claim frees the key");
    assert_ne!(first, second);
    assert_eq!(durable::claim(&store, &k, 1_003), Err(Refused::InFlight));
}

/// A claim nobody settled (its holder died) is in flight until it lapses with the replay window.
#[test]
fn an_unsettled_claim_is_in_flight_until_it_lapses() {
    let store = MemoryStore::new();
    let k = key("alice", "unsettled-1");
    durable::claim(&store, &k, 1_000).unwrap();
    assert_eq!(durable::claim(&store, &k, 1_001), Err(Refused::InFlight));
    // A store may extend a claim on every attempt that loses it: the claim lapses one window after
    // the LAST attempt, never before.
    assert!(durable::claim(&store, &k, 1_001 + IDEMPOTENCY_TTL_SECS).is_ok());
}

/// Two principals presenting the same header never share a claim.
#[test]
fn claims_are_scoped_to_the_principal() {
    let store = MemoryStore::new();
    durable::claim(&store, &key("alice", "same"), 1_000).unwrap();
    assert!(durable::claim(&store, &key("bob", "same"), 1_000).is_ok());
}
