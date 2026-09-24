// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ported assertions from `busbar-core::admin::tests` for the idempotency cache: a same-node
//! replay returns the committed value verbatim, a concurrent in-flight call is refused rather than
//! double-run, a cleared/expired reservation frees the key for a fresh mint, and the 600 s TTL is
//! honoured exactly.

use std::sync::{Arc, Mutex};

use crate::idempotency::{ClaimJournal, IdempotencyCache, Probe, IDEMPOTENCY_TTL_SECS};

fn key(actor: &str, header: &str) -> (String, String) {
    (actor.to_string(), header.to_string())
}

/// A [`ClaimJournal`] fake that records every `(key, now)` it is called with, for asserting the
/// writer side of item 271: the cache journals a claim exactly once per first sighting, never on a
/// replay or an in-flight refusal.
#[derive(Default, Clone)]
struct RecordingJournal {
    calls: Arc<Mutex<Vec<((String, String), u64)>>>,
}

impl RecordingJournal {
    fn calls(&self) -> Vec<((String, String), u64)> {
        self.calls.lock().unwrap().clone()
    }
}

impl ClaimJournal for RecordingJournal {
    fn journal_claim(&self, key: &(String, String), now: u64) {
        self.calls.lock().unwrap().push((key.clone(), now));
    }
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

#[test]
fn first_sighting_journals_the_claim_exactly_once() {
    let journal = RecordingJournal::default();
    let cache: IdempotencyCache<String> = IdempotencyCache::with_journal(Arc::new(journal.clone()));
    let k = key("alice", "idem-journal-1");

    let reservation = match cache.probe(k.clone(), 1_000) {
        Probe::Reserved(r) => r,
        _ => panic!("first sighting must reserve"),
    };
    assert_eq!(
        journal.calls(),
        vec![(k.clone(), 1_000)],
        "the claim must be journalled exactly once, under the same (key, now) probe used"
    );
    reservation.commit("first-response".to_string(), 1_000);

    // A replay of an already-committed key never re-journals — a completed claim is not taken
    // again.
    match cache.probe(k, 1_100) {
        Probe::Replay(v) => assert_eq!(v, "first-response"),
        _ => panic!("expected a replay"),
    }
    assert_eq!(
        journal.calls().len(),
        1,
        "a replay of a committed key must never journal a second claim"
    );
}

#[test]
fn in_flight_refusal_never_journals_a_second_claim() {
    let journal = RecordingJournal::default();
    let cache: IdempotencyCache<String> = IdempotencyCache::with_journal(Arc::new(journal.clone()));
    let k = key("alice", "idem-journal-2");

    let _first = match cache.probe(k.clone(), 1_000) {
        Probe::Reserved(r) => r,
        _ => panic!("first sighting must reserve"),
    };
    match cache.probe(k, 1_005) {
        Probe::InFlight => {}
        _ => panic!("a concurrent retry against a live reservation must be InFlight"),
    }
    assert_eq!(
        journal.calls().len(),
        1,
        "a concurrent in-flight probe must never journal a second claim for the same key"
    );
}

#[test]
fn a_dropped_and_retried_reservation_journals_the_fresh_claim() {
    let journal = RecordingJournal::default();
    let cache: IdempotencyCache<String> = IdempotencyCache::with_journal(Arc::new(journal.clone()));
    let k = key("alice", "idem-journal-3");

    {
        let _reservation = match cache.probe(k.clone(), 1_000) {
            Probe::Reserved(r) => r,
            _ => panic!("first sighting must reserve"),
        };
        // Dropped without commit/clear/leak.
    }
    match cache.probe(k.clone(), 1_001) {
        Probe::Reserved(_) => {}
        _ => panic!("a dropped (uncommitted) reservation must free the key"),
    }
    assert_eq!(
        journal.calls(),
        vec![(k.clone(), 1_000), (k, 1_001)],
        "a fresh reservation after a dropped one is a NEW claim and must be journalled again"
    );
}

#[test]
fn no_journal_bound_takes_no_calls_and_behaves_exactly_as_before() {
    // Exactly `IdempotencyCache::new()`, the constructor every existing call site (and a node with
    // no data dir) still uses: no journal is ever consulted, and every prior assertion in this file
    // (proved against `IdempotencyCache::new()`) is unaffected by this seam's existence.
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let k = key("alice", "idem-journal-4");

    let reservation = match cache.probe(k.clone(), 1_000) {
        Probe::Reserved(r) => r,
        _ => panic!("first sighting must reserve"),
    };
    reservation.commit("first-response".to_string(), 1_000);
    match cache.probe(k, 1_100) {
        Probe::Replay(v) => assert_eq!(v, "first-response"),
        _ => panic!("expected a replay"),
    };
}

/// The sentinel's own bound -- what the replay window is, and is not, a bound on.
#[path = "sentinel_tests.rs"]
mod sentinel_tests;
