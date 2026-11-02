// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::idempotency::durable::{self, Refused, Settled};
use crate::idempotency::{IdempotencyCache, Probe, IDEMPOTENCY_TTL_SECS};
use busbar_kernel_testkit::test_support::store_double::MemoryStore;

fn key(actor: &str, header: &str) -> (String, String) {
    (actor.to_string(), header.to_string())
}

fn durable_store() -> MemoryStore {
    let store = MemoryStore::new();
    store.pin_token_clock(1_000);
    store
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
        reservation.leak();
    }

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

    match cache.probe(k.clone(), 1_000 + IDEMPOTENCY_TTL_SECS - 1) {
        Probe::Replay(v) => assert_eq!(v, "first-response"),
        _ => panic!("expected a replay just inside the TTL window"),
    }

    match cache.probe(k, 1_000 + IDEMPOTENCY_TTL_SECS) {
        Probe::Reserved(_) => {}
        _ => panic!("expected the expired entry to be swept and a fresh reservation returned"),
    };
}

#[test]
fn create_and_rotate_scoped_keys_never_replay_each_other() {
    use crate::idempotency::{create_replay_key, rotate_replay_key};

    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let rotate_key = key("alice", &rotate_replay_key("key-42", "shared-header"));
    let create_key = key("alice", &create_replay_key(&rotate_key.1));

    let r = match cache.probe(create_key, 1_000) {
        Probe::Reserved(r) => r,
        _ => panic!("first sighting must reserve"),
    };
    r.commit("created".to_string(), 1_000);

    match cache.probe(rotate_key, 1_000) {
        Probe::Reserved(_) => {}
        _ => panic!("a rotate's scoped key must not see the create's committed slot"),
    };
}

#[path = "sentinel_tests.rs"]
mod sentinel_tests;

#[test]
fn the_rotate_replay_key_is_framed_so_no_two_pairs_share_a_slot() {
    use crate::idempotency::{create_replay_key, rotate_replay_key};
    assert_eq!(rotate_replay_key("a:b", "c"), "rotate:3:a:b:1:c");
    assert_eq!(rotate_replay_key("a", "b:c"), "rotate:1:a:3:b:c");
    assert_ne!(rotate_replay_key("a:b", "c"), rotate_replay_key("a", "b:c"));
    assert_ne!(
        rotate_replay_key("x", "shared"),
        create_replay_key("shared")
    );
    assert_ne!(
        rotate_replay_key("x", "h"),
        create_replay_key("rotate:1:x:1:h")
    );
    assert_eq!(create_replay_key("é"), "create:2:é");

    assert_eq!(rotate_replay_key("é", "h"), "rotate:2:é:1:h");
}

#[test]
fn create_and_rotate_claims_are_disjoint_after_cache_loss() {
    use crate::idempotency::{create_replay_key, rotate_replay_key};
    let rotate = key("alice", &rotate_replay_key("x", "h"));
    let create = key("alice", &create_replay_key("rotate:1:x:1:h"));
    for (first, second) in [(&create, &rotate), (&rotate, &create)] {
        let store = durable_store();
        let claim = durable::claim(&store, first, 1_000).expect("first operation claims");
        durable::settle(&store, &claim, 1_001, &Settled::Applied("key".into()))
            .expect("first operation settles");
        assert!(
            durable::claim(&store, second, 1_002).is_ok(),
            "other operation must claim independently"
        );
        assert!(
            matches!(
                durable::claim(&store, first, 1_002),
                Err(Refused::Applied(_))
            ),
            "the original operation remains protected"
        );
    }
}

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

#[test]
fn an_applied_claim_is_refused_after_a_restart_not_run_again() {
    let store = durable_store();
    let k = key("alice", "restart-1");
    let claim = durable::claim(&store, &k, 1_000).expect("the first claim is granted");
    durable::settle(&store, &claim, 1_001, &Settled::Applied("key:vk_1".into())).unwrap();

    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    assert!(matches!(cache.probe(k.clone(), 1_002), Probe::Reserved(_)));
    assert_eq!(
        durable::claim(&store, &k, 1_002),
        Err(Refused::Applied("key:vk_1".into())),
    );
}

#[test]
fn a_settled_answer_is_handed_to_the_next_claimer() {
    let store = durable_store();
    let k = key("alice", "answer-1");
    let claim = durable::claim(&store, &k, 1_000).unwrap();
    durable::settle(&store, &claim, 1_000, &Settled::Answer(b"first".to_vec())).unwrap();
    assert_eq!(
        durable::claim(&store, &k, 1_010),
        Err(Refused::Answer(b"first".to_vec()))
    );
}

#[test]
fn a_released_claim_frees_the_key_for_exactly_one_retry() {
    let store = durable_store();
    let k = key("alice", "released-1");
    let first = durable::claim(&store, &k, 1_000).unwrap();
    durable::settle(&store, &first, 1_001, &Settled::Released).unwrap();
    let second = durable::claim(&store, &k, 1_002).expect("a released claim frees the key");
    assert_ne!(first, second);
    assert_eq!(durable::claim(&store, &k, 1_003), Err(Refused::InFlight));
}

#[test]
fn an_unsettled_claim_is_in_flight_until_it_lapses() {
    let store = durable_store();
    let k = key("alice", "unsettled-1");
    durable::claim(&store, &k, 1_000).unwrap();
    assert_eq!(durable::claim(&store, &k, 1_001), Err(Refused::InFlight));

    store.pin_token_clock(1_001 + IDEMPOTENCY_TTL_SECS);
    assert!(durable::claim(&store, &k, 1_001 + IDEMPOTENCY_TTL_SECS).is_ok());
}

#[test]
fn claims_are_scoped_to_the_principal() {
    let store = durable_store();
    durable::claim(&store, &key("alice", "same"), 1_000).unwrap();
    assert!(durable::claim(&store, &key("bob", "same"), 1_000).is_ok());
}

#[test]
fn a_held_claim_never_expires_while_its_effect_or_settlement_is_unknown() {
    let store = MemoryStore::new();
    let k = key("alice", "held-without-settlement");
    let first = durable::claim_held(&store, &k, 1_000).unwrap();
    let later = 1_000 + IDEMPOTENCY_TTL_SECS * 3;

    assert_eq!(
        durable::claim_held(&store, &k, later),
        Err(Refused::InFlight)
    );
    let receipt = b"the exact first operation, metadata, body and 503".to_vec();
    durable::settle(&store, &first, 1_000, &Settled::Retained(receipt.clone())).unwrap();

    let other = durable::claim_held(&store, &key("alice", "unrelated-held"), later).unwrap();
    durable::settle(&store, &other, later, &Settled::Answer(b"done".to_vec())).unwrap();
    assert_eq!(
        durable::claim_held(&store, &k, later),
        Err(Refused::Retained(receipt))
    );
}

#[test]
fn an_old_held_refusal_cannot_skip_a_newer_in_flight_generation() {
    let store = MemoryStore::new();
    let k = key("alice", "held-released");
    let first = durable::claim_held(&store, &k, 1_000).unwrap();
    durable::settle(&store, &first, 1_000, &Settled::Released).unwrap();
    let second = durable::claim_held(&store, &k, 1_001).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        durable::claim_held(&store, &k, 1_002),
        Err(Refused::InFlight)
    );
    let later = 1_000 + IDEMPOTENCY_TTL_SECS * 3;
    assert_eq!(
        durable::claim_held(&store, &k, later),
        Err(Refused::InFlight)
    );
    durable::settle(
        &store,
        &second,
        1_001,
        &Settled::Answer(b"completed".to_vec()),
    )
    .unwrap();
    let third = durable::claim_held(&store, &k, later).unwrap();
    assert_ne!(second, third, "only a definite answer expires normally");
    assert_eq!(
        durable::claim_held(&store, &k, later + 1),
        Err(Refused::InFlight)
    );
}

#[test]
fn a_late_predecessor_settlement_cannot_replace_a_successor_receipt() {
    let store = MemoryStore::new();
    let k = key("alice", "late-settlement");
    let first = durable::claim_held(&store, &k, 1_000).unwrap();
    durable::settle(&store, &first, 1_000, &Settled::Released).unwrap();
    let second = durable::claim_held(&store, &k, 1_001).unwrap();
    let receipt = Settled::Retained(b"exact successor operation and answer".to_vec());
    durable::settle(&store, &second, 1_001, &receipt).unwrap();

    durable::settle(&store, &first, 1_000, &Settled::Released).unwrap();
    assert_eq!(
        durable::claim_held(&store, &k, 10_000),
        Err(Refused::Retained(
            b"exact successor operation and answer".to_vec()
        ))
    );
}

#[test]
fn a_legacy_refusal_cannot_hide_its_pending_successor_during_migration() {
    let store = durable_store();
    let k = key("alice", "legacy-pending-successor");
    let first = durable::claim(&store, &k, 1_000).unwrap();
    durable::settle(&store, &first, 1_000, &Settled::Released).unwrap();
    let _pending = durable::claim(&store, &k, 1_001).unwrap();
    assert_eq!(
        durable::claim_held(&store, &k, 1_002),
        Err(Refused::InFlight)
    );
}
