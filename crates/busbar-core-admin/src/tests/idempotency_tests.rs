// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::idempotency::{IdempotencyCache, Probe, IDEMPOTENCY_TTL_SECS};

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
fn create_and_rotate_claim_inputs_are_disjoint_before_durable_claim() {
    use crate::idempotency::{create_replay_key, rotate_replay_key};
    let rotate = key("alice", &rotate_replay_key("x", "h"));
    let create = key("alice", &create_replay_key("rotate:1:x:1:h"));
    assert_ne!(
        create, rotate,
        "the private factories supply distinct durable claim keys"
    );
}

#[test]
fn exact_request_binding_precedes_secret_replay_and_inflight() {
    let cache = IdempotencyCache::<String>::new();
    let key = key("alice", "create:action");
    let a = busbar_contract::abi::sdk::digest::sha256(br#"{"name":"a"}"#);
    let b = busbar_contract::abi::sdk::digest::sha256(br#"{"name":"b"}"#);
    let invalid = busbar_contract::abi::sdk::digest::sha256(b"{");
    let reservation = match cache.probe_bound(key.clone(), a, 1000).unwrap() {
        Probe::Reserved(reservation) => reservation,
        _ => panic!("first request reserves"),
    };
    for changed in [b, invalid] {
        assert!(cache.probe_bound(key.clone(), changed, 1001).is_err());
    }
    assert!(matches!(
        cache.probe_bound(key.clone(), a, 1001),
        Ok(Probe::InFlight)
    ));
    reservation.commit("once-shown-secret".into(), 1002);
    for changed in [b, invalid] {
        assert!(cache.probe_bound(key.clone(), changed, 1003).is_err());
    }
    assert!(
        matches!(cache.probe_bound(key.clone(), a, 1003), Ok(Probe::Replay(value)) if value == "once-shown-secret")
    );
    assert!(matches!(
        cache.probe_bound(("bob".into(), key.1.clone()), b, 1003),
        Ok(Probe::Reserved(_))
    ));
    assert!(matches!(
        cache.probe_bound(key, b, 1002 + IDEMPOTENCY_TTL_SECS),
        Ok(Probe::Reserved(_))
    ));
}

/// #359 SEC-L6 (DES-359 r3): the key replay cache holds the once-shown answer (a live token)
/// only in wiped custody, so the stored copy is wiped when the window evicts it and when the
/// cache itself drops. Driven on the test thread, where `wipe_counts` observes the drop wipes.
#[test]
fn the_key_replay_cache_wipes_a_held_answer_on_eviction_and_drop() {
    use busbar_contract::secure::wipe_counts;
    let answer = br#"{"id":"vk_1","token":"bb_live_once_shown"}"#.to_vec();

    let cache = crate::keys::KeyReplayCache::new();
    match cache.probe(key("alice", "create:evicted"), 1_000) {
        Probe::Reserved(r) => r.commit(answer.clone().into(), 1_000),
        _ => panic!("first sighting must reserve"),
    }
    let (_, before) = wipe_counts();
    assert!(matches!(
        cache.probe(key("alice", "create:other"), 1_000 + IDEMPOTENCY_TTL_SECS),
        Probe::Reserved(_)
    ));
    let (_, evicted) = wipe_counts();
    assert!(
        evicted > before,
        "an answer the replay window evicts is wiped, not freed in the clear"
    );

    match cache.probe(key("alice", "create:dropped"), 5_000) {
        Probe::Reserved(r) => r.commit(answer.into(), 5_000),
        _ => panic!("first sighting must reserve"),
    }
    let (_, before) = wipe_counts();
    drop(cache);
    let (_, dropped) = wipe_counts();
    assert!(
        dropped > before,
        "an answer still held when the cache drops is wiped"
    );
}

/// #359 SEC-L6: a replay writes the held answer verbatim, so the retry receives exactly the bytes
/// the first caller received, as `application/json`, with no re-parse.
#[tokio::test]
async fn a_key_replay_answers_the_first_answers_exact_bytes() {
    use http_body_util::BodyExt as _;
    let body = serde_json::json!({"id": "vk_1", "token": "bb_live_once_shown", "expires_at": 7});
    let cache = crate::keys::KeyReplayCache::new();
    let k = key("alice", "create:verbatim");
    let reservation = match cache.probe(k.clone(), 1_000) {
        Probe::Reserved(r) => r,
        _ => panic!("first sighting must reserve"),
    };
    let first =
        crate::keys::commit_key_answer(Some(reservation), axum::http::StatusCode::CREATED, &body);
    let held = match cache.probe(k, 1_001) {
        Probe::Replay(held) => held,
        _ => panic!("a committed answer replays"),
    };
    let replay = crate::keys::answer_response(axum::http::StatusCode::CREATED, &held);
    assert_eq!(replay.status(), axum::http::StatusCode::CREATED);
    assert_eq!(
        replay.headers()[axum::http::header::CONTENT_TYPE],
        busbar_contract::protocol::APPLICATION_JSON
    );
    let first = first.into_body().collect().await.unwrap().to_bytes();
    let replay = replay.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        first, replay,
        "the replay is the first answer, byte for byte"
    );
    assert_eq!(&first[..], held.as_slice());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&first).unwrap(),
        body
    );
}
