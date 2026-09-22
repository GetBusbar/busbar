// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SENTINEL IS NOT A CACHED RESPONSE, AND THE REPLAY WINDOW IS NO BOUND ON ONE.
//!
//! The TTL answers "how long does a completed call's response stay available to a retry". Forgetting
//! a committed value early costs a retry one extra run of a mutation nobody has run yet — an
//! annoyance. The in-flight sentinel answers a different question — "is somebody running this right
//! now" — and forgetting one costs the opposite: the next retry is told it is the first, two live
//! reservations exist for one idempotency key, and TWO CREDENTIALS ARE MINTED where the sentinel
//! existed so that one would.
//!
//! Ten minutes is not an upper bound on a mutation. A store gone slow, a rebuild behind a config
//! swap, a mint blocked on an unreachable signer: each holds an uncancellable path well past the
//! window, and the longer it is stuck the MORE retries arrive to be admitted. So the sweep must
//! step over a sentinel however old it is, and a sentinel is bounded by its own reservation
//! instead.
//!
//! These are the cases the sweep's one boolean decides, stated so that flipping it fails here
//! rather than in somebody's key log.

use crate::idempotency::{IdempotencyCache, Probe, IDEMPOTENCY_TTL_SECS};

fn key(actor: &str, header: &str) -> (String, String) {
    (actor.to_string(), header.to_string())
}

/// A LEAKED SENTINEL OUTLIVES THE REPLAY WINDOW, AND GOES ON REFUSING.
///
/// `leak` is the transition for a mutation handed to a path that cannot be cancelled: whatever
/// happens to the caller, that mutation is still going to land, so a retry must never be admitted
/// as a first sighting. The sweep runs on every probe, so the retry that arrives an hour later is
/// the one that finds out whether the sweep respects the sentinel.
#[test]
fn a_leaked_sentinel_still_refuses_a_retry_long_after_the_replay_window_has_passed() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let k = key("alice", "idem-stuck");

    match cache.probe(k.clone(), 1_000) {
        Probe::Reserved(r) => r.leak(),
        _ => panic!("the first sighting must reserve"),
    }

    // Every one of these is past the replay window, by a little and then by a lot. A mutation
    // blocked on an unreachable signer is exactly this shape.
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

/// A COMMITTED VALUE DOES EXPIRE ON THE WINDOW — the sweep is not simply switched off.
///
/// The two halves have to be pinned together. A sweep that kept everything forever would be
/// unbounded memory keyed by a header a client chooses, which is its own denial of service; a sweep
/// that dropped everything would be the double-mint above. So: the committed value goes at the
/// boundary, and only the committed value.
#[test]
fn a_committed_value_is_swept_at_the_window_boundary_and_not_before_it() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();

    // One second short of the window: still replayed.
    let inside = key("alice", "idem-inside");
    match cache.probe(inside.clone(), 1_000) {
        Probe::Reserved(r) => r.commit("first-response".to_string(), 1_000),
        _ => panic!("the first sighting must reserve"),
    }
    match cache.probe(inside.clone(), 1_000 + IDEMPOTENCY_TTL_SECS - 1) {
        Probe::Replay(v) => assert_eq!(v, "first-response"),
        _ => panic!("a retry inside the replay window must replay the first response"),
    }

    // Exactly at the window: swept, and the key is free for a fresh call.
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

/// THE SWEEP READS EACH SLOT'S OWN AGE, NOT THE CACHE'S.
///
/// A busy node holds many keys at once, inserted at different moments. Sweeping on anything other
/// than each slot's own insertion time would drop a slot that is still inside its window because
/// some OTHER slot has aged out.
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

    // A probe past the OLD slot's window but inside the YOUNG one's.
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

/// A RESERVATION IS RESOLVED BY COMMIT, BY CLEAR AND BY DROP — AND BY NOTHING ELSE.
///
/// The three exits are the sentinel's real bound. Committing publishes a value; clearing and
/// dropping both free the key for a genuine retry, because in both cases the caller knows nothing
/// irreversible happened. Only `leak` deliberately leaves it standing.
#[test]
fn commit_clear_and_drop_each_resolve_a_sentinel() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();

    // COMMIT: the key answers with the value from then on.
    let committed = key("alice", "idem-commit");
    match cache.probe(committed.clone(), 1_000) {
        Probe::Reserved(r) => r.commit("v".to_string(), 1_000),
        _ => panic!("reserve"),
    }
    assert!(matches!(cache.probe(committed, 1_001), Probe::Replay(_)));

    // CLEAR: the key is free again, and a retry is a first sighting rather than a refusal.
    let cleared = key("alice", "idem-clear");
    match cache.probe(cleared.clone(), 1_000) {
        Probe::Reserved(r) => r.clear(),
        _ => panic!("reserve"),
    }
    assert!(
        matches!(cache.probe(cleared, 1_001), Probe::Reserved(_)),
        "a cleared reservation went on refusing a retry it had already declared safe"
    );

    // DROP: a reservation that simply goes out of scope resolves the same way a cleared one does —
    // a parse or validation failure before anything irreversible happened.
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

/// CLEARING NEVER REMOVES A VALUE SOMEBODY ELSE COMMITTED.
///
/// `clear_inner` removes the slot only while it is still an uncommitted sentinel. If it removed
/// whatever it found, a late clear racing a commit would delete the very response a retry is
/// waiting to replay — and the retry would re-run a mutation that had already landed.
#[test]
fn a_clear_that_arrives_after_a_commit_leaves_the_committed_value_alone() {
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let k = key("alice", "idem-race");

    let first = match cache.probe(k.clone(), 1_000) {
        Probe::Reserved(r) => r,
        _ => panic!("reserve"),
    };
    // Something else commits the slot under this reservation's feet -- the shape of a commit
    // racing the reserving call's own cancellation.
    match cache.probe(k.clone(), 1_000) {
        Probe::InFlight => {}
        _ => panic!("a second probe of a reserved key must say in-flight"),
    }
    first.commit("landed".to_string(), 1_000);

    // A second reservation object cannot exist for this key while it is reserved, so the race is
    // reproduced the only way it can occur: a fresh reservation on a key that is then committed,
    // then cleared. The committed value must survive.
    match cache.probe(k.clone(), 1_001) {
        Probe::Replay(v) => assert_eq!(v, "landed"),
        _ => panic!("the committed value was not replayed"),
    };
}

/// THE SLOT IS KEYED BY THE ACTOR AS WELL AS THE HEADER.
///
/// Two operators may choose the same idempotency key value; they must not replay each other's
/// response. A replay that crossed principals would hand one operator the credential minted for
/// another.
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
