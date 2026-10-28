// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral session substrate: opaque per-owner slots, deterministic TTL, LRU bound, and the
//! pin invariant that a durable/active tenant is never silently evicted.

use super::*;
use std::collections::BTreeSet;

const GATE: OwnerKey = "gate.screen";
const AFFINITY: OwnerKey = "route.affinity";
const TASK: OwnerKey = "relay.task";

#[test]
fn put_get_roundtrips_an_opaque_value_downcast_to_its_type() {
    let s = SessionStore::new(64, None);
    let set: BTreeSet<u64> = [1, 2, 3].into_iter().collect();
    s.put(SessionKey(7), GATE, Arc::new(set.clone()), 0, false, None);
    let got = s
        .get::<BTreeSet<u64>>(SessionKey(7), GATE, 0)
        .expect("present");
    assert_eq!(*got, set);
}

#[test]
fn a_wrong_type_downcast_returns_none_not_a_panic() {
    let s = SessionStore::new(64, None);
    s.put(SessionKey(1), GATE, Arc::new(5u32), 0, false, None);
    assert!(s.get::<String>(SessionKey(1), GATE, 0).is_none());
}

#[test]
fn distinct_owners_hold_independent_state_for_the_same_session() {
    let s = SessionStore::new(64, None);
    s.put(SessionKey(9), GATE, Arc::new(1u8), 0, false, None);
    s.put(SessionKey(9), AFFINITY, Arc::new(2u8), 0, false, None);
    assert_eq!(*s.get::<u8>(SessionKey(9), GATE, 0).unwrap(), 1);
    assert_eq!(*s.get::<u8>(SessionKey(9), AFFINITY, 0).unwrap(), 2);
}

#[test]
fn a_slot_expires_at_its_ttl_and_is_dropped_on_read() {
    let s = SessionStore::new(64, None);
    s.put(SessionKey(1), GATE, Arc::new(1u8), 1_000, false, Some(500));
    assert!(s.get::<u8>(SessionKey(1), GATE, 1_400).is_some()); // before expiry
    assert!(s.get::<u8>(SessionKey(1), GATE, 1_500).is_none()); // at expiry → dropped
    assert_eq!(s.len(), 0);
}

#[test]
fn the_lru_unpinned_slot_is_evicted_when_over_capacity() {
    let s = SessionStore::new(2, None);
    s.put(SessionKey(1), GATE, Arc::new(1u8), 10, false, None);
    s.put(SessionKey(2), GATE, Arc::new(2u8), 20, false, None);
    // Touch session 1 so session 2 becomes LRU.
    let _ = s.get::<u8>(SessionKey(1), GATE, 30);
    s.put(SessionKey(3), GATE, Arc::new(3u8), 40, false, None); // over cap → evict LRU (session 2)
    assert!(s.get::<u8>(SessionKey(1), GATE, 50).is_some());
    assert!(s.get::<u8>(SessionKey(2), GATE, 50).is_none());
    assert!(s.get::<u8>(SessionKey(3), GATE, 50).is_some());
}

#[test]
fn a_pinned_slot_is_never_evicted_even_over_capacity_or_past_ttl() {
    let s = SessionStore::new(1, Some(100));
    // Pin a durable tenant (e.g. another plane's live task).
    s.put(SessionKey(1), TASK, Arc::new(1u8), 0, true, None);
    // Push well past capacity with unpinned slots and past any TTL.
    s.put(SessionKey(2), GATE, Arc::new(2u8), 1_000, false, None);
    s.put(SessionKey(3), GATE, Arc::new(3u8), 2_000, false, None);
    // The pinned slot survives; unpinned ones are bounded/expired away.
    assert!(s.get::<u8>(SessionKey(1), TASK, 9_999).is_some());
}

#[test]
fn remove_drops_a_pinned_slot_the_only_way_it_leaves() {
    let s = SessionStore::new(64, None);
    s.put(SessionKey(1), TASK, Arc::new(1u8), 0, true, None);
    assert!(s.remove(SessionKey(1), TASK));
    assert!(s.get::<u8>(SessionKey(1), TASK, 0).is_none());
    assert!(s.is_empty());
}

/// No session id → the consumer never calls the substrate; but a wrong/absent key simply misses,
/// which is the safe-degradation contract (fall back to the stateless path).
#[test]
fn a_missing_session_is_a_plain_miss() {
    let s = SessionStore::new(64, None);
    assert!(s.get::<u8>(SessionKey(42), GATE, 0).is_none());
}

/// K5#5: A PUT DOES BOUNDED WORK UNDER THE LOCK. The store is process-wide at a production capacity of
/// 65,536 and the gate's incremental-scan tenant puts on every gated request; a put that walked every
/// slot (the `retain` over the whole map, then a `min_by_key` scan per eviction) serialised every
/// worker behind that walk. A put now drops at most `SWEEP_PER_PUT` expired slots, earliest expiry
/// first. On dev the one put below drops every expired slot at once, so the count falls to one.
#[test]
fn a_put_drops_a_bounded_batch_of_expired_slots_not_the_whole_backlog() {
    let backlog = 4 * SWEEP_PER_PUT as u64;
    let s = SessionStore::new(10_000, None);
    for i in 0..backlog {
        s.put(SessionKey(i), GATE, Arc::new(i), 0, false, Some(10));
    }
    assert_eq!(s.len() as u64, backlog);
    s.put(SessionKey(u64::MAX), GATE, Arc::new(0u64), 100, false, None);
    assert_eq!(
        s.len() as u64,
        backlog + 1 - SWEEP_PER_PUT as u64,
        "one put walked the whole expired backlog"
    );
    // The earliest-expiring are the ones dropped; the rest still read as misses, never as values.
    assert!(s.get::<u64>(SessionKey(backlog - 1), GATE, 100).is_none());
    // The backlog drains a batch per put.
    for i in 0..3 {
        s.put(
            SessionKey(u64::MAX - 1 - i),
            GATE,
            Arc::new(0u64),
            100,
            false,
            None,
        );
    }
    assert_eq!(s.len(), 4, "the backlog drains in bounded batches");
}

/// An expired slot makes room before a live one is evicted: the bounded sweep runs ahead of the LRU
/// bound, so a live slot that is older in recency than an expired one still survives the overflow.
#[test]
fn an_expired_slot_is_dropped_before_a_live_lru_slot_is_evicted() {
    let s = SessionStore::new(2, None);
    s.put(SessionKey(1), GATE, Arc::new(1u8), 0, false, None); // live, least recently touched
    s.put(SessionKey(2), GATE, Arc::new(2u8), 5, false, Some(10)); // expires at 15
    s.put(SessionKey(3), GATE, Arc::new(3u8), 20, false, None); // over cap at 20
    assert!(s.get::<u8>(SessionKey(1), GATE, 30).is_some());
    assert!(s.get::<u8>(SessionKey(3), GATE, 30).is_some());
    assert_eq!(s.len(), 2);
}

/// Replacing, touching, pinning and removing keep the recency and expiry orders in step with the
/// slots: a replaced slot is judged by its NEW touch and TTL, a removed slot is never chosen as a
/// victim, and a slot re-put as pinned leaves both orders.
#[test]
fn replace_touch_pin_and_remove_keep_the_orders_in_step() {
    let s = SessionStore::new(2, None);
    s.put(SessionKey(1), GATE, Arc::new(1u8), 10, false, Some(100)); // expires at 110
    s.put(SessionKey(2), GATE, Arc::new(2u8), 20, false, None);
    // Replace session 1 with no TTL: its old expiry must not drop the new value.
    s.put(SessionKey(1), GATE, Arc::new(11u8), 30, false, None);
    assert_eq!(*s.get::<u8>(SessionKey(1), GATE, 40).unwrap(), 11);
    // Past the old expiry, an overflow evicts session 2 (LRU), not the replaced session 1.
    s.put(SessionKey(3), GATE, Arc::new(3u8), 200, false, None);
    assert!(s.get::<u8>(SessionKey(2), GATE, 210).is_none());
    assert_eq!(*s.get::<u8>(SessionKey(1), GATE, 210).unwrap(), 11);
    // A removed slot is gone from the orders: the next overflow chooses between live slots only.
    assert!(s.remove(SessionKey(3), GATE));
    s.put(SessionKey(4), GATE, Arc::new(4u8), 220, false, None);
    s.put(SessionKey(5), GATE, Arc::new(5u8), 230, false, None);
    assert!(
        s.get::<u8>(SessionKey(1), GATE, 240).is_none(),
        "session 1 was LRU"
    );
    assert!(s.get::<u8>(SessionKey(4), GATE, 240).is_some());
    assert!(s.get::<u8>(SessionKey(5), GATE, 240).is_some());
    // Re-put session 4 pinned: it leaves the recency order, so overflow never picks it.
    s.put(SessionKey(4), GATE, Arc::new(9u8), 250, true, None);
    s.put(SessionKey(6), GATE, Arc::new(6u8), 260, false, None);
    s.put(SessionKey(7), GATE, Arc::new(7u8), 270, false, None);
    assert_eq!(*s.get::<u8>(SessionKey(4), GATE, 280).unwrap(), 9);
    assert!(s.get::<u8>(SessionKey(7), GATE, 280).is_some());
    assert_eq!(s.len(), 2);
}
