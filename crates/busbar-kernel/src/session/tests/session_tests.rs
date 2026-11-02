// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    assert!(s.get::<u8>(SessionKey(1), GATE, 1_400).is_some());
    assert!(s.get::<u8>(SessionKey(1), GATE, 1_500).is_none());
    assert_eq!(s.len(), 0);
}

#[test]
fn the_lru_unpinned_slot_is_evicted_when_over_capacity() {
    let s = SessionStore::new(2, None);
    s.put(SessionKey(1), GATE, Arc::new(1u8), 10, false, None);
    s.put(SessionKey(2), GATE, Arc::new(2u8), 20, false, None);

    let _ = s.get::<u8>(SessionKey(1), GATE, 30);
    s.put(SessionKey(3), GATE, Arc::new(3u8), 40, false, None);
    assert!(s.get::<u8>(SessionKey(1), GATE, 50).is_some());
    assert!(s.get::<u8>(SessionKey(2), GATE, 50).is_none());
    assert!(s.get::<u8>(SessionKey(3), GATE, 50).is_some());
}

#[test]
fn a_pinned_slot_is_never_evicted_even_over_capacity_or_past_ttl() {
    let s = SessionStore::new(1, Some(100));

    s.put(SessionKey(1), TASK, Arc::new(1u8), 0, true, None);

    s.put(SessionKey(2), GATE, Arc::new(2u8), 1_000, false, None);
    s.put(SessionKey(3), GATE, Arc::new(3u8), 2_000, false, None);

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

#[test]
fn a_missing_session_is_a_plain_miss() {
    let s = SessionStore::new(64, None);
    assert!(s.get::<u8>(SessionKey(42), GATE, 0).is_none());
}

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

    assert!(s.get::<u64>(SessionKey(backlog - 1), GATE, 100).is_none());

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

#[test]
fn an_expired_slot_is_dropped_before_a_live_lru_slot_is_evicted() {
    let s = SessionStore::new(2, None);
    s.put(SessionKey(1), GATE, Arc::new(1u8), 0, false, None);
    s.put(SessionKey(2), GATE, Arc::new(2u8), 5, false, Some(10));
    s.put(SessionKey(3), GATE, Arc::new(3u8), 20, false, None);
    assert!(s.get::<u8>(SessionKey(1), GATE, 30).is_some());
    assert!(s.get::<u8>(SessionKey(3), GATE, 30).is_some());
    assert_eq!(s.len(), 2);
}

#[test]
fn replace_touch_pin_and_remove_keep_the_orders_in_step() {
    let s = SessionStore::new(2, None);
    s.put(SessionKey(1), GATE, Arc::new(1u8), 10, false, Some(100));
    s.put(SessionKey(2), GATE, Arc::new(2u8), 20, false, None);

    s.put(SessionKey(1), GATE, Arc::new(11u8), 30, false, None);
    assert_eq!(*s.get::<u8>(SessionKey(1), GATE, 40).unwrap(), 11);

    s.put(SessionKey(3), GATE, Arc::new(3u8), 200, false, None);
    assert!(s.get::<u8>(SessionKey(2), GATE, 210).is_none());
    assert_eq!(*s.get::<u8>(SessionKey(1), GATE, 210).unwrap(), 11);

    assert!(s.remove(SessionKey(3), GATE));
    s.put(SessionKey(4), GATE, Arc::new(4u8), 220, false, None);
    s.put(SessionKey(5), GATE, Arc::new(5u8), 230, false, None);
    assert!(
        s.get::<u8>(SessionKey(1), GATE, 240).is_none(),
        "session 1 was LRU"
    );
    assert!(s.get::<u8>(SessionKey(4), GATE, 240).is_some());
    assert!(s.get::<u8>(SessionKey(5), GATE, 240).is_some());

    s.put(SessionKey(4), GATE, Arc::new(9u8), 250, true, None);
    s.put(SessionKey(6), GATE, Arc::new(6u8), 260, false, None);
    s.put(SessionKey(7), GATE, Arc::new(7u8), 270, false, None);
    assert_eq!(*s.get::<u8>(SessionKey(4), GATE, 280).unwrap(), 9);
    assert!(s.get::<u8>(SessionKey(7), GATE, 280).is_some());
    assert_eq!(s.len(), 2);
}
