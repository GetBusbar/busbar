// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral session substrate: opaque per-owner slots, deterministic TTL, LRU bound, and the
//! pin invariant that a durable/active tenant is never silently evicted.

use super::*;
use std::collections::BTreeSet;

const GATE: OwnerKey = "gate.screen";
const AFFINITY: OwnerKey = "llm.affinity";

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
    // Pin a durable tenant (e.g. an A2A live task).
    s.put(SessionKey(1), "a2a.task", Arc::new(1u8), 0, true, None);
    // Push well past capacity with unpinned slots and past any TTL.
    s.put(SessionKey(2), GATE, Arc::new(2u8), 1_000, false, None);
    s.put(SessionKey(3), GATE, Arc::new(3u8), 2_000, false, None);
    // The pinned slot survives; unpinned ones are bounded/expired away.
    assert!(s.get::<u8>(SessionKey(1), "a2a.task", 9_999).is_some());
}

#[test]
fn pinning_clears_ttl_and_unpinning_reapplies_it() {
    let s = SessionStore::new(64, None);
    s.put(SessionKey(1), GATE, Arc::new(1u8), 0, false, Some(100));
    assert!(s.set_pinned(SessionKey(1), GATE, true, 0, None));
    assert!(s.get::<u8>(SessionKey(1), GATE, 10_000).is_some()); // pinned → TTL ignored
    assert!(s.set_pinned(SessionKey(1), GATE, false, 10_000, Some(100)));
    assert!(s.get::<u8>(SessionKey(1), GATE, 10_050).is_some()); // within new TTL
    assert!(s.get::<u8>(SessionKey(1), GATE, 10_100).is_none()); // expired again
}

#[test]
fn remove_drops_a_pinned_slot_the_only_way_it_leaves() {
    let s = SessionStore::new(64, None);
    s.put(SessionKey(1), "a2a.task", Arc::new(1u8), 0, true, None);
    assert!(s.remove(SessionKey(1), "a2a.task"));
    assert!(s.get::<u8>(SessionKey(1), "a2a.task", 0).is_none());
    assert!(s.is_empty());
}

/// No session id → the consumer never calls the substrate; but a wrong/absent key simply misses,
/// which is the safe-degradation contract (fall back to the stateless path).
#[test]
fn a_missing_session_is_a_plain_miss() {
    let s = SessionStore::new(64, None);
    assert!(s.get::<u8>(SessionKey(42), GATE, 0).is_none());
}
