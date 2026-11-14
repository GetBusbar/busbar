// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, BTreeSet};

use super::Counted;

#[test]
fn counted_map_answers_as_its_map_and_counts_each_visit() {
    let mut plain = BTreeMap::new();
    let mut counted = Counted::<BTreeMap<u32, u32>>::default();
    for n in 0..10 {
        assert_eq!(counted.insert(n, n * 2), plain.insert(n, n * 2));
    }
    assert_eq!(counted.visits(), 10);
    assert_eq!(counted.get(&3), plain.get(&3));
    assert_eq!(counted.contains_key(&11), plain.contains_key(&11));
    if let Some(v) = counted.get_mut(&4) {
        *v = 0;
    }
    plain.insert(4, 0);
    assert_eq!(counted.remove(&5), plain.remove(&5));
    assert_eq!(counted.visits(), 14);
    assert_eq!(
        (counted.len(), counted.is_empty()),
        (plain.len(), plain.is_empty())
    );
    assert_eq!(counted.visits(), 14, "len and is_empty visit nothing");
    assert!(counted.iter().eq(plain.iter()));
    assert!(counted.keys().eq(plain.keys()));
    assert!(counted.values().eq(plain.values()));
    assert!(counted.range(2..6).eq(plain.range(2..6)));
    assert_eq!(
        counted.visits(),
        14 + 9 * 3 + 3,
        "every yielded entry is one visit"
    );
    assert!(counted.values().any(|v| *v == 2));
    assert_eq!(
        counted.visits(),
        14 + 9 * 3 + 3 + 2,
        "a short-circuit walk counts what it read"
    );
}

#[test]
fn counted_set_answers_as_its_set_and_counts_each_visit() {
    let mut plain = BTreeSet::new();
    let mut counted = Counted::<BTreeSet<(u64, u8)>>::default();
    for n in 0..6u8 {
        let value = (u64::from(n / 2), n);
        assert_eq!(counted.insert(value), plain.insert(value));
    }
    assert_eq!(counted.contains(&(1, 2)), plain.contains(&(1, 2)));
    assert_eq!(counted.remove(&(2, 4)), plain.remove(&(2, 4)));
    assert_eq!(counted.visits(), 8);
    assert!(counted
        .range((1, 0)..=(1, u8::MAX))
        .eq(plain.range((1, 0)..=(1, u8::MAX))));
    assert!(counted.iter().eq(plain.iter()));
    assert_eq!(counted.visits(), 8 + 2 + 5);
}
