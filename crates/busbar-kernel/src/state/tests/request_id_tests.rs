// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn request_id_counter_is_unique_and_monotonic_across_sequential_requests() {
    let counter = AtomicU64::new(seed());
    let a = next(&counter);
    let b = next(&counter);
    let c = next(&counter);
    assert!(b > a, "the counter must strictly increase: {a} then {b}");
    assert!(c > b, "the counter must strictly increase: {b} then {c}");
    assert_eq!(b, a + 1, "a plain fetch_add(1): no gaps between requests");
    assert_eq!(c, a + 2);
    let second = AtomicU64::new(seed());
    let d = next(&second);
    assert_ne!(
        d, a,
        "two independently-seeded counters must not coincide (boot entropy seed)"
    );
}
