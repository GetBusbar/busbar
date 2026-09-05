// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-llm/src/synth_rng.rs`.

use super::*;

#[test]
fn fills_exact_len_and_advances() {
    // Two draws that together exceed a fresh pool are still fully served (spans a refill).
    let mut a = [0u8; 30];
    let mut b = [0u8; 30];
    assert!(fill_entropy(&mut a));
    assert!(fill_entropy(&mut b));
    // Astronomically unlikely to be all-zero or identical if real entropy was served.
    assert!(a.iter().any(|&x| x != 0));
    assert!(a != b);
}

#[test]
fn draw_larger_than_pool_spans_refills() {
    let mut big = vec![0u8; POOL_BYTES * 2 + 7];
    assert!(fill_entropy(&mut big));
    assert!(big.iter().any(|&x| x != 0));
}

#[test]
fn many_small_draws_stay_distinct() {
    // Exhaust well past one pool block to exercise the refill path under repeated small draws.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..500 {
        let mut t = [0u8; 24];
        assert!(fill_entropy(&mut t));
        seen.insert(t);
    }
    // 500 distinct 24-byte draws — no collisions from a stuck/rewound pointer.
    assert_eq!(seen.len(), 500);
}
