// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-llm/src/codec/synth_rng.rs`.

use super::*;

#[test]
fn fills_exact_len_and_advances() {
    let mut a = [0u8; 30];
    let mut b = [0u8; 30];
    assert!(fill_entropy(crate::codec::test_host::HOST, &mut a));
    assert!(fill_entropy(crate::codec::test_host::HOST, &mut b));
    // Astronomically unlikely to be all-zero or identical if real entropy was served.
    assert!(a.iter().any(|&x| x != 0));
    assert!(a != b);
}

#[test]
fn a_large_draw_is_served_whole() {
    let mut big = vec![0u8; 8199];
    assert!(fill_entropy(crate::codec::test_host::HOST, &mut big));
    assert!(big.iter().any(|&x| x != 0));
}

#[test]
fn many_small_draws_stay_distinct() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..500 {
        let mut t = [0u8; 24];
        assert!(fill_entropy(crate::codec::test_host::HOST, &mut t));
        seen.insert(t);
    }
    // 500 distinct 24-byte draws — no collisions from a stuck or rewound source.
    assert_eq!(seen.len(), 500);
}

/// The plugin holds no per-thread entropy state (BUSBAR-1.6.0.md THE DESIGN §2: the one approved
/// per-thread slot is the door's log-capture slot). RED while the module kept a `thread_local!`
/// pool: its source names no thread-local.
#[test]
fn the_entropy_seam_keeps_no_thread_local_state() {
    let src = include_str!("../synth_rng.rs");
    assert!(
        !src.contains(concat!("thread", "_local!")),
        "synth_rng must not keep per-thread state"
    );
}
