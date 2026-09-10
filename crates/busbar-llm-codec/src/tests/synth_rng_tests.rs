// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-llm-codec/src/synth_rng.rs`.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// THE OS AS THE SOURCE, FOR THIS TEST BINARY ONLY. `getrandom` is a DEV-dependency of this crate:
/// the shipped codec carries no entropy source, and `installed_source` reaches this function only
/// under `cfg(test)`. It is the same one-line adapter the engine half's `install_os_entropy` installs in
/// production, so what the suites below exercise is the pool over the exact bytes the binary sees.
pub(super) fn os_entropy_for_tests(out: &mut [u8]) -> bool {
    getrandom::fill(out).is_ok()
}

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

// ── THE SEAM: the pool over an explicit source ─────────────────────────────────────────────────
//
// `install` is process-wide and set-once, so the seam's contract is exercised on a private pool
// with the source passed in — the same `EntropyPool::fill` the thread-local calls — rather than by
// installing throw-away sources into the one static every other test in this binary shares.

/// A source that never fills: the pool must report entropy-unavailable and serve nothing.
fn refusing_source(_out: &mut [u8]) -> bool {
    false
}

/// A source that fills with a fixed byte and counts its calls, so the amortisation is observable.
static COUNTING_CALLS: AtomicUsize = AtomicUsize::new(0);
fn counting_source(out: &mut [u8]) -> bool {
    COUNTING_CALLS.fetch_add(1, Ordering::SeqCst);
    out.fill(0xA5);
    true
}

#[test]
fn no_source_installed_is_entropy_unavailable() {
    let mut pool = EntropyPool::new();
    let mut out = [0x11u8; 16];
    assert!(!pool.fill(None, &mut out));
    // Drained and unhealthy: nothing was served, the buffer is the caller's to discard.
    assert!(!pool.healthy);
    assert_eq!(pool.pos, POOL_BYTES);
}

#[test]
fn a_source_that_refuses_is_entropy_unavailable_and_serves_no_stale_bytes() {
    let mut pool = EntropyPool::new();
    // A healthy fill first, so the buffer holds real bytes a broken refill must not re-serve.
    let mut warm = [0u8; POOL_BYTES];
    assert!(pool.fill(Some(counting_source), &mut warm));
    assert_eq!(pool.pos, POOL_BYTES);
    let mut out = [0u8; 8];
    assert!(!pool.fill(Some(refusing_source), &mut out));
    assert!(!pool.healthy);
    assert_eq!(pool.pos, POOL_BYTES);
}

#[test]
fn the_source_is_called_once_per_pool_block() {
    let mut pool = EntropyPool::new();
    let before = COUNTING_CALLS.load(Ordering::SeqCst);
    // 100 draws of 30 bytes = 3000 bytes: within one block, so exactly ONE source call.
    for _ in 0..100 {
        let mut t = [0u8; 30];
        assert!(pool.fill(Some(counting_source), &mut t));
        assert!(t.iter().all(|&b| b == 0xA5));
    }
    assert_eq!(COUNTING_CALLS.load(Ordering::SeqCst) - before, 1);
    // The 4097th byte crosses the block: a second call, and not before.
    let mut rest = vec![0u8; POOL_BYTES - 3000 + 1];
    assert!(pool.fill(Some(counting_source), &mut rest));
    assert_eq!(COUNTING_CALLS.load(Ordering::SeqCst) - before, 2);
}

#[test]
fn install_is_first_writer_wins_and_idempotent_for_the_same_source() {
    // Whatever the binary installed first (or nothing yet: then THIS install is the first), a
    // repeat of the same function is accepted and a different function is refused — the pool is
    // never re-pointed under a live process.
    let first = install(os_entropy_for_tests);
    let installed = SOURCE
        .get()
        .copied()
        .expect("a source is installed after install()");
    assert_eq!(
        first,
        std::ptr::fn_addr_eq(installed, os_entropy_for_tests as EntropySource)
    );
    assert!(install(installed));
    let other: EntropySource = if std::ptr::fn_addr_eq(installed, refusing_source as EntropySource)
    {
        counting_source
    } else {
        refusing_source
    };
    assert!(!install(other));
    assert!(std::ptr::fn_addr_eq(
        SOURCE.get().copied().expect("still installed"),
        installed
    ));
}
