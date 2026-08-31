// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-timing/src/lib.rs` (feature-off zero-cost proof).

//! Method: this test crate is built in the DEFAULT (feature-off) configuration. The proof has
//! two legs, both machine-checked here:
//!   1. `Timer` is a ZERO-SIZED TYPE: `size_of::<Timer>() == 0`. A ZST guard with an empty
//!      `Drop` occupies no stack and its drop lowers to nothing.
//!   2. The `timeit!` macro expands to `()`. `instrumented()` and `bare()` below are identical
//!      byte-for-byte except for the `timeit!` line; because that line IS `()`, the two functions
//!      have the same value and (being `#[inline(never)]`) the same emitted body. The
//!      `assert_eq!` fixes the observable-equivalence half; the codegen-equivalence half is the
//!      documented `cargo asm` check in the crate report.
use super::*;

#[inline(never)]
fn instrumented(x: u64) -> u64 {
    let _t = timeit!("zc_probe");
    x.wrapping_mul(2654435761).rotate_left(13)
}

#[inline(never)]
fn bare(x: u64) -> u64 {
    x.wrapping_mul(2654435761).rotate_left(13)
}

#[test]
fn timer_off_is_zero_sized() {
    assert_eq!(
        core::mem::size_of::<Timer>(),
        0,
        "feature-off Timer must be a ZST"
    );
}

#[test]
fn timeit_off_expands_to_unit() {
    // Binding `timeit!(..)` yields `()` — the macro produced a unit value, not a guard.
    let t: () = timeit!("expands_to_unit");
    assert_eq!(t, ());
}

#[test]
fn instrumented_matches_bare() {
    for x in [0u64, 1, 42, u64::MAX, 1 << 40] {
        assert_eq!(
            instrumented(x),
            bare(x),
            "instrumentation changed the result"
        );
    }
}

#[test]
fn off_entry_points_are_noops() {
    // These compile and do nothing; the point is they exist with the same signatures as the
    // feature-on build so call sites are source-identical across the feature.
    record("noop", 123);
    let v = scope("noop", || 7);
    assert_eq!(v, 7);
    dump();
    dump_scoped();
    reset();
    assert!(!enabled());
}
