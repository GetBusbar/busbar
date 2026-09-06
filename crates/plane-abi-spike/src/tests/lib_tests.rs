// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plane-abi-spike/src/lib.rs`.

use super::*;
use std::hint::black_box;

fn sample() -> ([u8; 8], u64, u64, u64, u32, u32) {
    (*b"pool-abc", 100, 1000, 42, 7, 1)
}

/// Correctness cross-check AND the ALLOC-GATE proof, in ONE test so nothing else runs
/// concurrently — the counting allocator is process-global, so a second test allocating in
/// parallel would pollute the measured region. POD paths (a)/(b) allocate ZERO across a batch;
/// (c) allocates once per call.
#[test]
fn shapes_agree_and_alloc_gate() {
    const N: u64 = 10_000;
    let (name, tokens, budget, tenant, prio, flags) = sample();
    let g = Facts::new(tokens, budget, tenant, prio, flags, &name);
    let enc = encode_facts(&g); // pre-encode OUTSIDE the measured region

    // Correctness: all three shapes agree.
    let a = govern_admit_direct(&g);
    let b = (PlaneHostVtable::IN_CORE.govern_admit)(&*g as *const Facts);
    let c = govern_admit_vec(&enc).unwrap();
    assert_eq!(a, b, "direct and vtable must agree");
    assert_eq!(a as u8, c[0], "direct and vec-returning must agree");

    // (a) direct — zero allocs.
    CountingAlloc::reset();
    for _ in 0..N {
        black_box(govern_admit_direct(black_box(&g)));
    }
    let a_allocs = CountingAlloc::count();
    assert_eq!(
        a_allocs, 0,
        "direct POD call must allocate 0, saw {a_allocs}"
    );

    // (b) vtable fn-pointer — zero allocs.
    let vt = &PlaneHostVtable::IN_CORE;
    CountingAlloc::reset();
    for _ in 0..N {
        black_box((vt.govern_admit)(black_box(&*g as *const Facts)));
    }
    let b_allocs = CountingAlloc::count();
    assert_eq!(
        b_allocs, 0,
        "vtable POD call must allocate 0, saw {b_allocs}"
    );

    // (c) vec-returning — exactly one alloc per call (the returned Vec).
    CountingAlloc::reset();
    for _ in 0..N {
        let out = black_box(govern_admit_vec(black_box(&enc))).unwrap();
        black_box(out);
    }
    let c_allocs = CountingAlloc::count();
    assert_eq!(
        c_allocs, N,
        "vec-returning anti-pattern must allocate once per call: expected {N}, saw {c_allocs}"
    );
}

/// A TRUNCATED request is refused, not panicked on. The serialized shape's fixed preamble runs
/// through the name-length field at bytes 40..44, so every length short of 44 must come back as an
/// error — the lengths in between are the ones a guard written against the scalar block alone lets
/// through and then indexes off the end of.
#[test]
fn a_truncated_request_is_refused_rather_than_indexed_off_the_end() {
    for len in 0..=43usize {
        assert!(
            govern_admit_vec(&vec![0u8; len]).is_err(),
            "a {len}-byte request is shorter than the fixed preamble and must be refused"
        );
    }
    // And the boundary from the other side: a well-formed request still parses.
    let (name, tokens, budget, tenant, prio, flags) = sample();
    let g = Facts::new(tokens, budget, tenant, prio, flags, &name);
    assert!(govern_admit_vec(&encode_facts(&g)).is_ok());
}
