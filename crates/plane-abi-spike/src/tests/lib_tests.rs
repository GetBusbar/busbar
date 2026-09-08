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

/// THE 1 µs/CALL BUDGET, ASSERTED — the claim this whole spike exists to prove.
///
/// `benches/abi_bench.rs` computes exactly this verdict and then `eprintln!`s it as the word
/// "UNDER" or "OVER". Nothing in that file can fail a run, and `cargo bench` is not something the
/// per-push suite runs, so the headline performance claim had no instrument with teeth behind it: a
/// change that made the vtable hop cost a millisecond would have printed "OVER" into a log nobody
/// reads and shipped green.
///
/// IGNORED BY DEFAULT, AND RUN EXPLICITLY. Two reasons, both about the measurement rather than about
/// the cost of running it:
///
///  - it measures WALL CLOCK, so a test binary running it alongside a dozen other tests on a shared
///    runner measures the runner's contention as much as the call. The qa-tier segment that invokes
///    it passes `--ignored --test-threads=1`, which is the only configuration in which the number
///    means anything.
///  - the counting allocator is process-global (`lib.rs`'s `#[cfg(test)] #[global_allocator]`), so
///    the alloc arms below can only be trusted when nothing else in the process is allocating —
///    the same reason `shapes_agree_and_alloc_gate` above keeps its arms in one test.
///
/// The estimator is the MINIMUM over several rounds, not the mean: scheduler noise can only ever add
/// time, so the smallest observation is the closest to the real cost and the one least able to make
/// this test flake. The budget is a CEILING on the difference, not a pin on either measurement.
#[test]
#[ignore = "measures wall clock and uses the process-global counting allocator; run alone via the qa-tier segment (--ignored --test-threads=1)"]
fn the_vtable_hop_stays_under_the_budget_and_the_pod_paths_still_do_not_allocate() {
    /// The per-call ceiling the spike's header claims, in nanoseconds.
    const BUDGET_NS: f64 = 1000.0;
    const N: u64 = 200_000;
    const ROUNDS: usize = 5;

    let (name, tokens, budget, tenant, prio, flags) = sample();
    let g = Facts::new(tokens, budget, tenant, prio, flags, &name);
    let vt = &PlaneHostVtable::IN_CORE;

    let per_call = |f: &dyn Fn()| -> f64 {
        // A warm round, discarded: the first pass pays for cold branch predictors and cold icache,
        // which is not what the budget is about.
        for _ in 0..N {
            f();
        }
        (0..ROUNDS)
            .map(|_| {
                let t = std::time::Instant::now();
                for _ in 0..N {
                    f();
                }
                t.elapsed().as_nanos() as f64 / N as f64
            })
            .fold(f64::INFINITY, f64::min)
    };

    let direct_ns = per_call(&|| {
        black_box(govern_admit_direct(black_box(&g)));
    });
    let vtable_ns = per_call(&|| {
        black_box((vt.govern_admit)(black_box(&*g as *const Facts)));
    });
    let overhead_ns = vtable_ns - direct_ns;

    assert!(
        overhead_ns < BUDGET_NS,
        "the vtable fn-pointer hop cost {overhead_ns:+.3} ns/call over the in-core direct call, \
         which is OVER the {BUDGET_NS} ns budget this spike exists to prove \
         (direct {direct_ns:.3} ns, vtable {vtable_ns:.3} ns, min of {ROUNDS} rounds of {N})"
    );

    // A positive control on the measurement itself: a per-call figure of zero would satisfy any
    // ceiling, so the timer has to have measured something.
    assert!(
        direct_ns > 0.0 && vtable_ns > 0.0,
        "the measurement is degenerate (direct {direct_ns} ns, vtable {vtable_ns} ns) — a budget \
         compared against nothing is not a budget"
    );

    // ── THE ALLOC-GATE, over the same two shapes the bench prints PASS/FAIL for. ──
    const M: u64 = 100_000;
    CountingAlloc::reset();
    for _ in 0..M {
        black_box(govern_admit_direct(black_box(&g)));
    }
    let direct_allocs = CountingAlloc::count();
    assert_eq!(
        direct_allocs, 0,
        "the direct POD call must allocate 0 across {M} calls, saw {direct_allocs}"
    );

    CountingAlloc::reset();
    for _ in 0..M {
        black_box((vt.govern_admit)(black_box(&*g as *const Facts)));
    }
    let vtable_allocs = CountingAlloc::count();
    assert_eq!(
        vtable_allocs, 0,
        "the vtable POD call must allocate 0 across {M} calls, saw {vtable_allocs} — the whole \
         point of passing repr(C) POD by pointer is that the hop is allocation-free"
    );

    // And the shipped anti-pattern, so the gate is known to be able to SEE an allocation rather
    // than reporting zero because the counter is not installed.
    let enc = encode_facts(&g);
    CountingAlloc::reset();
    for _ in 0..M {
        black_box(govern_admit_vec(black_box(&enc)).unwrap());
    }
    let vec_allocs = CountingAlloc::count();
    assert_eq!(
        vec_allocs, M,
        "the vec-returning shape must allocate once per call: expected {M}, saw {vec_allocs}"
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
