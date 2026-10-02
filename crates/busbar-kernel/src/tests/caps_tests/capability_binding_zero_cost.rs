// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE #74 ZERO-HOT-PATH-COST WITNESS.
//!
//! Per-call binding (#74) must not tax the hot path: a `Pass`/`Grant` stays a stack value stamped
//! with one `u64` generation, and a stage's binding check is a `u64` comparison — no heap, no crypto
//! (#71). This test reads the kernel test binary's own counting `#[global_allocator]`
//! (`CountingJemalloc`, crate root), which counts PER THREAD, across a batch of `mint_bound` +
//! `bound_to` calls (the in-process binding hot path) and asserts the allocation count is `== 0`
//! across it. The `BUSBAR_ALLOC_INJECT` knob allocates inside the measured region on purpose, so
//! the `== 0` assertion is proven RED-able rather than vacuously green.
//!
//! Moved here from `busbar-contract/tests/capability_binding_zero_cost.rs`, because the batch mints
//! and a token constructor is spelled only inside the kernel (construction `token-sealed`). The
//! contract's isolated binary carried its own counting allocator armed by a process-wide flag; this
//! binary already has one, and two `#[global_allocator]`s cannot link, so the count is the kernel's
//! per-thread one — which no concurrently running test can inflate.
//!
//! Run: `cargo test -p busbar-kernel --lib caps_tests::capability_binding_zero_cost -- --nocapture`

use crate::CountingJemalloc;
use busbar_contract::caps::{step::Meter, Admittance, CallId, Grant, KernelSeal, Pass};
use std::hint::black_box;
use std::time::Instant;

const BATCH: usize = 1_000_000;

#[test]
fn per_call_binding_allocates_nothing_on_the_hot_path() {
    // The proofs are one machine word: a stamp, not a heap handle.
    assert_eq!(
        std::mem::size_of::<Pass<Meter>>(),
        std::mem::size_of::<u64>(),
        "a Pass must be a single u64 stamp, no heap"
    );
    assert_eq!(
        std::mem::size_of::<Grant<Admittance>>(),
        std::mem::size_of::<u64>(),
        "a Grant must be a single u64 stamp, no heap"
    );

    let seal = KernelSeal::acquire_for_kernel();
    let call_a = CallId::seal(&seal, 1);
    let call_b = CallId::seal(&seal, 2);

    // The optional injector proves the counter fires: an allocation in the measured window is caught.
    let inject = std::env::var("BUSBAR_ALLOC_INJECT").is_ok();

    let mut accepted = 0u64;
    let mut rejected = 0u64;

    CountingJemalloc::reset();
    let start = Instant::now();
    for i in 0..BATCH {
        let pass: Pass<Meter> = Pass::mint_bound(&seal, call_a);
        let door: Grant<Admittance> = Grant::<Admittance>::mint_bound(&seal, call_a);
        // Accepted under its own call, rejected under another — the whole of the hot-path check.
        if black_box(pass.bound_to(call_a)) {
            accepted += 1;
        }
        if black_box(door.bound_to(call_b)) {
            rejected += 1;
        }
        if inject && i == 0 {
            // A single heap touch inside the measured region, to prove the counter is live.
            let v: Vec<u8> = Vec::with_capacity(32);
            black_box(&v);
        }
    }
    let elapsed = start.elapsed();
    let allocs = CountingJemalloc::count();
    let per_op_ns = elapsed.as_nanos() as f64 / (BATCH as f64 * 2.0);
    println!(
        "capability-binding zero-cost bench: {BATCH} iters, size_of Pass/Grant = {} bytes, \
         allocations in the measured region = {allocs}, {per_op_ns:.3} ns per mint+check",
        std::mem::size_of::<Pass<Meter>>()
    );
    assert_eq!(accepted, BATCH as u64, "every proof matches its own call");
    assert_eq!(rejected, 0, "no proof from call A matches call B");

    if inject {
        assert!(allocs > 0, "injector proves the counter is live");
    } else {
        assert_eq!(
            allocs, 0,
            "per-call binding must not allocate on the hot path (got {allocs})"
        );
    }
}
