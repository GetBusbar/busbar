// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What one unit costs the process allocator on the Teller path.
//!
//! ARCHITECTURE.md's measured-invariants table names this: *heap allocations per one-shot unit
//! outside the arena, scope the process allocator on the Teller path*, target **0**, on the ratchet
//! `measured 87, gated 107 → ≤ 20 at M4 → 0 at Phase 0.5 exit`. Until now the only instrument that
//! carried that number measured `busbar-llm`'s forward path. Nothing measured the kernel's own
//! `exit()`, which every unit that ends runs exactly once — so the invariant's stated scope was
//! wider than the instrument enforcing it, and an allocation added here was invisible to the
//! ratchet the design rests the number on. A ceiling nothing measures has been abolished rather
//! than met; this is the measurement.
//!
//! Its own test binary, because the instrument is a `#[global_allocator]` and an allocator belongs
//! to the whole binary it is installed in. An integration test target IS its own binary, so nothing
//! here reaches the library or any other test.
//!
//! The counter is thread-local rather than global, so two cases can run at once without reading
//! each other's work — the same shape `busbar-voice-codec`'s gate uses, and the reason this file is
//! allowed more than one case where `busbar-contract`'s process-global one is not.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use busbar_caps::{Canary, Outcome};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{exit, run_unit, AccrualMeter, Kernel, Run};

use common::{cell, ctx, TestUnits};

thread_local! {
    /// Allocations made by THIS thread since the counter was last read.
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

/// The system allocator, counting.
struct Counting;

// SAFETY: every call is forwarded verbatim to the system allocator; the counter is a thread-local
// `Cell` of a plain integer, touched only on the allocating thread, and never reads or writes the
// memory being handed out.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// How many allocations one call made on this thread.
fn allocations_of(f: impl FnOnce()) -> u64 {
    let before = ALLOCS.with(Cell::get);
    f();
    ALLOCS.with(Cell::get) - before
}

/// What one whole one-shot unit costs today, measured rather than hoped.
///
/// A bare number with "the design says 0" beside it is a gate abolished rather than met: it
/// green-lights that number forever. So what the number is MADE of is written down, and so is the
/// step that removes each part, exactly as `FORWARD_PASSTHROUGH_MAX_ALLOCS` does for the forward
/// path.
///
/// What is known about this figure, and what is not:
///
/// * **The kernel's own share includes the one-line `Vec<UsageLine>` the exit path settles from**,
///   which is what put this instrument here. Removing it means `Usage` holding its lines inline,
///   which is a `busbar-caps` surface change against a ceiling with nineteen lines left, so it is
///   the next ratchet step and not this one.
/// * **The boxed leg the synchronous entry point awaits** is one more: `run_unit` pins a
///   `Ready` future so a plane that answers in place needs no runtime.
/// * **`Units::verify` hands back a `Vec<VerifiedDestination>`** by signature, so the ABI buys one
///   per unit until it hands back a bounded list into the arena.
/// * **The rest is the test door's own bookkeeping** — it records the step it was called at and
///   clones its evidence — and separating the fixture's share from the kernel's is what the next
///   step down has to do first. The number is honest about being an upper bound on the kernel's
///   cost rather than a measurement of it.
///
/// It moves DOWN only. The target the design states is 0.
const ONE_SHOT_UNIT_MAX_ALLOCS: u64 = 21;

/// What the exit path alone costs — the one function every unit that ends runs, whatever its end.
///
/// Measured on its own as well as inside the whole unit, because the whole-unit number moves with
/// whatever door the fixture uses and this one barely does: it is the kernel's own settle, and one
/// of these three is the usage line the finding named.
const EXIT_MAX_ALLOCS: u64 = 3;

#[test]
fn one_one_shot_unit_stays_within_the_ratchet() {
    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let cell = cell(&kernel);
    let context = ctx(1);

    let allocations = allocations_of(|| {
        let ended = run_unit(
            &kernel,
            &units,
            &context,
            Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
            },
        );
        drop(ended);
    });

    assert!(
        allocations <= ONE_SHOT_UNIT_MAX_ALLOCS,
        "one one-shot unit allocated {allocations} times, over the ratchet of \
         {ONE_SHOT_UNIT_MAX_ALLOCS}; the target is 0 and this number only moves down"
    );
}

#[test]
fn the_exit_path_stays_within_the_ratchet() {
    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let cell = cell(&kernel);
    let context = ctx(1);

    let allocations = allocations_of(|| {
        let ended = exit(
            &kernel,
            &units,
            &context,
            Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
            },
            Outcome::Completed,
            true,
        );
        drop(ended);
    });

    assert!(
        allocations <= EXIT_MAX_ALLOCS,
        "the exit path allocated {allocations} times, over the ratchet of {EXIT_MAX_ALLOCS}; \
         the target is 0 and this number only moves down"
    );
}
