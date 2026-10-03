// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE #74 ZERO-HOT-PATH-COST WITNESS.
//!
//! Per-call binding (#74) must not tax the hot path: a `Pass`/`Grant` stays a stack value stamped
//! with one `u64` generation, and a stage's binding check is a `u64` comparison — no heap, no crypto
//! (#71). This isolated test binary installs a counting `#[global_allocator]` armed ONLY around a
//! batch of `mint_bound` + `bound_to` calls (the in-process binding hot path) and asserts the
//! allocation counter is `== 0` across it.
//!
//! The count is PER THREAD: only the measuring thread's allocations inside its own armed window are
//! counted. A process-wide counter also counted whatever the test harness's other threads (libtest's
//! main thread, a runner's bookkeeping) allocated while the window happened to be open, which is not
//! the hot path and made the witness flaky on shared CI (4 allocations seen across 1M iterations).
//! The claim proven is unchanged and exact: the thread running the hot path allocates nothing.
//!
//! RED arms, both always run: an allocation planted inside the measured loop on the measuring thread
//! is counted (the `== 0` assertion is RED-able, not vacuously green), and an allocation made by
//! another thread while the window is armed is not (the isolation the fix relies on is real).
//!
//! Run: `cargo test -p busbar-contract --test capability_binding_zero_cost -- --nocapture`

use busbar_contract::caps::{step::Meter, Admittance, CallId, Grant, KernelSeal, Pass};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

// ── the witness ──────────────────────────────────────────────────────────────────────────────

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<u64> = const { Cell::new(0) };
}

/// Count one allocation if this thread's window is armed. Const-initialised thread-locals with no
/// destructor never allocate on access; `try_with` covers a thread whose TLS is already torn down.
fn note() {
    let _ = ARMED.try_with(|a| {
        if a.get() {
            let _ = COUNT.try_with(|c| c.set(c.get() + 1));
        }
    });
}

/// `System`, counting this thread's allocations while armed.
struct CountingAlloc;

// SAFETY: every method forwards to `System` unchanged; the only addition is a thread-local counter
// bump, which allocates nothing (const-initialised, no destructor).
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: forwarded verbatim; the caller's obligations on `layout` are unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: as `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note();
        // SAFETY: forwarded verbatim; the caller's obligations on `p`/`layout` are unchanged.
        unsafe { System.realloc(p, layout, new_size) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        // SAFETY: forwarded verbatim.
        unsafe { System.dealloc(p, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// How many allocations `f` makes on THIS thread.
fn counted(f: impl FnOnce()) -> u64 {
    COUNT.with(|c| c.set(0));
    ARMED.with(|a| a.set(true));
    f();
    ARMED.with(|a| a.set(false));
    COUNT.with(Cell::get)
}

// ── the hot path ─────────────────────────────────────────────────────────────────────────────

const BATCH: usize = 1_000_000;

struct Run {
    allocs: u64,
    accepted: u64,
    rejected: u64,
    per_op_ns: f64,
}

/// The binding hot path, `BATCH` times, under the armed window. `plant` allocates once inside the
/// window, on this thread — the RED arm.
fn run_hot_path(plant: bool) -> Run {
    let seal = KernelSeal::acquire_for_kernel();
    let call_a = CallId::seal(&seal, 1);
    let call_b = CallId::seal(&seal, 2);

    let mut accepted = 0u64;
    let mut rejected = 0u64;
    let start = Instant::now();
    let allocs = counted(|| {
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
            if black_box(plant) && i == 0 {
                let v: Vec<u8> = Vec::with_capacity(32);
                black_box(&v);
            }
        }
    });
    let elapsed = start.elapsed();
    Run {
        allocs,
        accepted,
        rejected,
        per_op_ns: elapsed.as_nanos() as f64 / (BATCH as f64 * 2.0),
    }
}

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

    let run = run_hot_path(false);
    println!(
        "capability-binding zero-cost bench: {BATCH} iters, size_of Pass/Grant = {} bytes, \
         allocations under armed region = {}, {:.3} ns per mint+check",
        std::mem::size_of::<Pass<Meter>>(),
        run.allocs,
        run.per_op_ns
    );
    assert_eq!(
        run.accepted, BATCH as u64,
        "every proof matches its own call"
    );
    assert_eq!(run.rejected, 0, "no proof from call A matches call B");
    assert_eq!(
        run.allocs, 0,
        "per-call binding must not allocate on the hot path (got {})",
        run.allocs
    );
}

/// RED arm: one allocation planted in the measured loop, on the measuring thread, is caught.
#[test]
fn an_allocation_on_the_measured_thread_is_counted() {
    let run = run_hot_path(true);
    assert_eq!(run.accepted, BATCH as u64);
    assert_eq!(
        run.allocs, 1,
        "the planted allocation must be counted exactly once"
    );
}

/// Isolation: another thread allocating while the window is armed does not land in the count. This
/// is the noise a process-wide counter picked up from the harness's own threads.
#[test]
fn another_threads_allocation_inside_the_window_is_not_counted() {
    let go = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let neighbour = {
        let (go, done) = (Arc::clone(&go), Arc::clone(&done));
        std::thread::spawn(move || {
            while !go.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            let v: Vec<u8> = Vec::with_capacity(64);
            black_box(&v);
            drop(v);
            done.store(true, Ordering::Release);
        })
    };
    // Atomics only inside the window: the handshake itself allocates nothing on this thread.
    let allocs = counted(|| {
        go.store(true, Ordering::Release);
        while !done.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
    });
    neighbour.join().expect("neighbour thread");
    assert_eq!(
        allocs, 0,
        "a neighbour thread's allocation must not count against the measured thread"
    );
}
