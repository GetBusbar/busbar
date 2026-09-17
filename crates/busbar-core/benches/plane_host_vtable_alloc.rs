// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT-PATH ALLOC INSTRUMENT — the zero-allocation witness of
//! `docs/design/1.6.0-plane-extraction-LOCKED.md` §8 ("Alloc gate: `#[global_allocator]` counter =
//! 0 across the ISOLATED POD host-call batch"). It is owed alongside the perf instrument.
//!
//! # What is measured
//!
//! The HOT tier promises "zero alloc / zero serde on the call": a plane crossing into the host
//! through the [`PlaneHostVtable`] slots — POD args by pointer, results by value — must not touch the
//! global allocator at all. This file proves it with a counting `#[global_allocator]`
//! ([`CountingAlloc`]) that is ARMED only around the isolated POD host-call batch
//! (`POD_HOST_CALL_BATCH`): a batch of `govern_admit` crossings, each passing a `#[repr(C)]`
//! [`Facts`] POD by pointer and reading a [`Decision`] back by value. The allocation counter is
//! asserted `== 0` over that region.
//!
//! Arming ONLY the batch is load-bearing: criterion itself allocates freely, so a global counter
//! that was live for the whole process would measure the harness, not the seam. `ARMED` gates the
//! count to the exact isolated-batch window measured.
//!
//! The `BUSBAR_ALLOC_INJECT` environment knob allocates inside the armed region on purpose, which is
//! how the `== 0` assertion is proven RED-able rather than vacuously green.
//!
//! # THE PENDING-RIDER DEPENDENCY
//!
//! Like the perf instrument, this measures the vtable's own construction — the `#[repr(C)]` subject
//! `crates/busbar-plugin/tests/layout_golden.rs` pins — because [`PlaneHostVtable`] has no
//! production rider yet (the keystone loop-unification in `crates/busbar/src/root/kernel.rs` +
//! `main.rs`, reserved for the keystone wave). When the rider lands, the batch binds to the
//! production crossing unchanged: an allocation-free POD call is allocation-free wherever it is made.
//!
//! # Running it
//!
//! ```text
//! cargo bench -p busbar-core --bench plane_host_vtable_alloc
//! ```
//!
//! `cargo xtask gate hot-path-alloc` enforces that this instrument keeps making the zero-allocation claim; this
//! file is what measures it.

use busbar_plugin::hot::host::{GovernAdmitFn, HostCtx, PlaneHostVtable};
use busbar_plugin::hot::pod::{Decision, Facts};
use busbar_plugin::AbiPreamble;
use criterion::{criterion_group, criterion_main, Criterion};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Counts allocations ONLY while [`ARMED`], delegating to the system allocator otherwise. The window
/// is armed around the isolated POD host-call batch and nowhere else, so criterion's own churn is
/// never counted.
struct CountingAlloc;

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System`, the process's real allocator; the only added behaviour
// is a relaxed counter bump when the armed flag is set, which allocates nothing itself.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// The host capability under measurement: an `extern "C-unwind"` admit that reads the POD [`Facts`]
/// by pointer and returns a [`Decision`] by value. It allocates nothing — the whole point.
extern "C-unwind" fn host_govern_admit(_host: HostCtx, facts: *const Facts) -> Decision {
    // SAFETY: the batch below hands a live `&Facts`. Reading a scalar field crosses no allocation.
    let tokens = unsafe { (*facts).tokens };
    if tokens > 1_000_000 {
        Decision::Throttle
    } else {
        Decision::Admit
    }
}

/// A [`PlaneHostVtable`] with `govern_admit` populated and every other slot `None` — see the perf
/// instrument's `armed_vtable` for the soundness of the zeroed construction.
fn armed_vtable() -> PlaneHostVtable {
    // SAFETY: every field of `PlaneHostVtable` is valid all-zero (integer/`AbiPreamble` header;
    // `Option<extern "C-unwind" fn>` slots whose `None` is the null-pointer niche).
    let mut vt: PlaneHostVtable = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    vt.abi = AbiPreamble::CURRENT;
    vt.size = std::mem::size_of::<PlaneHostVtable>() as u32;
    vt.version = 1;
    vt.govern_admit = Some(host_govern_admit as GovernAdmitFn);
    vt
}

/// A zeroed `#[repr(C)]` [`Facts`], with the sized-struct header set. All-zero is a valid `Facts`:
/// every field is a scalar or a borrowed pointer the host fn above never dereferences.
fn pod_facts() -> Facts {
    // SAFETY: `Facts` is a `#[repr(C)]` POD of scalars and borrowed raw pointers; all-zero is a
    // valid, fully-initialised value (null borrowed pointers the measured call never reads).
    let mut f: Facts = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    f.size = std::mem::size_of::<Facts>() as u32;
    f.tokens = 42;
    f
}

/// THE ALLOC ASSERTION — zero allocations across the isolated POD host-call batch.
fn assert_zero_alloc_pod_batch() {
    let null: HostCtx = std::ptr::null_mut();
    let vt = armed_vtable();
    let facts = pod_facts();
    let facts_ptr: *const Facts = &facts;
    let inject = std::env::var_os("BUSBAR_ALLOC_INJECT").is_some();

    let admit = vt.govern_admit.expect("govern_admit slot is armed");
    let mut sink: u64 = 0;

    // POD_HOST_CALL_BATCH: arm the counter, cross the seam N times, disarm. Nothing but the crossing
    // runs inside the armed window.
    ALLOC_COUNT.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    for _ in 0..100_000u32 {
        let decision = admit(null, black_box(facts_ptr));
        sink = sink.wrapping_add(decision as u64);
        if inject {
            // The RED shape: an allocation inside the isolated batch, which the zero-alloc contract forbids.
            let v: Vec<u8> = Vec::with_capacity(16);
            sink = sink.wrapping_add(black_box(v).capacity() as u64);
        }
    }
    ARMED.store(false, Ordering::Relaxed);
    black_box(sink);

    let allocations = ALLOC_COUNT.load(Ordering::Relaxed);
    assert_eq!(
        allocations, 0,
        "HOT-PATH ALLOC: the isolated POD host-call batch performed {allocations} global \
         allocation(s); the HOT-tier contract requires 0 (zero alloc / zero serde on the crossing)."
    );
}

fn hot_path_alloc(c: &mut Criterion) {
    let null: HostCtx = std::ptr::null_mut();
    let vt = armed_vtable();
    let facts = pod_facts();
    let facts_ptr: *const Facts = &facts;
    let admit = vt.govern_admit.expect("govern_admit slot is armed");

    c.bench_function("POD_HOST_CALL_BATCH", |b| {
        b.iter(|| black_box(admit(null, black_box(facts_ptr))) as u64);
    });

    // The gating assertion runs once per invocation: any allocation in the armed window takes the
    // process down non-zero.
    assert_zero_alloc_pod_batch();
}

criterion_group!(plane_host_vtable_alloc, hot_path_alloc);
criterion_main!(plane_host_vtable_alloc);
