// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT-PATH ALLOC INSTRUMENT — the zero-allocation witness of
//! `docs/design/BUSBAR-1.6.0.md` Part 3 §8 ("Alloc gate: `#[global_allocator]` counter =
//! 0 across the ISOLATED POD host-call batch"), owed alongside the perf instrument as part of the
//! tests/benches 8→9 rise.
//!
//! # What is measured
//!
//! The memory ABI promises "no allocation on the hot path" (THE DESIGN §11.2, §11.9): a plugin
//! crossing into the host through the host-services table ([`HostSlots`], §11.12) — the `in` by
//! pointer, the answer written into the caller's `out` — must not touch the global allocator at all.
//! This file proves it with a counting `#[global_allocator]` ([`CountingAlloc`]) that is ARMED only
//! around the isolated host-call batch (`POD_HOST_CALL_BATCH`): a batch of `clock.now` crossings
//! ([`op::CLOCK_NOW`]), each passing a `#[repr(C)]` [`ClockNowIn`] by pointer, the service writing
//! its [`ClockReading`] into the caller's buffer and its outcome back by value. The allocation
//! counter is asserted `== 0` over that region.
//!
//! Arming ONLY the batch is load-bearing: criterion itself allocates freely, so a global counter
//! that was live for the whole process would measure the harness, not the seam. `ARMED` gates the
//! count to the exact window the alloc budget names.
//!
//! The `BUSBAR_ALLOC_INJECT` environment knob allocates inside the armed region on purpose, which is
//! how the `== 0` assertion is proven RED-able rather than vacuously green.
//!
//! The instrument is ARMED against the table's own construction — the `#[repr(C)]` subject
//! `crates/busbar-contract/tests/layout_golden.rs` pins: an allocation-free call is allocation-free
//! wherever it is made.
//!
//! # Running it
//!
//! ```text
//! cargo bench -p busbar-kernel --bench plane_host_vtable_alloc
//! ```
//!
//! `cargo xtask gate hot-path-alloc` enforces that this instrument keeps making the alloc-budget claim; this
//! file is what measures it.

use busbar_contract::abi::host::service::{
    op, ClockNowIn, ClockReading, HostSlots, ServiceFn, ServiceHead, ServiceOut, SERVICES,
};
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};
use criterion::{criterion_group, criterion_main, Criterion};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Counts allocations ONLY while [`ARMED`], delegating to the system allocator otherwise. The window
/// is armed around the isolated host-call batch and nowhere else, so criterion's own churn is
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

/// The host service under measurement: `clock.now` on the one service call shape, reading its
/// [`ClockNowIn`] by pointer and writing the [`ClockReading`] into the caller's buffer. It allocates
/// nothing — the whole point.
extern "C" fn host_clock_now(
    _ctx: HostCtx,
    input: *const c_void,
    _out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: the batch below hands a live `ClockNowIn` whose `reading` addresses a live
    // `ClockReading`. Writing scalar fields crosses no allocation.
    unsafe {
        let input = &*input.cast::<ClockNowIn>();
        (*input.reading).wall_ns = 42;
        (*input.reading).mono_ns = 7;
    }
    RawOutcome::of(Outcome::Ready)
}

/// A [`HostSlots`] table with `clock_now` populated and every other slot `None` — see the perf
/// instrument's `armed_vtable` for the soundness of the zeroed construction.
fn armed_vtable() -> HostSlots {
    // SAFETY: every field of `HostSlots` is valid all-zero (an integer header; `Option<extern "C"
    // fn>` slots whose `None` is the null-pointer niche).
    let mut vt: HostSlots = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    vt.size = std::mem::size_of::<HostSlots>() as u32;
    vt.slots = SERVICES;
    vt.clock_now = Some(host_clock_now as ServiceFn);
    vt
}

/// The `clock.now` call's `in`, the reading it names and the host's `out`, built once before the
/// armed window so the batch itself builds nothing.
struct ClockCall {
    reading: ClockReading,
    input: ClockNowIn,
    out: ServiceOut,
}

fn clock_call() -> Box<ClockCall> {
    // SAFETY: `ClockReading` and `ServiceOut` are integers, a null-able `AbiStr` and padding, all
    // valid zeroed; the `in` is written whole below.
    let mut call = Box::new(ClockCall {
        reading: unsafe { std::mem::MaybeUninit::zeroed().assume_init() },
        input: ClockNowIn {
            head: ServiceHead {
                size: std::mem::size_of::<ClockNowIn>() as u32,
                op: op::CLOCK_NOW,
                handle: CompletionHandle {
                    ticket: Ticket::NONE,
                    seq: 0,
                    _reserved: 0,
                },
            },
            reading: std::ptr::null_mut(),
        },
        out: unsafe { std::mem::MaybeUninit::zeroed().assume_init() },
    });
    call.input.reading = std::ptr::addr_of_mut!(call.reading);
    call
}

/// THE ALLOC-BUDGET ASSERTION — zero allocations across the isolated POD host-call batch.
fn assert_zero_alloc_pod_batch() {
    let null: HostCtx = HostCtx::NONE;
    let vt = armed_vtable();
    let mut call = clock_call();
    let input: *const c_void = std::ptr::addr_of!(call.input).cast();
    let out: *mut ServiceOut = std::ptr::addr_of_mut!(call.out);
    let inject = std::env::var_os("BUSBAR_ALLOC_INJECT").is_some();

    let clock_now = vt.clock_now.expect("clock_now slot is armed");
    let mut sink: u64 = 0;

    // POD_HOST_CALL_BATCH: arm the counter, cross the seam N times, disarm. Nothing but the crossing
    // runs inside the armed window.
    ALLOC_COUNT.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    for _ in 0..100_000u32 {
        let answered = clock_now(null, black_box(input), black_box(out));
        sink = sink.wrapping_add(u64::from(answered.0));
        if inject {
            // The RED shape: an allocation inside the isolated batch, which the budget forbids.
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
         allocation(s); the budget requires 0 (no allocation on the host-table crossing)."
    );
}

fn hot_path_alloc(c: &mut Criterion) {
    let null: HostCtx = HostCtx::NONE;
    let vt = armed_vtable();
    let mut call = clock_call();
    let input: *const c_void = std::ptr::addr_of!(call.input).cast();
    let out: *mut ServiceOut = std::ptr::addr_of_mut!(call.out);
    let clock_now = vt.clock_now.expect("clock_now slot is armed");

    c.bench_function("POD_HOST_CALL_BATCH", |b| {
        b.iter(|| u64::from(black_box(clock_now(null, black_box(input), black_box(out))).0));
    });

    // The gating assertion runs once per invocation: any allocation in the armed window takes the
    // process down non-zero.
    assert_zero_alloc_pod_batch();
}

criterion_group!(plane_host_vtable_alloc, hot_path_alloc);
criterion_main!(plane_host_vtable_alloc);
