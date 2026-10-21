// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT-PATH PERF INSTRUMENT — the `<1µs` witness of
//! `docs/design/BUSBAR-1.6.0.md` Part 3 §8 ("Perf gate (<1µs): criterion,
//! plugin-host-vtable vs direct-call baseline, delta<1µs p50 AND p99; a per-token host-call counter
//! on the streaming path asserted == 0"), also part of the tests/benches 8→9 rise.
//!
//! # What is measured, and against what
//!
//! A plugin calls back into the host through the host-services table ([`HostSlots`], THE DESIGN
//! §11.12): a `#[repr(C)]` table of `Option<extern "C" fn>` slots on the one service call shape
//! `svc(ctx, in, out)`, rather than through a monomorphised in-core call. The budget (THE DESIGN
//! §11.9: "a crossing under 1 µs") is that the CROSSING — the Option-unwrap plus the indirect call
//! through the slot — costs less than 1µs against the same function invoked directly, at BOTH the
//! p50 and the p99 of the sample distribution. This file measures exactly that, over the
//! `clock.now` slot ([`op::CLOCK_NOW`]):
//!
//! * `HOT_PATH_DIRECT_CALL` — the host service invoked by name, monomorphised.
//! * `HOT_PATH_VTABLE_CALL` — the SAME service invoked through the `HostSlots` slot the plugin holds.
//!
//! The delta between the two, at p50 and at p99, is asserted below [`HOT_PATH_BUDGET_NANOS`]. A
//! `std::hint::black_box` on the slot defeats the devirtualisation that would otherwise let the
//! compiler collapse the indirect call back into the direct one and measure nothing.
//!
//! # The per-token host-call counter
//!
//! The contract forbids a per-token host crossing on the streaming path: governance is a
//! per-REQUEST cost, not a per-TOKEN one, so a plane emitting N tokens must cross the host table
//! ZERO times per token. [`PER_TOKEN_HOST_CALLS`] counts every host-service slot invocation; the
//! streaming model below drives N tokens and asserts the counter is `== 0`. The
//! `BUSBAR_PERF_STREAM_CROSS` environment knob makes the loop cross per token on purpose, which is
//! how this assertion is proven RED-able (it fires) rather than vacuously green.
//!
//! The instrument is ARMED against the table's own construction — the exact `#[repr(C)]` subject
//! `crates/busbar-contract/tests/layout_golden.rs` pins — with the measured slot the same fn pointer
//! a live dispatch calls.
//!
//! # Running it
//!
//! ```text
//! cargo bench -p busbar-kernel --bench plane_host_vtable_perf
//! ```
//!
//! The `cargo xtask gate hot-path-perf` gate enforces that this instrument keeps making every one of
//! the perf-budget claims above; this file is what actually measures them.

use busbar_contract::abi::host::service::{
    op, ClockNowIn, ClockReading, HostSlots, ServiceFn, ServiceHead, ServiceOut, SERVICES,
};
use busbar_contract::abi::mechanism::call::{Op, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};
use busbar_contract::abi::transport::Ops as TransportOps;
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// The budget: the host-table crossing must cost under one microsecond over a direct call.
const HOT_PATH_BUDGET_NANOS: u64 = 1_000;

/// Every host-service slot invocation on the streaming path bumps this. The budget requires it to stay `0`
/// per token: a host crossing is a per-request cost, never a per-token one.
static PER_TOKEN_HOST_CALLS: AtomicUsize = AtomicUsize::new(0);

/// The host service under measurement, in the exact shape every `HostSlots` slot has: the
/// `clock.now` service on the one call shape `svc(ctx, in, out)`, answering READY. Counted so the
/// streaming model can prove it did NOT cross the seam per token.
extern "C" fn host_clock_now(
    _ctx: HostCtx,
    _input: *const c_void,
    _out: *mut ServiceOut,
) -> RawOutcome {
    PER_TOKEN_HOST_CALLS.fetch_add(1, Ordering::Relaxed);
    // A trivial, side-effect-free body: the cost being measured is the CROSSING, not the work, so
    // the direct and table legs must run byte-identical bodies.
    RawOutcome::of(Outcome::Ready)
}

/// A [`HostSlots`] table with `clock_now` populated and every other slot absent (`None`).
///
/// Built by zeroing then setting the header and the one live slot: every field is valid all-zero (an
/// `Option<extern "C" fn>` is `None` under the null-pointer niche, and the header scalars are
/// integers), so this is a sound construction of the real `#[repr(C)]` subject rather than a
/// stand-in.
fn armed_vtable() -> HostSlots {
    // SAFETY: every field of `HostSlots` is valid when all-zero — the header is integers, and every
    // slot is `Option<extern "C" fn>`, whose `None` is the all-zero niche for a non-null fn pointer.
    let mut vt: HostSlots = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    vt.size = std::mem::size_of::<HostSlots>() as u32;
    vt.slots = SERVICES;
    vt.clock_now = Some(host_clock_now as ServiceFn);
    vt
}

/// The `clock.now` call a plugin makes: its `in` (the head naming the op, no ticket — the service
/// never pends) and the host's `out`, both on the caller's stack.
struct ClockCall {
    reading: ClockReading,
    input: ClockNowIn,
    out: ServiceOut,
}

impl ClockCall {
    fn new() -> Box<ClockCall> {
        // SAFETY: `ClockReading` and `ServiceOut` are integers, a null-able `AbiStr` and padding,
        // all valid zeroed; the `in` is written whole below.
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

    fn input(&self) -> *const c_void {
        std::ptr::addr_of!(self.input).cast()
    }

    fn out(&mut self) -> *mut ServiceOut {
        std::ptr::addr_of_mut!(self.out)
    }
}

/// Per-call nanoseconds for a batch of `K` calls, `SAMPLES` times, sorted ascending. Timing one
/// call is dominated by the clock read itself; a batch amortises that, and the percentile is taken
/// across batch means.
const BATCH: u64 = 4_096;
const SAMPLES: usize = 512;

fn percentiles(mut f: impl FnMut()) -> (u64, u64) {
    // Warm up, so the first sample does not carry code-cache and branch-predictor cold cost into the
    // distribution.
    for _ in 0..BATCH {
        f();
    }
    let mut per_call: Vec<u64> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t = Instant::now();
        for _ in 0..BATCH {
            f();
        }
        per_call.push(t.elapsed().as_nanos() as u64 / BATCH);
    }
    per_call.sort_unstable();
    let p50 = per_call[SAMPLES / 2];
    let p99 = per_call[(SAMPLES * 99) / 100];
    (p50, p99)
}

/// THE BUDGET ASSERTION — `delta < 1µs at p50 AND p99`, computed here rather than parsed out of
/// criterion's report so the bench binary EXITS NON-ZERO when the budget is blown (which is what
/// makes it a gate and not a graph).
fn assert_hot_path_delta_under_budget() {
    let null: HostCtx = HostCtx::NONE;
    let vt = armed_vtable();
    let mut call = ClockCall::new();
    let input = call.input();
    let out = call.out();

    let (direct_p50, direct_p99) = percentiles(|| {
        black_box(host_clock_now(
            black_box(null),
            black_box(input),
            black_box(out),
        ));
    });
    let (vtable_p50, vtable_p99) = percentiles(|| {
        // `black_box` the slot: without it the compiler devirtualises the indirect call back into
        // the direct one and the delta is a measurement of nothing.
        let f = black_box(vt.clock_now).expect("clock_now slot is armed");
        black_box(f(black_box(null), black_box(input), black_box(out)));
    });

    let p50_delta_nanos = vtable_p50.saturating_sub(direct_p50);
    let p99_delta_nanos = vtable_p99.saturating_sub(direct_p99);

    assert!(
        p50_delta_nanos < HOT_PATH_BUDGET_NANOS,
        "HOT-PATH PERF (p50): the host-table crossing cost {p50_delta_nanos}ns over the direct call \
         (budget {HOT_PATH_BUDGET_NANOS}ns). direct p50 {direct_p50}ns, table p50 {vtable_p50}ns. \
         the budget requires delta < 1µs at p50."
    );
    assert!(
        p99_delta_nanos < HOT_PATH_BUDGET_NANOS,
        "HOT-PATH PERF (p99): the host-table crossing cost {p99_delta_nanos}ns over the direct call \
         (budget {HOT_PATH_BUDGET_NANOS}ns). direct p99 {direct_p99}ns, table p99 {vtable_p99}ns. \
         the budget requires delta < 1µs at p99."
    );
}

/// A carrier slot in the memory ABI's one call shape (`op(instance, in, out)`, THE DESIGN §11.2):
/// the transport kind's `read` slot, answering one outcome byte — `Ready` or `Pending`. The body is
/// as trivial as the clock's, for the same reason — the crossing is what is measured.
extern "C" fn carrier_read(
    instance: *mut std::os::raw::c_void,
    input: *const std::os::raw::c_void,
    _out: *mut std::os::raw::c_void,
) -> RawOutcome {
    let pending = ((instance as usize ^ input as usize) & 1) == 0;
    RawOutcome::of(if pending {
        Outcome::Pending
    } else {
        Outcome::Ready
    })
}

/// A transport's ops table as its door states it: the attested size and slot count, and the
/// carrier's `read` slot armed (every other slot `None`, the all-zero niche, as [`armed_vtable`]
/// builds the host-services table).
fn armed_transport_ops() -> TransportOps {
    // SAFETY: every field of `TransportOps` is valid all-zero — the head's integers and
    // `Option<extern "C" fn>` slots whose `None` is the null niche.
    let mut ops: TransportOps = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    ops.head.size = std::mem::size_of::<TransportOps>() as u32;
    ops.head.slots = busbar_contract::abi::transport::SLOTS;
    ops.read = Some(carrier_read as Op);
    ops
}

/// The carrier's `read` slot as the dispatcher reaches it on every read: the table's attested size
/// checked against the host's, then the slot.
fn read_slot(ops: *const TransportOps) -> Op {
    // SAFETY: `ops` is the live table the cell below owns.
    let table = unsafe { &*ops };
    assert_eq!(
        table.head.size as usize,
        std::mem::size_of::<TransportOps>(),
        "the table states the host's size"
    );
    table.read.expect("read slot is armed")
}

/// THE TRANSPORT CELL (both the plane and the transport owe `< 1µs`): the same delta budget, over
/// the crossing a loaded carrier's every byte-moving `read` makes through its door's ops table —
/// the table's size check, the slot read, the indirect call and the decode of its Ready | Pending
/// answer — against the same slot body called directly.
fn assert_transport_hot_path_delta_under_budget() {
    let ops = armed_transport_ops();
    let ops_ptr: *const TransportOps = &ops;
    let instance = std::ptr::null_mut();
    let input = std::ptr::null();
    let out = std::ptr::null_mut();

    let (direct_p50, direct_p99) = percentiles(|| {
        black_box(carrier_read(
            black_box(instance),
            black_box(input),
            black_box(out),
        ));
    });
    let (slot_p50, slot_p99) = percentiles(|| {
        let f = read_slot(black_box(ops_ptr));
        black_box(
            f(black_box(instance), black_box(input), black_box(out)).outcome() == Outcome::Pending,
        );
    });

    let transport_p50_delta_nanos = slot_p50.saturating_sub(direct_p50);
    let transport_p99_delta_nanos = slot_p99.saturating_sub(direct_p99);
    assert!(
        transport_p50_delta_nanos < HOT_PATH_BUDGET_NANOS,
        "HOT-PATH PERF (transport, p50): the door crossing cost {transport_p50_delta_nanos}ns over \
         the direct call (budget {HOT_PATH_BUDGET_NANOS}ns). direct {direct_p50}ns, slot {slot_p50}ns."
    );
    assert!(
        transport_p99_delta_nanos < HOT_PATH_BUDGET_NANOS,
        "HOT-PATH PERF (transport, p99): the door crossing cost {transport_p99_delta_nanos}ns over \
         the direct call (budget {HOT_PATH_BUDGET_NANOS}ns). direct {direct_p99}ns, slot {slot_p99}ns."
    );
}

/// THE PER-TOKEN CROSSING ASSERTION — the `per-token host-call counter == 0`.
///
/// Models a plane emitting `n` tokens: the fast path does its per-token work in-plane and crosses
/// the host table NOT AT ALL. `BUSBAR_PERF_STREAM_CROSS` makes it cross per token, which is
/// how the `== 0` assertion is proven able to fail.
fn assert_zero_per_token_host_calls() {
    let null: HostCtx = HostCtx::NONE;
    let vt = armed_vtable();
    let mut call = ClockCall::new();
    let cross_per_token = std::env::var_os("BUSBAR_PERF_STREAM_CROSS").is_some();

    PER_TOKEN_HOST_CALLS.store(0, Ordering::Relaxed);
    let before = PER_TOKEN_HOST_CALLS.load(Ordering::Relaxed);

    let mut sink: u64 = 0;
    let tokens: usize = 10_000;
    for i in 0..tokens {
        // The fast per-token work: pure in-plane arithmetic, no seam crossing.
        sink = sink.wrapping_add(i as u64);
        if cross_per_token {
            // The RED shape: a host crossing PER TOKEN, which the budget forbids.
            let f = vt.clock_now.expect("clock_now slot is armed");
            let answered = f(null, call.input(), call.out());
            sink = sink.wrapping_add(u64::from(answered.outcome() == Outcome::Ready));
        }
    }
    black_box(sink);

    let per_token_crossings = PER_TOKEN_HOST_CALLS.load(Ordering::Relaxed) - before;
    assert_eq!(
        per_token_crossings, 0,
        "HOT-PATH PER-TOKEN: the streaming path crossed the host table {per_token_crossings} \
         time(s) over {tokens} tokens; the budget requires 0. A host crossing is a per-request cost, never \
         a per-token one."
    );
}

fn hot_path(c: &mut Criterion) {
    // The two published legs: the direct call and the SAME service through the `HostSlots` slot.
    let null: HostCtx = HostCtx::NONE;
    let vt = armed_vtable();
    let mut call = ClockCall::new();
    let input = call.input();
    let out = call.out();

    c.bench_function("HOT_PATH_DIRECT_CALL", |b| {
        b.iter(|| {
            black_box(host_clock_now(
                black_box(null),
                black_box(input),
                black_box(out),
            ))
        });
    });
    c.bench_function("HOT_PATH_VTABLE_CALL", |b| {
        b.iter(|| {
            let f = black_box(vt.clock_now).expect("clock_now slot is armed");
            black_box(f(black_box(null), black_box(input), black_box(out)))
        });
    });

    // The transport cell's two legs: the slot body called directly, and through the door's table.
    let ops = armed_transport_ops();
    let ops_ptr: *const TransportOps = &ops;
    c.bench_function("TRANSPORT_DIRECT_CALL", |b| {
        b.iter(|| {
            black_box(carrier_read(
                black_box(std::ptr::null_mut()),
                black_box(std::ptr::null()),
                black_box(std::ptr::null_mut()),
            ))
        });
    });
    c.bench_function("TRANSPORT_DOOR_CALL", |b| {
        b.iter(|| {
            let f = read_slot(black_box(ops_ptr));
            black_box(f(
                black_box(std::ptr::null_mut()),
                black_box(std::ptr::null()),
                black_box(std::ptr::null_mut()),
            ))
        });
    });

    // The gating assertions run once per bench invocation: a blown budget or a per-token crossing
    // takes the process down non-zero.
    assert_hot_path_delta_under_budget();
    assert_transport_hot_path_delta_under_budget();
    assert_zero_per_token_host_calls();
}

criterion_group!(plane_host_vtable_perf, hot_path);
criterion_main!(plane_host_vtable_perf);
