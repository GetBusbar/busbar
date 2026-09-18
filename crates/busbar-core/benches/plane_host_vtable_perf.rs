// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT-PATH PERF INSTRUMENT — the `<1µs` witness of
//! `docs/design/1.6.0-plane-extraction-LOCKED.md` §8 ("Perf gate (<1µs): criterion,
//! plugin-host-vtable vs direct-call baseline, delta<1µs p50 AND p99; a per-token host-call counter
//! on the streaming path asserted == 0"), also owed by §11b's tests/benches 8→9 rise.
//!
//! # What is measured, and against what
//!
//! §2's HOT tier is a `#[repr(C)]` fn-pointer vtable ([`PlaneHostVtable`]): a plane calls back into
//! the host through a `Option<extern "C-unwind" fn>` slot rather than through a monomorphised
//! in-core call. §8's budget is that the CROSSING — the Option-unwrap plus the indirect call through
//! the slot — costs less than 1µs against the same function invoked directly, at BOTH the p50 and
//! the p99 of the sample distribution. This file measures exactly that:
//!
//! * `HOT_PATH_DIRECT_CALL` — the host capability invoked by name, monomorphised.
//! * `HOT_PATH_VTABLE_CALL` — the SAME capability invoked through the vtable slot the plane holds.
//!
//! The delta between the two, at p50 and at p99, is asserted below [`HOT_PATH_BUDGET_NANOS`]. A
//! `std::hint::black_box` on the slot defeats the devirtualisation that would otherwise let the
//! compiler collapse the indirect call back into the direct one and measure nothing.
//!
//! # The per-token host-call counter
//!
//! §2/§8 forbid a per-token host crossing on the streaming path: governance is a per-REQUEST cost,
//! not a per-TOKEN one, so a plane streaming N tokens must cross the host vtable ZERO times per
//! token. [`PER_TOKEN_HOST_CALLS`] counts every host-vtable slot invocation; the streaming model
//! below drives N tokens and asserts the counter is `== 0`. The `BUSBAR_PERF_STREAM_CROSS`
//! environment knob makes the loop cross per token on purpose, which is how this assertion is proven
//! RED-able (it fires) rather than vacuously green.
//!
//! # THE PENDING-RIDER DEPENDENCY (why this measures the vtable DIRECTLY today)
//!
//! [`PlaneHostVtable`] currently has NO production rider: the loop that will call the host through it
//! (the keystone loop-unification, `crates/busbar/src/root/kernel.rs` + `main.rs`, reserved for the
//! keystone wave) has not landed. So this instrument is ARMED against the vtable's own construction —
//! the exact `#[repr(C)]` subject `crates/busbar-plugin/tests/layout_golden.rs` pins — rather than
//! against a live dispatch site. When the rider lands, the `HOT_PATH_VTABLE_CALL` leg binds to the
//! production crossing with no change to the budget: the slot is the same fn pointer either way.
//!
//! # Running it
//!
//! ```text
//! cargo bench -p busbar-core --bench plane_host_vtable_perf
//! ```
//!
//! The `cargo xtask gate hot-path-perf` gate enforces that this instrument keeps making every one of
//! the §8 claims above; this file is what actually measures them.

use busbar_plugin::hot::host::{ClockNowFn, HostCtx, PlaneHostVtable};
use busbar_plugin::AbiPreamble;
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// §8's budget: the vtable crossing must cost under one microsecond over a direct call.
const HOT_PATH_BUDGET_NANOS: u64 = 1_000;

/// Every host-vtable slot invocation on the streaming path bumps this. §8 requires it to stay `0`
/// per token: a host crossing is a per-request cost, never a per-token one.
static PER_TOKEN_HOST_CALLS: AtomicUsize = AtomicUsize::new(0);

/// The host capability under measurement, in the exact shape §2's HOT tier mandates: an
/// `extern "C-unwind"` POD-by-value clock read. Counted so the streaming model can prove it did NOT
/// cross the seam per token.
extern "C-unwind" fn host_clock_now(_host: HostCtx) -> u64 {
    PER_TOKEN_HOST_CALLS.fetch_add(1, Ordering::Relaxed);
    // A trivial, side-effect-free body: the cost being measured is the CROSSING, not the work, so
    // the direct and vtable legs must run byte-identical bodies.
    0x5145_1145
}

/// A [`PlaneHostVtable`] with `clock_now` populated and every other slot absent (`None`) — the
/// vtable as a plane holds it before the production rider lands.
///
/// Built by zeroing then setting the header and the one live slot: every field is valid all-zero (an
/// `Option<extern "C-unwind" fn>` is `None` under the null-pointer niche, and the header scalars are
/// integers), so this is a sound construction of the real `#[repr(C)]` subject rather than a
/// stand-in.
fn armed_vtable() -> PlaneHostVtable {
    // SAFETY: every field of `PlaneHostVtable` is valid when all-zero — the header is
    // integers/`AbiPreamble` (also integers), and every capability slot is
    // `Option<extern "C-unwind" fn>`, whose `None` is the all-zero niche for a non-null fn pointer.
    let mut vt: PlaneHostVtable = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    vt.abi = AbiPreamble::CURRENT;
    vt.size = std::mem::size_of::<PlaneHostVtable>() as u32;
    vt.version = 1;
    vt.clock_now = Some(host_clock_now as ClockNowFn);
    vt
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

/// THE BUDGET ASSERTION — §8's `delta < 1µs at p50 AND p99`, computed here rather than parsed out of
/// criterion's report so the bench binary EXITS NON-ZERO when the budget is blown (which is what
/// makes it a gate and not a graph).
fn assert_hot_path_delta_under_budget() {
    let null: HostCtx = HostCtx::NULL;
    let vt = armed_vtable();

    let (direct_p50, direct_p99) = percentiles(|| {
        black_box(host_clock_now(black_box(null)));
    });
    let (vtable_p50, vtable_p99) = percentiles(|| {
        // `black_box` the slot: without it the compiler devirtualises the indirect call back into
        // the direct one and the delta is a measurement of nothing.
        let f = black_box(vt.clock_now).expect("clock_now slot is armed");
        black_box(f(black_box(null)));
    });

    let p50_delta_nanos = vtable_p50.saturating_sub(direct_p50);
    let p99_delta_nanos = vtable_p99.saturating_sub(direct_p99);

    assert!(
        p50_delta_nanos < HOT_PATH_BUDGET_NANOS,
        "HOT-PATH PERF (p50): the vtable crossing cost {p50_delta_nanos}ns over the direct call \
         (budget {HOT_PATH_BUDGET_NANOS}ns). direct p50 {direct_p50}ns, vtable p50 {vtable_p50}ns. \
         §8 requires delta < 1µs at p50."
    );
    assert!(
        p99_delta_nanos < HOT_PATH_BUDGET_NANOS,
        "HOT-PATH PERF (p99): the vtable crossing cost {p99_delta_nanos}ns over the direct call \
         (budget {HOT_PATH_BUDGET_NANOS}ns). direct p99 {direct_p99}ns, vtable p99 {vtable_p99}ns. \
         §8 requires delta < 1µs at p99."
    );
}

/// THE PER-TOKEN CROSSING ASSERTION — §8's `per-token host-call counter == 0`.
///
/// Models a plane streaming `n` tokens: the POD-fast path does its per-token work in-plane and
/// crosses the host vtable NOT AT ALL. `BUSBAR_PERF_STREAM_CROSS` makes it cross per token, which is
/// how the `== 0` assertion is proven able to fail.
fn assert_zero_per_token_host_calls() {
    let null: HostCtx = HostCtx::NULL;
    let vt = armed_vtable();
    let cross_per_token = std::env::var_os("BUSBAR_PERF_STREAM_CROSS").is_some();

    PER_TOKEN_HOST_CALLS.store(0, Ordering::Relaxed);
    let before = PER_TOKEN_HOST_CALLS.load(Ordering::Relaxed);

    let mut sink: u64 = 0;
    let tokens: usize = 10_000;
    for i in 0..tokens {
        // The POD-fast per-token work: pure in-plane arithmetic, no seam crossing.
        sink = sink.wrapping_add(i as u64);
        if cross_per_token {
            // The RED shape: a host crossing PER TOKEN, which §8 forbids.
            let f = vt.clock_now.expect("clock_now slot is armed");
            sink = sink.wrapping_add(f(null));
        }
    }
    black_box(sink);

    let per_token_crossings = PER_TOKEN_HOST_CALLS.load(Ordering::Relaxed) - before;
    assert_eq!(
        per_token_crossings, 0,
        "HOT-PATH PER-TOKEN: the streaming path crossed the host vtable {per_token_crossings} \
         time(s) over {tokens} tokens; §8 requires 0. A host crossing is a per-request cost, never \
         a per-token one."
    );
}

fn hot_path(c: &mut Criterion) {
    // The two published legs: the direct call and the SAME capability through the vtable slot.
    let null: HostCtx = HostCtx::NULL;
    let vt = armed_vtable();

    c.bench_function("HOT_PATH_DIRECT_CALL", |b| {
        b.iter(|| black_box(host_clock_now(black_box(null))));
    });
    c.bench_function("HOT_PATH_VTABLE_CALL", |b| {
        b.iter(|| {
            let f = black_box(vt.clock_now).expect("clock_now slot is armed");
            black_box(f(black_box(null)))
        });
    });

    // The gating assertions run once per bench invocation: a blown budget or a per-token crossing
    // takes the process down non-zero.
    assert_hot_path_delta_under_budget();
    assert_zero_per_token_host_calls();
}

criterion_group!(plane_host_vtable_perf, hot_path);
criterion_main!(plane_host_vtable_perf);
