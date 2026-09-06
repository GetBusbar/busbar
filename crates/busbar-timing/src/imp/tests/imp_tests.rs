// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-timing/src/lib.rs` (feature-on registry, module `imp`).

use super::*;

/// The runtime gate is a PROCESS-global atomic, so the tests that drive it cannot run concurrently:
/// one flipping it on while another asserts the disabled behaviour makes the second flaky. This lock
/// serializes exactly those tests and nothing else.
static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the gate lock, ignoring poisoning — a failed assertion in one gate test must not cascade
/// into unrelated failures in the others.
fn gate_lock() -> std::sync::MutexGuard<'static, ()> {
    GATE.lock().unwrap_or_else(|p| p.into_inner())
}

#[test]
fn bucket_monotonic_and_percentiles_separate_scales() {
    let mut s = MethodStat::default();
    // 1000 samples near 500ns, 1 sample near 25us.
    for _ in 0..1000 {
        s.record(500);
    }
    s.record(25_000);
    assert_eq!(s.count, 1001);
    // p50 sits in the ~500ns band (bucket floor 256), p99 also (only 1/1001 is the outlier),
    // and max captures the 25us outlier exactly.
    assert!(s.percentile(0.50) <= 512, "p50 {}", s.percentile(0.50));
    assert_eq!(s.max_ns, 25_000);
    assert_eq!(s.min_ns, 500);
}

#[test]
fn bucket_of_is_log2() {
    assert_eq!(bucket_of(0), 0);
    assert_eq!(bucket_of(1), 1);
    assert_eq!(bucket_of(2), 2);
    assert_eq!(bucket_of(3), 2);
    assert_eq!(bucket_of(4), 3);
    assert_eq!(bucket_of(1023), 10);
    assert_eq!(bucket_of(1024), 11);
}

/// A single bucket must keep counting past the 32-bit ceiling, in both `record` and `merge`.
///
/// The buckets were `u32` while `count` was `u64`, so the bucket overflowed first: a method logging
/// ~1M samples/s into one latency band tips it in about 70 minutes. This crate is debug-only, and in
/// debug that is an arithmetic PANIC inside `record` — the timing probe killing the request it was
/// timing. In release it wraps, and then `percentile`'s cumulative sum can never reach a `target`
/// computed from the exact `count`, so the loop falls through and reports `max_ns` for p50 and p99
/// alike. The assertion below is on the bucket VALUE rather than on the absence of a panic, so it
/// fails in release (where the wrap is silent) as well as in debug.
#[test]
fn a_bucket_keeps_counting_past_the_32_bit_ceiling() {
    let ceiling = u64::from(u32::MAX);
    let idx = bucket_of(500);

    let saturated = || {
        let mut s = MethodStat {
            count: ceiling,
            ..Default::default()
        };
        s.buckets[idx] = ceiling;
        s
    };

    let mut a = saturated();
    a.record(500);
    assert_eq!(
        a.buckets[idx],
        ceiling + 1,
        "the bucket wrapped instead of counting past 2^32"
    );

    a.merge(&saturated());
    assert_eq!(
        a.buckets[idx],
        2 * ceiling + 1,
        "merging two saturated per-thread histograms wrapped the fold"
    );

    // The consequence the width exists to prevent: percentiles still resolve to a real bucket
    // instead of falling through the loop and collapsing onto `max_ns`.
    a.max_ns = 9_999_999;
    assert_eq!(a.percentile(0.50), bucket_floor(idx));
}

#[test]
fn merge_sums_counts_and_extents() {
    let mut a = MethodStat::default();
    a.record(100);
    a.record(300);
    let mut b = MethodStat::default();
    b.record(50);
    b.record(9000);
    a.merge(&b);
    assert_eq!(a.count, 4);
    assert_eq!(a.total_ns, 100 + 300 + 50 + 9000);
    assert_eq!(a.min_ns, 50);
    assert_eq!(a.max_ns, 9000);
}

#[test]
fn scoped_record_and_reset_are_thread_local() {
    let _gate = gate_lock();
    set_enabled(true);
    reset();
    record("m_a", 1234);
    record("m_a", 2345);
    record("m_b", 10);
    let snap = LOCAL.with(|a| a.lock().unwrap().clone());
    assert_eq!(snap.get("m_a").unwrap().count, 2);
    assert_eq!(snap.get("m_b").unwrap().count, 1);
    reset();
    let snap2 = LOCAL.with(|a| a.lock().unwrap().clone());
    assert!(snap2.is_empty());
}

/// The thread registry must not grow with threads that have EXITED. Holding an `Arc` there made the
/// vector the OWNER of every accumulator it ever saw, so a churning worker pool accumulated one live
/// `HashMap` per thread ever spawned, for the life of the process — the diagnostic becoming the
/// leak. With `Weak` handles the registry dies with its thread and a walk sweeps the tombstone.
#[test]
fn dead_threads_do_not_accumulate_in_the_registry() {
    let _gate = gate_lock();
    set_enabled(true);

    for _ in 0..1_000 {
        std::thread::spawn(|| record("scratch", 1))
            .join()
            .expect("worker thread");
    }

    // The dump walks the vector, and pruning rides along with the walk — no reaper needed.
    dump();

    let remaining = threads().lock().unwrap_or_else(|p| p.into_inner()).len();
    assert!(
        remaining < 32,
        "the registry must not retain an entry per dead thread; {remaining} left after 1000 joins"
    );
}

/// With the feature ON but the runtime gate OFF, a timer must record NOTHING — and, per the module
/// header, cost only the gate check. Both halves are asserted: no sample lands, and the guard holds
/// no start instant at all, which two unconditional `Instant::now()` calls used to falsify.
#[test]
fn a_disabled_gate_records_nothing_and_reads_no_clock() {
    let _gate = gate_lock();
    set_enabled(false);
    reset();

    {
        let _t = timer("must_not_be_recorded");
        scope("also_must_not_be_recorded", || ());
        record("nor_this", 42);
    }

    assert!(
        timer("probe").start.is_none(),
        "a disabled timer must not read the clock"
    );

    let recorded = LOCAL.with(|a| a.lock().unwrap_or_else(|p| p.into_inner()).len());
    assert_eq!(recorded, 0, "a disabled gate must record nothing");

    set_enabled(true);
}
