// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

pub(super) static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(super) fn gate_lock() -> std::sync::MutexGuard<'static, ()> {
    GATE.lock().unwrap_or_else(|p| p.into_inner())
}

#[test]
fn bucket_monotonic_and_percentiles_separate_scales() {
    let mut s = MethodStat::default();

    for _ in 0..1000 {
        s.record(500);
    }
    s.record(25_000);
    assert_eq!(s.count, 1001);

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
    let snap = LOCAL.with(|h| h.0.lock().unwrap().clone());
    assert_eq!(snap.get("m_a").unwrap().count, 2);
    assert_eq!(snap.get("m_b").unwrap().count, 1);
    reset();
    let snap2 = LOCAL.with(|h| h.0.lock().unwrap().clone());
    assert!(snap2.is_empty());
}

#[test]
fn dead_threads_do_not_accumulate_in_the_registry() {
    let _gate = gate_lock();
    set_enabled(true);

    for _ in 0..1_000 {
        std::thread::spawn(|| record("scratch", 1))
            .join()
            .expect("worker thread");
    }

    dump();

    let remaining = threads().lock().unwrap_or_else(|p| p.into_inner()).len();
    assert!(
        remaining < 32,
        "the registry must not retain an entry per dead thread; {remaining} left after 1000 joins"
    );
}

#[test]
fn samples_from_an_exited_thread_survive_in_the_process_merge() {
    let _gate = gate_lock();
    set_enabled(true);

    std::thread::spawn(|| {
        record("exited_worker_probe", 1_000);
        record("exited_worker_probe", 3_000);
    })
    .join()
    .expect("worker thread");

    let merged = merged_snapshot();
    let s = merged
        .get("exited_worker_probe")
        .expect("an exited thread's samples must still appear in the process merge");
    assert_eq!(s.count, 2, "both of the worker's samples must survive it");
    assert_eq!(s.total_ns, 4_000);
    assert_eq!(s.min_ns, 1_000);
    assert_eq!(s.max_ns, 3_000);
}

#[test]
fn live_and_exited_samples_are_counted_exactly_once() {
    let _gate = gate_lock();
    set_enabled(true);

    const N: u64 = 7;
    const M: u64 = 5;

    for _ in 0..N {
        record("exactly_once_probe", 100);
    }
    std::thread::spawn(|| {
        for _ in 0..M {
            record("exactly_once_probe", 100);
        }
    })
    .join()
    .expect("worker thread");

    let merged = merged_snapshot();
    let s = merged
        .get("exactly_once_probe")
        .expect("the live thread's own samples must appear in the process merge");
    assert_eq!(s.count, N + M, "every sample counted once and only once");
    assert_eq!(s.total_ns, (N + M) * 100);
}

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

    let recorded = LOCAL.with(|h| h.0.lock().unwrap_or_else(|p| p.into_inner()).len());
    assert_eq!(recorded, 0, "a disabled gate must record nothing");

    set_enabled(true);
}
