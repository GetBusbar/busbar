// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-timing/src/lib.rs` (feature-on registry, module `imp`).

use super::*;

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
