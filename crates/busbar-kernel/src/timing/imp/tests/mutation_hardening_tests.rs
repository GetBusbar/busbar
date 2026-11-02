// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::tests::gate_lock;
use super::*;

#[test]
fn a_cached_disabled_gate_does_not_resample_the_environment() {
    let _gate = gate_lock();

    ENABLED.store(1, Ordering::Relaxed);

    unsafe { std::env::set_var("BUSBAR_TIMING", "1") };
    let result = std::panic::catch_unwind(enabled);
    unsafe { std::env::remove_var("BUSBAR_TIMING") };

    ENABLED.store(0, Ordering::Relaxed);
    assert!(
        !result.unwrap(),
        "a cached-disabled gate must answer from the cache, not re-read an environment that \
         would have said otherwise"
    );
}

#[test]
fn enabling_the_gate_installs_the_atexit_latch_exactly_once() {
    let _gate = gate_lock();
    set_enabled(true);
    assert!(
        ATEXIT_INSTALLED.load(Ordering::Acquire),
        "set_enabled(true) must install the atexit dump latch"
    );

    set_enabled(true);
    assert!(ATEXIT_INSTALLED.load(Ordering::Acquire));
    set_enabled(false);
}

#[test]
fn bucket_floor_is_pinned_to_independent_values() {
    assert_eq!(bucket_floor(0), 0);
    assert_eq!(bucket_floor(1), 1 << 0);
    assert_eq!(bucket_floor(2), 1 << 1);
    assert_eq!(bucket_floor(3), 1 << 2);
    assert_eq!(bucket_floor(4), 1 << 3);
    assert_eq!(bucket_floor(10), 1 << 9);
    assert_eq!(bucket_floor(11), 1 << 10);
    assert_eq!(bucket_floor(64), 1 << 63);

    for ns in [1u64, 2, 3, 4, 1023, 1024, 1025, u32::MAX as u64, u64::MAX] {
        let idx = bucket_of(ns);
        assert!(
            bucket_floor(idx) <= ns,
            "bucket_floor({idx}) = {} must not exceed the sample {ns} that fell in it",
            bucket_floor(idx)
        );
    }
}
