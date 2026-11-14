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
