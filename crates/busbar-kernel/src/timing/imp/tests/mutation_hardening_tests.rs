// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::tests::gate_lock;
use super::*;

#[test]
fn a_cached_disabled_gate_does_not_resample_the_environment() {
    let _gate = gate_lock();

    ENABLED.store(1, Ordering::Relaxed);

    // An environment that would say ON: the cached answer must win without consulting it.
    let result = std::panic::catch_unwind(|| enabled_from(|| true));

    ENABLED.store(0, Ordering::Relaxed);
    assert!(
        !result.unwrap(),
        "a cached-disabled gate must answer from the cache, not re-read an environment that \
         would have said otherwise"
    );
}
