// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-RANDOM (ABI-MIN3-INTERFACE §14): the host's `random`. The length bounds of its body are W1-H0's (merged).
//! The compile-fail bounds of the safe `Host::random::<N>` and the failing-backend arm (the facade's test-support
//! stub: `random` returns `Err(Rng)` and the arena holds no zero-filled result) need A2's safe API and `HOST`, so
//! they are W1-A2's, not H0's (W1-H0 handoff, design hole 1).
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::host::crypto_status;
use busbar_plugin_abi::host_side::host_vt::vt;

#[test]
fn random_answers_invalid_outside_1_to_65536_and_fills_inside() {
    for len in [0, 65_537] {
        let out = vt::random(len);
        assert_eq!(out.crypto_status(), crypto_status::INVALID, "{len}");
        assert!(out.is_empty());
    }
    let out = vt::random(65_536);
    assert_eq!(out.crypto_status(), crypto_status::OK);
    assert_eq!(out.len(), 65_536);
    assert!(out.read(|bytes| bytes.len() == 65_536 && bytes.iter().any(|&b| b != 0)));
}

#[test]
#[ignore = "owner: W1-A2"]
fn random_0_and_65_537_fail_to_compile() {
    todo!("owner: W1-A2 (C-RANDOM)")
}

#[test]
#[ignore = "owner: W1-A2"]
fn a_failing_backend_answers_err_rng_with_no_zero_filled_array() {
    todo!("owner: W1-A2 (C-RANDOM)")
}
