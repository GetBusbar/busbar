// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one installed LIMIT this engine reads, and the property that matters about it: with nothing
//! installed it returns the HISTORICAL default, so a test that never installs limits sees exactly
//! the behaviour the shipped 1.2.1 build had.
//!
//! This assertion travelled here from `busbar_core::limits`'s own battery when the accessor's only
//! reader moved. It is the same slot — `busbar_substrate::config::limits::installed()` — and the
//! same const, which is the whole reason moving the accessor was safe: one knob, one answer, wherever
//! the process asks.

use busbar_substrate::config::limits::LIMITS_TEST_LOCK;

#[test]
fn uninstalled_policy_timeout_is_the_historical_default() {
    // Under the shared lock because other tests in the workspace DO install non-default limits:
    // without it this can read the slot mid-swap and fail for a reason that has nothing to do with
    // the fallback it is asserting.
    let _lock = LIMITS_TEST_LOCK.blocking_lock();
    assert_eq!(
        crate::limits::default_policy_timeout_ms(),
        crate::config::DEFAULT_POLICY_TIMEOUT_MS,
        "with no limits installed the policy timeout must be the historical default: a build that \
         returned anything else would change every un-configured deployment's routing deadline"
    );
}
