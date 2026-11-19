// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-clock to `Instant` bridge is exact: a reading maps to the `Instant` it was taken at,
//! whatever reading the process's first caller handed in. Its own test binary, so this test makes
//! the process's first conversion.

use std::time::{Duration, Instant};

use busbar_contract::clock::system_now;
use busbar_contract::mono_instant::instant_at;

#[test]
fn a_deadline_from_a_reading_after_a_stale_first_reading_expires_when_configured() {
    // A reading that is stale by the time it is converted.
    let stale = system_now().mono_ns;
    let before = Instant::now();
    // The operation's reading, taken inside [before, after].
    let fresh = system_now().mono_ns;
    let mut after = Instant::now();
    // The clock itself moves the window open; nothing sleeps.
    while after == before {
        after = Instant::now();
    }
    // The process's first conversion is of the stale reading.
    assert!(
        instant_at(stale) <= before,
        "a reading converted late maps to a later Instant than the one it was taken at"
    );
    // A request head with timeout 0, from the operation's reading: expired by `after`, never later.
    let deadline = instant_at(fresh) + Duration::ZERO;
    assert!(
        before <= deadline && deadline <= after,
        "a deadline derived from a reading after a stale first reading is stretched"
    );
}
