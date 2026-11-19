// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Deadlines the engine derives from its monotonic clock expire when configured, whatever reading
//! first crossed the `Instant` bridge. Its own test binary, so this test makes the process's first
//! conversion.

use std::time::{Duration, Instant};

use busbar_kernel::inbound::native::Arrival;
use busbar_kernel::store::monotonic_ns;

#[test]
fn an_expired_head_deadline_is_not_stretched_by_a_stale_first_reading() {
    // A reading that is stale by the time it is converted.
    let stale = monotonic_ns();
    let before = Instant::now();
    // The request's arrival reading, taken inside [before, after].
    let arrived = monotonic_ns();
    let mut after = Instant::now();
    // The clock itself moves the window open; nothing sleeps.
    while after == before {
        after = Instant::now();
    }
    // The process's first conversion is of the stale reading.
    let first = busbar_contract::mono_instant::instant_at(stale);
    assert!(
        first <= before,
        "the node's monotonic clock and the Instant bridge disagree on when a reading was taken"
    );
    // A request head with timeout 0: its deadline has passed by `after`, never later.
    let head = Arrival::at(arrived, Duration::ZERO).expect("a zero timeout is in range");
    assert!(
        before <= head.deadline() && head.deadline() <= after,
        "an expired head's deadline is stretched past the instant it expired"
    );
}
