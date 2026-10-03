// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The four terminals, and the words each of them says.
//!
//! Carried over from the previous release's on-exhausted tests. Every literal asserted here — the
//! status, the kind, the detail, the wait — is the one that shipped, and each is compared against
//! the constant rather than a retyped copy of it, so a reworded constant fails the test that reads
//! it rather than passing a test that repeats the same mistake.

use crate::exhaustion::AT_CAPACITY_RETRY_AFTER_SECS;

/// The two units hold the same floor, and this is the only place that says so.
///
/// A unit crate does not depend on another unit crate — the composition root binds them — so the
/// breaker's floor and this crate's are two constants by construction, not by oversight. What would
/// be an oversight is nothing checking they still agree, since they are the same operator-visible
/// `Retry-After`. The breaker is a dev-dependency here for exactly this kind of proof.
#[test]
fn the_at_capacity_floor_matches_the_breaker_units_own() {
    assert_eq!(
        AT_CAPACITY_RETRY_AFTER_SECS,
        busbar_kernel_breaker::AT_CAPACITY_RETRY_AFTER_SECS,
        "the two units advertise one at-capacity Retry-After between them"
    );
}
