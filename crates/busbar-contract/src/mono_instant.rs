// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one bridge from the host's monotonic clock to [`std::time::Instant`], for sans-IO crates
//! (str0m, timers) whose API takes an `Instant`.
//!
//! Request-path code never reads the OS clock (LINT-RULES R7): it takes the host's reading
//! (`mono_ns`, from the clock service or the op's lent `now_monotonic_ns`) and, where a library
//! needs an `Instant`, converts that reading here. The host's monotonic clock IS an `Instant`
//! clock: a reading is the time elapsed since the process's origin `Instant` ([`monotonic_ns`]),
//! so the conversion is that origin plus the reading, exact, with no pairing of two clocks. No
//! caller's reading anchors anything: a reading taken long before its conversion still maps to
//! the instant it was taken at, so no deadline derived from it is stretched.

use std::time::{Duration, Instant};

use crate::clock::os;

/// Where [`instant_at`] puts a reading past what an `Instant` can hold (`Deadline::NEVER`): about
/// 136 years after the origin.
const FAR_FUTURE: Duration = Duration::from_secs(1 << 32);

/// One reading of the node's monotonic clock: nanoseconds since the process's origin `Instant`.
/// The clock every `mono_ns` the engine converts here is stated in. It ORDERS and MEASURES; it
/// never dates anything.
#[must_use]
pub fn monotonic_ns() -> u64 {
    os::mono()
}

/// The `Instant` for `mono_ns` on the host's monotonic clock ([`monotonic_ns`]): the origin plus
/// the reading. Arithmetic only; the origin is fixed by the process's first reading.
#[must_use]
pub fn instant_at(mono_ns: u64) -> Instant {
    let origin = os::origin();
    origin
        .checked_add(Duration::from_nanos(mono_ns))
        .or_else(|| origin.checked_add(FAR_FUTURE))
        .unwrap_or(origin)
}
