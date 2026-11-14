// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one bridge from the host's monotonic clock to [`std::time::Instant`], for sans-IO crates
//! (str0m, timers) whose API takes an `Instant`.
//!
//! Request-path code never reads the OS clock (LINT-RULES R7): it takes the host's reading
//! (`mono_ns`, from the clock service or the op's lent `now_monotonic_ns`) and, where a library
//! needs an `Instant`, converts that reading here. std cannot build an `Instant` without an OS
//! read, so the first call in a process pairs one `Instant::now` with the caller's reading; every
//! later call is arithmetic on that anchor. Both clocks are monotonic in the same process, so the
//! anchor's offset is fixed and every distance between readings is kept exactly.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

static ANCHOR: OnceLock<(Instant, u64)> = OnceLock::new();

/// The `Instant` for `mono_ns` on the host's monotonic clock. One OS read per process (the first
/// call); arithmetic only after that.
pub fn instant_at(mono_ns: u64) -> Instant {
    let &(base, base_ns) = ANCHOR.get_or_init(|| (Instant::now(), mono_ns));
    if mono_ns >= base_ns {
        base.checked_add(Duration::from_nanos(mono_ns - base_ns))
            .unwrap_or(base)
    } else {
        base.checked_sub(Duration::from_nanos(base_ns - mono_ns))
            .unwrap_or(base)
    }
}
