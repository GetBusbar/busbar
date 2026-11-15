// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CPU-TIME ROW (SDK-SAFE-TEST-HOST §3.4): the calling thread's CPU time, for a bench or a
//! test that budgets work by CPU rather than by wall clock. `std` has no thread CPU clock, so
//! this is the one reviewed `clock_gettime` in test code.

/// The CPU time the calling thread has used, in nanoseconds (`CLOCK_THREAD_CPUTIME_ID`).
///
/// # Panics
/// When the platform refuses the thread CPU clock.
#[cfg(unix)]
#[must_use]
pub fn thread_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, exclusively borrowed `timespec` the call writes and nothing else
    // reads meanwhile; the clock id is a constant every supported unix defines.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
    assert_eq!(rc, 0, "the thread CPU clock is unavailable");
    u64::try_from(ts.tv_sec).unwrap_or(0) * 1_000_000_000 + u64::try_from(ts.tv_nsec).unwrap_or(0)
}
