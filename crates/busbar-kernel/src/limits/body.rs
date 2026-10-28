// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND BODY'S TIME POLICY, ONE SOURCE (row 192 C; THE DESIGN §6 step 4, l.940-941): how
//! long a request body may occupy a connection, on three axes, as plain functions over an injected
//! clock reading. The root's listener (`busbar::root::listener`, its `TimeoutBody`) and the
//! accepted path a transport frames both read it; each holds its own IO and timers and asks this
//! page what the reading means.
//!
//! * **Between frames**, [`read_timeout`]: `limits.request_body_read_timeout_secs` (default 30 s).
//!   No frame within it is [`BodyBound::Idle`].
//! * **The throughput floor**, [`MIN_THROUGHPUT_BYTES_PER_SEC`] (1 KiB/s) once
//!   [`THROUGHPUT_GRACE`] (10 s) has passed: a client that dribbles a byte just inside the
//!   inter-frame bound forever is [`BodyBound::Throughput`].
//! * **The total deadline**, [`total_deadline_for`] the body cap (cap / floor): the whole cap,
//!   sustained at the floor, and no longer; past it is [`BodyBound::Total`].
//!
//! The words each bound fails with are the listener's, unchanged (a body that fails is answered by
//! the router's body read, whose `400 text/plain` names the error).

use std::time::Duration;

/// The MINIMUM sustained throughput a body read must keep once [`THROUGHPUT_GRACE`] has passed.
/// Fixed (owner ruling): far below any honest client's rate, well above a client stalling a byte
/// every inter-frame bound.
pub const MIN_THROUGHPUT_BYTES_PER_SEC: u64 = 1024;

/// How long a body read runs before the throughput floor is judged: before it, `bytes / elapsed`
/// is unstable.
pub const THROUGHPUT_GRACE: Duration = Duration::from_secs(10);

/// The words of [`BodyBound::Idle`].
pub const IDLE_TEXT: &str = "inbound request body read timed out (slow-loris body bound)";
/// The words of [`BodyBound::Total`].
pub const TOTAL_TEXT: &str = "inbound request body exceeded its total read deadline";
/// The words of [`BodyBound::Throughput`].
pub const THROUGHPUT_TEXT: &str = "inbound request body fell below the minimum throughput floor";

/// The most time allowed BETWEEN two body frames: `limits.request_body_read_timeout_secs`, read
/// now (the installed value, or the default when none is installed).
#[must_use]
pub fn read_timeout() -> Duration {
    Duration::from_secs(super::request_body_read_timeout_secs())
}

/// The TOTAL deadline for a body under a cap of `cap_bytes`: the whole cap at the floor.
#[must_use]
pub const fn total_deadline_for(cap_bytes: u64) -> Duration {
    Duration::from_secs(cap_bytes / MIN_THROUGHPUT_BYTES_PER_SEC)
}

/// [`total_deadline_for`] the body cap installed now (`request_body_max_bytes`, the translate cap).
#[must_use]
pub fn total_deadline() -> Duration {
    total_deadline_for(busbar_kernel_egress::upstream::max_translate_body_bytes() as u64)
}

/// The bound a body read broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyBound {
    /// No frame within [`read_timeout`].
    Idle,
    /// Past the total deadline.
    Total,
    /// Below the throughput floor after the grace.
    Throughput,
}

impl BodyBound {
    /// The bound's words: generic, no client byte in them.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Idle => IDLE_TEXT,
            Self::Total => TOTAL_TEXT,
            Self::Throughput => THROUGHPUT_TEXT,
        }
    }
}

impl std::fmt::Display for BodyBound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text())
    }
}

impl std::error::Error for BodyBound {}

/// THE RETENTION BOUNDS at a reading: `elapsed` since the body read began, `bytes` of data
/// delivered so far, under `total` ([`total_deadline`]). Past `total` is [`BodyBound::Total`];
/// past [`THROUGHPUT_GRACE`] with fewer than [`MIN_THROUGHPUT_BYTES_PER_SEC`] per whole second
/// elapsed is [`BodyBound::Throughput`]; `None` = neither. Judged on every frame delivered and on
/// every wait: a dribbling client polls at least once per byte.
#[must_use]
pub fn bounds(elapsed: Duration, bytes: u64, total: Duration) -> Option<BodyBound> {
    if elapsed > total {
        return Some(BodyBound::Total);
    }
    if elapsed > THROUGHPUT_GRACE
        && bytes < MIN_THROUGHPUT_BYTES_PER_SEC.saturating_mul(elapsed.as_secs())
    {
        return Some(BodyBound::Throughput);
    }
    None
}

/// THE INTER-FRAME BOUND at a reading: `since_frame` since the last frame (or the read's start),
/// under `read_timeout` ([`read_timeout`]). At or past it is [`BodyBound::Idle`], as the
/// listener's timer fires.
#[must_use]
pub fn idle(since_frame: Duration, read_timeout: Duration) -> Option<BodyBound> {
    (since_frame >= read_timeout).then_some(BodyBound::Idle)
}

#[cfg(test)]
#[path = "tests/body_tests.rs"]
mod tests;
