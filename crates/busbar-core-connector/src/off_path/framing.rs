// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What `framer` fixes once per process: the host clock's epoch, read by the process's first
//! reading and never again.

use std::sync::OnceLock;
use std::time::Instant;

/// The one instant every host-clock reading (`framer::now_ns`) and every instant it names
/// (`framer::instant_of`) counts from.
static EPOCH: OnceLock<Instant> = OnceLock::new();

/// [`EPOCH`], fixed by the process's first reading: the OS clock is read for it once per process.
pub(crate) fn epoch() -> Instant {
    *EPOCH.get_or_init(Instant::now)
}

/// The OS monotonic clock read, as the time since [`epoch`]: the one place the host clock is read
/// for `framer::now_ns`.
pub(crate) fn since_epoch() -> std::time::Duration {
    epoch().elapsed()
}

/// One reading of the clock a MIN-3 transport session runs on (IF §8.7): the OS monotonic instant and,
/// taken with it, the host's `mono` nanoseconds (`Host::mono`, the one clock WAKE_AT and
/// `ConnIn.mono_ns` are stated in). The session task reads it once per wake and passes it down.
pub(crate) fn session_clock() -> (Instant, u64) {
    (
        Instant::now(),
        busbar_plugin_abi::host_side::host_vt::vt::mono(),
    )
}

/// The OS wall clock, nanoseconds since the Unix epoch (`0` before it): read once as a framing
/// begins.
pub(crate) fn unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// One field of an opening block, owned: kept once per stream, as its opening is read.
pub(crate) fn owned_field(name: &[u8], value: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (name.to_vec(), value.to_vec())
}

/// The streams whose stall deadline has passed at `now`, ascending: taken once per tick.
pub(crate) fn stalled_streams<'a>(
    held: impl Iterator<Item = (&'a u64, &'a std::time::Instant)>,
    now: std::time::Instant,
) -> Vec<u64> {
    let mut due: Vec<u64> = held
        .filter(|(_, deadline)| **deadline <= now)
        .map(|(stream, _)| *stream)
        .collect();
    due.sort_unstable();
    due
}

/// A framing's opening field block, owned: kept once, as the framing begins.
pub(crate) fn owned_opening(opening: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    opening.to_vec()
}
