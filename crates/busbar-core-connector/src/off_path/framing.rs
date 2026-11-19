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

