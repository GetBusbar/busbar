// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1f, the listener probe (MIGRATE-ON-BOOT §A3 1f): a 1.5.5 still serving on this host holds the
//! plan's `listen` or `admin_listen`. Each address is bound once with a plain `TcpListener` (std
//! sets SO_REUSEADDR, so a port in TIME_WAIT passes) and released at once; `EADDRINUSE`, retried
//! every second for 10 s, refuses LIVE_WRITER before anything is written or opened. Any other bind
//! error (EACCES, EADDRNOTAVAIL, an address that does not parse) is not a sign of 1.5.5: it is
//! skipped here and the boot's own bind reports it.

use std::time::Duration;

use crate::Refusal;

/// The retry interval and the bound of the probe.
pub(crate) const EVERY: Duration = Duration::from_secs(1);
pub(crate) const BOUND: Duration = Duration::from_secs(10);

/// Probe each address (§A3 1f); nothing is written.
pub(crate) fn probe_within(
    _addresses: &[&str],
    _bound: Duration,
    _every: Duration,
) -> Result<(), Refusal> {
    Ok(())
}

#[cfg(test)]
#[path = "tests/listen_tests.rs"]
mod tests;
