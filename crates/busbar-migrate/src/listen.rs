// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1f, the listener probe (MIGRATE-ON-BOOT §A3 1f): a 1.5.5 still serving on this host holds the
//! plan's `listen` or `admin_listen`. Each address is bound once with a plain `TcpListener` (std
//! sets SO_REUSEADDR, so a port in TIME_WAIT passes) and released at once; `EADDRINUSE`, retried
//! every second for 10 s, refuses LIVE_WRITER before anything is written or opened. Any other bind
//! error (EACCES, EADDRNOTAVAIL, an address that does not parse) is not a sign of 1.5.5: it is
//! skipped here and the boot's own bind reports it.

use std::io::ErrorKind;
use std::net::TcpListener;
use std::time::{Duration, Instant};

use crate::Refusal;

/// The retry interval and the bound of the probe.
pub(crate) const EVERY: Duration = Duration::from_secs(1);
pub(crate) const BOUND: Duration = Duration::from_secs(10);

/// Probe each address (§A3 1f), in order, each once more every `every` while it is in use and
/// `bound` has not passed since its first try; nothing is written.
pub(crate) fn probe_within(
    addresses: &[&str],
    bound: Duration,
    every: Duration,
) -> Result<(), Refusal> {
    for (index, address) in addresses.iter().enumerate() {
        if addresses[..index].contains(address) {
            continue;
        }
        let started = Instant::now();
        loop {
            match TcpListener::bind(address) {
                // Bound: nothing serves there. Dropping the listener releases it at once.
                Ok(listener) => {
                    drop(listener);
                    break;
                }
                Err(error) if error.kind() == ErrorKind::AddrInUse => {
                    if started.elapsed() >= bound {
                        return Err(Refusal::LiveWriter(format!(
                            "`{address}` is in use: a busbar 1.5.5 (or another process) still \
                             serves on this host; stop every 1.5.5 instance, then boot again; \
                             nothing was written"
                        )));
                    }
                    std::thread::sleep(every);
                }
                // Not a sign of 1.5.5 (EACCES, EADDRNOTAVAIL, no such address): the boot's bind
                // reports it.
                Err(_) => break,
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/listen_tests.rs"]
mod tests;
