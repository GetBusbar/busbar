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
