// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host entry guard's thread state (IF §10.7, I10; W1-H0).
//!
//! Round 24: `OWNER` is a host-side `const`-initialised `thread_local!` `Cell<u32>` (`u32::MAX` = none): the
//! slot of the entry running on this thread, saved and set by every guard and restored at its exit and on
//! unwind, whatever the watch claim state. `Host::log` attributes every line by it (§10.7 `set_log_sink`), and
//! `watch::current_slot()` reads it, so a line from a live entry is attributed and scrubbed even on an
//! unwatched thread. Outside an entry it is none and the sink drops the line.
//!
//! `guard` itself (with `EntryOwner`, `DEPTH`, ACTIVE, the watch word and the outermost-exit arena reset) wraps
//! the pool's raw out buffer, the watch words and `Instance` (W1-H1, which the WBS orders after this task) and
//! lands with them. Rounds 7-9's `cold`, `cold_detached`, `cold_step`, `ColdStep`/`ColdPhase`/`ImageTail`,
//! `OwnedEntryOwner` and `set_cold_hop` stay deleted (§16.92): every entry is inline under the guard.

use core::cell::Cell;

std::thread_local! {
    static OWNER: Cell<u32> = const { Cell::new(u32::MAX) };
}

/// The slot of the entry running on this thread, or None outside an entry.
pub(crate) fn owner() -> Option<u32> {
    match OWNER.with(Cell::get) {
        u32::MAX => None,
        slot => Some(slot),
    }
}
