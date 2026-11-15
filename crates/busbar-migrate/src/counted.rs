// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The test-build call counter (MIGRATE-ON-BOOT §9 C1 (sz2), "cold and once"): every entry point
//! of this crate counts itself on the calling thread, so a test asserts that a stamped boot enters
//! none of them and an unstamped one plans once and writes once. Built only for this crate's own
//! tests and under the `counted` feature (the gateway's tests); no shipped build has it.

use std::cell::Cell;

/// How often each entry point ran on this thread.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Entries {
    /// [`crate::plan`].
    pub plan: u32,
    /// [`crate::write`].
    pub write: u32,
    /// [`crate::probe_listeners`].
    pub probe: u32,
    /// [`crate::write_back`].
    pub write_back: u32,
    /// Every other public function.
    pub other: u32,
}

impl Entries {
    /// Whether no entry point ran.
    #[must_use]
    pub fn none(&self) -> bool {
        *self == Self::default()
    }
}

thread_local! {
    static ENTRIES: Cell<Entries> = const { Cell::new(Entries {
        plan: 0,
        write: 0,
        probe: 0,
        write_back: 0,
        other: 0,
    }) };
}

/// This thread's counts so far.
#[must_use]
pub fn entries() -> Entries {
    ENTRIES.with(Cell::get)
}

/// Count one entry on this thread.
pub(crate) fn enter(count: impl FnOnce(&mut Entries)) {
    ENTRIES.with(|cell| {
        let mut entries = cell.get();
        count(&mut entries);
        cell.set(entries);
    });
}
