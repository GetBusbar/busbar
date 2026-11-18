// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::port_observations`' off-path code: the observation custody's book, made once at boot
//! (`root/min3_boot.rs` builds the process's one [`ObsCustody`]) with every slot it will ever hold. A registration
//! on the request path only claims a slot made here.

use std::sync::{Arc, Mutex};

use crate::host_services::WallMs;
use crate::plane_driver::port_observations::{Book, ByPrincipal, ObsCustody, MAX_UNITS};

impl Book {
    /// Boot only. `MAX_UNITS` empty slots, all free, and the principal map's room.
    pub(crate) fn make() -> Self {
        let mut slots = Vec::with_capacity(MAX_UNITS);
        slots.resize_with(MAX_UNITS, || None);
        let last = u32::try_from(MAX_UNITS).expect("the slot count fits u32");
        // Popped from the end: slot 0 is claimed first.
        let mut free = Vec::with_capacity(MAX_UNITS);
        free.extend((0..last).rev());
        // Twice the slots: a principal's key is removed with its last unit, and a map with room for twice its
        // most keys rehashes its removed markers in place rather than growing (hashbrown's `reserve_rehash`
        // rehashes in place while the keys are at most half its capacity).
        let mut by_principal = ByPrincipal::default();
        by_principal.reserve(2 * MAX_UNITS);
        Book {
            slots,
            free,
            by_principal,
        }
    }
}

impl ObsCustody {
    /// Boot only: the process's one custody (`root/min3_boot.rs`), and test fixtures.
    #[must_use]
    pub fn new(wall_ms: WallMs) -> Self {
        Self {
            book: Arc::new(Mutex::new(Book::make())),
            wall_ms,
        }
    }
}
