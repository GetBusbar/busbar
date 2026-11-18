// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the SDK's request-path modules need made once, when an instance opens, and never on a
//! request. This module carries no request-path marker: nothing here runs per request.

use std::sync::Mutex;

use super::transport::table::{Free, Slot, Table};

impl<T> Table<T> {
    /// Instance open only. A table of `slots` values, every slot and the free list made now; a
    /// request only claims one (`insert` answers `None` when all are in use).
    #[must_use]
    pub fn with_capacity(slots: usize) -> Table<T> {
        Table {
            slots: (0..slots).map(|_| Slot::default()).collect(),
            free: Mutex::new(Free {
                idle: Vec::with_capacity(slots),
                next: 0,
            }),
        }
    }
}
