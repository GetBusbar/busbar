// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Process-owned MIN-3 resources shared by every boot and serving candidate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::instance::{OpenError, SlotTable};

/// Process-wide reservations. Dropping a failed candidate never returns its IDs.
#[derive(Default)]
pub struct InstanceIds {
    next: AtomicU64,
}

impl InstanceIds {
    /// Reserve a nonzero ID, refusing permanently at exhaustion rather than wrapping.
    pub fn next(&self) -> Result<u64, OpenError> {
        self.next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |previous| {
                previous.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| OpenError::Unknown("process instance IDs exhausted".into()))
    }
}

/// Constructed at S0, before describing any image; owned until process shutdown.
/// Registries borrow its complete table and allocator instead of installing sinks.
pub struct ProcessResources {
    slots: Arc<SlotTable>,
    ids: Arc<InstanceIds>,
    _watchdog: crate::watchdog::Watchdog,
}

impl ProcessResources {
    pub fn new() -> Result<Self, String> {
        let slots = Arc::new(SlotTable::new());
        crate::instance::install_sinks(&slots)?;
        let watchdog = crate::watchdog::Watchdog::start(Arc::clone(&slots))?;
        Ok(Self {
            slots,
            ids: Arc::new(InstanceIds::default()),
            _watchdog: watchdog,
        })
    }

    pub fn slots(&self) -> &Arc<SlotTable> {
        &self.slots
    }

    pub fn ids(&self) -> &Arc<InstanceIds> {
        &self.ids
    }
}

#[cfg(test)]
mod tests;
