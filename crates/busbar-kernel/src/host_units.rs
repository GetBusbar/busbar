// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIT RECORD (`BUSBAR-1.6.0.md` THE DESIGN, §6): what the kernel holds for each unit in
//! flight, keyed by the unit key it minted. The one place a request's verified principal lives
//! while its unit runs; a host service called inside a crossing that serves the unit answers from
//! it.
//!
//! The unit's admission writes the record once, after Authenticate: the principal, or `None` for
//! an ungoverned deployment. The unit's end removes it. A unit never admitted, or already ended,
//! has no record, and every question asked of it is answered fail-closed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::records::VirtualKey;

/// One unit in flight.
#[derive(Debug, Clone, Default)]
pub struct UnitRecord {
    /// The unit's verified principal; `None` = the deployment is ungoverned.
    pub principal: Option<Arc<VirtualKey>>,
    /// How deep the unit is nested: `0` for a unit a caller sent, one more than its parent's for a
    /// unit `unit.nest` ran (the depth cap reads it).
    pub depth: u32,
}

/// Every unit in flight, by unit key.
#[derive(Debug, Default)]
pub struct UnitRecords {
    inner: Mutex<HashMap<u64, Arc<UnitRecord>>>,
}

impl UnitRecords {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Arc<UnitRecord>>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The unit `unit` is admitted with `record`.
    pub fn admitted(&self, unit: u64, record: UnitRecord) {
        self.lock().insert(unit, Arc::new(record));
    }

    /// The unit `unit` ended.
    pub fn ended(&self, unit: u64) {
        self.lock().remove(&unit);
    }

    /// The record of `unit`, while it is in flight.
    #[must_use]
    pub fn get(&self, unit: u64) -> Option<Arc<UnitRecord>> {
        self.lock().get(&unit).cloned()
    }
}
