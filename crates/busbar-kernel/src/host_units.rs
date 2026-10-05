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
//!
//! THE UNIT'S HOOK STAGE rides beside its record ([`UnitRecords::staged`]): the driver states it
//! when the unit's route leg starts (the plane instance, the pool the kernel routes it over, the
//! configuration generation's hooks), and `hook.call` / `content.scan` run over it, never over
//! anything the plane names. The unit's end removes it with the record.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::records::VirtualKey;
use busbar_contract::services::HookAsk;

/// What a unit's hook stage answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageAnswer {
    /// Every hook asked passed (a gate), or none from there on rewrote (a rewrite chain).
    Pass,
    /// Hook `index` of the rewrite chain rewrote the request: the rewrite document.
    Rewrote {
        /// The hook's index in the chain.
        index: u32,
        /// `{"messages", "tools"}`.
        rewrite: Vec<u8>,
    },
    /// A hook stopped it: its clamped status and sanitised words.
    Stop {
        /// The status.
        status: u16,
        /// The words.
        words: String,
    },
    /// The stage could not run (its runtime is gone).
    Failed(&'static str),
}

/// Where a stage's answer goes: called once, from any thread.
pub type StageDone = Box<dyn FnOnce(StageAnswer) + Send>;

/// THE HOOK STAGE ONE UNIT BINDS, for its in-session sub-operations: the hooks of the unit's
/// kernel-recorded plane and pool, at the configuration generation the unit was bound under. Each
/// call runs off the caller's thread and answers through `done`.
pub trait UnitHookStage: Send + Sync {
    /// The label of the plane instance the unit runs on.
    fn instance(&self) -> &str;
    /// `hook.call`: run `ask`.
    fn call(self: Arc<Self>, ask: HookAsk, done: StageDone);
    /// `content.scan`: pass `content` through the unit's gates.
    fn scan(self: Arc<Self>, content: Vec<u8>, done: StageDone);
}

/// One unit in flight.
#[derive(Debug, Clone, Default)]
pub struct UnitRecord {
    /// The unit's verified principal; `None` = the deployment is ungoverned.
    pub principal: Option<Arc<VirtualKey>>,
    /// How deep the unit is nested: `0` for a unit a caller sent, one more than its parent's for a
    /// unit `unit.nest` ran (the depth cap reads it).
    pub depth: u32,
}

/// Every unit in flight, by unit key, and the hook stage each one's route leg stated.
#[derive(Default)]
pub struct UnitRecords {
    inner: Mutex<HashMap<u64, Arc<UnitRecord>>>,
    stages: Mutex<HashMap<u64, Arc<dyn UnitHookStage>>>,
}

impl std::fmt::Debug for UnitRecords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnitRecords")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl UnitRecords {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Arc<UnitRecord>>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_stages(&self) -> MutexGuard<'_, HashMap<u64, Arc<dyn UnitHookStage>>> {
        self.stages.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The unit `unit` is admitted with `record`.
    pub fn admitted(&self, unit: u64, record: UnitRecord) {
        self.lock().insert(unit, Arc::new(record));
    }

    /// The unit `unit` ended: its record and its hook stage leave.
    pub fn ended(&self, unit: u64) {
        let mut records = self.lock();
        records.remove(&unit);
        self.lock_stages().remove(&unit);
    }

    /// The route leg of `unit` states its hook stage. Only a unit in flight holds one: for any
    /// other the stage is dropped (`false`). The first stage stated stands.
    pub fn staged(&self, unit: u64, stage: Arc<dyn UnitHookStage>) -> bool {
        let records = self.lock();
        if !records.contains_key(&unit) {
            return false;
        }
        self.lock_stages().entry(unit).or_insert(stage);
        true
    }

    /// The hook stage of `unit`, while it is in flight and its route leg stated one.
    #[must_use]
    pub fn stage(&self, unit: u64) -> Option<Arc<dyn UnitHookStage>> {
        let records = self.lock();
        if !records.contains_key(&unit) {
            return None;
        }
        self.lock_stages().get(&unit).cloned()
    }

    /// The record of `unit`, while it is in flight.
    #[must_use]
    pub fn get(&self, unit: u64) -> Option<Arc<UnitRecord>> {
        self.lock().get(&unit).cloned()
    }
}
