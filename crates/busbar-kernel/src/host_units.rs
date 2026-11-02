// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::records::VirtualKey;
use busbar_contract::services::HookAsk;

use crate::inflight::SHARDS;

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

pub type StageDone = Box<dyn FnOnce(StageAnswer) + Send>;

pub trait UnitHookStage: Send + Sync {
    fn instance(&self) -> &str;

    fn call(self: Arc<Self>, ask: HookAsk, done: StageDone);

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

/// What the kernel holds for one unit: its record, the hook stage its route leg stated, and the
/// caller credential it lends its passthrough member (the caller-credential lending), held while
/// the unit runs and dropped (zeroised) at its end.
#[derive(Default)]
struct UnitEntry {
    record: Option<Arc<UnitRecord>>,
    stage: Option<Arc<dyn UnitHookStage>>,
    lent: Option<busbar_contract::redacted::Secret<Vec<u8>>>,
    /// What admitted the unit, for `ticket.take`: `Some(Some(record))` the record of the ticket
    /// the gate spent admitting it, `Some(None)` a key; `None` never stated, or taken. The unit's
    /// end drops what was never taken.
    ticket: Option<Option<Vec<u8>>>,
}

pub struct UnitRecords {
    shards: Vec<Mutex<HashMap<u64, UnitEntry>>>,
}

impl Default for UnitRecords {
    fn default() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }
}

impl std::fmt::Debug for UnitRecords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnitRecords").finish_non_exhaustive()
    }
}

impl UnitRecords {
    fn lock(&self, unit: u64) -> MutexGuard<'_, HashMap<u64, UnitEntry>> {
        self.shards[(unit as usize) & (SHARDS - 1)]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub fn admitted(&self, unit: u64, record: UnitRecord) {
        self.lock(unit).entry(unit).or_default().record = Some(Arc::new(record));
    }

    pub fn ended(&self, unit: u64) {
        self.lock(unit).remove(&unit);
    }

    pub fn ticketed(&self, unit: u64, ticket: Option<Vec<u8>>) -> bool {
        match self.lock(unit).get_mut(&unit) {
            Some(entry) if entry.record.is_some() => {
                entry.ticket = Some(ticket);
                true
            }
            _ => false,
        }
    }

    pub fn take_ticket(&self, unit: u64) -> Option<Option<Vec<u8>>> {
        self.lock(unit).get_mut(&unit)?.ticket.take()
    }

    pub fn lend(&self, unit: u64, credential: busbar_contract::redacted::Secret<Vec<u8>>) {
        self.lock(unit).entry(unit).or_default().lent = Some(credential);
    }

    pub fn staged(&self, unit: u64, stage: Arc<dyn UnitHookStage>) -> bool {
        match self.lock(unit).get_mut(&unit) {
            Some(entry) if entry.record.is_some() => {
                entry.stage.get_or_insert(stage);
                true
            }
            _ => false,
        }
    }

    #[must_use]
    pub fn stage(&self, unit: u64) -> Option<Arc<dyn UnitHookStage>> {
        let shard = self.lock(unit);
        let entry = shard.get(&unit).filter(|e| e.record.is_some())?;
        entry.stage.clone()
    }

    #[must_use]
    pub fn get(&self, unit: u64) -> Option<Arc<UnitRecord>> {
        self.lock(unit).get(&unit)?.record.clone()
    }
}

impl busbar_contract::conn::LendCredential for UnitRecords {
    fn lent(&self, unit: u64) -> Option<busbar_contract::redacted::Secret<Vec<u8>>> {
        self.lock(unit).get(&unit)?.lent.clone()
    }
}
