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

/// What the kernel holds for one unit: its record, the hook stage its route leg stated, and the
/// caller credential it lends its passthrough member (the caller-credential lending), held while
/// the unit runs and dropped (zeroised) at its end.
#[derive(Default)]
struct UnitEntry {
    record: Option<Arc<UnitRecord>>,
    stage: Option<Arc<dyn UnitHookStage>>,
    lent: Option<busbar_contract::redacted::Secret<Vec<u8>>>,
}

/// Every unit in flight, by unit key, split across the in-flight table's shards by the key so a
/// request takes one shard's lock, never a process-wide one.
pub struct UnitRecords {
    shards: Vec<Mutex<HashMap<u64, UnitEntry>>>,
}

impl Default for UnitRecords {
    fn default() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }
    /// What admitted each unit, for `ticket.take`: `Some` the record of the ticket the gate spent
    /// admitting it, `None` a key. Taken once; the unit's end drops what was never taken.
    tickets: Mutex<HashMap<u64, Option<Vec<u8>>>>,
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

    /// The unit `unit` is admitted with `record`.
    pub fn admitted(&self, unit: u64, record: UnitRecord) {
        self.lock(unit).entry(unit).or_default().record = Some(Arc::new(record));
    }

    /// The unit `unit` ended: its record goes, its hook stage, and the credential it lent.
    pub fn ended(&self, unit: u64) {
        self.lock(unit).remove(&unit);
        self.lock_tickets().remove(&unit);
    }

    fn lock_tickets(&self) -> MutexGuard<'_, HashMap<u64, Option<Vec<u8>>>> {
        self.tickets.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The unit `unit` was admitted by `ticket`: `Some` the record of the ticket the gate spent
    /// admitting it, `None` a key. Only a unit in flight holds one (`false` otherwise).
    pub fn ticketed(&self, unit: u64, ticket: Option<Vec<u8>>) -> bool {
        let records = self.lock();
        if !records.contains_key(&unit) {
            return false;
        }
        self.lock_tickets().insert(unit, ticket);
        true
    }

    /// TAKE what admitted `unit`, once: `Some(Some(record))` a ticket's record, `Some(None)` a key,
    /// and `None` for a unit not in flight or one already taken.
    pub fn take_ticket(&self, unit: u64) -> Option<Option<Vec<u8>>> {
        self.lock_tickets().remove(&unit)
    }

    /// The caller of `unit` presented `credential`: lent, while the unit runs, to a passthrough
    /// member's auth call made inside it (a request the plane makes on its own need included: the
    /// connector keys a binding by (instance, need, member, target origin); a request naming no
    /// member gets no binding).
    pub fn lend(&self, unit: u64, credential: busbar_contract::redacted::Secret<Vec<u8>>) {
        self.lock(unit).entry(unit).or_default().lent = Some(credential);
    }

    /// The route leg of `unit` states its hook stage. Only a unit in flight holds one: for any
    /// other the stage is dropped (`false`). The first stage stated stands.
    pub fn staged(&self, unit: u64, stage: Arc<dyn UnitHookStage>) -> bool {
        match self.lock(unit).get_mut(&unit) {
            Some(entry) if entry.record.is_some() => {
                entry.stage.get_or_insert(stage);
                true
            }
            _ => false,
        }
    }

    /// The hook stage of `unit`, while it is in flight and its route leg stated one.
    #[must_use]
    pub fn stage(&self, unit: u64) -> Option<Arc<dyn UnitHookStage>> {
        let shard = self.lock(unit);
        let entry = shard.get(&unit).filter(|e| e.record.is_some())?;
        entry.stage.clone()
    }

    /// The record of `unit`, while it is in flight.
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
