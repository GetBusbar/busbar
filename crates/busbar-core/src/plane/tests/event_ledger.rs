// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST-ONLY DURABLE SINK FOR TASK EVENTS — the read-back half of every claim about the A2A
//! provenance chain.
//!
//! ## Why a double is needed at all, rather than the shipped memory store
//!
//! `busbar_store_memory` is DOCUMENTED as genuinely ephemeral and implements none of the task
//! methods, so the trait defaults apply: `append_task_event` accepts and keeps nothing and
//! `list_task_events` answers with an empty list. Teaching it to persist would silently change a
//! product contract (`taskstore_tests` keeps a permanent negative twin asserting the RAM default
//! really does lose everything), so this holds the rows instead.
//!
//! ## And why the read-back is the whole point
//!
//! `Ok(())` from a write proves nothing — the defaults return it while discarding the row — so
//! durability, and therefore the existence of the chain at all, is only ever learned by READING
//! BACK. Every test that uses this asserts on what comes out of [`EventLedger::events_for`], never
//! on the return value of a write.

use std::collections::BTreeMap;
use std::sync::Mutex;

use busbar_api::{StoreResult, TaskEventRow, TaskRow};

/// Holds task rows and chained task events for the life of one test process.
#[derive(Default)]
pub(crate) struct EventLedger {
    tasks: Mutex<BTreeMap<String, TaskRow>>,
    /// Keyed by `(task_id, seq)`, so a read-back comes out in chain order without the test having to
    /// sort — and so a second write at the same sequence overwrites rather than duplicating, which
    /// is what a real backend's primary key does.
    events: Mutex<BTreeMap<(String, u64), TaskEventRow>>,
}

impl EventLedger {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Every event this ledger holds for one task, oldest first.
    pub(crate) fn events_for(&self, task_id: &str) -> Vec<TaskEventRow> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|((id, _), _)| id == task_id)
            .map(|(_, row)| row.clone())
            .collect()
    }
}

impl busbar_api::Store for EventLedger {
    // ── The task surface: the only part of this double that keeps anything ──────────────────────
    // ── Everything else: the methods the trait requires and this double has no business having ──
    //
    // The registry only ever reaches a sink for tasks and task events, so these exist to satisfy the
    // trait and answer emptily. They deliberately do NOT delegate to a real store: a double that
    // half-works is a double a test can accidentally depend on for something it is not asserting.
    fn put_key(&self, _key: &busbar_api::VirtualKey) -> StoreResult<()> {
        Ok(())
    }

    fn get_key(&self, _id: &str) -> StoreResult<Option<busbar_api::VirtualKey>> {
        Ok(None)
    }

    fn list_keys(&self) -> StoreResult<Vec<busbar_api::VirtualKey>> {
        Ok(Vec::new())
    }

    fn delete_key(&self, _id: &str) -> StoreResult<()> {
        Ok(())
    }

    fn get_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
    ) -> StoreResult<busbar_api::UsageLedger> {
        Ok(busbar_api::UsageLedger::default())
    }

    fn put_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
        _ledger: &busbar_api::UsageLedger,
    ) -> StoreResult<()> {
        Ok(())
    }

    fn add_metering(&self, _delta: &busbar_api::MeteringDelta) -> StoreResult<()> {
        Ok(())
    }

    fn list_metering(&self, _bucket: u64) -> StoreResult<Vec<busbar_api::MeteringRow>> {
        Ok(Vec::new())
    }

    // ── The neutral kind-tagged verbs, delegating to the named task methods above ────────────────
    fn upsert_plane_record(&self, record: &busbar_api::PlaneRecord) -> StoreResult<()> {
        match record.kind.as_str() {
            crate::plane::store::KIND_TASK => {
                self.put_task(&crate::plane::store::decode(&record.body)?)
            }
            _ => Ok(()),
        }
    }
    fn get_plane_record(&self, kind: &str, id: &str) -> StoreResult<Option<Vec<u8>>> {
        match kind {
            crate::plane::store::KIND_TASK => self
                .get_task(id)?
                .map(|r| crate::plane::store::encode(&r))
                .transpose(),
            _ => Ok(None),
        }
    }
    fn append_plane_record(&self, record: &busbar_api::PlaneRecord) -> StoreResult<()> {
        match record.kind.as_str() {
            crate::plane::store::KIND_TASK_EVENT => {
                self.append_task_event(&crate::plane::store::decode(&record.body)?)
            }
            _ => Ok(()),
        }
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &busbar_api::PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        match (kind, selector) {
            (crate::plane::store::KIND_TASK, busbar_api::PlaneSelector::All) => self
                .list_tasks()?
                .iter()
                .map(crate::plane::store::encode)
                .collect(),
            (crate::plane::store::KIND_TASK_EVENT, busbar_api::PlaneSelector::Parent(p)) => self
                .list_task_events(p)?
                .iter()
                .map(crate::plane::store::encode)
                .collect(),
            _ => Ok(Vec::new()),
        }
    }
}

impl EventLedger {
    fn put_task(&self, task: &TaskRow) -> StoreResult<()> {
        self.tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(task.task_id.clone(), task.clone());
        Ok(())
    }

    fn get_task(&self, task_id: &str) -> StoreResult<Option<TaskRow>> {
        Ok(self
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(task_id)
            .cloned())
    }

    fn list_tasks(&self) -> StoreResult<Vec<TaskRow>> {
        Ok(self
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }

    fn append_task_event(&self, event: &TaskEventRow) -> StoreResult<()> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((event.task_id.clone(), event.seq), event.clone());
        Ok(())
    }

    fn list_task_events(&self, task_id: &str) -> StoreResult<Vec<TaskEventRow>> {
        Ok(self.events_for(task_id))
    }
}
