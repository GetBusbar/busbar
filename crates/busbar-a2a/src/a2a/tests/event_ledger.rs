// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST-ONLY DURABLE SINK FOR TASK EVENTS — the read-back half of every claim about the A2A
//! provenance chain. Relocated from `busbar-core/src/plane/tests/event_ledger.rs` with the task
//! subsystem (1.7.0 plane extraction); it now speaks the plane's OWN `TaskRow`/`TaskEventRow` and the
//! plane-owned `KIND_TASK`/`KIND_TASK_EVENT` tags.
//!
//! ## Why a double is needed at all, rather than the shipped memory store
//!
//! `busbar_store_memory` is DOCUMENTED as genuinely ephemeral and implements none of the plane-record
//! methods, so the trait defaults apply and nothing persists. Teaching it to persist would silently
//! change a product contract, so this holds the rows instead.
//!
//! ## And why the read-back is the whole point
//!
//! `Ok(())` from a write proves nothing — the defaults return it while discarding the row — so
//! durability, and therefore the existence of the chain at all, is only ever learned by READING BACK.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::record::{KIND_TASK, KIND_TASK_EVENT};
use crate::{TaskEventRow, TaskRow};
use busbar_api::StoreResult;

/// Holds task rows and chained task events for the life of one test process.
#[derive(Default)]
pub struct EventLedger {
    tasks: Mutex<BTreeMap<String, TaskRow>>,
    /// The chained events, keyed by `(task_id, seq)` so a read-back comes out in chain order and a
    /// re-write at the same sequence overwrites (a real backend's primary key). The value is the
    /// OPAQUE stored BODY the plane persists, kept verbatim, exactly as a durable backend holds it.
    events: Mutex<BTreeMap<(String, u64), Vec<u8>>>,
}

impl EventLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every event this ledger holds for one task, oldest first — reconstructed from the stored bodies.
    pub fn events_for(&self, task_id: &str) -> Vec<TaskEventRow> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|((id, _), _)| id == task_id)
            .map(|(_, body)| {
                TaskEventRow::from_body(body).expect("a stored task_event body decodes")
            })
            .collect()
    }
}

impl busbar_api::Store for EventLedger {
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

    fn upsert_plane_record(&self, record: &busbar_api::PlaneRecord) -> StoreResult<()> {
        if record.kind == KIND_TASK {
            self.tasks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(record.id.clone(), TaskRow::from_body(&record.body)?);
        }
        Ok(())
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> StoreResult<Option<Vec<u8>>> {
        if kind == KIND_TASK {
            return self
                .tasks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(id)
                .map(|r| r.to_plane_record().map(|rec| rec.body))
                .transpose();
        }
        Ok(None)
    }

    fn append_plane_record(&self, record: &busbar_api::PlaneRecord) -> StoreResult<()> {
        if record.kind == KIND_TASK_EVENT {
            let task_id = record.parent.clone().unwrap_or_else(|| record.id.clone());
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert((task_id, record.seq), record.body.clone());
        }
        Ok(())
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &busbar_api::PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        match (kind, selector) {
            (KIND_TASK, busbar_api::PlaneSelector::All) => self
                .tasks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .map(|r| r.to_plane_record().map(|rec| rec.body))
                .collect(),
            (KIND_TASK_EVENT, busbar_api::PlaneSelector::Parent(p)) => Ok(self
                .events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|((id, _), _)| id == p)
                .map(|(_, body)| body.clone())
                .collect()),
            _ => Ok(Vec::new()),
        }
    }
}
