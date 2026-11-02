// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::store::plane_view::{decode, encode, PlaneStore, KIND_DEMOTION, KIND_TRUST_DECISION};
use crate::trust::book::RulingRow;
use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector, RecordStoreResult};
use std::sync::{Arc, Mutex};

/// The CORE-NEUTRAL demotion row — the pure durable fact the quarantine mechanism keeps. It names no
/// plane type (the plane owns the protocol-named twin, which lives plane-side); its
/// serde shape is the on-disk `demotion` body, so a body written here reads back through the plane's
/// own typed view field-for-field. Keyed by its upstream, upserted, never purged by age.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DemotionRow {
    /// The registered upstream's local id — the row's primary key. On disk the member is `server`,
    /// the name the recorded bodies carry, so a body written before this rename reads back unchanged.
    #[serde(rename = "server")]
    pub upstream: String,
    /// The operator-facing word for why it was demoted. Never free-form caller text.
    pub reason: String,
    /// Unix seconds the demotion was recorded.
    pub recorded_at: u64,
}

fn upsert<T: serde::Serialize>(
    store: &dyn PlaneStore,
    kind: &str,
    id: String,
    ts: u64,
    body: &T,
) -> RecordStoreResult<()> {
    let record = PlaneRecord {
        kind: kind.to_string(),
        id,
        parent: None,
        seq: 0,
        ts,
        disposition: PlaneDisposition::Active,
        body: encode(body)?,
    };
    store.upsert_plane_record(record.view())
}

/// The durable demotion record's write side. No `Debug`: `dyn Store` is not `Debug`, deliberately —
/// a backend must not be obliged to render itself, and one that did would be a place a credential
/// could surface in a log.
#[derive(Default)]
pub struct DemotionRecord {
    sink: Mutex<Option<Arc<dyn PlaneStore>>>,
}

impl DemotionRecord {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub fn set_sink(&self, store: Arc<dyn PlaneStore>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    fn sink(&self) -> Option<Arc<dyn PlaneStore>> {
        self.sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
    }

    pub(crate) fn record(&self, upstream: &str, reason: &str, now: u64) {
        let Some(store) = self.sink() else {
            return;
        };
        let row = DemotionRow {
            upstream: upstream.to_string(),
            reason: reason.to_string(),
            recorded_at: now,
        };
        if let Err(e) = upsert(&*store, KIND_DEMOTION, row.upstream.clone(), now, &row) {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_DEMOTION_WRITE_FAILED,
                server = %upstream,
                reason = %reason,
                error = %e,
                "the durable demotion record could NOT be written: this upstream is demoted in \
                 THIS process and a restart will re-open it until the next sweep looks again"
            );
        }
    }

    pub(crate) fn clear(&self, upstream: &str) {
        let Some(store) = self.sink() else {
            return;
        };
        if let Err(e) = store.delete_plane_record(KIND_DEMOTION, upstream) {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_DEMOTION_CLEAR_FAILED,
                server = %upstream,
                error = %e,
                "the durable demotion record for this upstream could NOT be cleared: it is \
                 serving again in THIS process, and a restart would re-establish a quarantine the \
                 operator has already worked"
            );
        }
    }

    pub fn read(&self) -> Result<Vec<DemotionRow>, String> {
        self.list_kind(KIND_DEMOTION)
            .map_err(|e| format!("the durable demotion records could not be read: {e}"))
    }

    fn list_kind<T: serde::de::DeserializeOwned>(&self, kind: &str) -> RecordStoreResult<Vec<T>> {
        let Some(store) = self.sink() else {
            return Ok(Vec::new());
        };
        store
            .list_plane_records(kind, &PlaneSelector::All)
            .and_then(|bodies| bodies.iter().map(|body| decode(body)).collect())
    }

    #[cfg(test)]
    pub fn list(&self) -> Vec<DemotionRow> {
        self.read().expect("the test store answers")
    }

    pub fn keep_decision(&self, row: &RulingRow, now: u64) -> Result<(), String> {
        let Some(store) = self.sink() else {
            return Ok(());
        };
        let sep = crate::host_services::DEMOTION_SEP;
        let mut id = format!("{}{sep}{}", row.instance, row.counterparty);
        if let Some(item) = &row.item {
            id.push(sep);
            id.push_str(item);
        }
        upsert(&*store, KIND_TRUST_DECISION, id, now, row).map_err(|e| e.to_string())
    }

    pub fn decisions(&self) -> Result<Vec<RulingRow>, String> {
        self.list_kind(KIND_TRUST_DECISION)
            .map_err(|e| format!("the durable trust decisions could not be read: {e}"))
    }
}

pub(crate) fn settle(demotions: &DemotionRecord, upstream: &str, state: crate::trust::TrustState) {
    match state {
        crate::trust::TrustState::Quarantined => {
            demotions.record(upstream, state.word(), busbar_kernel::store::now())
        }
        crate::trust::TrustState::Approved => demotions.clear(upstream),
        _ => {}
    }
}

#[cfg(test)]
#[path = "tests/demotion_tests.rs"]
mod demotion_tests;
