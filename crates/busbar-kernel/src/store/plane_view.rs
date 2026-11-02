// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::{PlaneRecordRef, RecordStoreError, RecordStoreResult};

pub const KIND_AUDIT: &str = "audit";

pub const KIND_RESIDUAL: &str = "usage_residual";

pub const KIND_DEMOTION: &str = "demotion";

pub const KIND_TRUST_DECISION: &str = "trust_decision";

pub const KERNEL_RECORD_KINDS: &[&str] = &[
    KIND_AUDIT,
    KIND_RESIDUAL,
    KIND_DEMOTION,
    KIND_TRUST_DECISION,
    crate::governance::TICKET_RECORD_KIND,
];

const PLANE_OWNED_LABEL: &str = "\u{1}plane\u{1}";

#[must_use]
pub fn plane_owned_kind(plane: &str, kind: &str) -> Option<String> {
    let fit = |s: &str| !s.is_empty() && !s.chars().any(char::is_control);
    (fit(plane) && fit(kind)).then(|| format!("{PLANE_OWNED_LABEL}{plane}\u{1}{kind}"))
}

pub fn encode<T: serde::Serialize>(row: &T) -> RecordStoreResult<Vec<u8>> {
    serde_json::to_vec(row).map_err(|e| RecordStoreError(format!("plane body encode: {e}")))
}

pub fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> RecordStoreResult<T> {
    serde_json::from_slice(body).map_err(|e| RecordStoreError(format!("plane body decode: {e}")))
}

#[cfg(test)]
#[path = "tests/plane_view_tests.rs"]
mod plane_view_tests;

use busbar_contract::records::{PlaneSelector, RecordStore, Retention};
use std::sync::Arc;

pub trait PlaneStore: Send + Sync + 'static {
    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()>;

    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>>;

    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()>;

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>>;

    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>>;

    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64>;

    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()>;

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool>;

    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool>;
}

pub struct PlaneStoreView(Arc<dyn RecordStore>);

impl PlaneStoreView {
    pub fn narrow(store: Arc<dyn RecordStore>) -> Arc<dyn PlaneStore> {
        Arc::new(Self(store))
    }
}

impl PlaneStore for PlaneStoreView {
    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.0.upsert_plane_record(record)
    }
    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        self.0.get_plane_record(kind, id)
    }
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.0.append_plane_record(record)
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        self.0.list_plane_records(kind, selector)
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        self.0.list_plane_record_parents(kind)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        self.0.purge_plane_records(kind, before, retention)
    }
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.0.delete_plane_record(kind, id)
    }
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.0.redeem_plane_token(kind, token, expires_at, now)
    }
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.0.plane_token_live(kind, token, expires_at, now)
    }
}
