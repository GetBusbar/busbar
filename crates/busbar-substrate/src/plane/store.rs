// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE STORE SEAM'S NARROWING ADAPTER — the trait a plane persists through and the one bridge
//! that narrows a real `busbar_api::Store` to it, relocated to the neutral substrate so a plane crate
//! holds an `Arc<dyn PlaneStore>` without naming `busbar_core::plane::store`.
//!
//! [`PlaneStore`] declares ONLY the eight neutral kind-tagged PLANE-RECORD verbs and NONE of the
//! audit-chain / credential / key / usage authority `busbar_api::Store` also carries; [`PlaneStoreView`]
//! wraps an `Arc<dyn Store>` and forwards each verb one-to-one, exposing only [`PlaneStore`]. Both name
//! only `busbar_api` leaf types (`PlaneRecord`/`PlaneSelector`/`StoreResult`/`Store`), so they live
//! here; core re-exports them, so `crate::plane::store::{PlaneStore, PlaneStoreView}` still resolves
//! there. The typed-row `KIND_*` mapping, the `encode`/`decode` bridge and the record builders stay
//! core beside the plane row types they serialize.

use busbar_api::{PlaneRecord, PlaneSelector, Store, StoreResult};
use std::sync::Arc;

/// The PLANE-FACING durable sink: exactly the eight neutral kind-tagged verbs of
/// [`busbar_api::Store`], and provably none of its audit-chain / key / credential / usage authority.
/// A plane persists its trust state through this and cannot reach [`Store::append_audit`] because the
/// method is not on the trait.
///
/// The method names and signatures MIRROR `Store`'s neutral verbs so a `Store` implementation
/// forwards to them one-to-one (see [`PlaneStoreView`]); the mirroring is deliberate and is NOT a
/// modification of `Store` — this is an additional, strictly-narrower trait owned by core.
pub trait PlaneStore: Send + Sync + 'static {
    /// See [`Store::upsert_plane_record`] — the neutral upsert (kind `task` / `demotion`).
    fn upsert_plane_record(&self, record: &PlaneRecord) -> StoreResult<()>;
    /// See [`Store::get_plane_record`] — the neutral point read (kind `task`).
    fn get_plane_record(&self, kind: &str, id: &str) -> StoreResult<Option<Vec<u8>>>;
    /// See [`Store::append_plane_record`] — the neutral append (kind `task_event` / `call`).
    fn append_plane_record(&self, record: &PlaneRecord) -> StoreResult<()>;
    /// See [`Store::list_plane_records`] — the neutral list (kind × selector).
    fn list_plane_records(&self, kind: &str, selector: &PlaneSelector)
        -> StoreResult<Vec<Vec<u8>>>;
    /// See [`Store::list_plane_record_parents`] — the neutral parent enumeration (kind `call`).
    fn list_plane_record_parents(&self, kind: &str) -> StoreResult<Vec<String>>;
    /// See [`Store::purge_plane_records_before`] — the neutral retention purge (kind `task` /
    /// `call`, honoring the terminal-only-vs-all-older split per kind).
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> StoreResult<u64>;
    /// See [`Store::delete_plane_record`] — the neutral delete (kind `demotion`).
    fn delete_plane_record(&self, kind: &str, id: &str) -> StoreResult<()>;
    /// See [`Store::redeem_plane_token`] — the neutral single-use test-and-set (kind `ask`).
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> StoreResult<bool>;
}

/// The one bridge across the plane store seam: wraps the real [`busbar_api::Store`] and forwards
/// each neutral verb to it, exposing ONLY [`PlaneStore`]. Boot builds one per configured store via
/// [`PlaneStoreView::narrow`] and every plane state type holds the resulting `Arc<dyn PlaneStore>`,
/// so a plane's durable writes reach the same backend the engine uses while its handle carries none
/// of the audit-chain authority `Store` also holds.
///
/// No `Debug`: `dyn Store` is deliberately not `Debug` (a backend must not be obliged to render
/// itself, where a credential could surface in a log), so neither is this.
pub struct PlaneStoreView(Arc<dyn Store>);

impl PlaneStoreView {
    /// Narrow a real store handle to a plane-facing one. The ONLY place an `Arc<dyn Store>` becomes
    /// an `Arc<dyn PlaneStore>`; called once per configured store at boot.
    pub fn narrow(store: Arc<dyn Store>) -> Arc<dyn PlaneStore> {
        Arc::new(Self(store))
    }
}

impl PlaneStore for PlaneStoreView {
    fn upsert_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        self.0.upsert_plane_record(record)
    }
    fn get_plane_record(&self, kind: &str, id: &str) -> StoreResult<Option<Vec<u8>>> {
        self.0.get_plane_record(kind, id)
    }
    fn append_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        self.0.append_plane_record(record)
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        self.0.list_plane_records(kind, selector)
    }
    fn list_plane_record_parents(&self, kind: &str) -> StoreResult<Vec<String>> {
        self.0.list_plane_record_parents(kind)
    }
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> StoreResult<u64> {
        self.0.purge_plane_records_before(kind, before)
    }
    fn delete_plane_record(&self, kind: &str, id: &str) -> StoreResult<()> {
        self.0.delete_plane_record(kind, id)
    }
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> StoreResult<bool> {
        self.0.redeem_plane_token(kind, token, expires_at, now)
    }
}
