// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE STORE SEAM — the narrowing adapter that lets a plane persist its own trust state
//! WITHOUT ever holding a handle that can write the append-only audit chain.
//!
//! [`busbar_contract::records::RecordStore`] is ONE trait that carries two unrelated authorities at once: the durable
//! governance AUDIT CHAIN (`append_audit`/`list_audit`/`list_audit_tail`) and the per-plane durable
//! state (one plane's task table, another plane's per-call log and demotion record, the spent-approval
//! ledger). Handing a plane an `Arc<dyn Store>` to persist its rows would, by the same handle, let it
//! append audit records and forge a record's `prev_hash`/`hash` — the one thing the chain exists to
//! make impossible.
//!
//! [`PlaneStore`] is the narrower of the two. It declares ONLY the eight neutral kind-tagged
//! PLANE-RECORD verbs (`upsert_plane_record`/`append_plane_record`/… over the [`PlaneRecord`]
//! envelope), and NONE of the audit-chain, credential, key, usage or metering methods.
//!
//! ## Neutral kind-tagged verbs, OPAQUE bodies
//!
//! The neutral verbs speak in an OPAQUE `body: Vec<u8>` carried on a [`PlaneRecord`] whose every other
//! field is a typed sidecar column. This crate names NO concrete plane record type: the mapping
//! between a plane concept and its `kind`, and how a plane row is serialized into (and back out of)
//! an opaque body, lives PLANE-SIDE now (each plane crate's own `to_plane_record`/`from_body`
//! helpers). Core keeps only the neutral pieces every plane shares: the `KIND_*` tag constants and the
//! generic `serde_json` [`encode`]/[`decode`] round-trip. The serde is `serde_json`, byte-for-byte the
//! same the store plugins decode it with, so a body written through this seam reads back identically
//! no matter which side of the plugin ABI persisted it.
//!
//! ## Digests are computed BEFORE they cross this seam
//!
//! Every hash-chained row a plane persists has its `prev_hash`/`hash` computed engine-side, in the
//! chain types under [`crate::audit`], BEFORE the row reaches a store method. The store — and this
//! wrapper — receives an already-sealed row and persists it verbatim; it never computes or recomputes
//! a digest.

use busbar_contract::records::{RecordStoreError, RecordStoreResult};

// THE NARROWING ADAPTER — the `PlaneStore` trait a plane persists through and the `PlaneStoreView`
// that narrows a real `busbar_contract::records::RecordStore` to it — lives in the neutral substrate so a plane crate
// holds an `Arc<dyn PlaneStore>` without naming core. Re-exported here so every in-core call site is
// unchanged.

// ── THE KIND TAG CONSTANTS (the neutral on-wire `PlaneRecord.kind` vocabulary) ───────────────────
//
// One constant per plane concept, so a consumer names a `kind` in exactly one place and a typo is a
// missing symbol rather than a silently-inert string. These are the on-wire tags a store branches on;
// they are neutral strings that name no Rust plane type, and they match the reference `impl Store` in
// `store-example-plugin` verbatim. A plane crate mirrors the constant it owns (e.g. `busbar_mcp`'s
// `KIND_CALL`, `busbar_a2a`'s `KIND_TASK`) so the tag it writes and the tag core reads agree.

/// One plane's task row kind.
pub const KIND_TASK: &str = "task";
/// That same plane's per-task provenance event kind.
pub const KIND_TASK_EVENT: &str = "task_event";
/// Another plane's per-call log record kind.
pub const KIND_CALL: &str = "call";
/// The administrative AUDIT chain record kind — the neutral store tag the administrative mutation
/// log's durable journal seam persists its hash-chained records under.
pub const KIND_AUDIT: &str = "audit";
/// That same plane's demotion record kind.
pub(crate) const KIND_DEMOTION: &str = "demotion";
/// The spent-approval ledger kind (a single-use token).
pub(crate) const KIND_ASK: &str = "ask";

/// Serialize a typed plane row into an opaque [`PlaneRecord::body`]. `serde_json`, matching the store
/// plugins' decode, so the bytes round-trip identically across the plugin ABI. Generic over any
/// `Serialize`, so this names no plane type — the caller supplies whatever neutral or plane-owned row
/// it is persisting.
pub fn encode<T: serde::Serialize>(row: &T) -> RecordStoreResult<Vec<u8>> {
    serde_json::to_vec(row).map_err(|e| RecordStoreError(format!("plane body encode: {e}")))
}

/// Decode an opaque [`PlaneRecord::body`] back into its typed plane row — the exact inverse of
/// [`encode`]. A malformed body is a STORE ERROR the caller sees, never a silently-dropped read.
pub fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> RecordStoreResult<T> {
    serde_json::from_slice(body).map_err(|e| RecordStoreError(format!("plane body decode: {e}")))
}

#[cfg(test)]
#[path = "tests/store_seam_tests.rs"]
mod store_seam_tests;

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
use busbar_contract::records::{PlaneRecord, PlaneSelector, RecordStore};
use std::sync::Arc;

/// The PLANE-FACING durable sink: exactly the eight neutral kind-tagged verbs of
/// [`busbar_contract::records::RecordStore`], and provably none of its audit-chain / key / credential / usage authority.
/// A plane persists its trust state through this and cannot reach [`RecordStore::append_audit`] because the
/// method is not on the trait.
///
/// The method names and signatures MIRROR `Store`'s neutral verbs so a `Store` implementation
/// forwards to them one-to-one (see [`PlaneStoreView`]); the mirroring is deliberate and is NOT a
/// modification of `Store` — this is an additional, strictly-narrower trait owned by core.
pub trait PlaneStore: Send + Sync + 'static {
    /// See [`RecordStore::upsert_plane_record`] — the neutral upsert (kind `task` / `demotion`).
    fn upsert_plane_record(&self, record: &PlaneRecord) -> RecordStoreResult<()>;
    /// See [`RecordStore::get_plane_record`] — the neutral point read (kind `task`).
    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>>;
    /// See [`RecordStore::append_plane_record`] — the neutral append (kind `task_event` / `call`).
    fn append_plane_record(&self, record: &PlaneRecord) -> RecordStoreResult<()>;
    /// See [`RecordStore::list_plane_records`] — the neutral list (kind × selector).
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>>;
    /// See [`RecordStore::list_plane_record_parents`] — the neutral parent enumeration (kind `call`).
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>>;
    /// See [`RecordStore::purge_plane_records_before`] — the neutral retention purge (kind `task` /
    /// `call`, honoring the terminal-only-vs-all-older split per kind).
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64>;
    /// See [`RecordStore::delete_plane_record`] — the neutral delete (kind `demotion`).
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()>;
    /// See [`RecordStore::redeem_plane_token`] — the neutral single-use test-and-set (kind `ask`).
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool>;
    /// See [`RecordStore::plane_token_live`] — the neutral MULTI-USE capability check (kind `push_config`):
    /// live while the record is present, still `Active`, and inside its deadline. Spends nothing.
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool>;
}

/// The one bridge across the plane store seam: wraps the real [`busbar_contract::records::RecordStore`] and forwards
/// each neutral verb to it, exposing ONLY [`PlaneStore`]. Boot builds one per configured store via
/// [`PlaneStoreView::narrow`] and every plane state type holds the resulting `Arc<dyn PlaneStore>`,
/// so a plane's durable writes reach the same backend the engine uses while its handle carries none
/// of the audit-chain authority `Store` also holds.
///
/// No `Debug`: `dyn Store` is deliberately not `Debug` (a backend must not be obliged to render
/// itself, where a credential could surface in a log), so neither is this.
pub struct PlaneStoreView(Arc<dyn RecordStore>);

impl PlaneStoreView {
    /// Narrow a real store handle to a plane-facing one. The ONLY place an `Arc<dyn Store>` becomes
    /// an `Arc<dyn PlaneStore>`; called once per configured store at boot.
    pub fn narrow(store: Arc<dyn RecordStore>) -> Arc<dyn PlaneStore> {
        Arc::new(Self(store))
    }
}

impl PlaneStore for PlaneStoreView {
    fn upsert_plane_record(&self, record: &PlaneRecord) -> RecordStoreResult<()> {
        self.0.upsert_plane_record(record)
    }
    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        self.0.get_plane_record(kind, id)
    }
    fn append_plane_record(&self, record: &PlaneRecord) -> RecordStoreResult<()> {
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
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        self.0.purge_plane_records_before(kind, before)
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
