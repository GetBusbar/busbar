// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE STORE SEAM — the narrowing adapter that lets a plane persist its own trust state
//! WITHOUT ever holding a handle that can write the append-only audit chain.
//!
//! [`busbar_api::Store`] is ONE trait that carries two unrelated authorities at once: the durable
//! governance AUDIT CHAIN (`append_audit`/`list_audit`/`list_audit_tail`) and the per-plane durable
//! state (the A2A task table, the MCP per-call log, the MCP demotion record, the spent-approval
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

use busbar_api::{StoreError, StoreResult};

// THE NARROWING ADAPTER — the `PlaneStore` trait a plane persists through and the `PlaneStoreView`
// that narrows a real `busbar_api::Store` to it — lives in the neutral substrate so a plane crate
// holds an `Arc<dyn PlaneStore>` without naming core. Re-exported here so every in-core call site is
// unchanged.
pub use busbar_substrate::plane::store::{PlaneStore, PlaneStoreView};

// ── THE KIND TAG CONSTANTS (the neutral on-wire `PlaneRecord.kind` vocabulary) ───────────────────
//
// One constant per plane concept, so a consumer names a `kind` in exactly one place and a typo is a
// missing symbol rather than a silently-inert string. These are the on-wire tags a store branches on;
// they are neutral strings that name no Rust plane type, and they match the reference `impl Store` in
// `store-example-plugin` verbatim. A plane crate mirrors the constant it owns (e.g. `busbar_mcp`'s
// `KIND_CALL`, `busbar_a2a`'s `KIND_TASK`) so the tag it writes and the tag core reads agree.

/// The A2A task row kind.
pub const KIND_TASK: &str = "task";
/// The A2A per-task provenance event kind.
pub const KIND_TASK_EVENT: &str = "task_event";
/// The MCP per-call log record kind.
pub const KIND_CALL: &str = "call";
/// The admin AUDIT chain record kind — the neutral store tag the admin mutation log's durable journal
/// seam persists its hash-chained records under.
pub const KIND_AUDIT: &str = "audit";
/// The MCP demotion record kind.
pub(crate) const KIND_DEMOTION: &str = "demotion";
/// The spent-approval ledger kind (a single-use token).
pub(crate) const KIND_ASK: &str = "ask";

/// Serialize a typed plane row into an opaque [`PlaneRecord::body`]. `serde_json`, matching the store
/// plugins' decode, so the bytes round-trip identically across the plugin ABI. Generic over any
/// `Serialize`, so this names no plane type — the caller supplies whatever neutral or plane-owned row
/// it is persisting.
pub fn encode<T: serde::Serialize>(row: &T) -> StoreResult<Vec<u8>> {
    serde_json::to_vec(row).map_err(|e| StoreError(format!("plane body encode: {e}")))
}

/// Decode an opaque [`PlaneRecord::body`] back into its typed plane row — the exact inverse of
/// [`encode`]. A malformed body is a STORE ERROR the caller sees, never a silently-dropped read.
pub fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> StoreResult<T> {
    serde_json::from_slice(body).map_err(|e| StoreError(format!("plane body decode: {e}")))
}

#[cfg(test)]
#[path = "tests/store_seam_tests.rs"]
mod store_seam_tests;
