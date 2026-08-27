// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE STORE SEAM — the narrowing adapter that lets a plane persist its own trust state
//! WITHOUT ever holding a handle that can write the append-only audit chain.
//!
//! [`busbar_api::Store`] is ONE trait that carries two unrelated authorities at once: the durable
//! governance AUDIT CHAIN (`append_audit`/`list_audit`/`list_audit_tail`) and the per-plane durable
//! state (the A2A task table, the MCP per-call log, the MCP demotion record, the spent-approval
//! ledger). Handing a plane an `Arc<dyn Store>` to persist its task rows would, by the same handle,
//! let it append audit records and forge a record's `prev_hash`/`hash` — the one thing the chain
//! exists to make impossible.
//!
//! [`PlaneStore`] is the narrower of the two. It declares ONLY the eight neutral kind-tagged
//! PLANE-RECORD verbs (`upsert_plane_record`/`append_plane_record`/… over the [`PlaneRecord`]
//! envelope), and NONE of the audit-chain, credential, key, usage or metering methods. It is a NEW
//! trait owned by core, not a re-hierarching of `Store`: the external store plugins
//! (sqlite/postgres/valkey/mysql) still `impl busbar_api::Store` unchanged, so nothing about the
//! signed plugin ABI moves.
//!
//! ## Neutral kind-tagged verbs, typed rows on either side
//!
//! Core speaks in TYPED rows (`TaskRow`, `TaskEventRow`, `McpCallRecord`, `McpDemotionRow`); the
//! neutral verbs speak in an OPAQUE `body: Vec<u8>` carried on a [`PlaneRecord`] whose every other
//! field is a typed sidecar column. The mapping between the two — which plane concept is which
//! `kind`, and how a typed row is serialized into (and back out of) an opaque body — lives in the
//! free helpers at the bottom of this module ([`task_record`], [`decode`], the `KIND_*` constants,
//! …), so a consumer builds a [`PlaneRecord`] with one call and reads a body back with one call. The
//! serde is `serde_json`, byte-for-byte the same the store plugins decode it with, so a body written
//! through this seam reads back identically no matter which side of the plugin ABI persisted it.
//!
//! [`PlaneStoreView`] is the one bridge across the seam. It wraps an `Arc<dyn Store>` and forwards
//! each neutral verb to the store's matching neutral verb, one-to-one. Boot constructs exactly one
//! and hands the plane state types an `Arc<dyn PlaneStore>`; from there no plane ever sees an
//! `Arc<dyn Store>` again.
//!
//! ## Digests are computed BEFORE they cross this seam
//!
//! Every hash-chained row the plane persists (`TaskEventRow`, `McpCallRecord`, the per-task chain)
//! has its `prev_hash`/`hash` computed engine-side, in the chain types under this module
//! (`TaskChain`, `CallChain`, `provenance`), BEFORE the row reaches a store method. The store — and
//! therefore this wrapper — receives an already-sealed row and persists it verbatim; it never
//! computes or recomputes a digest. So `PlaneStoreView` is a PURE FORWARDER: no `audit::Chain`, no
//! signing key, no `GovCtx` is needed inside it, and none crosses to a plane. If a future plane
//! method ever needed a digest computed at the seam, it would be computed HERE, inside the wrapper,
//! against engine-owned material — never by handing the plane the material to compute it itself.

use busbar_api::{
    McpCallRecord, McpDemotionRow, PlaneDisposition, PlaneRecord, StoreError, StoreResult,
    TaskEventRow, TaskRow,
};

// THE NARROWING ADAPTER — the `PlaneStore` trait a plane persists through and the `PlaneStoreView`
// that narrows a real `busbar_api::Store` to it — relocated to the neutral substrate so a plane crate
// holds an `Arc<dyn PlaneStore>` without naming core. Re-exported here so every in-core call site
// (`crate::plane::store::PlaneStore`, `PlaneStoreView::narrow` at boot, the plane trust-state
// `set_sink`s, the test doubles' `impl PlaneStore`) is unchanged. The typed-row `KIND_*` mapping and
// the `encode`/`decode`/record builders below stay core beside the plane row types they serialize.
pub use busbar_substrate::plane::store::{PlaneStore, PlaneStoreView};

// The full `busbar_api::Store` trait and the `PlaneSelector` list selector are named only by the
// test-only named-vocabulary extension (`StoreNamedTestExt`) and the `task_event`/`call` read-back
// helpers below now that the narrowing adapter moved to the substrate; gate their import to test
// builds so it is not an unused import under `-D warnings`.
#[cfg(test)]
use busbar_api::{PlaneSelector, Store};

// ── THE KIND↔CONCEPT MAPPING (the 14→8 table's row-per-concept, made concrete) ─────────────────
//
// One constant per plane concept, so a consumer names a `kind` in exactly one place and a typo is a
// missing symbol rather than a silently-inert string. These are the on-wire tags a store branches
// on; they match the reference `impl Store` in `store-example-plugin` verbatim.

/// The A2A task row kind — the neutral `put_task`/`get_task`/`list_tasks`/`purge_tasks_before`.
pub const KIND_TASK: &str = "task";
/// The A2A per-task provenance event kind — the neutral `append_task_event`/`list_task_events`.
pub const KIND_TASK_EVENT: &str = "task_event";
/// The MCP per-call log record kind — the neutral `append_mcp_call`/`list_mcp_calls`/… .
pub const KIND_CALL: &str = "call";
/// The admin AUDIT chain record kind — the neutral store tag the admin mutation log's durable
/// journal seam persists its hash-chained records under (scope = the constant `admin` log). Distinct
/// from the legacy `append_audit`/`list_audit` table; the durable seam writes these as plane records.
pub const KIND_AUDIT: &str = "audit";
/// The MCP demotion record kind — the neutral `put_mcp_demotion`/`list_mcp_demotions`/… .
pub(crate) const KIND_DEMOTION: &str = "demotion";
/// The spent-approval ledger kind — the neutral `redeem_ask_state` (a single-use token).
pub(crate) const KIND_ASK: &str = "ask";

/// The A2A task states that are FINAL — the terminal set the task kind's retention contract drops.
/// Kept beside the mapping (not re-derived at each call site) so the `disposition` a record carries
/// and the purge that reads it agree by construction.
const TERMINAL_TASK_STATES: [&str; 4] = ["completed", "failed", "canceled", "rejected"];

/// Serialize a typed plane row into an opaque [`PlaneRecord::body`]. `serde_json`, matching the
/// store plugins' decode, so the bytes round-trip identically across the plugin ABI.
///
/// Deliberately `pub(crate)`, NOT `pub`: this is the row-FORGING primitive the in-core tamper tests
/// use to stage a mutated persisted body. When the `store` module is widened to `pub` under the
/// test-support surface (so the extracted planes can name the read-side helpers), `encode` stays
/// crate-private so no out-of-crate caller can mint a forged row through this crate's own encoder —
/// tamper discipline is a property of the module, not of any one build's feature set.
pub(crate) fn encode<T: serde::Serialize>(row: &T) -> StoreResult<Vec<u8>> {
    serde_json::to_vec(row).map_err(|e| StoreError(format!("plane body encode: {e}")))
}

/// Decode an opaque [`PlaneRecord::body`] back into its typed plane row — the exact inverse of
/// [`encode`]. A malformed body is a STORE ERROR the caller sees, never a silently-dropped read.
pub fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> StoreResult<T> {
    serde_json::from_slice(body).map_err(|e| StoreError(format!("plane body decode: {e}")))
}

/// Build the neutral upsert envelope for an A2A task row (kind `task`). `ts` is the row's
/// `updated_at` (the axis retention compares against) and `disposition` is `Terminal` exactly when
/// the task's state is final, so `purge_plane_records_before` can honor the terminal-only contract
/// from the typed sidecar without decoding the body.
pub fn task_record(row: &TaskRow) -> StoreResult<PlaneRecord> {
    let disposition = if TERMINAL_TASK_STATES.contains(&row.state.as_str()) {
        PlaneDisposition::Terminal
    } else {
        PlaneDisposition::Active
    };
    Ok(PlaneRecord {
        kind: KIND_TASK.to_string(),
        id: row.task_id.clone(),
        parent: None,
        seq: 0,
        ts: row.updated_at,
        disposition,
        body: encode(row)?,
    })
}

/// Build the neutral append envelope for a per-task provenance event (kind `task_event`), hung off
/// its task via `parent` and ordered by the event's own `seq`.
pub fn task_event_record(event: &TaskEventRow) -> StoreResult<PlaneRecord> {
    Ok(PlaneRecord {
        kind: KIND_TASK_EVENT.to_string(),
        id: event.task_id.clone(),
        parent: Some(event.task_id.clone()),
        seq: event.seq,
        ts: event.ts,
        disposition: PlaneDisposition::Active,
        body: encode(event)?,
    })
}

/// Build the neutral append envelope for an MCP per-call record (kind `call`), hung off its
/// principal via `parent` and ordered by the record's own `seq`. The `call` kind's retention drops
/// ALL rows older than a cutoff, so its disposition is immaterial to the purge and is left `Active`.
pub fn call_record(record: &McpCallRecord) -> StoreResult<PlaneRecord> {
    Ok(PlaneRecord {
        kind: KIND_CALL.to_string(),
        id: record.principal.clone(),
        parent: Some(record.principal.clone()),
        seq: record.seq,
        ts: record.ts,
        disposition: PlaneDisposition::Active,
        body: encode(record)?,
    })
}

/// Build the neutral upsert envelope for an MCP demotion record (kind `demotion`), keyed by its
/// server. Demotions are never purged by age (they clear on an agreeing observation, not a cutoff),
/// so the disposition is immaterial and left `Active`.
pub fn demotion_record(row: &McpDemotionRow) -> StoreResult<PlaneRecord> {
    Ok(PlaneRecord {
        kind: KIND_DEMOTION.to_string(),
        id: row.server.clone(),
        parent: None,
        seq: 0,
        ts: row.recorded_at,
        disposition: PlaneDisposition::Active,
        body: encode(row)?,
    })
}

/// TEST-ONLY convenience reads/writes in the OLD protocol-named vocabulary, expressed over the
/// neutral kind-tagged `Store` verbs. The named `Store` trait methods were deleted in the 1.6.0
/// 14→8 collapse; the plane test suites still read and write in typed-row terms
/// (`get_task`/`list_mcp_calls`/…), and this blanket-impl'd extension keeps those call sites terse
/// and byte-identical to the neutral path without re-introducing anything on the shipped trait. It
/// exists only under `cfg(test)`. A test double that keeps its own typed map provides INHERENT
/// methods of the same names, which win method resolution over this blanket impl (so a double reads
/// its own storage), while a bare `dyn Store` resolves here.
/// TEST-ONLY read-back DECODE BRIDGE for a `task_event` body: reconstruct a [`TaskEventRow`] from the
/// NEW neutral `{seq,prev_hash,hash,content}` body the durable seam persists (P5-C9), OR an OLD
/// `serde(TaskEventRow)` body a store held before the cleave. Digest-faithful: the rebuilt fields feed
/// `TaskEventRow::digest_fields` the SAME bytes the stored `hash` was sealed over (the neutral
/// `content` is the pre-framed suffix `|ts|kind|context_id|principal|agent_id|state`), so a chain read
/// back through it `verify_chain`-passes byte-identically. `request_id` is never in the digest and is
/// absent from the neutral body, so it comes back empty.
#[cfg(test)]
pub fn task_event_row_from_body(task_id: &str, body: &[u8]) -> StoreResult<TaskEventRow> {
    use crate::audit::journal::NeutralBody;
    if let Ok(nb) = decode::<NeutralBody>(body) {
        let suffix = String::from_utf8_lossy(&nb.content);
        let f: Vec<&str> = suffix.trim_start_matches('|').splitn(6, '|').collect();
        return Ok(TaskEventRow {
            task_id: task_id.to_string(),
            seq: nb.seq,
            ts: f.first().and_then(|v| v.parse().ok()).unwrap_or(0),
            kind: f.get(1).copied().unwrap_or_default().to_string(),
            context_id: f.get(2).copied().unwrap_or_default().to_string(),
            principal: f.get(3).copied().unwrap_or_default().to_string(),
            agent_id: f.get(4).copied().unwrap_or_default().to_string(),
            state: f.get(5).copied().unwrap_or_default().to_string(),
            request_id: String::new(),
            prev_hash: nb.prev_hash,
            hash: nb.hash,
        });
    }
    decode::<TaskEventRow>(body)
}

#[cfg(test)]
#[allow(dead_code)] // a complete named-vocabulary surface; not every method is exercised by every suite
pub(crate) trait StoreNamedTestExt: Store {
    fn put_task(&self, task: &TaskRow) -> StoreResult<()> {
        self.upsert_plane_record(&task_record(task)?)
    }
    fn get_task(&self, task_id: &str) -> StoreResult<Option<TaskRow>> {
        self.get_plane_record(KIND_TASK, task_id)?
            .map(|b| decode(&b))
            .transpose()
    }
    fn list_tasks(&self) -> StoreResult<Vec<TaskRow>> {
        self.list_plane_records(KIND_TASK, &PlaneSelector::All)?
            .iter()
            .map(|b| decode(b))
            .collect()
    }
    fn purge_tasks_before(&self, before: u64) -> StoreResult<u64> {
        self.purge_plane_records_before(KIND_TASK, before)
    }
    fn append_task_event(&self, event: &TaskEventRow) -> StoreResult<()> {
        self.append_plane_record(&task_event_record(event)?)
    }
    fn list_task_events(&self, task_id: &str) -> StoreResult<Vec<TaskEventRow>> {
        self.list_plane_records(KIND_TASK_EVENT, &PlaneSelector::Parent(task_id.to_string()))?
            .iter()
            .map(|b| task_event_row_from_body(task_id, b))
            .collect()
    }
    fn append_mcp_call(&self, record: &McpCallRecord) -> StoreResult<()> {
        self.append_plane_record(&call_record(record)?)
    }
    fn list_mcp_calls(&self, principal: &str) -> StoreResult<Vec<McpCallRecord>> {
        self.list_plane_records(KIND_CALL, &PlaneSelector::Parent(principal.to_string()))?
            .iter()
            .map(|b| crate::calllog::mcp_call_record_from_body(principal, b))
            .collect()
    }
    fn list_mcp_call_principals(&self) -> StoreResult<Vec<String>> {
        self.list_plane_record_parents(KIND_CALL)
    }
    fn purge_mcp_calls_before(&self, before: u64) -> StoreResult<u64> {
        self.purge_plane_records_before(KIND_CALL, before)
    }
    fn put_mcp_demotion(&self, row: &McpDemotionRow) -> StoreResult<()> {
        self.upsert_plane_record(&demotion_record(row)?)
    }
    fn list_mcp_demotions(&self) -> StoreResult<Vec<McpDemotionRow>> {
        self.list_plane_records(KIND_DEMOTION, &PlaneSelector::All)?
            .iter()
            .map(|b| decode(b))
            .collect()
    }
    fn clear_mcp_demotion(&self, server: &str) -> StoreResult<()> {
        self.delete_plane_record(KIND_DEMOTION, server)
    }
    fn redeem_ask_state(&self, nonce: &str, expires_at: u64, now: u64) -> StoreResult<bool> {
        self.redeem_plane_token(KIND_ASK, nonce, expires_at, now)
    }
}

#[cfg(test)]
impl<T: Store + ?Sized> StoreNamedTestExt for T {}

#[cfg(test)]
#[path = "tests/store_seam_tests.rs"]
mod store_seam_tests;
