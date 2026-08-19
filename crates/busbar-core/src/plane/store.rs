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
//! [`PlaneStore`] is the narrower of the two. It declares ONLY the plane methods, with the SAME
//! names and signatures they carry on `Store`, and NONE of the audit-chain, credential, key, usage
//! or metering methods. It is a NEW trait owned by core, not a re-hierarching of `Store`: the
//! external store plugins (sqlite/postgres/valkey/mysql) still `impl busbar_api::Store` unchanged, so
//! nothing about the signed plugin ABI moves.
//!
//! [`PlaneStoreView`] is the one bridge across the seam. It wraps an `Arc<dyn Store>` and forwards
//! each plane method to it. Boot constructs exactly one and hands the plane state types an
//! `Arc<dyn PlaneStore>`; from there no plane ever sees an `Arc<dyn Store>` again.
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

use busbar_api::{McpCallRecord, McpDemotionRow, Store, StoreResult, TaskEventRow, TaskRow};
use std::sync::Arc;

/// The PLANE-FACING durable sink: exactly the plane methods of [`busbar_api::Store`], and provably
/// none of its audit-chain / key / credential / usage authority. A plane persists its trust state
/// through this and cannot reach [`Store::append_audit`] because the method is not on the trait.
///
/// The method names and signatures MIRROR `Store`'s so a `Store` implementation forwards to them
/// one-to-one (see [`PlaneStoreView`]); the mirroring is deliberate and is NOT a modification of
/// `Store` — this is an additional, strictly-narrower trait owned by core.
pub(crate) trait PlaneStore: Send + Sync + 'static {
    // ── A2A TASK STATE ───────────────────────────────────────────────────────────────────────
    /// See [`Store::put_task`].
    fn put_task(&self, task: &TaskRow) -> StoreResult<()>;
    /// See [`Store::get_task`].
    fn get_task(&self, task_id: &str) -> StoreResult<Option<TaskRow>>;
    /// See [`Store::list_tasks`].
    fn list_tasks(&self) -> StoreResult<Vec<TaskRow>>;
    /// See [`Store::purge_tasks_before`].
    fn purge_tasks_before(&self, before: u64) -> StoreResult<u64>;
    /// See [`Store::append_task_event`].
    fn append_task_event(&self, event: &TaskEventRow) -> StoreResult<()>;
    /// See [`Store::list_task_events`].
    fn list_task_events(&self, task_id: &str) -> StoreResult<Vec<TaskEventRow>>;

    // ── MCP PER-CALL LOG ─────────────────────────────────────────────────────────────────────
    /// See [`Store::append_mcp_call`].
    fn append_mcp_call(&self, record: &McpCallRecord) -> StoreResult<()>;
    /// See [`Store::list_mcp_calls`].
    fn list_mcp_calls(&self, principal: &str) -> StoreResult<Vec<McpCallRecord>>;
    /// See [`Store::list_mcp_call_principals`].
    fn list_mcp_call_principals(&self) -> StoreResult<Vec<String>>;
    /// See [`Store::purge_mcp_calls_before`].
    fn purge_mcp_calls_before(&self, before: u64) -> StoreResult<u64>;

    // ── MCP DEMOTION RECORD ──────────────────────────────────────────────────────────────────
    /// See [`Store::put_mcp_demotion`].
    fn put_mcp_demotion(&self, row: &McpDemotionRow) -> StoreResult<()>;
    /// See [`Store::list_mcp_demotions`].
    fn list_mcp_demotions(&self) -> StoreResult<Vec<McpDemotionRow>>;
    /// See [`Store::clear_mcp_demotion`].
    fn clear_mcp_demotion(&self, server: &str) -> StoreResult<()>;

    // ── SPENT-APPROVAL LEDGER ────────────────────────────────────────────────────────────────
    /// See [`Store::redeem_ask_state`].
    fn redeem_ask_state(&self, nonce: &str, expires_at: u64, now: u64) -> StoreResult<bool>;
}

/// The one bridge across the plane store seam: wraps the real [`busbar_api::Store`] and forwards
/// each plane method to it, exposing ONLY [`PlaneStore`]. Boot builds one per configured store via
/// [`PlaneStoreView::narrow`] and every plane state type holds the resulting `Arc<dyn PlaneStore>`,
/// so a plane's durable writes reach the same backend the engine uses while its handle carries none
/// of the audit-chain authority `Store` also holds.
///
/// No `Debug`: `dyn Store` is deliberately not `Debug` (a backend must not be obliged to render
/// itself, where a credential could surface in a log), so neither is this.
pub(crate) struct PlaneStoreView(Arc<dyn Store>);

impl PlaneStoreView {
    /// Narrow a real store handle to a plane-facing one. The ONLY place an `Arc<dyn Store>` becomes
    /// an `Arc<dyn PlaneStore>`; called once per configured store at boot.
    pub(crate) fn narrow(store: Arc<dyn Store>) -> Arc<dyn PlaneStore> {
        Arc::new(Self(store))
    }
}

impl PlaneStore for PlaneStoreView {
    fn put_task(&self, task: &TaskRow) -> StoreResult<()> {
        self.0.put_task(task)
    }
    fn get_task(&self, task_id: &str) -> StoreResult<Option<TaskRow>> {
        self.0.get_task(task_id)
    }
    fn list_tasks(&self) -> StoreResult<Vec<TaskRow>> {
        self.0.list_tasks()
    }
    fn purge_tasks_before(&self, before: u64) -> StoreResult<u64> {
        self.0.purge_tasks_before(before)
    }
    fn append_task_event(&self, event: &TaskEventRow) -> StoreResult<()> {
        self.0.append_task_event(event)
    }
    fn list_task_events(&self, task_id: &str) -> StoreResult<Vec<TaskEventRow>> {
        self.0.list_task_events(task_id)
    }
    fn append_mcp_call(&self, record: &McpCallRecord) -> StoreResult<()> {
        self.0.append_mcp_call(record)
    }
    fn list_mcp_calls(&self, principal: &str) -> StoreResult<Vec<McpCallRecord>> {
        self.0.list_mcp_calls(principal)
    }
    fn list_mcp_call_principals(&self) -> StoreResult<Vec<String>> {
        self.0.list_mcp_call_principals()
    }
    fn purge_mcp_calls_before(&self, before: u64) -> StoreResult<u64> {
        self.0.purge_mcp_calls_before(before)
    }
    fn put_mcp_demotion(&self, row: &McpDemotionRow) -> StoreResult<()> {
        self.0.put_mcp_demotion(row)
    }
    fn list_mcp_demotions(&self) -> StoreResult<Vec<McpDemotionRow>> {
        self.0.list_mcp_demotions()
    }
    fn clear_mcp_demotion(&self, server: &str) -> StoreResult<()> {
        self.0.clear_mcp_demotion(server)
    }
    fn redeem_ask_state(&self, nonce: &str, expires_at: u64, now: u64) -> StoreResult<bool> {
        self.0.redeem_ask_state(nonce, expires_at, now)
    }
}

#[cfg(test)]
#[path = "tests/store_seam_tests.rs"]
mod store_seam_tests;
