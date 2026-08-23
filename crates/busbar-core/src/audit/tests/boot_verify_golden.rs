// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PERSISTED-FIXTURE BOOT-VERIFY GOLDEN — the tripwire for silent digest drift.
//!
//! ## Why this file, and why it is not the recompute goldens
//!
//! `chain_tests.rs` already proves the three real digests "did not move" by recomputing each
//! formula the OLD way, in-test, and requiring the mechanism to agree. That is a real guard, but it
//! is a recompute against a HAND-ROLLED formula living in the same build: if a future refactor moved
//! BOTH the production digest and a parallel test formula the same way, it could pass while every
//! deployed store began reporting TAMPERED at its next boot. That is the exact failure the chain
//! cleave risks — the seq-authority state machine is being relocated into a generic `audit::Journal`,
//! and the one thing that must not change is the bytes a persisted record hashes to.
//!
//! So this golden is a different KIND of check. The fixtures below are OPAQUE PERSISTED BYTES —
//! the verbatim `serde_json` bodies a store holds on disk — captured from the code at the moment the
//! cleave began and FROZEN as literals. Each carries its own `hash`, computed by that past build.
//! The test hands these frozen bytes to the SAME boot-verify runtime path a real restart runs
//! (`PlaneCallLog::restore_from_store`, `TaskRegistry::restore_from_store`, and the shared
//! `verify_chain` the admin ring restore walks), which decodes each body and RECOMPUTES the digest
//! from the record's own fields. If the recompute no longer equals the frozen `hash`, the chain
//! fails to verify and this test goes RED — before a single deployed store does. The expected hash is
//! a constant produced by a past build, not a value this build recomputes, so it cannot drift with
//! the code the way a parallel formula can.
//!
//! ## Coverage — all three framings, plus the two landmines
//!
//! - **MCP per-call** (`LengthPrefixed`, scope in the digest) — the CLEAN cleave-first target.
//! - **A2A task provenance** (`PipeSeparated`, scope in the digest) — carries the PipeSeparated
//!   GENESIS LANDMINE: the first event's `prev_hash` is empty, and the leading `|` before `task_id`
//!   that the empty-but-present `prev_hash` produces is load-bearing. A cleave that dropped it would
//!   shift every A2A digest by one separator.
//! - **Admin audit** (`PipeSeparated`, NO scope in the digest) — the `digests_scope = false` shape,
//!   proving the generic prelude framing omits the scope for exactly the streams that omit it.
//!
//! Every fixture is a two-record chain: record 1 is GENESIS (empty `prev_hash`), record 2 LINKS it,
//! so both the genesis anchor and the inter-record linkage are exercised. DO NOT REGENERATE these
//! bytes to make a failing test pass: a change here is a change to a persisted digest, and the test
//! failing is the tripwire working.

use crate::plane::store::{
    decode, encode, PlaneStore, KIND_AUDIT, KIND_CALL, KIND_TASK, KIND_TASK_EVENT,
};
use busbar_api::{
    AuditRecord, McpCallRecord, PlaneRecord, PlaneSelector, StoreResult, TaskEventRow, TaskRow,
};

// ── THE FROZEN PERSISTED BYTES — captured from the pre-cleave build, opaque on purpose ──────────
//
// These are the verbatim `serde_json` bodies a store returns from `list_plane_records`. Each embeds
// the `hash` the pre-cleave engine computed. They are treated as opaque here: the test decodes and
// verifies them through the real boot path and NEVER recomputes them to compare against itself.

const MCP_1: &[u8] = br#"{"principal":"vk_alice","seq":1,"ts":1700000000,"server":"srv","tool":"srv_tool","outcome":"dispatched","reason":"","tool_digest":"abc123","pin_generation":7,"request_id":"req-1","prev_hash":"","hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718"}"#;
const MCP_2: &[u8] = br#"{"principal":"vk_alice","seq":2,"ts":1700000060,"server":"srv","tool":"srv_other","outcome":"refused","reason":"not_granted","tool_digest":"","pin_generation":7,"request_id":"req-2","prev_hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718","hash":"721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a"}"#;

const A2A_1: &[u8] = br#"{"task_id":"task-1","seq":1,"ts":1700000000,"kind":"task.submitted","context_id":"ctx-1","principal":"vk_alice","agent_id":"planner","state":"submitted","request_id":"req-1","prev_hash":"","hash":"1b293d0202f52529b9ae75292c5638675a4ed2ab59e57db5b0f26016a7ef22e1"}"#;
const A2A_2: &[u8] = br#"{"task_id":"task-1","seq":2,"ts":1700000060,"kind":"task.working","context_id":"ctx-1","principal":"vk_alice","agent_id":"planner","state":"working","request_id":"req-2","prev_hash":"1b293d0202f52529b9ae75292c5638675a4ed2ab59e57db5b0f26016a7ef22e1","hash":"6059096fd763aa3293489637e995f70ca396752aa2313d7d4a05105883fe7e19"}"#;

const AD_1: &[u8] = br#"{"seq":1,"ts":1700000000,"action":"hook.register","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"","hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"}"#;
const AD_2: &[u8] = br#"{"seq":2,"ts":1700000060,"action":"hook.delete","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa","hash":"33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264"}"#;

// The frozen hashes named explicitly, so a diff of this file shows WHICH digest a change perturbed
// rather than only "some bytes moved". They are the tail links of each two-record chain.
const MCP_TAIL_HASH: &str = "721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a";
const A2A_TAIL_HASH: &str = "6059096fd763aa3293489637e995f70ca396752aa2313d7d4a05105883fe7e19";
const AD_TAIL_HASH: &str = "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264";

// ── A FROZEN-BYTES PLANE STORE ──────────────────────────────────────────────────────────────────
//
// Serves the opaque fixture bodies back VERBATIM, exactly as a durable backend that persisted them
// before this process started would. It computes nothing and interprets nothing — the whole point is
// that the bytes crossing back into the engine are the frozen ones, not anything this build produced.

struct FrozenStore {
    /// kind -> parent -> ordered bodies. `None` parent is the `All` bucket.
    rows: std::collections::HashMap<(String, Option<String>), Vec<Vec<u8>>>,
}

impl FrozenStore {
    fn new() -> Self {
        Self {
            rows: std::collections::HashMap::new(),
        }
    }
    fn put(&mut self, kind: &str, parent: Option<&str>, body: &[u8]) {
        self.rows
            .entry((kind.to_string(), parent.map(str::to_string)))
            .or_default()
            .push(body.to_vec());
    }
}

impl PlaneStore for FrozenStore {
    fn upsert_plane_record(&self, _record: &PlaneRecord) -> StoreResult<()> {
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, _record: &PlaneRecord) -> StoreResult<()> {
        Ok(())
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        let parent = match selector {
            PlaneSelector::All => None,
            PlaneSelector::Parent(p) => Some(p.clone()),
        };
        Ok(self
            .rows
            .get(&(kind.to_string(), parent))
            .cloned()
            .unwrap_or_default())
    }
    fn list_plane_record_parents(&self, kind: &str) -> StoreResult<Vec<String>> {
        let mut parents: Vec<String> = self
            .rows
            .keys()
            .filter(|(k, _)| k == kind)
            .filter_map(|(_, p)| p.clone())
            .collect();
        parents.sort();
        parents.dedup();
        Ok(parents)
    }
    fn purge_plane_records_before(&self, _kind: &str, _before: u64) -> StoreResult<u64> {
        Ok(0)
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> StoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> StoreResult<bool> {
        Ok(true)
    }
}

/// MCP per-call chain (LengthPrefixed, scope-in-digest): the frozen opaque bodies restore through the
/// REAL boot path and verify byte-identically — zero chain breaks — with the tail hash intact.
#[test]
fn mcp_call_chain_boot_verifies_from_frozen_bytes() {
    let mut store = FrozenStore::new();
    store.put(KIND_CALL, Some("vk_alice"), MCP_1);
    store.put(KIND_CALL, Some("vk_alice"), MCP_2);

    // The chain position cache is host-side now: register a fresh isolated stream and host-drive the
    // rehydrate. The FROZEN BYTES/HASHES above are unchanged — only the scaffolding that replays them
    // through the durable seam changed. The rehydrate SEEDS positions from the store passed here (the
    // frozen bytes), so the throwaway app the harness registers against is immaterial to the digests.
    let h = crate::plane::calllog::CallTestHarness::over(std::sync::Arc::new(
        busbar_store_memory::MemoryStore::new(),
    ));
    let restored = h.restore_from_store(&store).expect("store read");
    assert!(
        restored.chain_breaks.is_empty(),
        "a persisted MCP chain reported TAMPERED means the digest drifted: {:?}",
        restored.chain_breaks
    );
    assert_eq!(restored.principals, 1);
    assert_eq!(restored.records, 2, "both frozen records restored");
    assert_eq!(restored.empty_chains, 0);

    // And the tail hash the pre-cleave build wrote is exactly what the frozen bytes still carry.
    let tail: McpCallRecord = decode(MCP_2).unwrap();
    assert_eq!(tail.hash, MCP_TAIL_HASH);
}

/// A2A task provenance chain (PipeSeparated, scope-in-digest, GENESIS LANDMINE): the frozen opaque
/// events restore through the real boot path and verify — proving the leading-`|` before `task_id`
/// that the empty genesis `prev_hash` produces is preserved by the framing.
#[test]
fn a2a_task_chain_boot_verifies_from_frozen_bytes() {
    // The task row is NOT hash-chained (only its events are), so it is built here rather than frozen;
    // it must be a non-terminal row `Task::from_row` accepts so the events are loaded and verified.
    let task_row = TaskRow {
        task_id: "task-1".to_string(),
        context_id: "ctx-1".to_string(),
        principal: "vk_alice".to_string(),
        direction: "inbound".to_string(),
        state: "working".to_string(),
        agent_id: "planner".to_string(),
        artifact_cursor: 0,
        push_callback: String::new(),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_060,
    };
    let mut store = FrozenStore::new();
    store.put(KIND_TASK, None, &encode(&task_row).unwrap());
    store.put(KIND_TASK_EVENT, Some("task-1"), A2A_1);
    store.put(KIND_TASK_EVENT, Some("task-1"), A2A_2);

    // The chain position cache is host-side now: register a fresh isolated stream and host-drive the
    // rehydrate. The FROZEN BYTES/HASHES above are unchanged — only the scaffolding that replays them
    // through the durable seam changed. The rehydrate SEEDS positions from the store passed here (the
    // frozen bytes), so the throwaway app the harness registers against is immaterial to the digests.
    let h = crate::plane::taskstore::TaskTestHarness::over(std::sync::Arc::new(
        busbar_store_memory::MemoryStore::new(),
    ));
    let rehydrated = h
        .host(|host| h.reg.restore_from_store(host, &store))
        .expect("store read");
    assert!(
        rehydrated.chain_breaks.is_empty(),
        "a persisted A2A chain reported TAMPERED means the digest drifted: {:?}",
        rehydrated.chain_breaks
    );
    assert_eq!(rehydrated.active, 1, "the working task is resumed");
    assert_eq!(rehydrated.unreadable, 0);

    let tail: TaskEventRow = decode(A2A_2).unwrap();
    assert_eq!(tail.hash, A2A_TAIL_HASH);
}

/// Admin audit chain (PipeSeparated, NO scope in the digest): the frozen opaque records restore
/// through the REAL boot path — the NEUTRAL journal seam the admin audit stream is registered on, with
/// `digests_scope = false` — and verify byte-identically (zero chain breaks) with the tail hash intact.
/// This is the `digests_scope = false` framing shape: the scope must NOT enter the digest, and the
/// frozen bytes are the legacy `serde(AuditRecord)` rows, reframed by the stream's own decode bridge.
#[test]
fn admin_audit_chain_boot_verifies_from_frozen_bytes() {
    let mut store = FrozenStore::new();
    store.put(KIND_AUDIT, Some("admin"), AD_1);
    store.put(KIND_AUDIT, Some("admin"), AD_2);

    // The chain position cache is host-side now: register a fresh isolated stream and host-drive the
    // restore. The FROZEN BYTES/HASHES above are unchanged — only the scaffolding that replays them
    // through the durable seam changed. The restore SEEDS positions from the store passed here (the
    // frozen bytes), so the throwaway app the harness registers against is immaterial to the digests.
    let h = crate::plane::auditlog::AuditTestHarness::over(std::sync::Arc::new(
        busbar_store_memory::MemoryStore::new(),
    ));
    let restored = h.restore_from_store(&store).expect("store read");
    assert!(
        restored.chain_breaks.is_empty(),
        "a persisted admin chain reported TAMPERED means the digest drifted: {:?}",
        restored.chain_breaks
    );
    assert_eq!(restored.records, 2, "both frozen records restored");

    let tail: AuditRecord = decode(AD_2).unwrap();
    assert_eq!(tail.hash, AD_TAIL_HASH);

    // A7.3b: the restore ALSO seeds the read-model RING (the source `GET /audit` reads once cut over).
    // The seeded ring must equal the frozen tail byte-for-byte, newest-first — a perturbation of the
    // reframe/decode or the seq-ordered push would fail this against the same frozen bytes above.
    let head: AuditRecord = decode(AD_1).unwrap();
    let ring = h
        .log
        .list_filtered(0, crate::admin::audit::MAX_AUDIT_ENTRIES, None, None);
    assert_eq!(
        ring.len(),
        2,
        "the ring is seeded with both restored records"
    );
    assert_eq!(
        (ring[0].seq, ring[0].hash.as_str()),
        (tail.seq, tail.hash.as_str()),
        "newest-first: the tail record leads"
    );
    assert_eq!(
        (ring[1].seq, ring[1].hash.as_str()),
        (head.seq, head.hash.as_str()),
        "the older record follows, seq-ordered"
    );
    assert!(
        ring.iter().all(|e| !e.recorded_here),
        "restored ring entries are seeded (recorded_here = false), never live appends"
    );
}
