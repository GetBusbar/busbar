// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The frozen byte-layout golden for the A2A per-task provenance chain — see the doc comment on\n//! the `chain_golden` declaration in `taskstore.rs`. Relocated out of `taskstore.rs` per the\n//! tests-in-their-own-file convention.

use super::*;
use busbar_api::{PlaneRecord, PlaneSelector, StoreResult};

// The LEGACY v1 (pipe-join) GENESIS event and its successor, frozen — typed `TaskEventRow` JSON
// bodies EXACTLY as a pre-fix deployment persisted them: no `digest_version` field, so serde
// defaults them to `DIGEST_VERSION_LEGACY_PIPE` and they still verify byte-identically. The genesis
// hash proves the leading-`|` before `task_id` (the empty `prev_hash` "landmine") is in the v1
// digest input.
const A2A_1: &[u8] = br#"{"task_id":"task-1","seq":1,"ts":1700000000,"kind":"task.submitted","context_id":"ctx-1","principal":"vk_alice","agent_id":"planner","state":"submitted","request_id":"req-1","prev_hash":"","hash":"1b293d0202f52529b9ae75292c5638675a4ed2ab59e57db5b0f26016a7ef22e1"}"#;
const A2A_2: &[u8] = br#"{"task_id":"task-1","seq":2,"ts":1700000060,"kind":"task.working","context_id":"ctx-1","principal":"vk_alice","agent_id":"planner","state":"working","request_id":"req-2","prev_hash":"1b293d0202f52529b9ae75292c5638675a4ed2ab59e57db5b0f26016a7ef22e1","hash":"6059096fd763aa3293489637e995f70ca396752aa2313d7d4a05105883fe7e19"}"#;
const A2A_TAIL_HASH: &str = "6059096fd763aa3293489637e995f70ca396752aa2313d7d4a05105883fe7e19";

// The SAME two-event chain, re-sealed under the INJECTIVE v2 framing — `digest_version:2` present,
// and the hashes the length-prefixed digest produces. Frozen so a drift in the v2 preimage layout
// (field order, the domain tag, the u64-le length prefixes) fails here rather than silently
// reporting every v2 chain as tampered.
const A2A_V2_1: &[u8] = br#"{"task_id":"task-1","seq":1,"ts":1700000000,"kind":"task.submitted","context_id":"ctx-1","principal":"vk_alice","agent_id":"planner","state":"submitted","request_id":"req-1","prev_hash":"","hash":"07d3b2028b0729c42fdaae5f4d59c3a98749aa88db89caabcacb5ebe3981ec28","digest_version":2}"#;
const A2A_V2_2: &[u8] = br#"{"task_id":"task-1","seq":2,"ts":1700000060,"kind":"task.working","context_id":"ctx-1","principal":"vk_alice","agent_id":"planner","state":"working","request_id":"req-2","prev_hash":"07d3b2028b0729c42fdaae5f4d59c3a98749aa88db89caabcacb5ebe3981ec28","hash":"c77eb9be8b1da1f46888ba29c137914b17c91ec0303c61bdb99870bc5d1c9f2d","digest_version":2}"#;
const A2A_V2_TAIL_HASH: &str = "c77eb9be8b1da1f46888ba29c137914b17c91ec0303c61bdb99870bc5d1c9f2d";

/// A read-only store returning exactly the one working task and its two frozen events.
struct FrozenStore;
impl PlaneStore for FrozenStore {
    fn upsert_plane_record(&self, _r: &PlaneRecord) -> StoreResult<()> {
        Ok(())
    }
    fn get_plane_record(&self, _k: &str, _i: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, _r: &PlaneRecord) -> StoreResult<()> {
        Ok(())
    }
    fn list_plane_records(&self, kind: &str, sel: &PlaneSelector) -> StoreResult<Vec<Vec<u8>>> {
        Ok(match (kind, sel) {
            (KIND_TASK, PlaneSelector::All) => {
                let row = TaskRow {
                    task_id: "task-1".into(),
                    context_id: "ctx-1".into(),
                    principal: "vk_alice".into(),
                    direction: "inbound".into(),
                    state: "working".into(),
                    agent_id: "planner".into(),
                    artifact_cursor: 0,
                    push_callback: String::new(),
                    created_at: 1_700_000_000,
                    updated_at: 1_700_000_060,
                };
                vec![row.to_plane_record().unwrap().body]
            }
            (KIND_TASK_EVENT, PlaneSelector::Parent(p)) if p == "task-1" => {
                vec![A2A_1.to_vec(), A2A_2.to_vec()]
            }
            _ => Vec::new(),
        })
    }
    fn list_plane_record_parents(&self, _k: &str) -> StoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn purge_plane_records_before(&self, _k: &str, _b: u64) -> StoreResult<u64> {
        Ok(0)
    }
    fn delete_plane_record(&self, _k: &str, _i: &str) -> StoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(&self, _k: &str, _t: &str, _e: u64, _n: u64) -> StoreResult<bool> {
        Ok(false)
    }
}

#[test]
fn the_frozen_a2a_chain_recomputes_from_its_own_bytes() {
    let e1 = TaskEventRow::from_body(A2A_1).unwrap();
    let e2 = TaskEventRow::from_body(A2A_2).unwrap();
    // A pre-fix body carries no `digest_version`, so serde defaults it to the legacy pipe framing —
    // this is the version gate that keeps chains persisted before the fix verifiable.
    assert_eq!(
        e1.digest_version,
        crate::record::DIGEST_VERSION_LEGACY_PIPE,
        "a pre-fix body must default to the legacy framing"
    );
    // The digest recomputes to the frozen genesis hash — the byte layout is pinned.
    assert_eq!(digest_of(&e1), e1.hash, "genesis digest drifted");
    assert_eq!(
        e1.hash,
        "1b293d0202f52529b9ae75292c5638675a4ed2ab59e57db5b0f26016a7ef22e1"
    );
    assert_eq!(digest_of(&e2), e2.hash, "tail digest drifted");
    assert_eq!(e2.hash, A2A_TAIL_HASH);
    verify_chain(&[e1, e2]).expect("the frozen chain must verify");
}

/// THE v2 GOLDEN: the injective length-prefixed framing recomputes to its own frozen hashes, and the
/// re-sealed chain verifies. Guards the v2 preimage layout (domain tag, field order, u64-le length
/// prefixes) against silent drift — a change here would report every v2 chain as tampered.
#[test]
fn the_frozen_v2_chain_recomputes_from_its_own_bytes() {
    let e1 = TaskEventRow::from_body(A2A_V2_1).unwrap();
    let e2 = TaskEventRow::from_body(A2A_V2_2).unwrap();
    assert_eq!(
        e1.digest_version, DIGEST_VERSION_LEN_PREFIXED,
        "the v2 golden must carry the length-prefixed framing version"
    );
    assert_eq!(digest_of(&e1), e1.hash, "v2 genesis digest drifted");
    assert_eq!(
        e1.hash,
        "07d3b2028b0729c42fdaae5f4d59c3a98749aa88db89caabcacb5ebe3981ec28"
    );
    assert_eq!(digest_of(&e2), e2.hash, "v2 tail digest drifted");
    assert_eq!(e2.hash, A2A_V2_TAIL_HASH);
    verify_chain(&[e1, e2]).expect("the frozen v2 chain must verify");
}

/// THE REGRESSION for F-A2A2 (hash-chain field-injection forgery): two DISTINCT event tuples that
/// differ only in where a `|` falls across two attacker-influenced free-text fields. Under the old
/// pipe-join framing (v1) both produced the SAME digest input — a forgery primitive; under the
/// injective framing (v2) they MUST produce distinct digests. Fails-before (this test did not exist,
/// and v2 did not exist) / passes-after.
#[test]
fn pipe_shifting_tuples_that_collided_under_v1_are_distinct_under_v2() {
    // `("a|b", "c")` vs `("a", "b|c")` in (context_id, principal): both flatten to the same
    // `…|a|b|c|…` under the unframed pipe-join.
    let v1_a = digest_event(
        crate::record::DIGEST_VERSION_LEGACY_PIPE,
        "",
        "t",
        1,
        1,
        "k",
        "a|b",
        "c",
        "ag",
        "s",
    );
    let v1_b = digest_event(
        crate::record::DIGEST_VERSION_LEGACY_PIPE,
        "",
        "t",
        1,
        1,
        "k",
        "a",
        "b|c",
        "ag",
        "s",
    );
    assert_eq!(
        v1_a, v1_b,
        "the legacy pipe-join framing COLLIDES these two distinct tuples — the vulnerability"
    );

    let v2_a = digest_event(
        DIGEST_VERSION_LEN_PREFIXED,
        "",
        "t",
        1,
        1,
        "k",
        "a|b",
        "c",
        "ag",
        "s",
    );
    let v2_b = digest_event(
        DIGEST_VERSION_LEN_PREFIXED,
        "",
        "t",
        1,
        1,
        "k",
        "a",
        "b|c",
        "ag",
        "s",
    );
    assert_ne!(
        v2_a, v2_b,
        "the injective length-prefixed framing MUST separate these tuples — the fix"
    );
}

#[test]
fn a_boot_restore_of_the_frozen_chain_reports_no_tamper() {
    let reg = TaskRegistry::new();
    let out = reg
        .restore_from_store(&FrozenStore, crate::a2a::task::readable_row)
        .expect("store read");
    assert!(
        out.chain_breaks.is_empty(),
        "a persisted A2A chain reported TAMPERED means the digest drifted: {:?}",
        out.chain_breaks
    );
    assert_eq!(out.active, 1, "the working task is resumed");
    assert_eq!(out.unreadable, 0);
}

/// A store holding ONE undecodable task row (and one undecodable event on the good task) must not
/// lose the rest of the working set: the bad rows are COUNTED as `unreadable` and SKIPPED, the good
/// working task is still restored, and the surviving events still verify. Before the per-record
/// tolerance fix a single decode `Err` `?`-aborted the entire rehydrate.
struct PartlyUnreadableStore;
impl PlaneStore for PartlyUnreadableStore {
    fn upsert_plane_record(&self, _r: &PlaneRecord) -> StoreResult<()> {
        Ok(())
    }
    fn get_plane_record(&self, _k: &str, _i: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, _r: &PlaneRecord) -> StoreResult<()> {
        Ok(())
    }
    fn list_plane_records(&self, kind: &str, sel: &PlaneSelector) -> StoreResult<Vec<Vec<u8>>> {
        Ok(match (kind, sel) {
            (KIND_TASK, PlaneSelector::All) => {
                let good = TaskRow {
                    task_id: "task-1".into(),
                    context_id: "ctx-1".into(),
                    principal: "vk_alice".into(),
                    direction: "inbound".into(),
                    state: "working".into(),
                    agent_id: "planner".into(),
                    artifact_cursor: 0,
                    push_callback: String::new(),
                    created_at: 1_700_000_000,
                    updated_at: 1_700_000_060,
                };
                // A garbage body the row decoder cannot parse, then a good working task.
                vec![
                    b"{not a task row".to_vec(),
                    good.to_plane_record().unwrap().body,
                ]
            }
            // The good task's events, with an undecodable body wedged BETWEEN the two real ones;
            // skipping it leaves A2A_1 -> A2A_2, which still verifies.
            (KIND_TASK_EVENT, PlaneSelector::Parent(p)) if p == "task-1" => {
                vec![A2A_1.to_vec(), b"{not an event".to_vec(), A2A_2.to_vec()]
            }
            _ => Vec::new(),
        })
    }
    fn list_plane_record_parents(&self, _k: &str) -> StoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn purge_plane_records_before(&self, _k: &str, _b: u64) -> StoreResult<u64> {
        Ok(0)
    }
    fn delete_plane_record(&self, _k: &str, _i: &str) -> StoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(&self, _k: &str, _t: &str, _e: u64, _n: u64) -> StoreResult<bool> {
        Ok(false)
    }
}

#[test]
fn one_undecodable_record_does_not_drop_the_others_on_restore() {
    let reg = TaskRegistry::new();
    let out = reg
        .restore_from_store(&PartlyUnreadableStore, crate::a2a::task::readable_row)
        .expect("a single undecodable record must not abort the whole rehydrate");
    assert_eq!(
        out.unreadable, 2,
        "the undecodable task row AND the undecodable event are each counted"
    );
    assert_eq!(
        out.active, 1,
        "the GOOD working task is still restored despite the bad rows"
    );
    assert!(
        out.chain_breaks.is_empty(),
        "the surviving events still form an intact chain: {:?}",
        out.chain_breaks
    );
}
