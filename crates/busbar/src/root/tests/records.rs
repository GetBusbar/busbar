// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PERSISTED-FIXTURE BOOT-VERIFY GOLDEN, replayed through the record leg.
//!
//! ## Why this file, and why it is not a recompute
//!
//! A recompute golden proves a digest "did not move" by computing it a second way in the same
//! build. That is a real guard, but a refactor that moved the production digest and the test's
//! parallel formula the same way would pass it while every deployed store began reporting TAMPERED
//! at its next boot.
//!
//! So this is a different KIND of check. The fixtures below are OPAQUE PERSISTED BYTES — the
//! verbatim bodies a store holds on disk — captured from the code at the moment the durable chain
//! was first cleaved off its engine, and FROZEN as literals. Each carries its own `hash`, computed
//! by that past build. The test hands them to the SAME path a real restart runs, which decodes each
//! body and RECOMPUTES the digest from the record's own fields. If the recompute no longer equals
//! the frozen hash, the chain fails to verify and this test goes RED — before a single deployed
//! store does.
//!
//! ## What moved under them, and what did not
//!
//! The bytes did not move. What moved is everything around them: the chain that used to be minted
//! through a foreign-function seam inside the engine is now minted by the audit unit, admitted by
//! the kernel as a record leg, and landed on the published store protocol by the composition root.
//! Three owners instead of one file, and the same digest — which is the whole claim, and is why
//! these fixtures are replayed here rather than regenerated.
//!
//! Both fixtures are two-record chains: record one is GENESIS (empty previous hash), record two
//! LINKS it, so the genesis anchor and the inter-record linkage are both exercised. DO NOT
//! REGENERATE these bytes to make a failing test pass: a change here is a change to a persisted
//! digest, and the test failing is the tripwire working.

use std::sync::Arc;

use busbar_api::{PlaneRecord, PlaneSelector, StoreResult};
use busbar_plane_admin::records as audit_record;
use busbar_plane_mcp::records as call_record;
use busbar_unit_audit::legacy::Framing;

use super::{DeclaredSchemas, RecordLeg};

// ── THE FROZEN PERSISTED BYTES — opaque on purpose ──────────────────────────────────────────────
//
// The call chain's bodies are the neutral envelope a store holds post-cleave: `{seq, prev_hash,
// hash, content}`, where `content` is the length-prefixed field suffix the digest was sealed over.
const MCP_1: &[u8] = br#"{"seq":1,"prev_hash":"","hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718","content":[0,0,0,0,0,0,0,8,0,0,0,0,101,83,241,0,0,0,0,0,0,0,0,3,115,114,118,0,0,0,0,0,0,0,8,115,114,118,95,116,111,111,108,0,0,0,0,0,0,0,10,100,105,115,112,97,116,99,104,101,100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6,97,98,99,49,50,51,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,7]}"#;
const MCP_2: &[u8] = br#"{"seq":2,"prev_hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718","hash":"721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a","content":[0,0,0,0,0,0,0,8,0,0,0,0,101,83,241,60,0,0,0,0,0,0,0,3,115,114,118,0,0,0,0,0,0,0,9,115,114,118,95,111,116,104,101,114,0,0,0,0,0,0,0,7,114,101,102,117,115,101,100,0,0,0,0,0,0,0,11,110,111,116,95,103,114,97,110,116,101,100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,7]}"#;

// The audit chain's bodies are the PREVIOUS RELEASE's flat rows, which is the whole point of them:
// a store that has never been written to since the upgrade still holds exactly these, and the leg
// has to verify them without re-sealing a single one.
const AD_1: &[u8] = br#"{"seq":1,"ts":1700000000,"action":"hook.register","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"","hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"}"#;
const AD_2: &[u8] = br#"{"seq":2,"ts":1700000060,"action":"hook.delete","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa","hash":"33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264"}"#;

/// The tail links of the two chains, named explicitly so a diff of this file shows WHICH digest a
/// change perturbed rather than only that some bytes moved.
const MCP_TAIL_HASH: &str = "721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a";
const AD_TAIL_HASH: &str = "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264";

/// The chain scopes each fixture was written under.
const MCP_SCOPE: &str = "vk_alice";
const AD_SCOPE: &str = "admin";

// ── A FROZEN-BYTES STORE ────────────────────────────────────────────────────────────────────────
//
// Serves the opaque fixture bodies back VERBATIM, exactly as a durable backend that persisted them
// before this process started would. It computes nothing and interprets nothing — the whole point
// is that the bytes crossing back into the leg are the frozen ones, not anything this build made.

/// Kind and parent to the bodies held under them, which is the whole of what a record leg asks a
/// store for.
type FrozenRows = std::collections::HashMap<(String, String), Vec<Vec<u8>>>;

#[derive(Default)]
struct FrozenStore {
    rows: std::sync::Mutex<FrozenRows>,
}

impl FrozenStore {
    fn with(kind: &str, parent: &str, bodies: &[&[u8]]) -> Arc<Self> {
        let store = Arc::new(FrozenStore::default());
        store.rows.lock().unwrap().insert(
            (kind.to_string(), parent.to_string()),
            bodies.iter().map(|b| b.to_vec()).collect(),
        );
        store
    }
}

impl busbar_api::Store for FrozenStore {
    // The four key verbs and the four accounting verbs are the store protocol's REQUIRED half and
    // have nothing to do with a record leg. They are answered emptily here on purpose: a fixture
    // that implemented them would be a second store, and the one thing this one must do is hand
    // back the frozen bytes unaltered.
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

    fn list_plane_record_parents(&self, kind: &str) -> StoreResult<Vec<String>> {
        let rows = self.rows.lock().unwrap();
        let mut parents: Vec<String> = rows
            .keys()
            .filter(|(k, _)| k == kind)
            .map(|(_, p)| p.clone())
            .collect();
        parents.sort();
        Ok(parents)
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        let parent = match selector {
            PlaneSelector::All => return Ok(Vec::new()),
            PlaneSelector::Parent(p) => p.clone(),
        };
        Ok(self
            .rows
            .lock()
            .unwrap()
            .get(&(kind.to_string(), parent))
            .cloned()
            .unwrap_or_default())
    }

    fn append_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        self.rows
            .lock()
            .unwrap()
            .entry((
                record.kind.clone(),
                record.parent.clone().unwrap_or_default(),
            ))
            .or_default()
            .push(record.body.clone());
        Ok(())
    }
}

/// The call stream's leg: the MCP plane's declared schema, length-prefixed, with the principal in
/// the digest, over whatever store it is handed.
fn call_leg(store: Arc<dyn busbar_api::Store>) -> RecordLeg {
    RecordLeg::new(
        store,
        Box::new(DeclaredSchemas::of(
            call_record::RECORD_SCHEMAS,
            call_record::operations_for,
        )),
        call_record::SCHEMA_CALL,
        Framing::LengthPrefixed,
        true,
        None,
    )
}

/// The audit stream's leg: the admin plane's declared schema, pipe-separated, with the scope OUT of
/// the digest, and the previous release's flat row recognised on the way in.
fn audit_leg(store: Arc<dyn busbar_api::Store>) -> RecordLeg {
    RecordLeg::new(
        store,
        Box::new(DeclaredSchemas::of(
            audit_record::RECORD_SCHEMAS,
            audit_record::operations_for,
        )),
        audit_record::SCHEMA_AUDIT,
        Framing::PipeSeparated,
        false,
        Some(audit_record::legacy_row),
    )
}

/// THE CALL CHAIN (length-prefixed, scope in the digest): the frozen opaque bodies restore through
/// the leg and verify byte-identically — zero chain breaks — with the tail hash intact.
#[test]
fn the_call_chain_boot_verifies_from_frozen_bytes() {
    let store = FrozenStore::with("call", MCP_SCOPE, &[MCP_1, MCP_2]);
    let leg = call_leg(store);

    let restored = leg.restore().expect("the store reads");
    assert!(
        restored.chain_breaks.is_empty(),
        "a persisted call chain reported TAMPERED means the digest drifted: {:?}",
        restored.chain_breaks
    );
    assert_eq!(restored.scopes, 1);
    assert_eq!(restored.records, 2, "both frozen records restored");
    assert_eq!(restored.unreadable, 0);
    assert_eq!(restored.empty_chains, 0);
    assert_eq!(
        restored.rows.last().expect("a tail").hash,
        MCP_TAIL_HASH,
        "the tail the past build sealed is the one these bytes still carry"
    );
}

/// THE AUDIT CHAIN (pipe-separated, scope NOT in the digest): the previous release's flat rows
/// restore through the leg and verify byte-identically, with the tail hash intact.
///
/// The scope must stay OUT of the prelude here. Folding it in would frame one extra field before
/// the sequence and make every already-persisted admin record report a digest mismatch at the next
/// boot — which is precisely what these two rows are here to catch.
#[test]
fn the_audit_chain_boot_verifies_from_frozen_bytes() {
    let store = FrozenStore::with("audit", AD_SCOPE, &[AD_1, AD_2]);
    let leg = audit_leg(store);

    let restored = leg.restore().expect("the store reads");
    assert!(
        restored.chain_breaks.is_empty(),
        "a persisted admin chain reported TAMPERED means the digest drifted: {:?}",
        restored.chain_breaks
    );
    assert_eq!(restored.scopes, 1);
    assert_eq!(restored.records, 2, "both frozen records restored");
    assert_eq!(restored.unreadable, 0);
    assert_eq!(
        restored.rows.last().expect("a tail").hash,
        AD_TAIL_HASH,
        "the tail the past build sealed is the one these bytes still carry"
    );
    assert_eq!(
        audit_record::parse_audit_suffix(&restored.rows[1].content).action,
        "hook.delete",
        "the suffix the digest was sealed over reads back as the record it was"
    );
}

/// A restored chain CONTINUES: the next append takes the sequence after the restored tail and links
/// to its hash, so a restart adds to the persisted chain rather than opening a second one under the
/// same scope at sequence one.
#[test]
fn an_append_after_a_restore_continues_the_persisted_chain() {
    let store = FrozenStore::with("audit", AD_SCOPE, &[AD_1, AD_2]);
    let leg = audit_leg(store);
    leg.restore().expect("the store reads");
    assert_eq!(leg.next_seq(AD_SCOPE), 3);

    let suffix = audit_record::audit_suffix(
        1_700_000_120,
        "hook.replace",
        "hook:compress",
        "applied",
        "admin",
    );
    let appended = leg
        .append(AD_SCOPE, audit_record::OP_APPEND, 1_700_000_120, &suffix)
        .expect("the leg is admitted and the store keeps it");
    assert_eq!(appended.seq, 3);
    assert_eq!(
        appended.prev_hash, AD_TAIL_HASH,
        "the new record links to the persisted tail"
    );

    // And reading the whole chain back verifies it, genesis to the record just written.
    let reread = leg.restore().expect("the store reads");
    assert_eq!(reread.records, 3);
    assert!(
        reread.chain_breaks.is_empty(),
        "the appended record extended the frozen chain: {:?}",
        reread.chain_breaks
    );
}

/// The KERNEL refuses a leg the plane never declared, and the store is never reached.
///
/// The three checks are the kernel's, in the one place a leg is run, and this asserts the leg is
/// actually going through it rather than around it.
#[test]
fn a_leg_the_schema_does_not_declare_is_refused_before_the_store() {
    let store = FrozenStore::with("audit", AD_SCOPE, &[]);
    let leg = audit_leg(store.clone());
    let error = leg
        .append(AD_SCOPE, "delete", 1, b"|1|a|r|applied|admin")
        .expect_err("the audit schema declares append and scan only");
    assert!(
        format!("{error}").contains("delete"),
        "the refusal names what was attempted: {error}"
    );
    assert!(
        store.rows.lock().unwrap()[&("audit".to_string(), AD_SCOPE.to_string())].is_empty(),
        "a refused leg wrote nothing"
    );
}

/// A row nothing recognises is COUNTED and SKIPPED, never invented and never fatal.
///
/// Aborting the restore on one bad row would leave every chain after it unseeded and fork it at
/// sequence one on the next append — a governance durability loss triggered by a single corrupt
/// byte. The good rows still restore, and the count is what carries the loss back.
#[test]
fn an_unreadable_row_is_counted_and_skipped_rather_than_aborting_the_restore() {
    let store = FrozenStore::with("audit", AD_SCOPE, &[AD_1, b"{ not a record }", AD_2]);
    let leg = audit_leg(store);
    let restored = leg.restore().expect("the store reads");
    assert_eq!(restored.unreadable, 1);
    assert_eq!(restored.records, 2, "the readable rows still restored");
    assert!(restored.chain_breaks.is_empty());
}

/// A TAMPERED row is REPORTED and the chain still resumes from the broken tail.
///
/// Refusing to restore a chain that does not verify would turn a detection control into a deletion
/// primitive: anyone who could write to the store could erase a whole history by corrupting one
/// byte of one record.
#[test]
fn a_tampered_row_is_reported_and_the_chain_still_resumes() {
    let edited = AD_2.to_vec();
    let edited = String::from_utf8(edited)
        .unwrap()
        .replace("hook.delete", "hook.keeper")
        .into_bytes();
    let store = FrozenStore::with("audit", AD_SCOPE, &[AD_1, &edited]);
    let leg = audit_leg(store);
    let restored = leg.restore().expect("the store reads");
    assert_eq!(restored.chain_breaks.len(), 1, "the edit is detected");
    assert_eq!(restored.records, 2, "and the rows are still restored");
    assert_eq!(
        leg.next_seq(AD_SCOPE),
        3,
        "the chain resumes from the broken tail rather than stopping the evidence"
    );
}
