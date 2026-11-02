// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::store::plane_view::{decode, PlaneStore, KIND_AUDIT};
use busbar_contract::records::{AuditRecord, PlaneRecordRef, PlaneSelector, RecordStoreResult};

/// The one field this golden reads back off a frozen scoped-stream body — the tail digest. Decoded
/// through a NEUTRAL local shape (matching the on-disk field name) so this core test names no stream
/// record type: the frozen bytes are opaque persisted evidence, and all the golden asserts of them is
/// that the digest the past build sealed is still the one they carry.
#[derive(serde::Deserialize)]
struct FrozenTailDigest {
    hash: String,
}

const SCOPED_1: &[u8] = br#"{"seq":1,"prev_hash":"","hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718","content":[0,0,0,0,0,0,0,8,0,0,0,0,101,83,241,0,0,0,0,0,0,0,0,3,115,114,118,0,0,0,0,0,0,0,8,115,114,118,95,116,111,111,108,0,0,0,0,0,0,0,10,100,105,115,112,97,116,99,104,101,100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6,97,98,99,49,50,51,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,7]}"#;
const SCOPED_2: &[u8] = br#"{"seq":2,"prev_hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718","hash":"721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a","content":[0,0,0,0,0,0,0,8,0,0,0,0,101,83,241,60,0,0,0,0,0,0,0,3,115,114,118,0,0,0,0,0,0,0,9,115,114,118,95,111,116,104,101,114,0,0,0,0,0,0,0,7,114,101,102,117,115,101,100,0,0,0,0,0,0,0,11,110,111,116,95,103,114,97,110,116,101,100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,7]}"#;

pub(in crate::audit) const AD_1: &[u8] = br#"{"seq":1,"ts":1700000000,"action":"hook.register","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"","hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"}"#;
pub(in crate::audit) const AD_2: &[u8] = br#"{"seq":2,"ts":1700000060,"action":"hook.delete","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa","hash":"33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264"}"#;

const SCOPED_TAIL_HASH: &str = "721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a";
const AD_TAIL_HASH: &str = "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264";

struct FrozenStore {
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
    fn upsert_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        let parent = match selector {
            PlaneSelector::All => None,
            PlaneSelector::Parent(p) => Some(p.to_string()),
        };
        Ok(self
            .rows
            .get(&(kind.to_string(), parent))
            .cloned()
            .unwrap_or_default())
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
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
    fn purge_plane_records(
        &self,
        _kind: &str,
        _before: u64,
        _retention: busbar_contract::records::Retention,
    ) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(true)
    }

    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }
}

const KIND_SCOPED: &str = "scoped_golden";

const FROZEN_SCOPE: &str = "vk_alice";

fn scoped_reframe(
    scope: &str,
    body: &[u8],
) -> RecordStoreResult<crate::audit::stream_registry::StreamRecord> {
    let b: crate::audit::journal::NeutralBody = decode(body)?;
    Ok(crate::audit::stream_registry::StreamRecord::from_parts(
        scope.to_string(),
        b.seq,
        b.prev_hash,
        b.hash,
        b.content,
        crate::audit::Framing::LengthPrefixed,
        true,
    ))
}

#[test]
fn scoped_chain_boot_verifies_from_frozen_bytes() {
    use crate::audit::stream_registry;

    let mut store = FrozenStore::new();
    store.put(KIND_SCOPED, Some(FROZEN_SCOPE), SCOPED_1);
    store.put(KIND_SCOPED, Some(FROZEN_SCOPE), SCOPED_2);
    let bodies = store
        .list_plane_records(KIND_SCOPED, &PlaneSelector::Parent(FROZEN_SCOPE.into()))
        .expect("store read");

    let kind_id = crate::audit::auditlog::fresh_test_kind_id();
    stream_registry::register(
        kind_id,
        KIND_SCOPED.to_string(),
        crate::audit::Framing::LengthPrefixed,
        true,
        stream_registry::Decode::Native(scoped_reframe),
        usize::MAX,
        None,
    );
    let broke = stream_registry::seed(kind_id, FROZEN_SCOPE, &bodies).expect("the bodies decode");
    assert!(
        !broke,
        "a persisted length-prefixed scoped chain reported TAMPERED means the digest drifted"
    );

    let tail: FrozenTailDigest = decode(SCOPED_2).unwrap();
    assert_eq!(tail.hash, SCOPED_TAIL_HASH);
    let (seq, prev_hash, _hash) =
        stream_registry::append_full(kind_id, FROZEN_SCOPE, b"next").expect("append");
    assert_eq!(
        (seq, prev_hash.as_str()),
        (3, SCOPED_TAIL_HASH),
        "the chain resumes after its frozen tail"
    );
}

#[test]
fn admin_audit_chain_boot_verifies_from_frozen_bytes() {
    let neutral = |frozen: &[u8]| {
        let r: AuditRecord = decode(frozen).unwrap();
        crate::store::plane_view::encode(&crate::audit::journal::NeutralBody {
            seq: r.seq,
            prev_hash: r.prev_hash,
            hash: r.hash,
            content: crate::audit::auditlog::audit_suffix(
                r.ts,
                &r.action,
                &r.resource,
                &r.outcome,
                &r.principal,
            ),
        })
        .unwrap()
    };
    let mut store = FrozenStore::new();
    store.put(KIND_AUDIT, Some("admin"), &neutral(AD_1));
    store.put(KIND_AUDIT, Some("admin"), &neutral(AD_2));

    let h = crate::audit::auditlog::AuditTestHarness::over(crate::real_store::store());
    let restored = h.restore_from_store(&store).expect("store read");
    assert!(
        restored.chain_breaks.is_empty(),
        "a persisted admin chain reported TAMPERED means the digest drifted: {:?}",
        restored.chain_breaks
    );
    assert_eq!(restored.records, 2, "both frozen records restored");

    let tail: AuditRecord = decode(AD_2).unwrap();
    assert_eq!(tail.hash, AD_TAIL_HASH);

    let head: AuditRecord = decode(AD_1).unwrap();
    let ring = h
        .log
        .list_filtered(0, crate::audit_ring::MAX_AUDIT_ENTRIES, None, None);
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
