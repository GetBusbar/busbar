// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane/auditlog.rs`.

use super::*;
use crate::audit::{digest, frame_prelude, Framing};

/// THE BYTE-IDENTITY GATE: the plane's pre-framed suffix, appended RAW after the host prelude
/// framed with `digests_scope = false`, reproduces the legacy [`AuditEntry`] digest byte-for-byte.
/// A perturbation of the suffix, the prelude framing, or the `digests_scope` flag would fail this.
fn assert_roundtrip(seq: u64, prev_hash: &str, ts: u64, act: &str, res: &str, out: &str, pr: &str) {
    // The seam's digest input: frame_prelude(PipeSeparated, prev_hash, None=no scope, seq) ⧺ suffix.
    let mut input = frame_prelude(Framing::PipeSeparated, prev_hash, None, seq);
    input.extend_from_slice(&audit_suffix(ts, act, res, out, pr));
    let via_seam = busbar_api::sha256_hex(&input);

    // The legacy digest: the AuditEntry's own `digest_fields` through the ONE canonicaliser.
    let entry = AuditEntry {
        seq,
        ts,
        action: act.to_string(),
        resource: res.to_string(),
        outcome: out.to_string(),
        principal: pr.to_string(),
        prev_hash: prev_hash.to_string(),
        hash: String::new(),
        recorded_here: true,
    };
    let legacy = digest(&entry);
    assert_eq!(
        via_seam, legacy,
        "seam digest (digests_scope=false) must byte-equal the legacy AuditEntry digest"
    );
}

#[test]
fn suffix_plus_scopeless_prelude_equals_legacy_audit_digest() {
    // Genesis (empty prev_hash) — the leading `|` before `seq` the empty prev_hash produces is
    // load-bearing; and a linked record.
    assert_roundtrip(
        1,
        "",
        1_700_000_000,
        "hook.register",
        "hook:compress",
        "applied",
        "admin",
    );
    assert_roundtrip(
        2,
        "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa",
        1_700_000_060,
        "hook.delete",
        "hook:compress",
        "applied",
        "admin",
    );
}

/// THE CONVERSION GATE: a converted site's record, appended through the SEAM, carries the SAME hash
/// the legacy admin ring computes for the same fields at the same chain position — genesis AND the
/// inter-record link. Feeds a fixed `ts` on both sides (the seam suffix built directly, the legacy
/// `AuditEntry` filled directly) so the comparison isolates the digest, not the clock.
#[test]
fn a_converted_sites_seam_record_matches_the_legacy_ring_hash() {
    let h = AuditTestHarness::over(std::sync::Arc::new(busbar_store_memory::MemoryStore::new()));
    let (ts, act, res, out, pr) = (
        1_700_000_123u64,
        "hook.register",
        "hook:x",
        "applied",
        "admin",
    );

    // Append through the seam (the converted-site path) and read the link each append sealed.
    let (seq1, prev1, hash1) = h.emit_full(ADMIN_LOG, audit_suffix(ts, act, res, out, pr));
    let (seq2, prev2, hash2) = h.emit_full(
        ADMIN_LOG,
        audit_suffix(ts + 60, "hook.delete", res, out, pr),
    );

    // The legacy ring's records for the SAME fields at the SAME chain positions.
    let mk = |seq, ts, action: &str, prev: String| AuditEntry {
        seq,
        ts,
        action: action.to_string(),
        resource: res.to_string(),
        outcome: out.to_string(),
        principal: pr.to_string(),
        prev_hash: prev,
        hash: String::new(),
        recorded_here: true,
    };
    assert_eq!((seq1, prev1.as_str()), (1, ""), "genesis position");
    assert_eq!(hash1, digest(&mk(1, ts, act, String::new())));
    assert_eq!((seq2, prev2), (2, hash1.clone()), "record 2 links record 1");
    assert_eq!(hash2, digest(&mk(2, ts + 60, "hook.delete", hash1)));
}

// ── A COMBINED DURABLE STORE DOUBLE for the boot-restore + migration witnesses ────────────────────
//
// MemoryStore uses the trait DEFAULTS for the audit table AND for `plane_records` (accept-and-keep-
// nothing), so it cannot back a durable round-trip. This double persists BOTH: the legacy audit table
// (`append_audit`/`list_audit`) and the neutral `plane_records` (`append_plane_record`/
// `list_plane_records`/`list_plane_record_parents`), delegating everything else to an inner MemoryStore
// so `GovState::new` is satisfied. `parent` keys `plane_records`, appended in seq order as a real
// backend would.
/// kind + optional parent → ordered opaque bodies, the `plane_records` a durable backend keeps.
type PlaneRows = std::collections::HashMap<(String, Option<String>), Vec<Vec<u8>>>;

struct DualDurableStore {
    inner: busbar_store_memory::MemoryStore,
    audit: std::sync::Mutex<std::collections::BTreeMap<u64, busbar_api::AuditRecord>>,
    plane: std::sync::Mutex<PlaneRows>,
}

impl DualDurableStore {
    fn new() -> Self {
        Self {
            inner: busbar_store_memory::MemoryStore::new(),
            audit: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            plane: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl busbar_api::Store for DualDurableStore {
    fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    // ── the legacy audit table ──
    fn append_audit(&self, entry: &busbar_api::AuditRecord) -> busbar_api::StoreResult<()> {
        self.audit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(entry.seq, entry.clone());
        Ok(())
    }
    fn list_audit(&self) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
        Ok(self
            .audit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }
    fn list_audit_tail(&self, limit: u64) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
        let limit = limit as usize;
        let audit = self.audit.lock().unwrap_or_else(|e| e.into_inner());
        let len = audit.len();
        Ok(audit
            .values()
            .skip(len.saturating_sub(limit))
            .cloned()
            .collect())
    }
    // ── the neutral plane_records ──
    fn append_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
        self.plane
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry((record.kind.clone(), record.parent.clone()))
            .or_default()
            .push(record.body.clone());
        Ok(())
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &busbar_api::PlaneSelector,
    ) -> busbar_api::StoreResult<Vec<Vec<u8>>> {
        let parent = match selector {
            busbar_api::PlaneSelector::All => None,
            busbar_api::PlaneSelector::Parent(p) => Some(p.clone()),
        };
        Ok(self
            .plane
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(kind.to_string(), parent))
            .cloned()
            .unwrap_or_default())
    }
    fn list_plane_record_parents(&self, kind: &str) -> busbar_api::StoreResult<Vec<String>> {
        let mut parents: Vec<String> = self
            .plane
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .filter(|(k, _)| k == kind)
            .filter_map(|(_, p)| p.clone())
            .collect();
        parents.sort();
        parents.dedup();
        Ok(parents)
    }
}

/// WITNESS (a) — ROUND-TRIP: a mutation written through the SEAM into `plane_records`, then a
/// simulated REBOOT (a fresh log + fresh chain positions over the SAME store) restores FROM
/// `plane_records`, verifies the chain (zero breaks), and yields records + digests + `GET /audit`
/// output BYTE-IDENTICAL to the legacy admin ring for the same fields at the same positions.
#[test]
fn seam_write_then_reboot_restore_roundtrips_byte_identically() {
    let store: std::sync::Arc<dyn busbar_api::Store> = std::sync::Arc::new(DualDurableStore::new());
    let (ts, res, out, pr) = (1_700_000_500u64, "hook:rt", "applied", "admin");

    // Process 1: two mutations through the seam. This PERSISTS the neutral bodies to `plane_records`.
    let h1 = AuditTestHarness::over(store.clone());
    let (s1, p1, hash1) = h1.emit_full(ADMIN_LOG, audit_suffix(ts, "hook.register", res, out, pr));
    let (s2, p2, hash2) = h1.emit_full(
        ADMIN_LOG,
        audit_suffix(ts + 60, "hook.delete", res, out, pr),
    );
    assert_eq!((s1, p1.as_str()), (1, ""), "genesis position");
    assert_eq!(
        (s2, p2.clone()),
        (2, hash1.clone()),
        "record 2 links record 1"
    );

    // The store durably holds both neutral bodies under (audit, admin).
    let bodies = store
        .list_plane_records(
            KIND_AUDIT,
            &busbar_api::PlaneSelector::Parent(ADMIN_LOG.to_string()),
        )
        .unwrap();
    assert_eq!(
        bodies.len(),
        2,
        "both seam records persisted to plane_records"
    );

    // Process 2 (a "restart"): a FRESH log + fresh host positions over the SAME store, restoring from
    // `plane_records` — the production boot source.
    let h2 = AuditTestHarness::over(store.clone());
    let plane = PlaneStoreView::narrow(store.clone());
    let restored = h2
        .host(|host| h2.log.restore_from_store(host, plane.as_ref()))
        .expect("plane_records read");
    assert!(
        restored.chain_breaks.is_empty(),
        "a restored seam chain reported TAMPERED: {:?}",
        restored.chain_breaks
    );
    assert_eq!(
        restored.records, 2,
        "both records restored from plane_records"
    );

    // The legacy admin ring's records for the SAME fields at the SAME positions — the byte-identity
    // reference. `digest` is the ONE canonicaliser both paths share.
    let mk = |seq, ts, action: &str, prev: String| AuditEntry {
        seq,
        ts,
        action: action.to_string(),
        resource: res.to_string(),
        outcome: out.to_string(),
        principal: pr.to_string(),
        prev_hash: prev,
        hash: String::new(),
        recorded_here: false,
    };
    let legacy_head = mk(1, ts, "hook.register", String::new());
    let legacy_tail = mk(2, ts + 60, "hook.delete", hash1.clone());
    assert_eq!(digest(&legacy_head), hash1, "seam genesis == legacy digest");
    assert_eq!(digest(&legacy_tail), hash2, "seam link == legacy digest");

    // GET /audit output: the seeded ring, newest-first, BYTE-IDENTICAL to the legacy records.
    let ring = h2
        .log
        .list_filtered(0, crate::admin::audit::MAX_AUDIT_ENTRIES, None, None);
    assert_eq!(
        ring.len(),
        2,
        "the ring is seeded with both restored records"
    );
    let same = |a: &AuditEntry, b: &AuditEntry| {
        (
            a.seq,
            &a.ts,
            &a.action,
            &a.resource,
            &a.outcome,
            &a.principal,
            &a.prev_hash,
            &a.hash,
        ) == (
            b.seq,
            &b.ts,
            &b.action,
            &b.resource,
            &b.outcome,
            &b.principal,
            &b.prev_hash,
            &b.hash,
        )
    };
    // Newest-first: the tail leads. Fill the reference hashes so every field is compared.
    let ref_tail = AuditEntry {
        hash: hash2.clone(),
        ..legacy_tail.clone()
    };
    let ref_head = AuditEntry {
        hash: hash1.clone(),
        ..legacy_head.clone()
    };
    assert!(
        same(&ring[0], &ref_tail),
        "tail record byte-identical, newest-first"
    );
    assert!(same(&ring[1], &ref_head), "head record byte-identical");
    assert!(
        ring.iter().all(|e| !e.recorded_here),
        "restored ring entries are seeded (recorded_here = false)"
    );
}

/// WITNESS (b) — OLD-STORE GOLDEN: a store whose audit lives ONLY in the legacy `list_audit` table
/// (every OLD store) BOOTS, MIGRATES `list_audit` → `plane_records`, RESTORES from `plane_records`,
/// and verifies BYTE-IDENTICALLY — proving "OLD stores boot-verify EXACTLY". The legacy rows are the
/// FROZEN pre-cleave bytes (identical to `boot_verify_golden`'s `AD_1`/`AD_2`), so a digest drift in
/// the migration or restore fails this against a hash a PAST build computed, not one this build did.
#[test]
fn old_store_audit_only_in_legacy_table_boots_migrates_and_verifies() {
    // The frozen pre-cleave `serde(AuditRecord)` rows and their frozen tail hash — copied verbatim
    // from `crate::audit::tests::boot_verify_golden` (that module is private).
    const AD_1: &[u8] = br#"{"seq":1,"ts":1700000000,"action":"hook.register","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"","hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"}"#;
    const AD_2: &[u8] = br#"{"seq":2,"ts":1700000060,"action":"hook.delete","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa","hash":"33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264"}"#;
    const AD_HEAD_HASH: &str = "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa";
    const AD_TAIL_HASH: &str = "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264";

    let store: std::sync::Arc<dyn busbar_api::Store> = std::sync::Arc::new(DualDurableStore::new());
    // Seed the LEGACY table only — plane_records is empty, exactly like an OLD store on first boot.
    let ad1: busbar_api::AuditRecord = crate::plane::store::decode(AD_1).unwrap();
    let ad2: busbar_api::AuditRecord = crate::plane::store::decode(AD_2).unwrap();
    store.append_audit(&ad1).unwrap();
    store.append_audit(&ad2).unwrap();
    assert!(
        store
            .list_plane_records(
                KIND_AUDIT,
                &busbar_api::PlaneSelector::Parent(ADMIN_LOG.to_string())
            )
            .unwrap()
            .is_empty(),
        "an OLD store has NO audit plane_records before migration"
    );

    // BOOT MIGRATION: list_audit -> plane_records, preserving the chain exactly.
    let migrated = migrate_legacy_table_to_plane_records(store.as_ref()).unwrap();
    assert_eq!(migrated, 2, "both legacy rows migrated");
    // IDEMPOTENT: a store already migrated does nothing.
    assert_eq!(
        migrate_legacy_table_to_plane_records(store.as_ref()).unwrap(),
        0,
        "a second migration is a no-op"
    );

    // BOOT RESTORE from plane_records: verifies + seeds the ring, byte-identical to the frozen bytes.
    let h = AuditTestHarness::over(store.clone());
    let plane = PlaneStoreView::narrow(store.clone());
    let restored = h
        .host(|host| h.log.restore_from_store(host, plane.as_ref()))
        .expect("plane_records read");
    assert!(
        restored.chain_breaks.is_empty(),
        "the migrated OLD-store chain reported TAMPERED: {:?}",
        restored.chain_breaks
    );
    assert_eq!(restored.records, 2, "both migrated records restored");

    // The ring `GET /audit` serves is byte-identical to the FROZEN bytes, newest-first.
    let ring = h
        .log
        .list_filtered(0, crate::admin::audit::MAX_AUDIT_ENTRIES, None, None);
    assert_eq!(ring.len(), 2);
    assert_eq!(
        (
            ring[0].seq,
            ring[0].hash.as_str(),
            ring[0].prev_hash.as_str()
        ),
        (2, AD_TAIL_HASH, AD_HEAD_HASH),
        "newest-first: the frozen tail leads, linking the frozen head"
    );
    assert_eq!(
        (
            ring[1].seq,
            ring[1].hash.as_str(),
            ring[1].prev_hash.as_str()
        ),
        (1, AD_HEAD_HASH, ""),
        "the frozen genesis follows"
    );
    assert_eq!(ring[0].action, "hook.delete");
    assert_eq!(ring[1].action, "hook.register");
    assert!(ring.iter().all(|e| !e.recorded_here));
}
