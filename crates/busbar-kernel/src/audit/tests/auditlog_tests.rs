// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/audit/auditlog.rs`.

use super::*;
use crate::audit::{digest, frame_prelude, Framing};

/// THE BYTE-IDENTITY GATE: the plane's pre-framed suffix, appended RAW after the host prelude
/// framed with `digests_scope = false`, reproduces the legacy [`AuditEntry`] digest byte-for-byte.
/// A perturbation of the suffix, the prelude framing, or the `digests_scope` flag would fail this.
fn assert_roundtrip(seq: u64, prev_hash: &str, ts: u64, act: &str, res: &str, out: &str, pr: &str) {
    // The seam's digest input: frame_prelude(PipeSeparated, prev_hash, None=no scope, seq) ⧺ suffix.
    let mut input = frame_prelude(Framing::PipeSeparated, prev_hash, None, seq);
    input.extend_from_slice(&audit_suffix(ts, act, res, out, pr));
    let via_seam = busbar_contract::redacted::sha256_hex(&input);

    // The legacy digest: the AuditEntry's own `digest_fields` through the ONE canonicaliser, forced
    // to scheme 1 -- the framing this suffix (a raw pipe join, built by `audit_suffix` above) is
    // actually in.
    let entry = AuditEntry {
        seq,
        ts,
        action: act.to_string(),
        resource: res.to_string(),
        outcome: out.to_string(),
        principal: pr.to_string(),
        prev_hash: prev_hash.to_string(),
        hash: String::new(),
        scheme: crate::audit_ring::AUDIT_SCHEME_PIPE,
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
    let h = AuditTestHarness::over(std::sync::Arc::new(crate::governance::MemoryStore::new()));
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

    // The legacy ring's records for the SAME fields at the SAME chain positions -- scheme 1, the
    // framing the manually-built `audit_suffix` fed through the seam above is actually in.
    let mk = |seq, ts, action: &str, prev: String| AuditEntry {
        seq,
        ts,
        action: action.to_string(),
        resource: res.to_string(),
        outcome: out.to_string(),
        principal: pr.to_string(),
        prev_hash: prev,
        hash: String::new(),
        scheme: crate::audit_ring::AUDIT_SCHEME_PIPE,
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
    inner: crate::governance::MemoryStore,
    audit: std::sync::Mutex<std::collections::BTreeMap<u64, busbar_contract::records::AuditRecord>>,
    plane: std::sync::Mutex<PlaneRows>,
}

impl DualDurableStore {
    fn new() -> Self {
        Self {
            inner: crate::governance::MemoryStore::new(),
            audit: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            plane: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl busbar_contract::records::RecordStore for DualDurableStore {
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_contract::records::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_contract::records::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_contract::records::MeteringDelta,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
    // ── the legacy audit table ──
    fn append_audit(
        &self,
        entry: &busbar_contract::records::AuditRecord,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.audit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(entry.seq, entry.clone());
        Ok(())
    }
    fn list_audit(
        &self,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::AuditRecord>>
    {
        Ok(self
            .audit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }
    fn list_audit_tail(
        &self,
        limit: u64,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::AuditRecord>>
    {
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
    fn append_plane_record(
        &self,
        record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        let record = &record.to_record();
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
        selector: &busbar_contract::records::PlaneSelector,
    ) -> busbar_contract::records::RecordStoreResult<Vec<Vec<u8>>> {
        let parent = match selector {
            busbar_contract::records::PlaneSelector::All => None,
            busbar_contract::records::PlaneSelector::Parent(p) => Some(p.to_string()),
        };
        Ok(self
            .plane
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(kind.to_string(), parent))
            .cloned()
            .unwrap_or_default())
    }
    fn list_plane_record_parents(
        &self,
        kind: &str,
    ) -> busbar_contract::records::RecordStoreResult<Vec<String>> {
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
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
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
            &busbar_contract::records::PlaneSelector::Parent(ADMIN_LOG.into()),
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
        .log
        .restore_from_store(plane.as_ref())
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
    // reference. `digest` is the ONE canonicaliser both paths share. Scheme 1: these fields went
    // through the seam as a raw `audit_suffix` (legacy) suffix above, so a correct restore must read
    // them back as scheme 1 too — see the `scheme` check added to `same` below.
    let mk = |seq, ts, action: &str, prev: String| AuditEntry {
        seq,
        ts,
        action: action.to_string(),
        resource: res.to_string(),
        outcome: out.to_string(),
        principal: pr.to_string(),
        prev_hash: prev,
        hash: String::new(),
        scheme: crate::audit_ring::AUDIT_SCHEME_PIPE,
        recorded_here: false,
    };
    let legacy_head = mk(1, ts, "hook.register", String::new());
    let legacy_tail = mk(2, ts + 60, "hook.delete", hash1.clone());
    assert_eq!(digest(&legacy_head), hash1, "seam genesis == legacy digest");
    assert_eq!(digest(&legacy_tail), hash2, "seam link == legacy digest");

    // GET /audit output: the seeded ring, newest-first, BYTE-IDENTICAL to the legacy records.
    let ring = h2
        .log
        .list_filtered(0, crate::audit_ring::MAX_AUDIT_ENTRIES, None, None);
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
            a.scheme,
        ) == (
            b.seq,
            &b.ts,
            &b.action,
            &b.resource,
            &b.outcome,
            &b.principal,
            &b.prev_hash,
            &b.hash,
            b.scheme,
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
    // `boot_verify_golden`'s frozen pre-cleave `serde(AuditRecord)` rows and their frozen hashes.
    use crate::audit::boot_verify_golden::{AD_1, AD_2};
    const AD_HEAD_HASH: &str = "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa";
    const AD_TAIL_HASH: &str = "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264";

    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    // Seed the LEGACY table only — plane_records is empty, exactly like an OLD store on first boot.
    let ad1: busbar_contract::records::AuditRecord =
        crate::store::plane_view::decode(AD_1).unwrap();
    let ad2: busbar_contract::records::AuditRecord =
        crate::store::plane_view::decode(AD_2).unwrap();
    store.append_audit(&ad1).unwrap();
    store.append_audit(&ad2).unwrap();
    assert!(
        store
            .list_plane_records(
                KIND_AUDIT,
                &busbar_contract::records::PlaneSelector::Parent(ADMIN_LOG.into())
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
        .log
        .restore_from_store(plane.as_ref())
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
        .list_filtered(0, crate::audit_ring::MAX_AUDIT_ENTRIES, None, None);
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

use crate::test_support::warn_capture::DiagCapture;

/// Serializes every test that restores an admin audit stream holding an undecodable row, because they
/// all hit the same process-wide tracing callsite (BUSBAR-2047). tracing caches a callsite's interest
/// process-wide: a test with no subscriber that hits the callsite while another test's capture is
/// being installed leaves the callsite disabled for the capture, so it saw nothing depending on test
/// order. Holding this lock for the whole restore keeps each test's subscriber the only one in play.
static DIAG_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The isolated capture: the serial lock, then `cap` as THIS thread's subscriber with tracing's
/// callsite interest cache rebuilt, both released when it drops.
struct IsolatedCapture {
    _guard: tracing::subscriber::DefaultGuard,
    _lock: std::sync::MutexGuard<'static, ()>,
}

fn capture_into(cap: &DiagCapture) -> IsolatedCapture {
    use tracing_subscriber::layer::SubscriberExt as _;
    let lock = DIAG_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(cap.clone()));
    tracing::callsite::rebuild_interest_cache();
    IsolatedCapture {
        _guard: guard,
        _lock: lock,
    }
}

/// TAMPER-EVIDENCE SILENT-SKIP CLOSED (mirrors BUSBAR-2045/2046): an UNDECODABLE row in the admin
/// audit `plane_records` — a corrupt or tampered body no released build wrote — must be reported
/// LOUDLY at the ring-seeding skip site with a coded diagnostic (`PLANE_AUDIT_ROW_UNREADABLE`,
/// BUSBAR-2047) at ERROR, not dropped in silence. A silently skipped evidence row on a tamper-evidence
/// surface is exactly the class of gap this pins. The GOOD row still seeds the read model the
/// `GET /audit` view serves — one bad sibling does not take the decodable rows down with it.
#[test]
fn restore_reports_an_undecodable_audit_row_loudly_and_still_seeds_the_good_row() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let (ts, res, out, pr) = (1_700_000_900u64, "hook:tamper", "applied", "admin");

    // Process 1: one GOOD mutation through the seam persists a decodable neutral body to plane_records.
    let h1 = AuditTestHarness::over(store.clone());
    let (s1, _p1, _hash1) =
        h1.emit_full(ADMIN_LOG, audit_suffix(ts, "hook.register", res, out, pr));
    assert_eq!(s1, 1, "the good record is genesis");

    // A raw UNDECODABLE body appended under the SAME (audit, admin) parent: it decodes as neither the
    // neutral body the seam writes nor a legacy `AuditRecord` — a corrupt/tampered row.
    store
        .append_plane_record(
            busbar_contract::records::PlaneRecord {
                kind: KIND_AUDIT.to_string(),
                id: ADMIN_LOG.to_string(),
                parent: Some(ADMIN_LOG.to_string()),
                seq: 2,
                ts: 0,
                disposition: busbar_contract::records::PlaneDisposition::Active,
                body: b"{ not an audit body".to_vec(),
            }
            .view(),
        )
        .unwrap();

    // Process 2 (a "restart"): a FRESH log over the SAME store restores from plane_records under a
    // diagnostics-capturing subscriber. The undecodable row must FIRE the coded diagnostic at ERROR.
    let h2 = AuditTestHarness::over(store.clone());
    let plane = PlaneStoreView::narrow(store.clone());
    let cap = DiagCapture::default();
    {
        let _g = capture_into(&cap);
        // The decodable row seeds the good row and the bad one is REPORTED — the behaviour under
        // test here. (The undecodable sibling no longer aborts the restore; that no-fork guarantee
        // is pinned by `restore_does_not_fork_the_chain_when_one_row_is_undecodable`.)
        let _ = h2.log.restore_from_store(plane.as_ref());
    }

    // The GOOD row still seeded the read model `GET /audit` serves.
    let ring = h2
        .log
        .list_filtered(0, crate::audit_ring::MAX_AUDIT_ENTRIES, None, None);
    assert_eq!(
        ring.len(),
        1,
        "the decodable row still seeds the ring despite an unreadable sibling"
    );
    assert_eq!(ring[0].seq, 1);
    assert_eq!(ring[0].action, "hook.register");

    // The undecodable row was reported LOUDLY, not skipped silently — a coded ERROR diagnostic.
    let diags = cap.0.lock().unwrap();
    assert!(
        diags.iter().any(|d| d.contains("BUSBAR-2047")),
        "the undecodable admin audit row must emit PLANE_AUDIT_ROW_UNREADABLE (BUSBAR-2047) at ERROR \
         at its ring-seeding skip site — a silent skip on a tamper-evidence surface is the gap being \
         closed; captured: {diags:?}"
    );
}

/// GOVERNANCE-CHAIN SEQ-1 FORK CLOSED: an undecodable sibling row must NOT abort the whole
/// admin-audit restore. Previously the ring-seed loop tolerated the bad row but the SEAM chain seed
/// was still handed the FULL body set — including the undecodable one — so it faulted and `?`-aborted
/// `restore_from_store`, leaving the host-side chain position UNSEEDED. The next mutation then minted
/// seq 1 again, FORKING the governance hash-chain (durability loss). The fix filters the seam seed to
/// the decodable bodies (mirroring the per-call log), so one bad row can neither abort the restore nor
/// fork the chain. This test pins BOTH: the restore returns Ok, and the chain resumes at seq 2.
#[test]
fn restore_does_not_fork_the_chain_when_one_row_is_undecodable() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let (ts, res, out, pr) = (1_700_001_100u64, "hook:fork", "applied", "admin");

    // Process 1: one GOOD genesis mutation persists a decodable neutral body to plane_records.
    let h1 = AuditTestHarness::over(store.clone());
    let (s1, _p1, _h1) = h1.emit_full(ADMIN_LOG, audit_suffix(ts, "hook.register", res, out, pr));
    assert_eq!(s1, 1, "the good record is genesis");

    // A raw UNDECODABLE body under the SAME (audit, admin) parent — a corrupt/tampered row.
    store
        .append_plane_record(
            busbar_contract::records::PlaneRecord {
                kind: KIND_AUDIT.to_string(),
                id: ADMIN_LOG.to_string(),
                parent: Some(ADMIN_LOG.to_string()),
                seq: 2,
                ts: 0,
                disposition: busbar_contract::records::PlaneDisposition::Active,
                body: b"{ not an audit body".to_vec(),
            }
            .view(),
        )
        .unwrap();

    // Process 2 (a "restart"): a FRESH log over the SAME store restores. The undecodable sibling must
    // NOT abort the restore (before the fix this `?`-aborted and returned Err → the chain forked).
    let h2 = AuditTestHarness::over(store.clone());
    let plane = PlaneStoreView::narrow(store.clone());
    let restored = {
        let _serial = DIAG_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        h2.log.restore_from_store(plane.as_ref())
    }
    .expect("one undecodable row must NOT abort the whole restore and fork the governance chain");
    assert_eq!(restored.unreadable, 1, "the bad row is counted, not fatal");
    assert_eq!(
        restored.records, 1,
        "only the decodable row is a restored record"
    );

    // The host-side chain position was seeded from the GOOD genesis, so the NEXT mutation continues
    // the chain at seq 2 — NOT a fork back at seq 1. This is the durability guarantee under test.
    let (s2, _p2, _h2) = h2.emit_full(ADMIN_LOG, audit_suffix(ts + 1, "hook.next", res, out, pr));
    assert_eq!(
        s2, 2,
        "the chain resumes after the good genesis; an undecodable sibling must not fork it to seq 1"
    );
}

// ── the legacy pipe-joined suffix is forgeable; `audit_suffix_safe` is not ─────────────────────────

/// THE FORGERY [`audit_suffix`] (legacy) IS VULNERABLE TO: a `|` inside a free-text field shifts
/// every field after it once split back apart, so a caller who controls `resource` can make a
/// restored record report a DIFFERENT outcome/principal than what actually happened — while the
/// digest still matches (same bytes either way), so `verify_chain` sees nothing wrong. This pins the
/// defect on the LEGACY path so nobody mistakes it for fixed, since fixing it there would change bytes
/// already sealed on disk.
#[test]
fn legacy_pipe_suffix_lets_an_embedded_pipe_forge_the_readback() {
    let ts = 1_700_000_000u64;
    // The attacker controls `resource` (e.g. a hook/task name echoed into the audit trail) and packs
    // it with the rest of the record it wants read back instead.
    let forged_resource = "innocuous|applied|root";
    let suffix = audit_suffix(ts, "hook.register", forged_resource, "rejected", "attacker");
    let (_, action, resource, outcome, principal, scheme) = parse_audit_suffix(&suffix);
    assert_eq!(
        scheme,
        crate::audit_ring::AUDIT_SCHEME_PIPE,
        "an unmarked, pipe-joined suffix must read back as scheme 1"
    );
    assert_eq!(action, "hook.register");
    // The real outcome/principal ("rejected"/"attacker") were swallowed into `resource` and the
    // forged tail split out as if they were the real outcome/principal.
    assert_eq!(resource, "innocuous");
    assert_eq!(
        outcome, "applied",
        "the forged outcome was read back, not the real one"
    );
    // `splitn(5, '|')` stops splitting after the 5th field, so the REAL outcome/principal
    // ("rejected"/"attacker") end up tacked onto the end of the forged principal rather than
    // vanishing — either way, what comes back as `outcome`/`principal` is not what was recorded.
    assert_eq!(
        principal, "root|rejected|attacker",
        "the forged principal was read back, not the real one, and the real outcome/principal are \
         buried inside it instead of being their own fields"
    );
}

/// THE FIX: the SAME embedded-`|` payload through [`audit_suffix_safe`] round-trips EXACTLY — no
/// byte any field carries can move a boundary, because boundaries come from the length prefixes, not
/// from scanning the content.
#[test]
fn safe_suffix_round_trips_a_pipe_carrying_payload_without_forgery() {
    let ts = 1_700_000_000u64;
    let forged_resource = "innocuous|applied|root";
    let suffix = audit_suffix_safe(ts, "hook.register", forged_resource, "rejected", "attacker");
    let (got_ts, action, resource, outcome, principal, scheme) = parse_audit_suffix(&suffix);
    assert_eq!(
        scheme,
        crate::audit_ring::AUDIT_SCHEME_LENGTH_PREFIXED,
        "a marker-prefixed, length-prefixed suffix must read back as scheme 2"
    );
    assert_eq!(got_ts, ts);
    assert_eq!(action, "hook.register");
    assert_eq!(
        resource, forged_resource,
        "the embedded `|` must not move a boundary"
    );
    assert_eq!(outcome, "rejected");
    assert_eq!(principal, "attacker");
}

/// Every field carrying `|` at once, plus empty fields — the safe suffix must not confuse any of it.
#[test]
fn safe_suffix_round_trips_pipes_in_every_field_and_empty_fields() {
    let suffix = audit_suffix_safe(42, "a|b", "", "o|u|t", "p|r");
    let (ts, action, resource, outcome, principal, scheme) = parse_audit_suffix(&suffix);
    assert_eq!(scheme, crate::audit_ring::AUDIT_SCHEME_LENGTH_PREFIXED);
    assert_eq!(ts, 42);
    assert_eq!(action, "a|b");
    assert_eq!(resource, "");
    assert_eq!(outcome, "o|u|t");
    assert_eq!(principal, "p|r");
}

/// BACK-COMPAT: a body a store already holds from before this change (the legacy pipe-joined suffix,
/// no [`SAFE_SUFFIX_MARKER`] byte) still parses as it always did — reading old records is unaffected.
#[test]
fn parse_audit_suffix_still_reads_legacy_bodies() {
    let suffix = audit_suffix(7, "hook.delete", "hook:compress", "applied", "admin");
    let (ts, action, resource, outcome, principal, scheme) = parse_audit_suffix(&suffix);
    assert_eq!(scheme, crate::audit_ring::AUDIT_SCHEME_PIPE);
    assert_eq!(ts, 7);
    assert_eq!(action, "hook.delete");
    assert_eq!(resource, "hook:compress");
    assert_eq!(outcome, "applied");
    assert_eq!(principal, "admin");
}

/// A record appended through the SEAM with the SAFE suffix (what [`emit_admin_hostless`] writes
/// for a record a pipe join would not read back) restores and reconstructs its EXACT typed fields —
/// including a `|`-carrying value that would have forged a different record under the legacy
/// suffix — via the same
/// [`audit_entry_from_body`] bridge a boot restore uses.
#[test]
fn a_safe_suffix_record_restores_with_exact_fields_despite_embedded_pipes() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(crate::governance::MemoryStore::new());
    let h = AuditTestHarness::over(store.clone());
    let ts = 1_700_000_555u64;
    let forged_resource = "x|applied|nobody";
    let (seq, _prev, hash) = h.emit_full(
        ADMIN_LOG,
        audit_suffix_safe(ts, "hook.register", forged_resource, "rejected", "attacker"),
    );
    assert_eq!(seq, 1);

    let rows = store
        .list_plane_records(KIND_AUDIT, &PlaneSelector::Parent(ADMIN_LOG.into()))
        .expect("list the just-appended plane record");
    assert_eq!(rows.len(), 1);
    let entry = audit_entry_from_body(ADMIN_LOG, &rows[0]).expect("decode the safe-suffix body");
    assert_eq!(entry.seq, seq);
    assert_eq!(entry.hash, hash);
    assert_eq!(entry.ts, ts);
    assert_eq!(entry.action, "hook.register");
    assert_eq!(
        entry.resource, forged_resource,
        "the embedded `|` must not have been split as a field boundary"
    );
    assert_eq!(entry.outcome, "rejected");
    assert_eq!(entry.principal, "attacker");
}

/// LENGTH-FIELD BOUNDS: a SAFE-marked suffix that is truncated — cut short inside a length prefix, or
/// declaring a length that runs past what remains — must decode to empty trailing fields rather than
/// panicking. `take_lp`'s "decode what you can, never panic" discipline is exercised here directly
/// rather than only reasoned about, since this is the one path a corrupt/tampered on-disk row (caught
/// by `verify_chain` separately) or a truncated write can actually reach at restore time.
#[test]
fn parse_audit_suffix_does_not_panic_on_a_truncated_safe_body() {
    // Marker only, nothing after it.
    let (ts, action, resource, outcome, principal, _scheme) =
        parse_audit_suffix(&[SAFE_SUFFIX_MARKER]);
    assert_eq!(
        (
            ts,
            action.as_str(),
            resource.as_str(),
            outcome.as_str(),
            principal.as_str()
        ),
        (0, "", "", "", "")
    );

    // Marker plus a length prefix cut short of its full 8 bytes.
    let mut short_len = vec![SAFE_SUFFIX_MARKER];
    short_len.extend_from_slice(&[0, 0, 0]);
    let (ts, action, ..) = parse_audit_suffix(&short_len);
    assert_eq!(ts, 0);
    assert_eq!(action, "");

    // Marker plus a complete length prefix that declares more bytes than actually follow.
    let mut over_declared = vec![SAFE_SUFFIX_MARKER];
    over_declared.extend_from_slice(&8u64.to_be_bytes()); // ts field claims 8 bytes...
    over_declared.extend_from_slice(&1_700_000_000u64.to_be_bytes()); // ...and gets them.
    over_declared.extend_from_slice(&1_000u64.to_be_bytes()); // action field claims 1000 bytes...
    over_declared.extend_from_slice(b"short"); // ...but only 5 follow.
    let (ts, action, resource, outcome, principal, _scheme) = parse_audit_suffix(&over_declared);
    assert_eq!(ts, 1_700_000_000);
    assert_eq!(
        action, "",
        "an over-declared length must yield an empty field, not a panic"
    );
    assert_eq!(resource, "");
    assert_eq!(outcome, "");
    assert_eq!(principal, "");
}

// ── AUDIT-INTEGRITY: THE PENDING RECOVERY QUEUE ─────────────────────────────────────────────────────
//
// `PendingAuditQueue` is tested directly, driven over an injected `mint` closure, rather than through
// `emit`/`emit_admin_hostless` themselves: those two are hardwired to the PRODUCTION `KIND_ID_AUDIT`
// stream (a process-wide singleton other parallel tests share via `global_audit_host_app`), so forcing
// a durable-write failure through them would either race those tests or require re-registering the
// shared stream mid-suite. The queue is the actual recoverability mechanism under test; driving it
// directly is a tighter, deterministic proof of the same fix.

fn pending(scope: &str, tag: u8) -> PendingAudit {
    PendingAudit {
        scope: scope.to_string(),
        suffix: vec![tag],
    }
}

/// RED-before-green shape: before this fix, a durable-write failure inside `emit`/`emit_admin_hostless`
/// was logged and the record was gone the instant the call returned — nothing existed to retry it.
/// GREEN: a record that fails to mint while the backend is down stays queued (not dropped), and is
/// delivered on the FIRST successful drain once the backend recovers.
#[test]
fn pending_audit_queue_recovers_a_write_once_the_backend_recovers() {
    let q = PendingAuditQueue::new(4);
    q.enqueue(pending("admin", 1));

    // First drain: the backend is STILL down — nothing recovers, and the record must stay queued.
    let mut recovered: Vec<(String, u64)> = Vec::new();
    q.drain_with(
        |_scope, _suffix| Err(()),
        |p, seq, _prev, _hash| recovered.push((p.scope.clone(), seq)),
    );
    assert!(
        recovered.is_empty(),
        "nothing recovers while the backend is still down"
    );
    assert_eq!(
        q.len(),
        1,
        "the record must stay queued, not be dropped, while the backend is down — this is the fix: \
         before it, the record vanished the instant `emit` returned"
    );

    // Second drain: the backend has recovered — the SAME record must now be delivered.
    q.drain_with(
        |_scope, _suffix| Ok((7, "prev".to_string(), "hash".to_string())),
        |p, seq, _prev, _hash| recovered.push((p.scope.clone(), seq)),
    );
    assert_eq!(
        recovered,
        vec![("admin".to_string(), 7)],
        "the queued record must be delivered on the first successful drain once the backend recovers"
    );
    assert_eq!(q.len(), 0, "a delivered record leaves the queue");
}

/// A STORE BACKEND THAT PANICS cannot take the request down or lose the record. The stream
/// registry calls its sink with no `catch_unwind` of its own: every production store is a door the
/// loader dispatches to, and the door's slot body runs under the SDK's mandatory `catch_unwind`
/// (`busbar-contract/src/abi/sdk/door.rs`, `export_door!`/`plugin_door!`'s trampoline), which
/// answers FAULT. Here the store is the kernel's store double opened THROUGH its door on the test
/// store axis, with a panic planted in its `append_plane_record` slot: the append comes back as an
/// error, never an unwind, and the admin record is QUEUED exactly as `emit_admin_hostless` queues a
/// failed write. RED if the boundary let the panic through: this test would unwind.
#[test]
fn a_panicking_store_behind_its_door_is_a_queued_fault_not_an_unwind() {
    use busbar_contract::store_calls::StoreDoor;
    let opened = crate::test_support::store_axis_stand_in()
        .open(
            StoreDoor::Linked(crate::test_support::store_double::door),
            crate::test_support::store_double::NAME,
            br#"{"panic_on_plane_append": true}"#,
        )
        .expect("the store double opens through its door");
    let kind_id = fresh_test_kind_id();
    crate::audit::stream_registry::register(
        kind_id,
        KIND_AUDIT.to_string(),
        AUDIT_FRAMING,
        AUDIT_DIGESTS_SCOPE,
        crate::audit::stream_registry::Decode::Native(reframe_audit),
        usize::MAX,
        Some(PlaneStoreView::narrow(opened.records)),
    );
    let suffix = audit_suffix(1_700_000_000, "hook.register", "hook:x", "applied", "admin");
    let refused = crate::audit::stream_registry::append_full(kind_id, ADMIN_LOG, &suffix);
    assert!(
        refused.is_err(),
        "the planted panic answers FAULT at the door and reads back as a store error"
    );

    // The emitter's own recovery step over the SAME path: the failed record stays queued.
    let q = PendingAuditQueue::new(4);
    q.enqueue(PendingAudit {
        scope: ADMIN_LOG.to_string(),
        suffix,
    });
    let mut recovered = 0;
    q.drain_with(
        |scope, suffix| {
            crate::audit::stream_registry::append_full(kind_id, scope, suffix).map_err(|_| ())
        },
        |_, _, _, _| recovered += 1,
    );
    assert_eq!(
        (recovered, q.len()),
        (0, 1),
        "a faulted write is queued for the next healthy write, never dropped"
    );
}

/// Multiple queued records drain OLDEST-FIRST, in the order they failed — a recovery that reordered
/// evidence would itself be a form of corruption.
#[test]
fn pending_audit_queue_drains_in_fifo_order() {
    let q = PendingAuditQueue::new(8);
    q.enqueue(pending("admin", 1));
    q.enqueue(pending("admin", 2));
    q.enqueue(pending("admin", 3));

    let mut seen: Vec<u8> = Vec::new();
    let next_seq = std::cell::Cell::new(100u64);
    q.drain_with(
        |_scope, _suffix| {
            let s = next_seq.get();
            next_seq.set(s + 1);
            Ok((s, String::new(), String::new()))
        },
        |p, _seq, _prev, _hash| seen.push(p.suffix[0]),
    );
    assert_eq!(seen, vec![1, 2, 3], "drained oldest-failed-first");
    assert_eq!(q.len(), 0);
}

/// A mint that fails partway through a multi-record drain stops WITHOUT losing or reordering the
/// records that had not yet been tried — they must still be queued, in their original order.
#[test]
fn pending_audit_queue_stops_at_the_first_failure_and_preserves_the_rest() {
    let q = PendingAuditQueue::new(8);
    q.enqueue(pending("admin", 1));
    q.enqueue(pending("admin", 2));

    let mut seen: Vec<u8> = Vec::new();
    // The FIRST row (tag 1) recovers; the SECOND (tag 2) still fails.
    q.drain_with(
        |_scope, suffix| {
            if suffix == [1] {
                Ok((1, String::new(), String::new()))
            } else {
                Err(())
            }
        },
        |p, _seq, _prev, _hash| seen.push(p.suffix[0]),
    );
    assert_eq!(seen, vec![1], "the recoverable row was delivered");
    assert_eq!(
        q.len(),
        1,
        "the still-failing row stays queued rather than being dropped"
    );

    // A later, fully-healthy drain finishes the job.
    q.drain_with(
        |_scope, _suffix| Ok((2, String::new(), String::new())),
        |p, _seq, _prev, _hash| seen.push(p.suffix[0]),
    );
    assert_eq!(
        seen,
        vec![1, 2],
        "the remaining row recovers once the backend is healthy"
    );
}

/// THE WATERMARK: once the recovery queue itself is full, the OLDEST entry is evicted to admit the
/// newest failure, and that eviction is a DETECTED, COUNTED gap — never a silent one. Proven both on
/// the counter and on the coded diagnostic actually firing at the eviction site.
#[test]
fn pending_audit_queue_reports_a_gap_when_it_overflows() {
    let q = PendingAuditQueue::new(2);

    let cap = DiagCapture::default();
    {
        let _g = capture_into(&cap);
        for tag in 0..3u8 {
            q.enqueue(pending("admin", tag));
        }
    }

    assert_eq!(q.len(), 2, "bounded: the queue never exceeds its cap");
    assert_eq!(
        q.dropped(),
        1,
        "the third failure, over the cap, evicted the oldest — a detected, counted gap"
    );

    // The SURVIVING two are the newest two: the oldest (tag 0) was evicted to make room.
    let mut seen: Vec<u8> = Vec::new();
    q.drain_with(
        |_s, _suffix| Ok((1, String::new(), String::new())),
        |p, _seq, _prev, _hash| seen.push(p.suffix[0]),
    );
    assert_eq!(
        seen,
        vec![1, 2],
        "tag 0 was evicted by overflow; tags 1 and 2 survived"
    );

    let diags = cap.0.lock().unwrap();
    assert!(
        diags.iter().any(|d| d.contains("BUSBAR-2044")),
        "the overflow eviction must emit PLANE_AUDITLOG_WRITE_FAILED (BUSBAR-2044) at ERROR — a \
         silent counter with no guaranteed log sink is exactly the regression being fixed; \
         captured: {diags:?}"
    );
}

/// RED ARM for the isolation above: the capture is per-test state. A restore over a CLEAN store, under
/// a fresh capture, must record nothing: if a previous test's captured diagnostics (or its subscriber)
/// leaked into this one, BUSBAR-2047 would show here.
#[test]
fn a_clean_restore_captures_no_unreadable_row_diagnostic() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let h = AuditTestHarness::over(store.clone());
    let plane = PlaneStoreView::narrow(store.clone());
    let cap = DiagCapture::default();
    {
        let _g = capture_into(&cap);
        let _ = h.log.restore_from_store(plane.as_ref());
    }
    assert!(
        cap.0.lock().unwrap().iter().all(|d| !d.contains("BUSBAR-2047")),
        "a clean restore must not report an unreadable audit row: capture state leaked between tests"
    );
}

// ── Q128 p12#1: what `GET /audit` serves for a record written today ─────────────────────────────

/// The newest record `emit_admin_hostless` pushed for `resource` (each test names its own).
fn served(resource: &str) -> AuditEntry {
    AUDIT_LOG
        .list_filtered(
            0,
            crate::audit_ring::MAX_AUDIT_ENTRIES,
            None,
            Some(resource),
        )
        .into_iter()
        .next()
        .expect("emit_admin_hostless pushed the record into the served read model")
}

/// THE LIVE WRITE PATH SERVES 1.5.5's HASH. A record whose `action`/`resource`/`outcome` carry no
/// `|` is sealed over the 1.5.5 pipe join, so the `hash` `GET /audit` serves is exactly
/// `sha256(prev_hash|seq|ts|action|resource|outcome|principal)` (v1.5.5
/// `crates/busbar/src/admin/audit.rs:61-73`; THE DESIGN §7 "`GET /audit` is unchanged"), the record
/// declares scheme 1, and recomputing it under that declared scheme gives the served hash.
///
/// RED before the fix: every live write was sealed over `prev_hash|seq` then the length-prefixed
/// safe suffix and declared scheme 2, so the served hash was neither 1.5.5's formula nor what scheme
/// 2 recomputes to.
#[test]
fn a_live_admin_record_serves_the_1_5_5_hash_under_the_scheme_it_declares() {
    ensure_global_audit_stream_registered();
    let resource = "q128-p12-1:plain";
    // A `|` in the principal (the last field) still reads back exactly.
    emit_admin_hostless(
        1_700_000_777,
        "test.write",
        resource,
        "applied",
        "issuer|subject",
    );
    let e = served(resource);
    assert_eq!(e.scheme, crate::audit_ring::AUDIT_SCHEME_PIPE);
    let v155 = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        e.prev_hash, e.seq, e.ts, e.action, e.resource, e.outcome, e.principal
    );
    assert_eq!(
        e.hash,
        busbar_contract::redacted::sha256_hex(v155.as_bytes()),
        "the served hash is 1.5.5's formula"
    );
    assert_eq!(
        digest(&e),
        e.hash,
        "the declared scheme recomputes the served hash"
    );

    let (suffix, scheme) = admin_suffix(e.ts, &e.action, &e.resource, &e.outcome, &e.principal);
    assert_eq!(scheme, crate::audit_ring::AUDIT_SCHEME_PIPE);
    let (ts, action, res, outcome, principal, read_scheme) = parse_audit_suffix(&suffix);
    assert_eq!(
        (
            ts,
            action.as_str(),
            res.as_str(),
            outcome.as_str(),
            principal.as_str()
        ),
        (e.ts, "test.write", resource, "applied", "issuer|subject"),
        "the pipe join reads back exactly when only the last field carries a `|`"
    );
    assert_eq!(read_scheme, crate::audit_ring::AUDIT_SCHEME_PIPE);
}

/// A record whose `resource` carries a `|` would not split back exactly from a pipe join, so it is
/// sealed under the length-prefixed suffix — and the scheme it declares (2) recomputes to exactly
/// the hash it was minted with.
///
/// RED before the fix: scheme 2 recomputed as one length-prefixed buffer over every field, a
/// different byte stream from the one the seam sealed, so the served record read as tampered.
#[test]
fn a_live_admin_record_with_a_bar_in_a_field_recomputes_under_its_declared_scheme() {
    ensure_global_audit_stream_registered();
    let resource = "q128-p12-1:with|bar";
    emit_admin_hostless(1_700_000_778, "test.write", resource, "applied", "admin");
    let e = served(resource);
    assert_eq!(e.scheme, crate::audit_ring::AUDIT_SCHEME_LENGTH_PREFIXED);
    assert_eq!(
        digest(&e),
        e.hash,
        "the declared scheme recomputes the served hash"
    );
    let mut sealed = frame_prelude(Framing::PipeSeparated, &e.prev_hash, None, e.seq);
    sealed.extend_from_slice(&audit_suffix_safe(
        e.ts,
        &e.action,
        &e.resource,
        &e.outcome,
        &e.principal,
    ));
    assert_eq!(e.hash, busbar_contract::redacted::sha256_hex(&sealed));
}

// ── Q128 arch u26 #2: GET /audit recomputes by the PUBLISHED recipe ─────────────────────────────

/// The recipe `AuditEntry.hash` publishes (its doc, which the served OpenAPI document carries),
/// rebuilt here from the served JSON alone: no kernel framing or digest code is called, so a drift
/// between what the node seals and what the contract states turns this red. Scheme 1 is the 1.5.5
/// pipe join; scheme 2 is `prev_hash|seq`, a zero byte, then each field as an 8-byte big-endian
/// length and its bytes (`ts` as its 8-byte big-endian value).
fn hash_by_the_published_recipe(served: &serde_json::Value) -> String {
    use sha2::{Digest as _, Sha256};
    let text = |k: &str| served[k].as_str().expect("a served text field").to_string();
    let num = |k: &str| served[k].as_u64().expect("a served integer field");
    let mut preimage = Vec::new();
    match num("scheme") {
        1 => preimage.extend_from_slice(
            format!(
                "{}|{}|{}|{}|{}|{}|{}",
                text("prev_hash"),
                num("seq"),
                num("ts"),
                text("action"),
                text("resource"),
                text("outcome"),
                text("principal")
            )
            .as_bytes(),
        ),
        2 => {
            preimage.extend_from_slice(format!("{}|{}", text("prev_hash"), num("seq")).as_bytes());
            preimage.push(0x00);
            preimage.extend_from_slice(&8u64.to_be_bytes());
            preimage.extend_from_slice(&num("ts").to_be_bytes());
            for k in ["action", "resource", "outcome", "principal"] {
                let field = text(k);
                preimage.extend_from_slice(&(field.len() as u64).to_be_bytes());
                preimage.extend_from_slice(field.as_bytes());
            }
        }
        other => panic!("a served record declares scheme {other}, which no recipe publishes"),
    }
    hex::encode(Sha256::digest(&preimage))
}

/// EVERY RECORD `GET /audit` SERVES RECOMPUTES BY THE PUBLISHED RECIPE, under the scheme it declares,
/// and the node's own verifier agrees with that recipe. The records cover both schemes: a `|` in
/// each of `action`, `resource` and `outcome` (scheme 2), a `|` only in `principal` (scheme 1, the
/// last field reads back), empty and non-ASCII fields.
///
/// RED on dev before p12#1: every record declared scheme 2 while the node's `digest` framed scheme 2
/// as one length-prefixed buffer over all seven fields, so `digest(entry)` disagreed with the served
/// `hash`, and a record with no `|` anywhere was not served under 1.5.5's formula (scheme 1).
#[test]
fn every_served_audit_record_recomputes_by_the_published_recipe() {
    ensure_global_audit_stream_registered();
    let tag = "q128b-u26-2:";
    let cases: [(&str, String, &str, &str); 6] = [
        ("test.write", format!("{tag}plain"), "applied", "admin"),
        ("test.write", format!("{tag}res|bar"), "applied", "admin"),
        (
            "test|write",
            format!("{tag}action-bar"),
            "rejected",
            "admin",
        ),
        (
            "test.write",
            format!("{tag}outcome-bar"),
            "app|lied",
            "admin",
        ),
        (
            "test.write",
            format!("{tag}principal-bar"),
            "applied",
            "iss|sübject",
        ),
        ("test.write", format!("{tag}empty-principal"), "applied", ""),
    ];
    for (i, (action, resource, outcome, principal)) in cases.iter().enumerate() {
        emit_admin_hostless(
            1_700_001_000 + i as u64,
            action,
            resource,
            outcome,
            principal,
        );
    }
    // What the `GET /audit` handler serializes: the read model's entries, as JSON.
    let served = serde_json::to_value(AUDIT_LOG.list_filtered(
        0,
        crate::audit_ring::MAX_AUDIT_ENTRIES,
        None,
        None,
    ))
    .expect("the served page serializes");
    let mine: Vec<&serde_json::Value> = served
        .as_array()
        .expect("a list")
        .iter()
        .filter(|e| e["resource"].as_str().is_some_and(|r| r.starts_with(tag)))
        .collect();
    assert_eq!(mine.len(), cases.len(), "every emitted record is served");
    let schemes: std::collections::BTreeSet<u64> =
        mine.iter().filter_map(|e| e["scheme"].as_u64()).collect();
    assert_eq!(
        schemes,
        [1, 2].into_iter().collect(),
        "the cases reach both published schemes"
    );
    for e in mine {
        let published = hash_by_the_published_recipe(e);
        assert_eq!(
            e["hash"].as_str(),
            Some(published.as_str()),
            "the served hash is the published recipe's: {e}"
        );
        let entry: AuditEntry =
            serde_json::from_value(e.clone()).expect("a served entry reads back");
        assert_eq!(
            digest(&entry),
            published,
            "the node's verifier agrees with the published recipe: {e}"
        );
        let bar_before_last = ["action", "resource", "outcome"]
            .iter()
            .any(|k| e[*k].as_str().is_some_and(|v| v.contains('|')));
        assert_eq!(
            e["scheme"].as_u64(),
            Some(if bar_before_last { 2 } else { 1 }),
            "scheme 1 exactly when the pipe join reads back: {e}"
        );
    }
}

// ── Q128 p12#2: a failed boot restore does not fork the chain ───────────────────────────────────

/// A store that answers every read with an error: the boot restore's read failing.
struct UnreadableStore;

impl PlaneStore for UnreadableStore {
    fn upsert_plane_record(
        &self,
        _record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> RecordStoreResult<()> {
        Err(RecordStoreError("store down (test)".to_string()))
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        Err(RecordStoreError("store down (test)".to_string()))
    }
    fn append_plane_record(
        &self,
        _record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> RecordStoreResult<()> {
        Err(RecordStoreError("store down (test)".to_string()))
    }
    fn list_plane_records(
        &self,
        _kind: &str,
        _selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        Err(RecordStoreError("store down (test)".to_string()))
    }
    fn list_plane_record_parents(&self, _kind: &str) -> RecordStoreResult<Vec<String>> {
        Err(RecordStoreError("store down (test)".to_string()))
    }
    fn purge_plane_records(
        &self,
        _kind: &str,
        _before: u64,
        _retention: busbar_contract::records::Retention,
    ) -> RecordStoreResult<u64> {
        Err(RecordStoreError("store down (test)".to_string()))
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError("store down (test)".to_string()))
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Err(RecordStoreError("store down (test)".to_string()))
    }
    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Err(RecordStoreError("store down (test)".to_string()))
    }
}

/// A boot restore that could not read the store leaves the chain unseeded; the next append must
/// read the persisted tail back and continue it, never write a second seq-1 record beside it.
///
/// RED before the fix: the restore error was only logged, the journal had never evicted, so the
/// append opened a fresh chain at seq 1 with an empty `prev_hash` and forked the durable log.
#[test]
fn a_failed_boot_restore_does_not_fork_the_chain_at_seq_one() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let (ts, res) = (1_700_001_000u64, "hook:restore-failed");

    // Process 1: two records persisted.
    let h1 = AuditTestHarness::over(store.clone());
    h1.emit_full(
        ADMIN_LOG,
        audit_suffix(ts, "hook.register", res, "applied", "admin"),
    );
    let (_s2, _p2, tail) = h1.emit_full(
        ADMIN_LOG,
        audit_suffix(ts + 1, "hook.delete", res, "applied", "admin"),
    );

    // Process 2: its boot restore cannot read the store.
    let h2 = AuditTestHarness::over(store.clone());
    assert!(
        h2.log.restore_from_store(&UnreadableStore).is_err(),
        "the restore read failed"
    );

    // The store answers again: the first append continues the persisted chain.
    let (seq, prev_hash, _hash) = h2.emit_full(
        ADMIN_LOG,
        audit_suffix(ts + 2, "hook.register", res, "applied", "admin"),
    );
    assert_eq!(
        (seq, prev_hash.as_str()),
        (3, tail.as_str()),
        "the append continued the persisted tail instead of forking a second seq 1"
    );
}

// ── Q128 p12#3: a part-way legacy migration resumes ─────────────────────────────────────────────

// The frozen pre-cleave legacy rows (the bytes `boot_verify_golden` pins).
use crate::audit::boot_verify_golden::{AD_1 as LEGACY_1, AD_2 as LEGACY_2};

/// A copy an earlier boot left part-way (legacy seq 1 copied, seq 2 not) is finished on the next
/// boot, and the restored chain carries the whole legacy history.
///
/// RED before the fix: the idempotency gate saw a non-empty `plane_records` and skipped, so legacy
/// seq 2 never reached the chain that is restored and served.
#[test]
fn a_part_way_legacy_migration_resumes_instead_of_skipping() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let ad1: busbar_contract::records::AuditRecord =
        crate::store::plane_view::decode(LEGACY_1).unwrap();
    let ad2: busbar_contract::records::AuditRecord =
        crate::store::plane_view::decode(LEGACY_2).unwrap();

    // The earlier boot: only seq 1 made it across before the store failed.
    store.append_audit(&ad1).unwrap();
    assert_eq!(
        migrate_legacy_table_to_plane_records(store.as_ref()).unwrap(),
        1
    );
    store.append_audit(&ad2).unwrap();

    // This boot finishes the copy.
    assert_eq!(
        migrate_legacy_table_to_plane_records(store.as_ref()).unwrap(),
        1,
        "the legacy record past the part-way copy is copied"
    );
    assert_eq!(
        migrate_legacy_table_to_plane_records(store.as_ref()).unwrap(),
        0,
        "a finished copy is a no-op"
    );

    let h = AuditTestHarness::over(store.clone());
    let plane = PlaneStoreView::narrow(store.clone());
    let restored = h
        .log
        .restore_from_store(plane.as_ref())
        .expect("plane_records read");
    assert!(
        restored.chain_breaks.is_empty(),
        "{:?}",
        restored.chain_breaks
    );
    assert_eq!(restored.records, 2, "the whole legacy history is restored");
}

/// `plane_records` that disagree with the legacy table at the seq they share (records written over
/// a part-way copy) are never spliced onto it: the migration copies nothing and says so.
#[test]
fn a_legacy_migration_refuses_to_splice_onto_a_chain_that_disagrees() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let h = AuditTestHarness::over(store.clone());
    h.emit_full(
        ADMIN_LOG,
        audit_suffix(
            1_700_002_000,
            "hook.register",
            "hook:other",
            "applied",
            "admin",
        ),
    );
    store
        .append_audit(&crate::store::plane_view::decode(LEGACY_1).unwrap())
        .unwrap();
    store
        .append_audit(&crate::store::plane_view::decode(LEGACY_2).unwrap())
        .unwrap();
    assert!(
        migrate_legacy_table_to_plane_records(store.as_ref()).is_err(),
        "a disagreeing chain is reported, not silently skipped or spliced"
    );
    let rows = store
        .list_plane_records(
            KIND_AUDIT,
            &busbar_contract::records::PlaneSelector::Parent(ADMIN_LOG.into()),
        )
        .unwrap();
    assert_eq!(rows.len(), 1, "nothing was copied");
}

/// v1.5.5's own digest, re-stated from `git show v1.5.5:crates/busbar/src/admin/audit.rs`
/// (`AuditEntry::compute_hash`) and computed on RustCrypto's sha2, independently of this build's
/// canonicaliser: `sha256(prev_hash|seq|ts|action|resource|outcome|principal)`, lowercase hex.
fn v1_5_5_hash(prev: &str, seq: u64, ts: u64, act: &str, res: &str, out: &str, pr: &str) -> String {
    use sha2::Digest as _;
    let canonical = format!("{prev}|{seq}|{ts}|{act}|{res}|{out}|{pr}");
    sha2::Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// THE S-7 READ-BACK GATE (b): a 1.5.5 deployment's admin audit table — rows in v1.5.5's own serde
/// shape (`busbar_api::AuditRecord`), hashed by v1.5.5's own formula — reads back through the boot
/// migration and restore with EVERY record intact (every field, byte for byte), the chain verifies,
/// and the next admin record this build seals CONTINUES the 1.5.5 chain: seq one past the 1.5.5
/// tail, `prev_hash` the 1.5.5 tail's hash, and `hash` the 1.5.5 formula over its own fields.
///
/// The last part is what pins the admin log's own chain: its link is admin record to admin record
/// under 1.5.5's digest, which is what `GET /audit` serves. A journal whose only chain links every
/// record class under one digest cannot produce that `prev_hash` or that `hash`.
#[test]
fn a_1_5_5_audit_table_reads_back_whole_and_the_next_record_continues_its_chain() {
    let rows = [
        (
            1_699_000_001u64,
            "key.create",
            "key:vk_a",
            "applied",
            "admin",
        ),
        (
            1_699_000_050,
            "hook.register",
            "hook:compress",
            "applied",
            "admin",
        ),
        (
            1_699_000_051,
            "hook.register",
            "hook:bad",
            "rejected",
            "vk_ops",
        ),
        (1_699_000_400, "key.revoke", "key:vk_a", "applied", "admin"),
        (
            1_699_000_999,
            "plugin.install",
            "plugin:store-sqlite",
            "applied",
            "anonymous",
        ),
    ];
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let mut prev = String::new();
    let mut legacy = Vec::new();
    for (i, (ts, act, res, out, pr)) in rows.iter().enumerate() {
        let seq = i as u64 + 1;
        let hash = v1_5_5_hash(&prev, seq, *ts, act, res, out, pr);
        // Exactly the JSON v1.5.5 serialised a row as: its struct's field order, no extra field.
        let json = format!(
            r#"{{"seq":{seq},"ts":{ts},"action":"{act}","resource":"{res}","outcome":"{out}","principal":"{pr}","prev_hash":"{prev}","hash":"{hash}"}}"#
        );
        let row: busbar_contract::records::AuditRecord =
            serde_json::from_str(&json).expect("a 1.5.5 row decodes as this build's record");
        store
            .append_audit(&row)
            .expect("legacy table takes the row");
        legacy.push(row);
        prev = hash;
    }

    assert_eq!(
        migrate_legacy_table_to_plane_records(store.as_ref()).expect("migrates"),
        rows.len(),
        "every 1.5.5 row is carried over"
    );
    let h = AuditTestHarness::over(store.clone());
    let plane = PlaneStoreView::narrow(store.clone());
    let restored = h.restore_from_store(plane.as_ref()).expect("restores");
    assert!(
        restored.chain_breaks.is_empty(),
        "the 1.5.5 chain verifies after the read-back: {:?}",
        restored.chain_breaks
    );
    assert_eq!(restored.records, rows.len());
    assert_eq!(restored.unreadable, 0);

    // Every record intact, as `GET /audit` serves it (newest first).
    let mut served = h
        .log
        .list_filtered(0, crate::audit_ring::MAX_AUDIT_ENTRIES, None, None);
    served.reverse();
    assert_eq!(served.len(), legacy.len());
    for (got, want) in served.iter().zip(&legacy) {
        assert_eq!(
            (
                got.seq,
                got.ts,
                got.action.as_str(),
                got.resource.as_str(),
                got.outcome.as_str(),
                got.principal.as_str(),
                got.prev_hash.as_str(),
                got.hash.as_str(),
            ),
            (
                want.seq,
                want.ts,
                want.action.as_str(),
                want.resource.as_str(),
                want.outcome.as_str(),
                want.principal.as_str(),
                want.prev_hash.as_str(),
                want.hash.as_str(),
            ),
            "1.5.5 record {} reads back exactly",
            want.seq
        );
    }

    // The next admin record continues the 1.5.5 chain under the 1.5.5 digest.
    let (ts, act, res, out, pr) = (
        1_700_000_000u64,
        "hook.delete",
        "hook:compress",
        "applied",
        "admin",
    );
    let (suffix, _scheme) = admin_suffix(ts, act, res, out, pr);
    let (seq, prev_hash, hash) = h.emit_full(ADMIN_LOG, suffix);
    let tail = legacy.last().expect("a tail");
    assert_eq!(
        seq,
        tail.seq + 1,
        "the numbering continues past the 1.5.5 tail"
    );
    assert_eq!(
        prev_hash, tail.hash,
        "the link is the 1.5.5 tail's own hash"
    );
    assert_eq!(
        hash,
        v1_5_5_hash(&tail.hash, seq, ts, act, res, out, pr),
        "the new record's hash is 1.5.5's formula, so a 1.5.5 verifier walks it"
    );
}

// ── PLUGIN REFUSALS AT BOOT AND BIND ─────────────────────────────────────────────────────────────

/// A held refusal named `n`.
fn held(n: u64) -> HeldRefusal {
    HeldRefusal {
        ts: n,
        refusal: PluginRefusal::Need,
        resource: plugin_refusal_resource("export", "hook", &format!("need.{n}.refused")),
    }
}

/// Raised before the chain opens, refusals are HELD in raise order and sealed, in that order, when it
/// opens; one raised after is sealed at once; a second open seals nothing again.
#[test]
fn held_refusals_seal_in_order_once_the_chain_opens() {
    let hold = RefusalHold::new();
    let sealed = std::cell::RefCell::new(Vec::new());
    hold.raise(held(1), |r| sealed.borrow_mut().push(r.clone()));
    hold.raise(held(2), |r| sealed.borrow_mut().push(r.clone()));
    assert!(
        sealed.borrow().is_empty(),
        "nothing is sealed before the chain opens"
    );

    let mut over = None;
    hold.open(|r| sealed.borrow_mut().push(r.clone()), |n| over = Some(n));
    assert_eq!(*sealed.borrow(), vec![held(1), held(2)]);
    assert_eq!(over, None, "nothing was over the bound");

    hold.raise(held(3), |r| sealed.borrow_mut().push(r.clone()));
    assert_eq!(*sealed.borrow(), vec![held(1), held(2), held(3)]);

    hold.open(
        |r| sealed.borrow_mut().push(r.clone()),
        |_| panic!("opened twice"),
    );
    assert_eq!(sealed.borrow().len(), 3, "a second open seals nothing");
}

/// Past the bound, a refusal is not lost silently: the count is sealed when the chain opens.
#[test]
fn refusals_over_the_hold_are_counted_and_sealed() {
    let hold = RefusalHold::new();
    for n in 0..(MAX_HELD_REFUSALS as u64 + 3) {
        hold.raise(held(n), |_| panic!("the chain is not open"));
    }
    let mut sealed = 0;
    let mut over = None;
    hold.open(|_| sealed += 1, |n| over = Some(n));
    assert_eq!(sealed, MAX_HELD_REFUSALS);
    assert_eq!(over, Some(3));
}

/// Every part of a refusal's resource is clamped to host words: a `|`, a newline or a long run of
/// plugin bytes cannot move a field boundary or carry text onto the chain.
#[test]
fn a_refusal_resource_is_clamped_to_host_words() {
    assert_eq!(
        plugin_refusal_resource("export", "hook", "need.0.refused"),
        "plugin:export/hook#need.0.refused"
    );
    assert_eq!(
        plugin_refusal_resource("auth", "oidc|x\ny", "JWKS URL/plain http"),
        "plugin:auth/oidc_x_y#JWKS_URL_plain_http"
    );
    assert_eq!(plugin_refusal_resource("", "", ""), "plugin:_/_#_");
    let long = "a".repeat(200);
    let clamped = plugin_refusal_resource(&long, &long, &long);
    assert_eq!(clamped.len(), "plugin:/#".len() + 3 * REFUSAL_PART_MAX);
}
