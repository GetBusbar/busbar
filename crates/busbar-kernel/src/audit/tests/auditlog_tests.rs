// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::audit::{digest, frame_prelude, Framing};

fn assert_roundtrip(seq: u64, prev_hash: &str, ts: u64, act: &str, res: &str, out: &str, pr: &str) {
    let mut input = frame_prelude(Framing::PipeSeparated, prev_hash, None, seq);
    input.extend_from_slice(&audit_suffix(ts, act, res, out, pr));
    let via_seam = busbar_contract::redacted::sha256_hex(&input);

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

#[test]
fn a_converted_sites_seam_record_matches_the_legacy_ring_hash() {
    let h = AuditTestHarness::over(crate::real_store::store());
    let (ts, act, res, out, pr) = (
        1_700_000_123u64,
        "hook.register",
        "hook:x",
        "applied",
        "admin",
    );

    let (seq1, prev1, hash1) = h.emit_full(ADMIN_LOG, audit_suffix(ts, act, res, out, pr));
    let (seq2, prev2, hash2) = h.emit_full(
        ADMIN_LOG,
        audit_suffix(ts + 60, "hook.delete", res, out, pr),
    );

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

type PlaneRows = std::collections::HashMap<(String, Option<String>), Vec<Vec<u8>>>;

struct DualDurableStore {
    inner: std::sync::Arc<busbar_plugin_loader::store_v3::LoadedStore>,
    audit: std::sync::Mutex<std::collections::BTreeMap<u64, busbar_contract::records::AuditRecord>>,
    plane: std::sync::Mutex<PlaneRows>,
}

impl DualDurableStore {
    fn new() -> Self {
        Self {
            inner: crate::real_store::store(),
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

#[test]
fn seam_write_then_reboot_restore_roundtrips_byte_identically() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let (ts, res, out, pr) = (1_700_000_500u64, "hook:rt", "applied", "admin");

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

#[test]
fn old_store_audit_only_in_legacy_table_boots_migrates_and_verifies() {
    use crate::audit::boot_verify_golden::{AD_1, AD_2};
    const AD_HEAD_HASH: &str = "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa";
    const AD_TAIL_HASH: &str = "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264";

    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());

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

    let migrated = migrate_legacy_table_to_plane_records(store.as_ref()).unwrap();
    assert_eq!(migrated, 2, "both legacy rows migrated");

    assert_eq!(
        migrate_legacy_table_to_plane_records(store.as_ref()).unwrap(),
        0,
        "a second migration is a no-op"
    );

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

static DIAG_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

#[test]
fn restore_reports_an_undecodable_audit_row_loudly_and_still_seeds_the_good_row() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let (ts, res, out, pr) = (1_700_000_900u64, "hook:tamper", "applied", "admin");

    let h1 = AuditTestHarness::over(store.clone());
    let (s1, _p1, _hash1) =
        h1.emit_full(ADMIN_LOG, audit_suffix(ts, "hook.register", res, out, pr));
    assert_eq!(s1, 1, "the good record is genesis");

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

    let h2 = AuditTestHarness::over(store.clone());
    let plane = PlaneStoreView::narrow(store.clone());
    let cap = DiagCapture::default();
    {
        let _g = capture_into(&cap);

        let _ = h2.log.restore_from_store(plane.as_ref());
    }

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

    let diags = cap.0.lock().unwrap();
    assert!(
        diags.iter().any(|d| d.contains("BUSBAR-2047")),
        "the undecodable admin audit row must emit PLANE_AUDIT_ROW_UNREADABLE (BUSBAR-2047) at ERROR \
         at its ring-seeding skip site — a silent skip on a tamper-evidence surface is the gap being \
         closed; captured: {diags:?}"
    );
}

#[test]
fn restore_does_not_fork_the_chain_when_one_row_is_undecodable() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let (ts, res, out, pr) = (1_700_001_100u64, "hook:fork", "applied", "admin");

    let h1 = AuditTestHarness::over(store.clone());
    let (s1, _p1, _h1) = h1.emit_full(ADMIN_LOG, audit_suffix(ts, "hook.register", res, out, pr));
    assert_eq!(s1, 1, "the good record is genesis");

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

    let (s2, _p2, _h2) = h2.emit_full(ADMIN_LOG, audit_suffix(ts + 1, "hook.next", res, out, pr));
    assert_eq!(
        s2, 2,
        "the chain resumes after the good genesis; an undecodable sibling must not fork it to seq 1"
    );
}

#[test]
fn legacy_pipe_suffix_lets_an_embedded_pipe_forge_the_readback() {
    let ts = 1_700_000_000u64;

    let forged_resource = "innocuous|applied|root";
    let suffix = audit_suffix(ts, "hook.register", forged_resource, "rejected", "attacker");
    let (_, action, resource, outcome, principal, scheme) = parse_audit_suffix(&suffix);
    assert_eq!(
        scheme,
        crate::audit_ring::AUDIT_SCHEME_PIPE,
        "an unmarked, pipe-joined suffix must read back as scheme 1"
    );
    assert_eq!(action, "hook.register");

    assert_eq!(resource, "innocuous");
    assert_eq!(
        outcome, "applied",
        "the forged outcome was read back, not the real one"
    );

    assert_eq!(
        principal, "root|rejected|attacker",
        "the forged principal was read back, not the real one, and the real outcome/principal are \
         buried inside it instead of being their own fields"
    );
}

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

#[test]
fn a_safe_suffix_record_restores_with_exact_fields_despite_embedded_pipes() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        crate::real_store::store();
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

#[test]
fn parse_audit_suffix_does_not_panic_on_a_truncated_safe_body() {
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

    let mut short_len = vec![SAFE_SUFFIX_MARKER];
    short_len.extend_from_slice(&[0, 0, 0]);
    let (ts, action, ..) = parse_audit_suffix(&short_len);
    assert_eq!(ts, 0);
    assert_eq!(action, "");

    let mut over_declared = vec![SAFE_SUFFIX_MARKER];
    over_declared.extend_from_slice(&8u64.to_be_bytes());
    over_declared.extend_from_slice(&1_700_000_000u64.to_be_bytes());
    over_declared.extend_from_slice(&1_000u64.to_be_bytes());
    over_declared.extend_from_slice(b"short");
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

fn pending(scope: &str, tag: u8) -> PendingAudit {
    PendingAudit {
        origin: EventOrigin::Mutation,
        scope: scope.to_string(),
        suffix: vec![tag],
    }
}

#[test]
fn pending_audit_queue_recovers_a_write_once_the_backend_recovers() {
    let q = PendingAuditQueue::new(4);
    q.enqueue(pending("admin", 1));

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

    let q = PendingAuditQueue::new(4);
    q.enqueue(PendingAudit {
        origin: EventOrigin::Mutation,
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

#[test]
fn pending_audit_queue_stops_at_the_first_failure_and_preserves_the_rest() {
    let q = PendingAuditQueue::new(8);
    q.enqueue(pending("admin", 1));
    q.enqueue(pending("admin", 2));

    let mut seen: Vec<u8> = Vec::new();

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

#[test]
fn a_live_admin_record_serves_the_1_5_5_hash_under_the_scheme_it_declares() {
    ensure_global_audit_stream_registered();
    let resource = "q128-p12-1:plain";

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

#[test]
fn a_failed_boot_restore_does_not_fork_the_chain_at_seq_one() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let (ts, res) = (1_700_001_000u64, "hook:restore-failed");

    let h1 = AuditTestHarness::over(store.clone());
    h1.emit_full(
        ADMIN_LOG,
        audit_suffix(ts, "hook.register", res, "applied", "admin"),
    );
    let (_s2, _p2, tail) = h1.emit_full(
        ADMIN_LOG,
        audit_suffix(ts + 1, "hook.delete", res, "applied", "admin"),
    );

    let h2 = AuditTestHarness::over(store.clone());
    assert!(
        h2.log.restore_from_store(&UnreadableStore).is_err(),
        "the restore read failed"
    );

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

use crate::audit::boot_verify_golden::{AD_1 as LEGACY_1, AD_2 as LEGACY_2};

#[test]
fn a_part_way_legacy_migration_resumes_instead_of_skipping() {
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(DualDurableStore::new());
    let ad1: busbar_contract::records::AuditRecord =
        crate::store::plane_view::decode(LEGACY_1).unwrap();
    let ad2: busbar_contract::records::AuditRecord =
        crate::store::plane_view::decode(LEGACY_2).unwrap();

    store.append_audit(&ad1).unwrap();
    assert_eq!(
        migrate_legacy_table_to_plane_records(store.as_ref()).unwrap(),
        1
    );
    store.append_audit(&ad2).unwrap();

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

fn v1_5_5_hash(prev: &str, seq: u64, ts: u64, act: &str, res: &str, out: &str, pr: &str) -> String {
    use sha2::Digest as _;
    let canonical = format!("{prev}|{seq}|{ts}|{act}|{res}|{out}|{pr}");
    sha2::Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

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

fn held(n: u64) -> HeldRefusal {
    HeldRefusal {
        origin: EventOrigin::Mutation,
        ts: n,
        refusal: PluginRefusal::Need,
        resource: plugin_refusal_resource("export", "hook", &format!("need.{n}.refused")),
    }
}

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

#[test]
fn a_refusal_raised_while_the_open_is_parked_in_the_store_is_not_held_behind_it() {
    use std::sync::mpsc;
    use std::time::Duration;

    let hold = RefusalHold::new();
    hold.raise(held(1), |_| panic!("the chain is not open"));
    let sealed = Mutex::new(Vec::new());
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel::<()>();
    let (done_tx, done) = mpsc::channel();
    let (hold, sealed) = (&hold, &sealed);
    std::thread::scope(|s| {
        s.spawn(move || {
            hold.open(
                |r| {
                    if r.ts == 1 {
                        entered_tx.send(()).unwrap();
                        let _ = release_rx.recv_timeout(Duration::from_secs(30));
                    }
                    sealed.lock().unwrap().push(r.clone());
                },
                |_| panic!("nothing was over the bound"),
            );
        });
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("the open reached the store");
        s.spawn(move || {
            hold.raise(held(2), |r| sealed.lock().unwrap().push(r.clone()));
            let _ = done_tx.send(());
        });
        let raised = done.recv_timeout(Duration::from_secs(5));
        release.send(()).unwrap();
        raised.expect("a refusal raised while the open was in the store waited on the hold's lock");
    });
    assert_eq!(*sealed.lock().unwrap(), vec![held(1), held(2)]);
}

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

#[test]
fn overlapping_pending_drains_cannot_overtake_the_oldest_row() {
    let q = PendingAuditQueue::new(4);
    q.enqueue(pending("admin", 1));
    q.enqueue(pending("admin", 2));
    let delivered = std::sync::Mutex::new(Vec::new());
    q.drain_with(
        |_scope, suffix| {
            if suffix == [1] {
                q.drain_with(
                    |_, _| Ok((2, String::new(), String::new())),
                    |row, _, _, _| delivered.lock().unwrap().push(row.suffix[0]),
                );
            }
            Ok((1, String::new(), String::new()))
        },
        |row, _, _, _| delivered.lock().unwrap().push(row.suffix[0]),
    );
    assert_eq!(*delivered.lock().unwrap(), vec![1, 2]);
    assert_eq!(q.len(), 0);
}

#[test]
fn a_failed_in_flight_row_cannot_overfill_the_pending_queue() {
    let q = PendingAuditQueue::new(1);
    q.enqueue(pending("admin", 1));
    let cap = DiagCapture::default();
    {
        let _capture = capture_into(&cap);
        q.drain_with(
            |_, _| {
                q.enqueue(pending("admin", 2));
                Err(())
            },
            |_, _, _, _| panic!("the write was refused"),
        );
    }
    assert_eq!(q.len(), 1);
    assert_eq!(
        q.dropped(),
        1,
        "the failed oldest row was evicted, not hidden"
    );
    let mut delivered = Vec::new();
    q.drain_with(
        |_, _| Ok((1, String::new(), String::new())),
        |row, _, _, _| delivered.push(row.suffix[0]),
    );
    assert_eq!(delivered, vec![2]);
    assert!(cap
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|line| line.contains("BUSBAR-2044")));
}

#[test]
fn an_enqueued_event_cannot_pass_an_older_failed_drain() {
    let q = PendingAuditQueue::new(4);
    q.enqueue(pending("admin", 1));
    let delivered = std::sync::Mutex::new(Vec::new());
    q.drain_with(
        |_, _| {
            q.enqueue(pending("admin", 2));
            q.drain_with(
                |_, _| Ok((1, String::new(), String::new())),
                |row, _, _, _| delivered.lock().unwrap().push(row.suffix[0]),
            );
            Err(())
        },
        |_, _, _, _| panic!("the oldest write was refused"),
    );
    assert!(delivered.lock().unwrap().is_empty());
    q.drain_with(
        |_, _| Ok((1, String::new(), String::new())),
        |row, _, _, _| delivered.lock().unwrap().push(row.suffix[0]),
    );
    assert_eq!(*delivered.lock().unwrap(), vec![1, 2]);
}
