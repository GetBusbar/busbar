// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::audit::{digest, frame_prelude, Framing};
use crate::store::plane_view::decode;

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

async fn native_harness() -> (Arc<NativeAudit>, PlaneAuditLog) {
    let kind = fresh_test_kind_id();
    stream_registry::register(
        kind,
        KIND_AUDIT.into(),
        AUDIT_FRAMING,
        AUDIT_DIGESTS_SCOPE,
        Decode::Native(reframe_audit),
        MAX_AUDIT_ENTRIES,
    );
    let native = install_native(kind, crate::real_store::core().await).unwrap();
    let log = PlaneAuditLog::with_kind_id(kind);
    restore_native(&log, &native).await.unwrap();
    native.ready.store(true, Ordering::Release);
    (native, log)
}
async fn native_emit(
    native: &Arc<NativeAudit>,
    log: &PlaneAuditLog,
    operation: u8,
    suffix: Vec<u8>,
) -> (u64, String, String) {
    let queue = PendingAuditQueue::new(1);
    queue.enqueue(PendingAudit {
        scope: ADMIN_LOG.into(),
        suffix,
        origin: EventOrigin::ExportFailure,
        operation: [operation; 16],
        prepared: None,
        confirmation: None,
    });
    drain_native(&queue, log, native.clone()).await.unwrap();
    let entry = log.list_filtered(0, 1, None, None).remove(0);
    (entry.seq, entry.prev_hash, entry.hash)
}

struct NativeHarness {
    native: Arc<NativeAudit>,
    log: PlaneAuditLog,
}
async fn native_over(store: Arc<CoreStore>) -> NativeHarness {
    let kind = fresh_test_kind_id();
    stream_registry::register(
        kind,
        KIND_AUDIT.into(),
        AUDIT_FRAMING,
        AUDIT_DIGESTS_SCOPE,
        Decode::Native(reframe_audit),
        MAX_AUDIT_ENTRIES,
    );
    let native = install_native(kind, store).unwrap();
    NativeHarness {
        native,
        log: PlaneAuditLog::with_kind_id(kind),
    }
}
impl NativeHarness {
    async fn restore(&self) -> RecordStoreResult<AuditRestored> {
        let result = restore_native(&self.log, &self.native).await;
        self.native.ready.store(result.is_ok(), Ordering::Release);
        result
    }
    async fn emit(&self, scope: &str, suffix: Vec<u8>) -> (u64, String, String) {
        if !self.native.ready.load(Ordering::Acquire) {
            self.restore().await.expect("native restore before append");
        }
        let mut operation = [0; 16];
        getrandom::fill(&mut operation).unwrap();
        let queue = PendingAuditQueue::new(1);
        queue.enqueue(PendingAudit {
            scope: scope.into(),
            suffix,
            origin: EventOrigin::ExportFailure,
            operation,
            prepared: None,
            confirmation: None,
        });
        drain_native(&queue, &self.log, self.native.clone())
            .await
            .unwrap();
        let entry = self.log.list_filtered(0, 1, None, None).remove(0);
        (entry.seq, entry.prev_hash, entry.hash)
    }
}
fn audit_history(store: Arc<CoreStore>) -> AsyncHistory {
    AsyncHistory::authorized(
        store,
        PERSISTENCE_OWNER,
        [HistoryCollection {
            kind: KIND_AUDIT,
            mode: HistoryMode::Append,
            retention: Retention::Age,
            parent: None,
        }],
    )
    .unwrap()
}
async fn seed_legacy(store: &CoreStore, record: &busbar_contract::records::AuditRecord) {
    use busbar_contract::persistence::{Candidate, Mutation, PreparedCandidate, CANDIDATE_VERSION};
    let rows = crate::host_records_async::migration_audit_rows(PERSISTENCE_OWNER, record).unwrap();
    let prepared = PreparedCandidate::new(Candidate {
        id: store.next_id().unwrap(),
        codec: CANDIDATE_VERSION,
        predicates: vec![],
        mutations: rows
            .into_iter()
            .map(|(address, value)| Mutation::Put { address, value })
            .collect(),
        time: None,
        result: busbar_contract::Secret::default(),
    })
    .unwrap();
    let result = store.submit(prepared).await.unwrap().result;
    assert!(
        matches!(result, crate::persistence::commit::SubmitResult::Decided(decision)
        if matches!(&*decision, busbar_contract::persistence::Decision::Applied(_)))
    );
}
async fn seed_envelope(store: Arc<CoreStore>, record: PlaneRecord) {
    assert_eq!(
        audit_history(store).append(record.view()).await.unwrap(),
        HistoryOutcome::Applied
    );
}
async fn bodies(store: Arc<CoreStore>, scope: &str) -> Vec<Vec<u8>> {
    audit_history(store)
        .list(KIND_AUDIT, &PlaneSelector::Parent(scope.into()))
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.body)
        .collect()
}

#[tokio::test]
async fn a_converted_sites_seam_record_matches_the_legacy_ring_hash() {
    let (native, log) = native_harness().await;
    let (ts, act, res, out, pr) = (
        1_700_000_123u64,
        "hook.register",
        "hook:x",
        "applied",
        "admin",
    );

    let (seq1, prev1, hash1) =
        native_emit(&native, &log, 1, audit_suffix(ts, act, res, out, pr)).await;
    let (seq2, prev2, hash2) = native_emit(
        &native,
        &log,
        2,
        audit_suffix(ts + 60, "hook.delete", res, out, pr),
    )
    .await;

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

#[tokio::test]
async fn seam_write_then_reboot_restore_roundtrips_byte_identically() {
    let store = crate::real_store::core().await;
    let (ts, res, out, pr) = (1_700_000_500u64, "hook:rt", "applied", "admin");

    let h1 = native_over(store.clone()).await;
    let (s1, p1, hash1) = h1
        .emit(ADMIN_LOG, audit_suffix(ts, "hook.register", res, out, pr))
        .await;
    let (s2, p2, hash2) = h1
        .emit(
            ADMIN_LOG,
            audit_suffix(ts + 60, "hook.delete", res, out, pr),
        )
        .await;
    assert_eq!((s1, p1.as_str()), (1, ""), "genesis position");
    assert_eq!(
        (s2, p2.clone()),
        (2, hash1.clone()),
        "record 2 links record 1"
    );

    let bodies = bodies(store.clone(), ADMIN_LOG).await;
    assert_eq!(
        bodies.len(),
        2,
        "both seam records persisted to plane_records"
    );

    let h2 = native_over(store.clone()).await;
    let restored = h2.restore().await.expect("plane_records read");
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

#[tokio::test]
async fn frozen_legacy_audit_rows_restore_natively_without_resealing() {
    use crate::audit::boot_verify_golden::{AD_1, AD_2};
    const HEAD: &str = "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa";
    const TAIL: &str = "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264";
    let store = crate::real_store::core().await;
    for frozen in [AD_1, AD_2] {
        seed_legacy(&store, &decode(frozen).unwrap()).await;
    }
    assert!(
        bodies(store.clone(), ADMIN_LOG).await.is_empty(),
        "historical evidence is not rewritten to modern bodies"
    );
    let h = native_over(store.clone()).await;
    for _ in 0..2 {
        let restored = h.restore().await.unwrap();
        assert_eq!(restored.records, 2);
        assert!(restored.chain_breaks.is_empty());
        let ring = h.log.list_filtered(0, MAX_AUDIT_ENTRIES, None, None);
        assert_eq!(
            ring.len(),
            2,
            "repeated native restore does not duplicate evidence"
        );
        assert_eq!(
            (
                ring[0].seq,
                ring[0].hash.as_str(),
                ring[0].prev_hash.as_str()
            ),
            (2, TAIL, HEAD)
        );
        assert_eq!(
            (
                ring[1].seq,
                ring[1].hash.as_str(),
                ring[1].prev_hash.as_str()
            ),
            (1, HEAD, "")
        );
        assert_eq!(ring[0].action, "hook.delete");
        assert_eq!(ring[1].action, "hook.register");
        assert!(ring.iter().all(|r| !r.recorded_here));
    }
    assert!(
        bodies(store, ADMIN_LOG).await.is_empty(),
        "restore performs no migration writes"
    );
}

#[derive(Clone, Default)]
struct AuditDiagnosticCodes(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AuditDiagnosticCodes {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() != tracing::Level::ERROR {
            return;
        }
        struct Code<'a>(&'a mut Vec<String>);
        impl tracing::field::Visit for Code<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "diag" {
                    self.0.push(format!("{value:?}"));
                }
            }
        }
        let mut codes = self.0.lock().unwrap();
        event.record(&mut Code(&mut codes));
    }
}

static DIAG_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct IsolatedCapture {
    _guard: tracing::subscriber::DefaultGuard,
    _lock: std::sync::MutexGuard<'static, ()>,
}

fn capture_into(cap: &AuditDiagnosticCodes) -> IsolatedCapture {
    use tracing_subscriber::layer::SubscriberExt as _;
    let lock = DIAG_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(cap.clone()));
    tracing::callsite::rebuild_interest_cache();
    IsolatedCapture {
        _guard: guard,
        _lock: lock,
    }
}

#[tokio::test]
async fn restore_reports_an_undecodable_audit_row_loudly_and_still_seeds_the_good_row() {
    let store = crate::real_store::core().await;
    let h1 = native_over(store.clone()).await;
    h1.emit(
        ADMIN_LOG,
        audit_suffix(
            1_700_000_900,
            "hook.register",
            "hook:tamper",
            "applied",
            "admin",
        ),
    )
    .await;
    seed_envelope(
        store.clone(),
        PlaneRecord {
            kind: KIND_AUDIT.into(),
            id: ADMIN_LOG.into(),
            parent: Some(ADMIN_LOG.into()),
            seq: 2,
            ts: 0,
            disposition: PlaneDisposition::Active,
            body: b"{ not an audit body".to_vec(),
        },
    )
    .await;
    let h = native_over(store.clone()).await;
    let cap = AuditDiagnosticCodes::default();
    {
        let _capture = capture_into(&cap);
        assert!(h.restore().await.is_err());
    }
    let ring = h.log.list_filtered(0, MAX_AUDIT_ENTRIES, None, None);
    assert_eq!(
        ring.len(),
        1,
        "good evidence remains visible beside unreadable evidence"
    );
    assert_eq!(ring[0].seq, 1);
    assert_eq!(ring[0].action, "hook.register");
    assert!(
        cap.0
            .lock()
            .unwrap()
            .iter()
            .any(|d| d.contains("BUSBAR-2047")),
        "unreadable evidence is diagnosed"
    );
    assert_eq!(
        bodies(store, ADMIN_LOG).await.len(),
        2,
        "restore preserves the unreadable original"
    );
}

#[tokio::test]
async fn restore_does_not_fork_the_chain_when_one_row_is_undecodable() {
    let store = crate::real_store::core().await;
    let h1 = native_over(store.clone()).await;
    h1.emit(
        ADMIN_LOG,
        audit_suffix(
            1_700_000_900,
            "hook.register",
            "hook:tamper",
            "applied",
            "admin",
        ),
    )
    .await;
    seed_envelope(
        store.clone(),
        PlaneRecord {
            kind: KIND_AUDIT.into(),
            id: ADMIN_LOG.into(),
            parent: Some(ADMIN_LOG.into()),
            seq: 2,
            ts: 0,
            disposition: PlaneDisposition::Active,
            body: b"{ not an audit body".to_vec(),
        },
    )
    .await;
    let h = native_over(store.clone()).await;
    assert!(
        h.restore().await.is_err(),
        "unreadable evidence prevents continuation"
    );
    let queue = PendingAuditQueue::new(1);
    queue.enqueue(pending(ADMIN_LOG, 5));
    assert!(drain_native(&queue, &h.log, h.native.clone())
        .await
        .is_err());
    assert_eq!(
        queue.len(),
        1,
        "the original append remains retained, not resealed at genesis"
    );
    assert_eq!(
        bodies(store, ADMIN_LOG).await.len(),
        2,
        "no new seq-one chain is invented"
    );
    assert_eq!(h.log.list_filtered(0, 10, None, None)[0].seq, 1);
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

#[tokio::test]
async fn a_safe_suffix_record_restores_with_exact_fields_despite_embedded_pipes() {
    let (native, log) = native_harness().await;
    let ts = 1_700_000_555u64;
    let forged_resource = "x|applied|nobody";
    let (seq, _prev, hash) = native_emit(
        &native,
        &log,
        3,
        audit_suffix_safe(ts, "hook.register", forged_resource, "rejected", "attacker"),
    )
    .await;
    assert_eq!(seq, 1);

    let rows = native
        .history
        .list(KIND_AUDIT, &PlaneSelector::Parent(ADMIN_LOG.into()))
        .await
        .expect("native persisted record");
    assert_eq!(rows.len(), 1);
    let entry =
        audit_entry_from_body(ADMIN_LOG, &rows[0].body).expect("decode the safe-suffix body");
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
        operation: [tag.wrapping_add(1); 16],
        prepared: None,
        confirmation: None,
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
    let suffix = audit_suffix(1_700_000_000, "hook.register", "hook:x", "applied", "admin");
    let refused = normalize_queued_append(Err(RecordStoreError(
        "the native append answered Fault".into(),
    )));
    assert!(
        refused.is_err(),
        "an append fault is normalized as a queued write failure"
    );

    let written = (7, "prior".to_string(), "next".to_string());
    assert_eq!(normalize_queued_append(Ok(written.clone())), Ok(written));

    let q = PendingAuditQueue::new(4);
    q.enqueue(PendingAudit {
        origin: EventOrigin::Mutation,
        scope: ADMIN_LOG.to_string(),
        suffix,
        operation: [7; 16],
        prepared: None,
        confirmation: None,
    });
    let mut recovered = 0;
    q.drain_with(
        |_, _| {
            normalize_queued_append(Err(RecordStoreError(
                "the native append answered Fault".into(),
            )))
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

    let cap = AuditDiagnosticCodes::default();
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
        "the new event was rejected at the cap; original pending owners remain retained"
    );

    let mut seen: Vec<u8> = Vec::new();
    q.drain_with(
        |_s, _suffix| Ok((1, String::new(), String::new())),
        |p, _seq, _prev, _hash| seen.push(p.suffix[0]),
    );
    assert_eq!(
        seen,
        vec![0, 1],
        "original tags 0 and 1 survive; the new event is rejected"
    );

    let diags = cap.0.lock().unwrap();
    assert!(
        diags.iter().any(|d| d.contains("BUSBAR-2044")),
        "the overflow eviction must emit PLANE_AUDITLOG_WRITE_FAILED (BUSBAR-2044) at ERROR — a \
         silent counter with no guaranteed log sink is exactly the regression being fixed; \
         captured: {diags:?}"
    );
}

#[tokio::test]
async fn a_clean_restore_captures_no_unreadable_row_diagnostic() {
    let store = crate::real_store::core().await;
    let h = native_over(store.clone()).await;
    let cap = AuditDiagnosticCodes::default();
    {
        let _g = capture_into(&cap);
        let _ = h.restore().await;
    }
    assert!(
        cap.0
            .lock()
            .unwrap()
            .iter()
            .all(|d| !d.contains("BUSBAR-2047")),
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

#[tokio::test]
async fn a_live_admin_record_serves_the_1_5_5_hash_under_the_scheme_it_declares() {
    ensure_global_audit_stream_registered().await;
    let resource = "q128-p12-1:plain";

    emit_admin_hostless(
        1_700_000_777,
        "test.write",
        resource,
        "applied",
        "issuer|subject",
    );
    flush_pending()
        .await
        .expect("native audit original confirmed");
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

#[tokio::test]
async fn a_live_admin_record_with_a_bar_in_a_field_recomputes_under_its_declared_scheme() {
    ensure_global_audit_stream_registered().await;
    let resource = "q128-p12-1:with|bar";
    emit_admin_hostless(1_700_000_778, "test.write", resource, "applied", "admin");
    flush_pending()
        .await
        .expect("native audit original confirmed");
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

#[tokio::test]
async fn every_served_audit_record_recomputes_by_the_published_recipe() {
    ensure_global_audit_stream_registered().await;
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

    flush_pending()
        .await
        .expect("all native audit originals confirmed");
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

#[tokio::test]
async fn a_failed_boot_restore_does_not_fork_the_chain_at_seq_one() {
    use busbar_contract::persistence::*;
    struct Unavailable {
        inner: Arc<dyn PersistenceBackend>,
        fail: Arc<AtomicBool>,
    }
    impl PersistenceBackend for Unavailable {
        fn info(&self) -> BackendInfo {
            self.inner.info()
        }
        fn read(&self, r: Arc<Read>) -> Call<'_, ReadResult> {
            Box::pin(async move {
                if self.fail.load(Ordering::SeqCst) {
                    Err(Failure::Unavailable)
                } else {
                    self.inner.read(r).await
                }
            })
        }
        fn scan(&self, r: Arc<Scan>) -> Call<'_, Page> {
            Box::pin(async move {
                if self.fail.load(Ordering::SeqCst) {
                    Err(Failure::Unavailable)
                } else {
                    self.inner.scan(r).await
                }
            })
        }
        fn clock(&self, d: DatasetId) -> Call<'_, ClockObservation> {
            self.inner.clock(d)
        }
        fn commit(&self, c: PreparedCandidate) -> Call<'_, Decision> {
            self.inner.commit(c)
        }
    }
    let fail = Arc::new(AtomicBool::new(false));
    let store = crate::real_store::core_over(Arc::new(Unavailable {
        inner: crate::real_store::native_backend().await,
        fail: fail.clone(),
    }))
    .await;
    let h1 = native_over(store.clone()).await;
    h1.emit(
        ADMIN_LOG,
        audit_suffix(
            100,
            "hook.register",
            "hook:restore-failed",
            "applied",
            "admin",
        ),
    )
    .await;
    let (_, _, tail) = h1
        .emit(
            ADMIN_LOG,
            audit_suffix(
                101,
                "hook.delete",
                "hook:restore-failed",
                "applied",
                "admin",
            ),
        )
        .await;
    let h2 = native_over(store).await;
    fail.store(true, Ordering::SeqCst);
    assert!(h2.restore().await.is_err());
    let queue = PendingAuditQueue::new(1);
    queue.enqueue(pending(ADMIN_LOG, 8));
    assert!(drain_native(&queue, &h2.log, h2.native.clone())
        .await
        .is_err());
    assert_eq!(
        queue.len(),
        1,
        "failed restore retains the append and never invents genesis"
    );
    fail.store(false, Ordering::SeqCst);
    h2.restore().await.unwrap();
    drain_native(&queue, &h2.log, h2.native.clone())
        .await
        .unwrap();
    let entry = h2.log.list_filtered(0, 1, None, None).remove(0);
    assert_eq!(
        (entry.seq, entry.prev_hash.as_str()),
        (3, tail.as_str()),
        "recovery continues the original durable tail"
    );
}

use crate::audit::boot_verify_golden::{AD_1 as LEGACY_1, AD_2 as LEGACY_2};

#[tokio::test]
async fn a_part_way_legacy_import_restores_the_complete_native_history() {
    let store = crate::real_store::core().await;
    let ad1: busbar_contract::records::AuditRecord = decode(LEGACY_1).unwrap();
    let ad2: busbar_contract::records::AuditRecord = decode(LEGACY_2).unwrap();
    seed_legacy(&store, &ad1).await;
    let h = native_over(store.clone()).await;
    assert_eq!(h.restore().await.unwrap().records, 1);
    seed_legacy(&store, &ad2).await;
    for _ in 0..2 {
        let restored = h.restore().await.unwrap();
        assert_eq!(
            restored.records, 2,
            "rows after the durable import checkpoint are not skipped"
        );
        assert!(restored.chain_breaks.is_empty());
    }
    let served = h.log.list_filtered(0, 10, None, None);
    assert_eq!(served.len(), 2);
    assert_eq!(served[0].hash, ad2.hash);
    assert_eq!(served[1].hash, ad1.hash);
    assert!(
        bodies(store, ADMIN_LOG).await.is_empty(),
        "restore never copies or reseals source evidence"
    );
}

#[tokio::test]
async fn native_restore_refuses_to_splice_legacy_and_modern_chains_that_disagree() {
    let store = crate::real_store::core().await;
    let h = native_over(store.clone()).await;
    h.emit(
        ADMIN_LOG,
        audit_suffix(
            1_700_002_000,
            "hook.register",
            "hook:other",
            "applied",
            "admin",
        ),
    )
    .await;
    let before = bodies(store.clone(), ADMIN_LOG).await;
    for bytes in [LEGACY_1, LEGACY_2] {
        seed_legacy(&store, &decode(bytes).unwrap()).await;
    }
    let restarted = native_over(store.clone()).await;
    assert!(
        restarted.restore().await.is_err(),
        "two different originals at one position cannot be spliced"
    );
    assert_eq!(
        bodies(store.clone(), ADMIN_LOG).await,
        before,
        "no evidence is rewritten"
    );
    let retained = restarted.log.list_filtered(0, 10, None, None);
    assert_eq!(
        retained.len(),
        3,
        "both disagreeing seq-one preimages remain evidence"
    );
    let queue = PendingAuditQueue::new(1);
    queue.enqueue(pending(ADMIN_LOG, 9));
    assert!(
        drain_native(&queue, &restarted.log, restarted.native.clone())
            .await
            .is_err()
    );
    assert_eq!(bodies(store, ADMIN_LOG).await.len(), 1);
}

fn v1_5_5_hash(prev: &str, seq: u64, ts: u64, act: &str, res: &str, out: &str, pr: &str) -> String {
    use sha2::Digest as _;
    let canonical = format!("{prev}|{seq}|{ts}|{act}|{res}|{out}|{pr}");
    sha2::Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn a_1_5_5_audit_table_reads_back_whole_and_the_next_record_continues_its_chain() {
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
    let store = crate::real_store::core().await;
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
        seed_legacy(&store, &row).await;
        legacy.push(row);
        prev = hash;
    }

    let h = native_over(store.clone()).await;
    let restored = h.restore().await.expect("restores");
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
    let (seq, prev_hash, hash) = h.emit(ADMIN_LOG, suffix).await;
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
    let cap = AuditDiagnosticCodes::default();
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

#[test]
fn accepted_event_projection_preserves_pinned_identity_and_bounds_disclosure() {
    use crate::export::projection::Projection;
    use busbar_contract::abi::export::{ExportField as F, ExportStream as S};
    let entry = AuditEntry {
        seq: 7,
        ts: 1_700_000_000,
        action: "config.mutate".into(),
        resource: "config:accepted".into(),
        outcome: "applied".into(),
        principal: "admin".into(),
        prev_hash: "prior".into(),
        hash: "digest".into(),
        scheme: crate::audit_ring::AUDIT_SCHEME_PIPE,
        recorded_here: true,
    };
    let full = project_audit_event(
        Projection::for_test(
            &[S::Events],
            crate::export::projection::produced_fields(S::Events),
        ),
        &entry,
    );
    let narrow = project_audit_event(
        Projection::for_test(&[S::Events], S::Events.pinned_fields()),
        &entry,
    );
    assert_eq!(full[F::Kind.as_token()], "config.mutate");
    assert_eq!(full[F::Actor.as_token()], "admin");
    assert_eq!(full[F::Outcome.as_token()], "applied");
    assert_eq!(full[F::Resource.as_token()], "config:accepted");
    for field in [F::Seq, F::Ts, F::PrevHash] {
        assert_eq!(
            narrow[field.as_token()],
            full[field.as_token()],
            "the same accepted record supplies both projections"
        );
    }
    for field in [F::Kind, F::Actor, F::Resource, F::Outcome] {
        assert!(
            narrow.get(field.as_token()).is_none(),
            "ungranted fields never cross the producer boundary"
        );
    }
    let logs = project_audit_event(
        Projection::for_test(
            &[S::Logs],
            crate::export::projection::produced_fields(S::Events),
        ),
        &entry,
    );
    assert_eq!(
        logs,
        serde_json::json!({}),
        "a log-only grant discloses no event fields"
    );
}

#[test]
fn accepted_event_origin_cannot_be_forged_by_mutation_resource_text() {
    use busbar_contract::plugin::Kind;
    let resource = plugin_refusal_resource(
        Kind::Export.root(),
        "accepted-events-failure",
        "delivery-failed",
    );
    assert!(resource.contains("accepted-events-failure"));
    assert!(
        !EventOrigin::for_plugin_refusal(PluginRefusal::Op, Kind::Export.root()).redispatch(),
        "an asynchronous export operation failure is durable evidence without recursive Events delivery"
    );
    assert!(
        EventOrigin::for_plugin_refusal(PluginRefusal::Op, Kind::Auth.root()).redispatch(),
        "an auth operation failure remains an Events producer"
    );
    assert!(
        EventOrigin::Mutation.redispatch(),
        "a normal mutation with identical export-failure resource text still dispatches"
    );
}

#[tokio::test]
async fn repeated_restore_keeps_exact_rows_once_and_preserves_raw_tamper_evidence() {
    async fn restore(log: &PlaneAuditLog, scope: &str, body: Vec<u8>) -> AuditRestored {
        let store = crate::real_store::core().await;
        seed_envelope(
            store.clone(),
            PlaneRecord {
                kind: KIND_AUDIT.into(),
                id: scope.into(),
                parent: Some(scope.into()),
                seq: 1,
                ts: 0,
                disposition: PlaneDisposition::Active,
                body,
            },
        )
        .await;
        let h = native_over(store).await;
        restore_native(log, &h.native).await.unwrap()
    }
    let store = crate::real_store::core().await;
    let h = native_over(store.clone()).await;
    h.emit(
        ADMIN_LOG,
        audit_suffix_safe(42, "hook.register", "hook:a", "applied", "admin"),
    )
    .await;
    let body = bodies(store, ADMIN_LOG).await.remove(0);
    let log = h.log;
    assert_eq!(restore(&log, ADMIN_LOG, body.clone()).await.records, 1);
    assert_eq!(restore(&log, ADMIN_LOG, body.clone()).await.records, 1);
    assert_eq!(log.list_filtered(0, 10, None, None).len(), 1);
    let mut raw: NeutralBody = decode(&body).unwrap();
    let displayed = parse_audit_suffix(&raw.content);
    raw.content.extend_from_slice(b"\xff");
    assert_eq!(
        parse_audit_suffix(&raw.content),
        displayed,
        "distinct raw bytes can have identical display fields"
    );
    let tampered = encode(&raw).unwrap();
    assert!(!restore(&log, ADMIN_LOG, tampered.clone())
        .await
        .chain_breaks
        .is_empty());
    assert_eq!(
        log.list_filtered(0, 10, None, None).len(),
        2,
        "same position/hash never hides a distinct preimage"
    );
    assert!(!restore(&log, ADMIN_LOG, tampered)
        .await
        .chain_breaks
        .is_empty());
    assert_eq!(log.list_filtered(0, 10, None, None).len(), 2);
    raw.hash = "different-claimed-hash".into();
    assert!(!restore(&log, ADMIN_LOG, encode(&raw).unwrap())
        .await
        .chain_breaks
        .is_empty());
    assert_eq!(log.list_filtered(0, 10, None, None).len(), 3);
    restore(&log, "other-scope", body).await;
    assert_eq!(
        log.list_filtered(0, 10, None, None).len(),
        4,
        "scope remains part of persisted evidence identity"
    );
}

#[test]
fn live_audit_page_metadata_tracks_append_and_eviction_without_claiming_completeness() {
    let log = PlaneAuditLog::new();
    let append = |seq| {
        log.push_entry(
            AuditEntry {
                seq,
                ts: seq,
                action: "test".into(),
                resource: "test".into(),
                outcome: "applied".into(),
                principal: "test".into(),
                prev_hash: String::new(),
                hash: seq.to_string(),
                scheme: crate::audit_ring::AUDIT_SCHEME_PIPE,
                recorded_here: false,
            },
            "admin",
            Vec::new(),
            false,
        );
    };
    for seq in 1..=MAX_AUDIT_ENTRIES as u64 {
        append(seq);
    }
    let first = log.list_page(0, 2, None, None);
    assert_eq!(first.retained_from.as_deref(), Some("1"));
    assert_eq!(first.returned_to.as_deref(), Some("1000"));
    assert!(first.truncated);
    append(1001);
    let second = log.list_page(2, 2, None, None);
    assert_eq!(second.retained_from.as_deref(), Some("2"));
    assert_eq!(second.retained_to.as_deref(), Some("1001"));
    assert_eq!(
        first.items[1].seq, second.items[0].seq,
        "live offsets can duplicate after an append"
    );
    assert_eq!(second.semantics, "live_offset");
    assert!(!second.complete);
    let empty = log.list_page(0, 100, Some("absent"), None);
    assert!(empty.returned_from.is_none());
    assert!(!empty.truncated);
    assert!(
        !empty.complete,
        "a filtered empty result proves no complete audit coverage"
    );
    assert_eq!(empty.retained_from.as_deref(), Some("2"));
}

#[tokio::test]
async fn admin_audit_chain_boot_verifies_from_frozen_bytes() {
    use crate::audit::boot_verify_golden::{AD_1, AD_2, AD_TAIL_HASH};
    use busbar_contract::records::AuditRecord;
    let store = crate::real_store::core().await;
    for frozen in [AD_1, AD_2] {
        seed_legacy(&store, &decode(frozen).unwrap()).await;
    }
    let h = native_over(store).await;
    let restored = h.restore().await.expect("native read of frozen audit rows");
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

#[tokio::test]
async fn a_request_refuses_an_unconfirmed_enqueue_even_when_the_caller_ignores_it() {
    let queue = PendingAuditQueue::new(0);
    let (_, publication) = confirmed_request(async {
        let pending = pending_audit(ADMIN_LOG, Vec::new(), EventOrigin::Mutation).unwrap();
        let _ignored = queue.try_enqueue(pending);
    })
    .await;
    let refused = publication.expect_err("an ignored queue refusal cannot publish success");
    assert!(
        refused
            .to_string()
            .contains("request audit enqueue was not confirmed"),
        "the request retains its enqueue failure: {refused}"
    );
    assert_eq!(queue.len(), 0);
}
