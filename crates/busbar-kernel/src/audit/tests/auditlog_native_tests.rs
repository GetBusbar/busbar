// SPDX-License-Identifier: Apache-2.0
//! Native audit witnesses reuse the existing primitive backend fixture; no
//! synchronous RecordStore adapter participates in these paths.
use super::*;
use crate::governance::persistence::prices::tests::{attach, Backend};
use busbar_contract::persistence::{Candidate, Mutation, PreparedCandidate, CANDIDATE_VERSION};

async fn fixture() -> (
    Arc<Backend>,
    Arc<CoreStore>,
    Arc<NativeAudit>,
    PlaneAuditLog,
) {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone()).await);
    let kind = fresh_test_kind_id();
    stream_registry::register(
        kind,
        KIND_AUDIT.into(),
        AUDIT_FRAMING,
        AUDIT_DIGESTS_SCOPE,
        Decode::Native(reframe_audit),
        MAX_AUDIT_ENTRIES,
    );
    let native = install_native(kind, store.clone()).unwrap();
    let log = PlaneAuditLog::with_kind_id(kind);
    restore_native(&log, &native).await.unwrap();
    native.ready.store(true, Ordering::Release);
    (backend, store, native, log)
}
fn event(operation: u8, action: &str) -> PendingAudit {
    let (suffix, _) = admin_suffix(123, action, "native:test", "applied", "original principal");
    PendingAudit {
        scope: ADMIN_LOG.into(),
        suffix,
        origin: EventOrigin::ExportFailure,
        operation: [operation; 16],
        prepared: None,
    }
}

#[tokio::test]
async fn native_full_queue_refuses_the_new_event_and_preserves_the_accepted_original() {
    let (_, _, native, log) = fixture().await;
    let queue = PendingAuditQueue::new(1);
    queue.try_enqueue(event(1, "accepted")).unwrap();
    let refused = queue.try_enqueue(event(2, "retry")).unwrap_err();
    assert!(refused.to_string().contains("queue is full"));
    assert_eq!(queue.len(), 1);
    drain_native(&queue, &log, native.clone()).await.unwrap();
    let rows = log.list_filtered(0, 10, None, None);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "accepted");
    queue.try_enqueue(event(2, "retry")).unwrap();
    drain_native(&queue, &log, native).await.unwrap();
    let rows = log.list_filtered(0, 10, None, None);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].action, "retry");
    assert_eq!(rows[0].prev_hash, rows[1].hash);
}

#[tokio::test]
async fn native_unknown_original_is_not_published_until_its_exact_applied_replay() {
    let (backend, _, native, log) = fixture().await;
    let queue = PendingAuditQueue::new(4);
    queue.enqueue(event(1, "safe|action"));
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(drain_native(&queue, &log, native.clone()).await.is_err());
    assert_eq!(queue.len(), 1);
    assert!(log.list_filtered(0, 10, None, None).is_empty());
    let original = backend.state.lock().unwrap().sent.last().unwrap().clone();
    let queued = queue.rows.lock().unwrap().queued.front().cloned().unwrap();
    assert_eq!(queued.operation, [1; 16]);
    assert!(queued.prepared.is_some());
    drain_native(&queue, &log, native).await.unwrap();
    let replay = backend.state.lock().unwrap().sent.last().unwrap().clone();
    assert_eq!(original.fingerprint(), replay.fingerprint());
    assert_eq!(original.candidate().id, replay.candidate().id);
    assert_eq!(queue.len(), 0);
    let served = log.list_filtered(0, 10, None, None);
    assert_eq!(served.len(), 1);
    assert_eq!(served[0].action, "safe|action");
    assert_eq!(
        served[0].scheme,
        crate::audit_ring::AUDIT_SCHEME_LENGTH_PREFIXED
    );
    assert_eq!(served[0].principal, "original principal");
}

#[tokio::test]
async fn native_cancelled_drain_keeps_original_envelope_operation_and_queue_position() {
    let (backend, _, native, log) = fixture().await;
    let queue = PendingAuditQueue::new(2);
    queue.enqueue(event(2, "cancelled"));
    queue.enqueue(event(3, "second"));
    backend.hang.store(true, Ordering::SeqCst);
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(10),
        drain_native(&queue, &log, native.clone())
    )
    .await
    .is_err());
    let original = backend.state.lock().unwrap().sent.last().unwrap().clone();
    assert_eq!(queue.len(), 2);
    assert!(log.list_filtered(0, 10, None, None).is_empty());
    backend.hang.store(false, Ordering::SeqCst);
    drain_native(&queue, &log, native).await.unwrap();
    let sent = backend.state.lock().unwrap().sent.clone();
    assert_eq!(sent[0].fingerprint(), original.fingerprint());
    assert_eq!(sent[1].fingerprint(), original.fingerprint());
    assert_eq!(sent[0].candidate().id, sent[1].candidate().id);
    let served = log.list_filtered(0, 10, None, None);
    assert_eq!(served.len(), 2);
    assert_eq!(served[0].action, "second");
    assert_eq!(served[1].action, "cancelled");
    assert_eq!(served[0].prev_hash, served[1].hash);
}

#[tokio::test]
async fn native_restore_retains_tampered_legacy_preimage_and_continues_its_actual_tail() {
    let (_, store, native, log) = fixture().await;
    native.ready.store(false, Ordering::Release);
    let record = busbar_contract::records::AuditRecord {
        seq: 1,
        ts: 7,
        action: "original".into(),
        resource: "untouched".into(),
        outcome: "applied".into(),
        principal: "operator".into(),
        prev_hash: String::new(),
        hash: "tampered-original-hash".into(),
    };
    let rows = crate::host_records_async::migration_audit_rows(PERSISTENCE_OWNER, &record).unwrap();
    let prepared = PreparedCandidate::new(Candidate {
        id: store.next_id().unwrap(),
        codec: CANDIDATE_VERSION,
        predicates: Vec::new(),
        mutations: rows
            .into_iter()
            .map(|(address, value)| Mutation::Put { address, value })
            .collect(),
        time: None,
        result: busbar_contract::Secret::default(),
    })
    .unwrap();
    assert!(matches!(
        store.submit(prepared).await.unwrap().result,
        crate::persistence::commit::SubmitResult::Decided(_)
    ));
    let restored = restore_native(&log, &native).await.unwrap();
    assert_eq!(restored.records, 1);
    assert!(!restored.chain_breaks.is_empty());
    assert_eq!(log.list_filtered(0, 10, None, None)[0].hash, record.hash);
    native.ready.store(true, Ordering::Release);
    let queue = PendingAuditQueue::new(2);
    queue.enqueue(event(4, "next"));
    drain_native(&queue, &log, native).await.unwrap();
    let served = log.list_filtered(0, 10, None, None);
    assert_eq!(served[0].prev_hash, record.hash);
    assert_eq!(served[0].seq, 2);
    let held = crate::persistence::history::Audit::authorized(&store, PERSISTENCE_OWNER)
        .list()
        .await
        .unwrap();
    assert_eq!(held, vec![record]);
}

#[test]
fn native_strict_body_admission_rejects_unknown_fields_and_duplicate_positions() {
    assert!(decode_audit_body(
        br#"{"seq":1,"prev_hash":"","hash":"x","content":[],"new_required":true}"#
    )
    .is_err());
    assert!(
        decode_audit_body(br#"{"seq":1,"seq":2,"prev_hash":"","hash":"x","content":[]}"#).is_err()
    );
}
