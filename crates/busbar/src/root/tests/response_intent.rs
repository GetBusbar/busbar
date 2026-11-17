// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use busbar_contract::response_delivery::{ResponseDisposition, ResponseStop};
use busbar_core_connector::response_delivery::DeliveryLedger;
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
use busbar_kernel_audit::response_intent::ResponseIntentStamp;
use busbar_kernel_audit::{
    AuditKeySet, AuditSigningKey, AuditVerifyingKey, BootstrapSigner, LiveSigner, Notary,
};

use super::response_intent::{ReleasePublication, ResponseIntentService};
use super::tests::NativeFixture;

fn stamp() -> ResponseIntentStamp {
    ResponseIntentStamp {
        lease_epoch: 2,
        policy_epoch: 3,
        wall: 100,
        mono: 9,
    }
}

async fn rig() -> (NativeFixture, Arc<ResponseIntentService>, DeliveryLedger) {
    let fixture = NativeFixture::new(71).await;
    let key = AuditSigningKey::from_seed(&[47; 32]);
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&key.public_key_hex()).unwrap());
    let (notary, boot) = key.into_grants(LiveSigner::SameAsBootstrap).unwrap();
    let signers = super::signer::spawn(
        Notary::new(notary),
        BootstrapSigner::new(boot),
        Arc::new(OnceLock::new()),
    )
    .unwrap();
    let service =
        ResponseIntentService::new(fixture.journal.clone(), 3, keys, signers.response_intent)
            .unwrap();
    let source = ProcessAdmission::new(0).connection_storage(AdmissionClass::Data);
    let ledger = DeliveryLedger::new(
        &source,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(4).unwrap(),
    )
    .unwrap();
    (fixture, service, ledger)
}

#[tokio::test]
async fn actual_publication_plan_and_confirmed_original_are_one_shot() {
    let (fixture, service, mut ledger) = rig().await;
    let connection = service.connection().unwrap();
    let key = connection.key(1, None).unwrap();
    let handles = ledger.admit(key).unwrap();
    let (mut plan, finalizer) = connection
        .admit(
            key,
            handles,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    plan.record_head(Some(200)).unwrap();
    plan.record_body().unwrap();
    plan.record_body().unwrap();
    let intent = plan
        .freeze(ResponseDisposition::End { status: Some(200) }, stamp())
        .unwrap();
    assert_eq!(intent.final_publication_ordinal, 4);
    assert_eq!(fixture.journal.pending_records(), 0);
    assert_eq!(
        finalizer.finalize(intent).await.unwrap(),
        ReleasePublication::Published
    );
    assert_eq!(
        finalizer.finalize(intent).await.unwrap(),
        ReleasePublication::AlreadyPublished
    );
    let records = fixture
        .journal
        .read_records(super::tests::BUDGET)
        .await
        .unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|r| busbar_kernel_audit::response_intent::is_response_intent(&r.body))
            .count(),
        1
    );
    assert!(finalizer.watch().snapshot().terminal.is_none());
    assert!(!finalizer.watch().snapshot().first_payload_written);
}

#[tokio::test]
async fn cancelled_scope_and_changed_intent_cannot_release() {
    let (_, service, mut ledger) = rig().await;
    let connection = service.connection().unwrap();
    let key = connection.key(1, None).unwrap();
    let handles = ledger.admit(key).unwrap();
    let (plan, finalizer) = connection
        .admit(
            key,
            handles,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let intent = plan
        .freeze(ResponseDisposition::End { status: None }, stamp())
        .unwrap();
    let mut wrong = intent;
    wrong.final_publication_ordinal += 1;
    assert!(finalizer.finalize(wrong).await.is_err());
    finalizer.cancel().cancel(ResponseStop::Cancelled);
    assert!(finalizer.finalize(intent).await.is_err());
    assert!(finalizer.watch().snapshot().terminal.is_none());
}

#[tokio::test]
async fn connection_and_stream_identity_are_not_reused() {
    let (_, service, _) = rig().await;
    let first = service.connection().unwrap();
    let second = service.connection().unwrap();
    let a = first.key(1, None).unwrap();
    let b = second.key(1, None).unwrap();
    assert_eq!((a.node, a.incarnation), (71, 3));
    assert_ne!(a.connection_generation, b.connection_generation);
    assert!(first.key(1, None).is_err());
    assert!(first.key(0, None).is_err());
}

#[tokio::test]
async fn only_fixed_response_purpose_can_sign_from_request_scope() {
    let (_, service, mut ledger) = rig().await;
    let connection = service.connection().unwrap();
    let key = connection.key(1, None).unwrap();
    let handles = ledger.admit(key).unwrap();
    let (plan, finalizer) = connection
        .admit(
            key,
            handles,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let intent = plan
        .freeze(
            ResponseDisposition::Refuse {
                status: 403,
                head_sent: false,
            },
            stamp(),
        )
        .unwrap();
    let result = super::signer::ON_REQUEST_PATH
        .scope(true, finalizer.finalize(intent))
        .await;
    assert_eq!(result.unwrap(), ReleasePublication::Published);
}

#[tokio::test]
async fn native_lost_ack_retries_one_original_and_restart_verifies_only_history() {
    use std::sync::atomic::Ordering;
    let (fixture, service, mut ledger) = rig().await;
    let connection = service.connection().unwrap();
    let key = connection
        .key(1, Some(busbar_contract::ids::UnitKey::new(19)))
        .unwrap();
    let handles = ledger.admit(key).unwrap();
    let (plan, finalizer) = connection
        .admit(
            key,
            handles,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let intent = plan
        .freeze(ResponseDisposition::End { status: None }, stamp())
        .unwrap();
    fixture.faults.clear_observations();
    fixture.faults.lose_acks.store(true, Ordering::Release);
    assert!(finalizer.finalize(intent).await.is_err());
    let next = fixture.journal.next_seq();
    assert_eq!(fixture.journal.pending_records(), 1);
    assert!(finalizer.watch().snapshot().terminal.is_none());
    fixture.faults.lose_acks.store(false, Ordering::Release);
    assert_eq!(
        finalizer.finalize(intent).await.unwrap(),
        ReleasePublication::Published
    );
    assert_eq!(fixture.journal.next_seq(), next);
    {
        let attempts = fixture.faults.requests.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].candidate().id, attempts[1].candidate().id);
        assert_eq!(attempts[0].fingerprint(), attempts[1].fingerprint());
    }
    let restarted = fixture.reopen().await;
    let key = AuditSigningKey::from_seed(&[47; 32]);
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&key.public_key_hex()).unwrap());
    super::response_intent::verify_history(&restarted, &keys).unwrap();
    assert!(super::response_intent::verify_history(&restarted, &AuditKeySet::new()).is_err());
    let foreign = AuditSigningKey::from_seed(&[48; 32]);
    let mut foreign_keys = AuditKeySet::new();
    foreign_keys.insert(AuditVerifyingKey::from_hex(&foreign.public_key_hex()).unwrap());
    assert!(super::response_intent::verify_history(&restarted, &foreign_keys).is_err());
    assert!(finalizer.watch().snapshot().terminal.is_none());
}

#[tokio::test]
async fn dropped_native_confirmation_waiter_retains_original_but_never_releases() {
    let (fixture, service, mut ledger) = rig().await;
    let connection = service.connection().unwrap();
    let key = connection.key(1, None).unwrap();
    let handles = ledger.admit(key).unwrap();
    let (plan, finalizer) = connection
        .admit(
            key,
            handles,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let intent = plan
        .freeze(ResponseDisposition::End { status: None }, stamp())
        .unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let gate = Arc::new(tokio::sync::Notify::new());
    let (observed, held) = (entered.clone(), gate.clone());
    *fixture.faults.on_commit.lock().unwrap() = Some(Arc::new(move |_| {
        let (observed, held) = (observed.clone(), held.clone());
        Box::pin(async move {
            observed.notify_one();
            held.notified().await;
            Ok(())
        })
    }));
    {
        let future = finalizer.finalize(intent);
        tokio::pin!(future);
        tokio::select! {
            result = &mut future => panic!("released before native confirmation: {result:?}"),
            () = entered.notified() => {}
        }
        assert_eq!(fixture.journal.pending_records(), 1);
        assert!(finalizer.watch().snapshot().terminal.is_none());
    }
    let sequence = fixture.journal.next_seq();
    assert_eq!(
        finalizer.watch().cancellation(),
        Some(ResponseStop::Cancelled)
    );
    *fixture.faults.on_commit.lock().unwrap() = None;
    fixture.journal.flush().await.unwrap();
    assert!(finalizer.finalize(intent).await.is_err());
    assert_eq!(fixture.journal.next_seq(), sequence);
    assert_eq!(fixture.journal.pending_records(), 0);
    assert!(finalizer.watch().snapshot().terminal.is_none());
}

#[tokio::test]
async fn terminal_stage_refusal_does_not_create_a_release_or_journal_record() {
    let (fixture, service, mut ledger) = rig().await;
    let connection = service.connection().unwrap();
    let key = connection.key(1, None).unwrap();
    let handles = ledger.admit(key).unwrap();
    let (plan, finalizer) = connection
        .admit(
            key,
            handles,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let intent = plan
        .freeze(
            ResponseDisposition::Refuse {
                status: 503,
                head_sent: false,
            },
            stamp(),
        )
        .unwrap();
    fixture.journal.stop_staging().unwrap();
    let sequence = fixture.journal.next_seq();
    assert!(finalizer.finalize(intent).await.is_err());
    assert_eq!(fixture.journal.next_seq(), sequence);
    assert_eq!(fixture.journal.pending_records(), 0);
    assert!(finalizer.watch().snapshot().terminal.is_none());
}
