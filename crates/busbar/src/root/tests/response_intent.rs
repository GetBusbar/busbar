// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The response's release (design 2, A1, A5, A7): no signature and no journal record on the
//! request; a count for a refusal with no identity; a wait for the group commit only when the
//! response carries a line under `advanced.wait_for_commit`.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::caps::{ReasonCode, StepName};
use busbar_contract::response_delivery::{ResponseDisposition, ResponseStop};
use busbar_core_connector::response_delivery::DeliveryLedger;

use super::core_audit::{CoreAudit, CoreFlusher};
use super::response_intent::{ReleasePublication, ResponseIntentService, ResponseRecord};
use super::tests::NativeFixture;

pub(crate) async fn rig() -> (
    NativeFixture,
    Arc<ResponseIntentService>,
    DeliveryLedger,
    CoreFlusher,
) {
    let fixture = NativeFixture::new(71).await;
    let incarnation = fixture.book().await.incarnation;
    let service = ResponseIntentService::new(fixture.journal.clone(), incarnation);
    (
        fixture,
        service,
        DeliveryLedger::default(),
        CoreFlusher::default(),
    )
}

fn soon() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(5)
}

#[tokio::test]
async fn rejected_registration_cancels_original_handles_without_publishing_release() {
    let (_fixture, service, mut ledger, cores) = rig().await;
    let original = service.connection(cores.core()).unwrap();
    let foreign = service.connection(cores.core()).unwrap();
    let key = original.key(1, None).unwrap();
    let handles = ledger.admit(key).unwrap();
    let watch = handles.watch.clone();
    assert!(foreign
        .admit(key, handles, soon(), ResponseRecord::Nothing)
        .is_err());
    assert_eq!(watch.key(), key);
    assert_eq!(watch.cancellation(), Some(ResponseStop::Integrity));
    assert!(watch.snapshot().terminal.is_none());
    assert!(!watch.snapshot().first_payload_written);
}

#[tokio::test]
async fn a_release_signs_nothing_writes_nothing_and_is_one_shot() {
    let (fixture, service, mut ledger, cores) = rig().await;
    let connection = service.connection(cores.core()).unwrap();
    let key = connection.key(1, None).unwrap();
    let handles = ledger.admit(key).unwrap();
    let (mut plan, finalizer) = connection
        .admit(key, handles, soon(), ResponseRecord::Nothing)
        .unwrap();
    plan.record_head(Some(200)).unwrap();
    plan.record_body().unwrap();
    plan.record_body().unwrap();
    let next = fixture.journal.next_seq();
    let intent = plan
        .freeze(ResponseDisposition::End { status: Some(200) })
        .unwrap();
    assert_eq!(intent.final_publication_ordinal, 4);
    assert_eq!(
        finalizer.finalize(intent).await.unwrap(),
        ReleasePublication::Published
    );
    assert_eq!(
        finalizer.finalize(intent).await.unwrap(),
        ReleasePublication::AlreadyPublished
    );
    assert_eq!(fixture.journal.pending_records(), 0, "nothing staged");
    assert_eq!(fixture.journal.next_seq(), next, "nothing appended");
}

#[tokio::test]
async fn cancelled_scope_and_changed_intent_cannot_release() {
    let (_, service, mut ledger, cores) = rig().await;
    let connection = service.connection(cores.core()).unwrap();
    let key = connection.key(1, None).unwrap();
    let handles = ledger.admit(key).unwrap();
    let (plan, finalizer) = connection
        .admit(key, handles, soon(), ResponseRecord::Nothing)
        .unwrap();
    let intent = plan
        .freeze(ResponseDisposition::End { status: None })
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
    let (fixture, service, _, cores) = rig().await;
    let first = service.connection(cores.core()).unwrap();
    let second = service.connection(cores.core()).unwrap();
    let a = first.key(1, None).unwrap();
    let b = second.key(1, None).unwrap();
    assert_eq!(
        (a.node, a.incarnation),
        (71, fixture.book().await.incarnation)
    );
    assert_ne!(a.connection_generation, b.connection_generation);
    assert!(first.key(1, None).is_err());
    assert!(first.key(0, None).is_err());
}

#[tokio::test]
async fn node_refuses_foreign_core_and_mismatched_book_incarnation() {
    let (fixture, service, _, _) = rig().await;
    let foreign = NativeFixture::new(72).await;
    let node = crate::root::plane_node::Node::new();
    node.bind_book(Arc::new(std::sync::Mutex::new(fixture.book().await)));
    assert!(node
        .bind_response_intents(foreign.core, service.clone())
        .is_err());

    let mut different_book = fixture.book().await;
    different_book.incarnation = different_book.incarnation.checked_add(1).unwrap();
    let different_node = crate::root::plane_node::Node::new();
    different_node.bind_book(Arc::new(std::sync::Mutex::new(different_book)));
    assert!(different_node
        .bind_response_intents(fixture.core, service)
        .is_err());
}

#[tokio::test]
async fn a_refusal_with_no_identity_is_one_count_on_its_core_and_no_record() {
    let (fixture, service, mut ledger, cores) = rig().await;
    let core: Arc<CoreAudit> = cores.core();
    let connection = service.connection(Arc::clone(&core)).unwrap();
    let next = fixture.journal.next_seq();
    for stream in 1..=3 {
        let key = connection.key(stream, None).unwrap();
        let handles = ledger.admit(key).unwrap();
        let (plan, finalizer) = connection
            .admit(
                key,
                handles,
                soon(),
                ResponseRecord::Counted {
                    listener: "public".into(),
                    step: StepName::Authenticate,
                    reason: ReasonCode::Unauthenticated,
                },
            )
            .unwrap();
        let intent = plan
            .freeze(ResponseDisposition::Refuse {
                status: 401,
                head_sent: false,
            })
            .unwrap();
        assert_eq!(
            finalizer.finalize(intent).await.unwrap(),
            ReleasePublication::Published
        );
    }
    let held = core.refusals_held();
    assert_eq!(held.len(), 1);
    assert_eq!((held[0].count, held[0].status), (3, 401));
    assert_eq!(core.records().held(), 0, "a count is not a line");
    assert_eq!(fixture.journal.next_seq(), next, "nothing appended");
    assert_eq!(fixture.journal.pending_records(), 0);
}

#[tokio::test]
async fn under_wait_for_commit_the_release_waits_for_the_commit_that_holds_its_line() {
    let (_fixture, service, mut ledger, cores) = rig().await;
    let core = cores.core();
    let connection = service.connection(Arc::clone(&core)).unwrap();
    let key = connection
        .key(1, Some(busbar_contract::ids::UnitKey::new(19)))
        .unwrap();
    let handles = ledger.admit(key).unwrap();
    let line = super::audit::tests::inputs(19);
    let (mut plan, finalizer) = connection
        .admit(
            key,
            handles,
            soon(),
            ResponseRecord::Committed(Box::new(line)),
        )
        .unwrap();
    plan.record_head(Some(201)).unwrap();
    let intent = plan
        .freeze(ResponseDisposition::End { status: Some(201) })
        .unwrap();
    let release = finalizer.finalize(intent);
    tokio::pin!(release);
    tokio::select! {
        result = &mut release => panic!("released before its line was committed: {result:?}"),
        () = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    let pulled = cores.pull();
    assert_eq!(pulled.lines.len(), 1, "the line is in the core's outbox");
    assert_eq!(
        pulled.lines[0].1.unit.status, 201,
        "with the answered status"
    );
    for (core, through) in &pulled.cores {
        core.records().settled(*through);
    }
    assert_eq!(release.await.unwrap(), ReleasePublication::Published);
}

#[tokio::test]
async fn a_release_waiting_for_a_commit_ends_at_its_deadline_unpublished() {
    let (_fixture, service, mut ledger, cores) = rig().await;
    let connection = service.connection(cores.core()).unwrap();
    let key = connection.key(1, None).unwrap();
    let handles = ledger.admit(key).unwrap();
    let (mut plan, finalizer) = connection
        .admit(
            key,
            handles,
            tokio::time::Instant::now() + Duration::from_millis(50),
            ResponseRecord::Committed(Box::new(super::audit::tests::inputs(3))),
        )
        .unwrap();
    plan.record_head(Some(200)).unwrap();
    let intent = plan
        .freeze(ResponseDisposition::End { status: Some(200) })
        .unwrap();
    assert!(finalizer.finalize(intent).await.is_err());
    assert!(finalizer.watch().snapshot().terminal.is_none());
}
