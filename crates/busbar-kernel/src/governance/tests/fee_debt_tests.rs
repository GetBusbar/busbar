// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FEE-DEBT r1 observer semantics over actual GovState identities and frozen captures.

use super::*;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};

async fn governance() -> Arc<super::super::GovState> {
    Arc::new(
        super::super::GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    )
}

fn source() -> StorageSource {
    ProcessAdmission::new(0)
        .try_enter(AdmissionClass::Data)
        .unwrap()
        .storage()
}

async fn observed(gov: &Arc<super::super::GovState>, buckets: &[&str]) -> Arc<FeeDebtObserver> {
    let observer = FeeDebtObserver::reserve(gov, &source()).unwrap();
    observer.prepare(gov, buckets.iter().copied()).unwrap();
    observer
}

/// The flusher's own association: with no bound owner it completes trivially, so tests offer
/// the capture to the observer directly, exactly as the Node callback would.
fn associate(gov: &super::super::GovState, observer: &FeeDebtObserver, capture: &Arc<FeeCapture>) {
    observer.offer(capture);
    gov.fee_debt.associate(capture);
}

#[tokio::test]
async fn applied_needs_the_associated_original_capture_to_finish() {
    let gov = governance().await;
    let observer = observed(&gov, &["k"]).await;
    observer.mark(0, "k", 5, 0, 1);
    assert_eq!(observer.status(), FeeDebtStatus::Pending);
    let capture = FeeCapture::frozen(&gov.fee_debt, "k", 5, 0, 1, false);
    associate(&gov, &observer, &capture);
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Pending,
        "unacknowledged flight"
    );
    capture.finish(true, false);
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Complete(FeeDebtReceipt {
            applied: 1,
            cancelled_before_send: 0
        })
    );
}

#[tokio::test]
async fn neutral_capture_is_cancelled_before_send_never_applied() {
    let gov = governance().await;
    let observer = observed(&gov, &["k"]).await;
    observer.mark(0, "k", 5, 0, 1);
    observer.mark(0, "k", 5, 0, 2);
    let capture = FeeCapture::frozen(&gov.fee_debt, "k", 5, 0, 2, true);
    associate(&gov, &observer, &capture);
    capture.finish(true, false);
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Complete(FeeDebtReceipt {
            applied: 0,
            cancelled_before_send: 1
        })
    );
}

#[tokio::test]
async fn a_later_mutation_cannot_join_an_older_capture() {
    let gov = governance().await;
    let observer = observed(&gov, &["k"]).await;
    observer.mark(0, "k", 5, 0, 1);
    let first = FeeCapture::frozen(&gov.fee_debt, "k", 5, 0, 1, false);
    associate(&gov, &observer, &first);
    observer.mark(0, "k", 5, 0, 2);
    first.finish(true, false);
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Pending,
        "refund after the cut"
    );
    let second = FeeCapture::frozen(&gov.fee_debt, "k", 5, 0, 2, false);
    associate(&gov, &observer, &second);
    second.finish(true, false);
    assert!(matches!(observer.status(), FeeDebtStatus::Complete(_)));
}

#[tokio::test]
async fn recreated_cells_and_foreign_governance_cannot_satisfy_a_target() {
    let gov = governance().await;
    let other = governance().await;
    let observer = observed(&gov, &["k"]).await;
    observer.mark(0, "k", 5, 0, 1);
    for capture in [
        FeeCapture::frozen(&gov.fee_debt, "k", 6, 0, 1, false),
        FeeCapture::frozen(&gov.fee_debt, "k", 5, 1, 1, false),
        FeeCapture::frozen(&other.fee_debt, "k", 5, 0, 1, false),
    ] {
        associate(&gov, &observer, &capture);
        capture.finish(true, false);
    }
    assert_eq!(observer.status(), FeeDebtStatus::Pending);
}

#[tokio::test]
async fn a_deferred_residual_waits_for_the_next_original_capture_once() {
    let gov = governance().await;
    let observer = observed(&gov, &["k"]).await;
    observer.mark(0, "k", 5, 0, 1);
    let first = FeeCapture::frozen(&gov.fee_debt, "k", 5, 0, 1, false);
    associate(&gov, &observer, &first);
    first.finish(true, true);
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Pending,
        "deferred is not Applied"
    );
    let next = FeeCapture::frozen(&gov.fee_debt, "k", 5, 0, 3, false);
    associate(&gov, &observer, &next);
    assert_eq!(observer.status(), FeeDebtStatus::Pending);
    next.finish(true, false);
    assert!(matches!(observer.status(), FeeDebtStatus::Complete(_)));
}

#[tokio::test]
async fn unassociated_or_unproven_captures_are_unresolved() {
    let gov = governance().await;
    let observer = observed(&gov, &["k"]).await;
    observer.mark(0, "k", 5, 0, 1);
    let capture = FeeCapture::frozen(&gov.fee_debt, "k", 5, 0, 1, false);
    observer.offer(&capture);
    // The flight finished before its association completed: no receipt can be published.
    capture.finish(true, false);
    assert_eq!(observer.status(), FeeDebtStatus::Unresolved);

    let observer = observed(&gov, &["k"]).await;
    observer.mark(0, "k", 5, 0, 1);
    let capture = FeeCapture::frozen(&gov.fee_debt, "k", 5, 0, 1, false);
    associate(&gov, &observer, &capture);
    capture.finish(false, false);
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Unresolved,
        "kept Intent is not Applied"
    );
}

#[tokio::test]
async fn every_target_leg_must_resolve() {
    let gov = governance().await;
    let observer = observed(&gov, &["key", "group"]).await;
    observer.mark(0, "key", 5, 0, 1);
    observer.mark(1, "group", 9, 0, 1);
    let key = FeeCapture::frozen(&gov.fee_debt, "key", 5, 0, 1, false);
    associate(&gov, &observer, &key);
    key.finish(true, false);
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Pending,
        "group leg outstanding"
    );
    let group = FeeCapture::frozen(&gov.fee_debt, "group", 9, 0, 1, true);
    associate(&gov, &observer, &group);
    group.finish(true, false);
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Complete(FeeDebtReceipt {
            applied: 1,
            cancelled_before_send: 1
        })
    );
}

#[tokio::test]
async fn unfunded_targets_refuse_before_any_mutation() {
    let gov = governance().await;
    let tiny = ProcessAdmission::with_limits(0, 8, 0)
        .try_enter(AdmissionClass::Data)
        .unwrap()
        .storage();
    assert!(FeeDebtObserver::reserve(&gov, &tiny).is_err());
    let observer = FeeDebtObserver::reserve(&gov, &source()).unwrap();
    let other = governance().await;
    assert!(matches!(
        observer.prepare(&other, ["k"].into_iter()),
        Err(FeeDebtRefusal::Identity)
    ));
}

/// A governance with the actual recovery journal and one unresolved usage owner that a
/// negative capture can absorb into, as the raw recovery fixtures build it.
async fn absorbing_owner() -> (
    Arc<super::super::GovState>,
    super::super::recovery::RecoveryEvent,
    super::super::raw_recovery::DurableUsageFlight,
) {
    use super::super::recovery::RecoveryState;
    let gov = governance().await;
    gov.attach_recovery_sink(Arc::new(super::super::recovery::tests::Journal::default()))
        .await
        .unwrap();
    let child = super::super::GovState::usage_recovery_child(
        "recovery-bucket",
        0,
        super::super::ExactUsageDelta {
            requests: 7,
            ..Default::default()
        },
        super::super::ExactUsageDelta::default(),
    )
    .unwrap()
    .unwrap();
    let owner = gov
        .new_recovery_event(
            child.operation_id,
            child.kind,
            child.body_fingerprint,
            RecoveryState::Intent,
            child.first_sent_at_ms,
            child.payload,
        )
        .unwrap();
    gov.keep_recovery_event(&owner).await.unwrap();
    let captured = gov
        .capture_usage_recovery(
            "recovery-bucket",
            0,
            super::super::ExactUsageDelta {
                requests: -3,
                ..Default::default()
            },
            Default::default(),
            &gov.capture_foreign_settled_snapshot().await,
        )
        .unwrap();
    assert_eq!(
        captured.prerequisite.as_ref().unwrap().operation_id,
        owner.operation_id
    );
    (gov, owner, captured)
}

/// An absorbed negative transfers its obligation to the exact retained owner: it is not
/// Applied by the kept Intent, and becomes Applied only once that owner's own raw operation
/// and handoff graph settle.
#[tokio::test]
async fn an_absorbed_obligation_waits_for_its_exact_owner_settled_proof() {
    let (gov, owner, captured) = absorbing_owner().await;
    let parent = captured.prerequisite.clone().unwrap();
    let observer = observed(&gov, &["recovery-bucket"]).await;
    observer.mark(0, "recovery-bucket", 5, 0, 1);
    let capture = FeeCapture::frozen(&gov.fee_debt, "recovery-bucket", 5, 0, 1, false);
    associate(&gov, &observer, &capture);
    // As the flusher does (3d43a0341f): the durable flight keeps the absorbing revision first, then
    // the exact owner is pinned at that kept revision before the flight retires.
    gov.drive_durable_usage_flight(&captured).await.unwrap();
    assert!(gov.fee_hold(
        parent.operation_id,
        parent.revision,
        parent.body_fingerprint
    ));
    assert!(capture.finish_transferred(
        true,
        false,
        parent.operation_id,
        parent.revision,
        parent.body_fingerprint
    ));
    gov.resolve_fee_transfers(&observer).await;
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Pending,
        "a kept Intent is not the owner's settled proof"
    );
    gov.drive_raw_recovery(owner.operation_id).await.unwrap();
    gov.resolve_fee_transfers(&observer).await;
    // FEE-DEBT r1 "Split debt": the owner must reach its existing settled proof including the
    // raw operations it owns; 3d43a0341f resolves only once recovery_children_settled holds. The
    // owner's own pass settles it and selects its handoff child as an Intent; that child is its
    // own raw operation, driven by the recovery pulse.
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Pending,
        "a settled owner whose handoff child is still an Intent is not the settled proof"
    );
    let settled = gov.recovery_event(owner.operation_id).unwrap();
    gov.resume_recovery_children(&settled).await.unwrap();
    gov.resolve_fee_transfers(&observer).await;
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Complete(FeeDebtReceipt {
            applied: 1,
            cancelled_before_send: 0
        })
    );
}

/// The live transfer pins its exact owner: forgetting cannot discard the settled proof the
/// obligation depends on, and the pin is released exactly once.
#[tokio::test]
async fn a_live_transfer_pins_its_exact_owner_against_forgetting() {
    let (gov, owner, captured) = absorbing_owner().await;
    let parent = captured.prerequisite.clone().unwrap();
    assert!(!gov.fee_hold(
        parent.operation_id,
        parent.revision + 1,
        parent.body_fingerprint
    ));
    assert!(!gov.fee_hold(parent.operation_id, parent.revision, [0; 32]));
    assert!(!gov.fee_hold([9; 16], parent.revision, parent.body_fingerprint));
    gov.drive_durable_usage_flight(&captured).await.unwrap();
    gov.drive_raw_recovery(owner.operation_id).await.unwrap();
    assert!(gov.fee_hold(
        parent.operation_id,
        parent.revision,
        parent.body_fingerprint
    ));
    gov.forget_confirmed_recovery(owner.operation_id);
    assert!(
        gov.recovery_event(owner.operation_id).is_some(),
        "a pinned owner's settled proof was forgotten"
    );
    gov.fee_release(owner.operation_id);
}

/// A transfer whose exact owner cannot be pinned never becomes a receipt.
#[tokio::test]
async fn an_unpinnable_transfer_is_unresolved() {
    let gov = governance().await;
    let observer = observed(&gov, &["k"]).await;
    observer.mark(0, "k", 5, 0, 1);
    let capture = FeeCapture::frozen(&gov.fee_debt, "k", 5, 0, 1, false);
    associate(&gov, &observer, &capture);
    assert!(!gov.fee_hold([7; 16], 1, [0; 32]));
    capture.finish(false, false);
    assert_eq!(observer.status(), FeeDebtStatus::Unresolved);
}

/// One actual observed native admission: the original charge reached real cells under the
/// fixture's key chain and published its markers.
async fn observed_admission() -> (Arc<super::super::GovState>, Arc<FeeDebtObserver>) {
    use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric};
    let gov = governance().await;
    let groups = std::collections::BTreeMap::from([(
        "g".to_owned(),
        GroupCfg {
            enabled: true,
            limits: vec![LimitCfg {
                selected: None,
                metric: LimitMetric::Concurrent,
                amount: 8,
                per: None,
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = crate::cost::CostModel::resolve_parts(None, 5, &groups);
    let key = busbar_contract::records::VirtualKey {
        id: "fee-debt-observed".into(),
        enabled: true,
        group: Some("g".into()),
        ..Default::default()
    };
    let plan = cost.plan_chain(&key).unwrap();
    let observer = FeeDebtObserver::reserve(&gov, &source()).unwrap();
    let grant = gov
        .try_admit_observed(
            &cost,
            &key,
            &format!("seat{}p", super::super::PLANE_LANE_SEP),
            1_700_000_000,
            Some(&plan),
            &observer,
        )
        .unwrap();
    // The grant's holds may go; the charged counts and markers stay in the cells.
    drop(grant);
    (gov, observer)
}

/// The observed extra fee-unit refund acts on exactly the legs the original charge reached and
/// publishes its marker there; a later capture must cover it. A recreated cell is Unresolved.
#[tokio::test]
async fn observed_fee_unit_refunds_use_the_charged_legs() {
    let (gov, observer) = observed_admission().await;
    let (_, window, _) = observer.charged_leg(0).unwrap();
    assert!(window.is_some(), "the charge marked its leg");
    let pool = format!("seat{}p", super::super::PLANE_LANE_SEP);
    gov.refund_fee_unit_observed(&pool, "extra", None, &observer);
    assert_ne!(observer.status(), FeeDebtStatus::Unresolved);
    let mut leg = 0;
    while let Some((bucket, window, incarnation)) = observer.charged_leg(leg) {
        let at_charge = FeeCapture::frozen(
            &gov.fee_debt,
            &bucket,
            incarnation,
            window.unwrap(),
            1,
            false,
        );
        associate(&gov, &observer, &at_charge);
        at_charge.finish(true, false);
        leg += 1;
    }
    assert_eq!(
        observer.status(),
        FeeDebtStatus::Pending,
        "the refund marker is newer than the charge capture"
    );

    let (gov, observer) = observed_admission().await;
    let (bucket, _, _) = observer.charged_leg(0).unwrap();
    gov.budget.write(&bucket).remove(&*bucket);
    gov.refund_fee_unit_observed(&pool, "extra", None, &observer);
    assert_eq!(observer.status(), FeeDebtStatus::Unresolved);
}

/// Deleting a bucket whose original cell a live native observer still depends on reports the
/// obligation unresolved instead of discarding the cell.
#[tokio::test]
async fn deletion_refuses_while_native_fee_obligations_live() {
    let (gov, observer) = observed_admission().await;
    let (bucket, _, _) = observer.charged_leg(0).unwrap();
    let refused = gov
        .settle_budget_flush_for_delete_async(&bucket)
        .await
        .unwrap_err();
    assert!(refused.0.contains("native fee obligations"), "{refused:?}");
    drop(observer);
    assert!(
        gov.budget
            .write(&bucket)
            .get(&*bucket)
            .is_some_and(|cell| cell.fee_obligations == 0),
        "dropping the observer releases its exact obligation"
    );
}
