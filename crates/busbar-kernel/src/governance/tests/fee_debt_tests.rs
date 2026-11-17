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
