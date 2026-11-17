// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;

use super::{PendingAdmission, *};
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric};
use crate::cost::CostModel;
use crate::governance::{GovState, WINDOW_TOTAL};

const NOW: u64 = 1_700_000_000;

struct Post;
impl EndPost for Post {
    fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
}

async fn fixture() -> (Arc<GovState>, PlaneMoney, UnitMoney) {
    let gov = Arc::new(
        GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    let groups = BTreeMap::from([(
        "g".into(),
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
                selected: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = Arc::new(CostModel::resolve_parts(None, 5, &groups));
    let key = Arc::new(VirtualKey {
        id: "native-pending".into(),
        enabled: true,
        group: Some("g".into()),
        ..Default::default()
    });
    let money = PlaneMoney::new(gov.clone(), Arc::new(Post));
    let unit = UnitMoney {
        key,
        cost,
        pool: "p".into(),
        lane: "m".into(),
        classes: Arc::from(Vec::<String>::new()),
        arrived: NOW,
        mode: ExhaustionMode::FinishUnit,
        fee: FeeRefund::CallerStatus,
        charge: Default::default(),
    };
    (gov, money, unit)
}

fn pending(gov: &Arc<GovState>, unit: &UnitMoney) -> PendingAdmission {
    let plan = unit.cost.plan_chain(&unit.key).unwrap();
    let grant = gov
        .try_admit_planned(&unit.cost, &unit.key, &unit.pool, unit.arrived, Some(&plan))
        .unwrap();
    PendingAdmission::new(gov.clone(), unit.clone(), grant)
}

async fn totals(gov: &GovState, unit: &UnitMoney) -> (u64, i64) {
    let usage = gov
        .derived_bucket_usage_async(&unit.cost, &unit.key.id, WINDOW_TOTAL, true, NOW)
        .await
        .unwrap();
    (usage.requests, usage.spend_cents)
}

#[tokio::test]
async fn cancelled_pending_admission_returns_only_its_actual_charge_and_hold() {
    let (gov, money, unit) = fixture().await;
    let first = pending(&gov, &unit);
    let second = pending(&gov, &unit);
    assert_eq!(totals(&gov, &unit).await, (2, 10));
    assert_eq!(gov.concurrent_in_flight("g"), 2);
    drop(second);
    assert_eq!(totals(&gov, &unit).await, (1, 5));
    assert_eq!(gov.concurrent_in_flight("g"), 1);
    drop(first);
    assert_eq!(totals(&gov, &unit).await, (0, 0));
    assert_eq!(gov.concurrent_in_flight("g"), 0);
    assert_eq!(money.open_units(), 0);
}

#[tokio::test]
async fn occupied_native_install_preserves_existing_open_and_refunds_new_admission() {
    let (gov, money, unit) = fixture().await;
    let first = pending(&gov, &unit);
    money
        .install_native_pending(UnitKey::new(1), first, |_, _, _| Ok(()))
        .unwrap();
    let original = money.shard(UnitKey::new(1))[&UnitKey::new(1)]
        .identity
        .clone();
    let second = pending(&gov, &unit);
    let result: Result<(), NativeAdmissionError> =
        money.install_native_pending(UnitKey::new(1), second, |_, _, _| {
            panic!("occupied insertion must not activate another receipt")
        });
    assert!(matches!(result, Err(NativeAdmissionError::Occupied)));
    assert!(Arc::ptr_eq(
        &original,
        &money.shard(UnitKey::new(1))[&UnitKey::new(1)].identity,
    ));
    assert_eq!(totals(&gov, &unit).await, (1, 5));
    assert_eq!(gov.concurrent_in_flight("g"), 1);
    money.settle_end(UnitKey::new(1), 200);
    assert_eq!(totals(&gov, &unit).await, (1, 5));
    assert_eq!(gov.concurrent_in_flight("g"), 0);
}

#[tokio::test]
async fn failed_phase_activation_removes_only_the_new_open_and_rolls_back_once() {
    let (gov, money, unit) = fixture().await;
    let pending = pending(&gov, &unit);
    let result: Result<(), NativeAdmissionError> =
        money.install_native_pending(UnitKey::new(1), pending, |_, _, _| {
            Err(NativeAdmissionError::NotLive)
        });
    assert!(matches!(result, Err(NativeAdmissionError::NotLive)));
    assert_eq!(money.open_units(), 0);
    assert_eq!(totals(&gov, &unit).await, (0, 0));
    assert_eq!(gov.concurrent_in_flight("g"), 0);
    money.settle_end(UnitKey::new(1), 499);
    assert_eq!(totals(&gov, &unit).await, (0, 0));
}

#[tokio::test]
async fn selected_fee_observer_neither_participates_nor_retains_the_admission_hold() {
    use crate::governance::unit_checkpoint::partitions::{CapturedFee, FeeResult};

    for child_incurred in [false, true] {
        let (gov, money, unit) = fixture().await;
        money
            .install_native_pending(UnitKey::new(1), pending(&gov, &unit), |_, _, _| Ok(()))
            .unwrap();
        let parent = money.parent_money(UnitKey::new(1), &unit.key).unwrap();
        money
            .open_child(
                &parent,
                UnitKey::new(2),
                "other\u{1f}model".into(),
                unit.classes.clone(),
                FeeRefund::CallerStatus,
            )
            .unwrap();
        let (captured, observer) = money.shard(UnitKey::new(1))[&UnitKey::new(1)]
            .fee
            .selected_fee();
        let observer = observer.expect("original fee owner has a nonparticipating observer");
        assert!(matches!(captured, CapturedFee::PendingOwner { .. }));
        assert!(
            captured.basis().lane.is_none(),
            "original flat fee, not child lane"
        );
        let (child_fee, child_observer) = money.shard(UnitKey::new(2))[&UnitKey::new(2)]
            .fee
            .selected_fee();
        assert!(matches!(child_fee, CapturedFee::NotOwner { .. }));
        assert_eq!(child_fee.basis(), captured.basis());
        assert!(child_observer.is_none());
        drop(parent);

        money.settle_end(UnitKey::new(1), 503);
        assert!(
            observer.observe().is_none(),
            "actual child still participates"
        );
        assert_eq!(gov.concurrent_in_flight("g"), 1);
        money.settle_end(UnitKey::new(2), if child_incurred { 200 } else { 503 });
        assert_eq!(
            observer.observe(),
            Some(if child_incurred {
                FeeResult::Charged
            } else {
                FeeResult::Refunded
            }),
        );
        assert_eq!(
            totals(&gov, &unit).await,
            (1, if child_incurred { 5 } else { 0 })
        );
        assert_eq!(
            gov.concurrent_in_flight("g"),
            0,
            "observer retains no grant"
        );
        money.settle_end(UnitKey::new(1), 503);
        money.settle_end(UnitKey::new(2), 503);
        assert_eq!(
            totals(&gov, &unit).await,
            (1, if child_incurred { 5 } else { 0 })
        );
    }
}

#[tokio::test]
async fn child_activation_refusal_does_not_mark_original_fee_incurred() {
    for child in [2, 17] {
        let (gov, money, unit) = fixture().await;
        money
            .install_native_pending(UnitKey::new(1), pending(&gov, &unit), |_, _, _| Ok(()))
            .unwrap();
        let parent = money.parent_money(UnitKey::new(1), &unit.key).unwrap();
        let result: Result<(), NativeAdmissionError> = money.install_child_with(
            &parent,
            UnitKey::new(child),
            "child\u{1f}model".into(),
            unit.classes.clone(),
            FeeRefund::CallerStatus,
            |_, _, _| Err(NativeAdmissionError::NotLive),
        );
        assert!(matches!(result, Err(NativeAdmissionError::NotLive)));
        assert_eq!(money.open_units(), 1);
        assert_eq!(totals(&gov, &unit).await, (1, 5));
        assert_eq!(gov.concurrent_in_flight("g"), 1);
        drop(parent);
        money.settle_end(UnitKey::new(1), 503);
        assert_eq!(totals(&gov, &unit).await, (1, 0));
        assert_eq!(gov.concurrent_in_flight("g"), 0);
    }
}

#[tokio::test]
async fn attempt_owned_scope_class_refuses_before_paid_observation_create_or_attach() {
    use crate::governance::unit_checkpoint::partitions::{
        Disposition, PartitionedUsageV1, SessionOrigin,
    };
    use crate::governance::unit_checkpoint::UnitCheckpoint;
    use crate::plane_driver::money::native_attempt::NativeMoney;
    use crate::plane_driver::{ObservationPolicy, ObservationRuntimeError};
    use std::collections::BTreeSet;

    let (gov, money, mut unit) = fixture().await;
    unit.classes = Arc::from(vec!["tokens.in".to_owned()]);
    money
        .install_native_pending(UnitKey::new(1), pending(&gov, &unit), |_, _, _| Ok(()))
        .unwrap();
    {
        let mut shard = money.shard(UnitKey::new(1));
        let open = shard.get_mut(&UnitKey::new(1)).unwrap();
        let (fee, _) = open.fee.selected_fee();
        let checkpoint = UnitCheckpoint {
            id: open.checkpoint_id,
            revision: 0,
            unit: 1,
            principal: unit.key.id.clone(),
            group: "g".into(),
            arrived: NOW,
            lane: String::new(),
            provider: None,
            era_at: open.money.charge.raw_era().effective_from,
            era_entry: open.money.charge.raw_era().entry_id.map(|id| id.0),
            units: BTreeMap::new(),
            targets: Vec::new(),
            metered: false,
            ended: false,
            terminal: None,
            audit: None,
            measurement: None,
            unread: None,
            partitions: Some(PartitionedUsageV1 {
                version: 1,
                request_pool: unit.pool.clone(),
                routing_generation: 0,
                attempt_limit: 1,
                declared_classes: BTreeSet::from(["tokens.in".into()]),
                attempt_classes: BTreeSet::from(["tokens.in".into()]),
                physical_classes: BTreeSet::from(["tokens.in".into()]),
                session_origin: SessionOrigin {
                    instance: "native".into(),
                    lane: "native\u{1f}".into(),
                    provider: None,
                },
                fee,
                session: None,
                attempts: Vec::new(),
                far_end_answered: false,
                caller_bytes_committed: false,
                disposition: Disposition::Running,
                final_target: None,
            }),
        };
        // Frozen ownership facts, with no accepted usage and no synthetic selection authority.
        open.native = Some(NativeMoney::from_accepted(Arc::new(checkpoint)));
    }
    let policy = ObservationPolicy {
        instance: "native".into(),
        destination: "provider".into(),
        serving_subject: "native\u{1f}m0".into(),
        accounting_namespace: "usage".into(),
        classes: vec![0],
        rated_subjects: Vec::new(),
        reserve_nanos: 1,
        ordered_revisions: true,
    };
    assert!(matches!(
        money
            .issue_observation_scope(UnitKey::new(1), &policy)
            .await,
        Err(ObservationRuntimeError::LegacyOverlap),
    ));
    assert!(matches!(
        money
            .attach_observation_scope(UnitKey::new(1), &policy, [0; 32])
            .await,
        Err(ObservationRuntimeError::LegacyOverlap),
    ));
    assert!(money.observation_scope(UnitKey::new(1)).is_none());
    assert_eq!(totals(&gov, &unit).await, (1, 5));
}
