// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::unit_checkpoint::{partitions::*, UnitCheckpoint};

fn checkpoint() -> UnitCheckpoint {
    let attempt = |preparation, subject: &str, amount: u64| AttemptPartition {
        preparation,
        dispatch: Some(preparation),
        kind: TargetKind::Model,
        instance: "plane".into(),
        selected_pool: "plane\u{1f}route".into(),
        resource: Some(subject.into()),
        usage: UsagePartition {
            lane: format!("plane\u{1f}{subject}").as_str().into(),
            provider: Some(format!("provider-{subject}").as_str().into()),
            classes: BTreeMap::from([(
                "input".into(),
                ClassFacts {
                    reported: Some(Count::from(amount)),
                    rate_high_water: Count::from(amount),
                    ..Default::default()
                },
            )]),
        },
        transport: Transport::Committed,
        finality: Finality::Complete,
    };
    UnitCheckpoint {
        id: [0x73; 16],
        revision: 0,
        unit: 1,
        principal: "k".into(),
        group: "g".into(),
        arrived: NOW,
        lane: String::new(),
        provider: None,
        era_at: 42,
        era_entry: None,
        units: BTreeMap::new(),
        targets: Vec::new(),
        metered: true,
        ended: false,
        terminal: None,
        audit: Some(b"{}".to_vec().into()),
        measurement: None,
        unread: None,
        partitions: Some(PartitionedUsageV1 {
            version: 1,
            request_pool: "plane\u{1f}original".into(),
            routing_generation: 0,
            attempt_limit: 2,
            declared_classes: ["input".into()].into(),
            attempt_classes: ["input".into()].into(),
            physical_classes: ["input".into()].into(),
            session_origin: SessionOrigin {
                instance: "plane".into(),
                lane: "plane\u{1f}".into(),
                provider: None,
            },
            fee: CapturedFee::NotOwner {
                basis: FeeBasis {
                    lane: None,
                    era: busbar_kernel_ledger::cost::RawRateEra::legacy(42),
                },
            },
            session: None,
            attempts: vec![attempt(1, "A", 12), attempt(2, "B", 8)],
            far_end_answered: true,
            caller_bytes_committed: true,
            disposition: Disposition::Running,
            final_target: Some(2),
        }),
    }
}

#[tokio::test]
async fn selected_quantity_fold_retains_both_attempts_without_legacy_attribution() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit).await;
    let accepted = r.gov.stage_selected_checkpoint(checkpoint(), None).unwrap();
    r.money
        .shard(UnitKey::new(1))
        .get_mut(&UnitKey::new(1))
        .unwrap()
        .native = Some(super::super::native_attempt::NativeMoney::from_accepted(
        accepted.clone(),
    ));
    let folded = r.money.usage_fold(UnitKey::new(1)).unwrap();
    assert_eq!(
        folded.by_class().collect::<Vec<_>>(),
        vec![(INPUT, Some(Count::from(20u64)))]
    );
    assert!(r.money.usage(UnitKey::new(1)).is_none());
    assert!(r.money.attributed_usage(UnitKey::new(1)).is_none());
    assert_eq!(
        r.money.last_counts(UnitKey::new(1)),
        Some(vec![(INPUT, Count::from(20u64))])
    );
    assert_eq!(
        r.money.serving(UnitKey::new(1), str::to_owned).as_deref(),
        Some("plane\u{1f}B")
    );
    let view = r.money.usage_view(UnitKey::new(1)).unwrap();
    assert!(
        matches!(view.as_ref(), UsageView::Partitioned(snapshot) if Arc::ptr_eq(snapshot, &accepted))
    );
}

#[tokio::test]
async fn selected_initial_builder_refuses_missing_admitted_chain_without_fallback() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit).await;
    let mut all = r.money.shard(UnitKey::new(1));
    let open = all.get_mut(&UnitKey::new(1)).unwrap();
    let original = Arc::make_mut(&mut open.money);
    original.lane = "plane\u{1f}".into();
    original.pool = "plane\u{1f}original".into();
    open.checkpoint_audit = Some(b"{}".to_vec().into());
    let mut parts = checkpoint().partitions.unwrap();
    parts.attempts.clear();
    parts.final_target = None;
    parts.far_end_answered = false;
    parts.caller_bytes_committed = false;
    assert!(r
        .money
        .selected_checkpoint_snapshot(UnitKey::new(1), open, parts)
        .is_err());
    assert!(open.native.is_none());
}
