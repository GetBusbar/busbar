// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::governance::unit_checkpoint::{partitions as raw, UnitCheckpoint};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn terminal() -> UnitCheckpoint {
    let classes = BTreeSet::from([busbar_contract::kept::Text::fixed("tokens.custom")]);
    UnitCheckpoint {
        id: [7; 16],
        revision: 3,
        unit: 91,
        principal: "payer".into(),
        group: "g".into(),
        arrived: 100,
        lane: String::new(),
        provider: None,
        era_at: 90,
        era_entry: None,
        units: BTreeMap::new(),
        targets: Vec::new(),
        metered: false,
        ended: true,
        terminal: None,
        audit: Some(vec![1].into()),
        measurement: None,
        unread: None,
        partitions: Some(raw::PartitionedUsageV1 {
            version: 1,
            request_pool: "seat\u{1f}p".into(),
            routing_generation: 8,
            attempt_limit: 2,
            declared_classes: classes.clone(),
            attempt_classes: classes.clone(),
            physical_classes: classes,
            session_origin: raw::SessionOrigin {
                instance: "seat".into(),
                lane: "seat\u{1f}".into(),
                provider: None,
            },
            fee: raw::CapturedFee::ResolvedOwner {
                basis: raw::FeeBasis {
                    lane: None,
                    era: busbar_kernel_ledger::cost::RawRateEra {
                        effective_from: 90,
                        entry_id: None,
                    },
                },
                result: raw::FeeResult::Refunded,
            },
            session: None,
            attempts: vec![raw::AttemptPartition {
                preparation: 1,
                dispatch: None,
                kind: raw::TargetKind::Model,
                instance: "seat".into(),
                selected_pool: "seat\u{1f}q".into(),
                resource: Some("resource".into()),
                usage: raw::UsagePartition {
                    lane: "seat\u{1f}model".into(),
                    provider: Some("provider".into()),
                    classes: BTreeMap::new(),
                },
                transport: raw::Transport::NoSend,
                finality: raw::Finality::Unknown,
            }],
            far_end_answered: false,
            caller_bytes_committed: false,
            disposition: raw::Disposition::Failed,
            final_target: None,
        }),
    }
}

#[test]
fn unreported_no_send_class_remains_unknown_in_signed_projection() {
    let snapshot = terminal();
    let view = raw::ValidatedSelectedCheckpoint::try_from(&snapshot).unwrap();
    let billing = super::selected_report::selected_billing(&view).unwrap();
    let part = &billing.facts().partitions[0];
    let class = &part.classes["tokens.custom"];
    assert_eq!(class.reported, None);
    assert_eq!(class.floor, None);
    assert_eq!(class.estimated, None);
    assert_eq!(class.selected, None);
    assert_eq!(class.billed, None);
    assert_eq!(part.lane, "seat\u{1f}model");
    assert_eq!(part.selected_pool.as_deref(), Some("seat\u{1f}q"));
    assert_eq!(billing.facts().request_pool, "seat\u{1f}p");
    assert_eq!(billing.fee_count(), 0);
}

#[test]
fn unresolved_original_fee_cannot_be_signed_as_final() {
    let mut snapshot = terminal();
    let parts = snapshot.partitions.as_mut().unwrap();
    parts.fee = raw::CapturedFee::PendingOwner {
        basis: parts.fee.basis().clone(),
    };
    let view = raw::ValidatedSelectedCheckpoint::try_from(&snapshot).unwrap();
    assert!(super::selected_report::selected_billing(&view).is_err());
}

#[test]
fn historical_running_audit_does_not_invent_selected_identity() {
    let encoded = br#"{"incarnation":3,"principal":"payer","op_class":"chat","origin":"direct","parent":null,"wall":100,"mono":4,"destination":null,"rate_card":null,"policy_epoch":0,"hooks":[]}"#;
    let mut audit: crate::root::durability::RunningAudit =
        busbar_contract::json::parse(encoded).unwrap();
    assert!(audit.selected_identity.is_none());
    audit.selected_identity = Some(crate::root::durability::SelectedAuditIdentity {
        node: 7,
        boot_nonce: [9; 16],
        user: Some("captured-user".into()),
        labels: vec![("purpose".into(), "original".into())],
    });
    let serialized = busbar_contract::json::to_vec(&audit).unwrap();
    let decoded: crate::root::durability::RunningAudit =
        busbar_contract::json::parse(&serialized).unwrap();
    let identity = decoded.selected_identity.unwrap();
    assert_eq!(identity.node, 7);
    assert_eq!(identity.boot_nonce, [9; 16]);
    assert_eq!(identity.user.as_deref(), Some("captured-user"));
    assert_eq!(
        identity.labels,
        [("purpose".to_owned(), "original".to_owned())]
    );
}
