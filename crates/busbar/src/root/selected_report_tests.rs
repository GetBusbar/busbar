// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::governance::unit_checkpoint::{partitions as raw, UnitCheckpoint};
use std::collections::{BTreeMap, BTreeSet};

fn terminal() -> UnitCheckpoint {
    let classes = BTreeSet::from(["tokens.custom".to_owned()]);
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
        audit: Some(vec![1]),
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
