// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
#[test]
fn synthetic_original_values_keep_exact_submission_order_and_fingerprint() {
    let plain = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![],
    };
    let dated = UsageDelta {
        // Request/fee counters live in the aggregate. The dated sibling
        // preserves the same fee through its existing era-qualified unit.
        models: vec![busbar_contract::records::ModelTokensDelta {
            scale: COUNT_SCALE,
            model: era_tag(RawRateEra::legacy(7)),
            usage_units: std::collections::BTreeMap::from([(ERA_FEE_UNIT.into(), 1_000_000)]),
        }],
        ..UsageDelta::default()
    };
    let child = GovState::usage_recovery_child(
        "bucket",
        60,
        ExactUsageDelta::try_from_signed(&plain).unwrap(),
        ExactUsageDelta::try_from_signed(&dated).unwrap(),
        crate::store::now_ms(),
    )
    .unwrap()
    .unwrap();
    let mut event = RecoveryEvent {
        operation_id: child.operation_id,
        revision: 0,
        previous_event: None,
        kind: child.kind,
        body_fingerprint: child.body_fingerprint,
        state: RecoveryState::Intent,
        first_sent_at_ms: child.first_sent_at_ms,
        payload: child.payload,
    };
    let values = GovState::legacy_usage_values(&event).unwrap();
    assert_eq!(
        values,
        vec![
            ("bucket".into(), 60, plain),
            (era_bucket("bucket"), 60, dated)
        ]
    );
    event.body_fingerprint = [0; 32];
    assert!(GovState::legacy_usage_values(&event).is_err());
}
