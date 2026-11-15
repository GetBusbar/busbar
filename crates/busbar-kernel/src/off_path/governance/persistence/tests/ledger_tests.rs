// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::ModelTokens;

#[test]
fn usage_import_preserves_exact_counts_zero_evidence_and_partition_discovery() {
    let row = UsageLedger {
        requests: u64::MAX,
        billable_requests: 0,
        models: vec![
            ModelTokens {
                scale: 6,
                model: "exact".into(),
                usage_units: BTreeMap::from([("maximum".into(), i128::MAX), ("zero".into(), 0)]),
            },
            ModelTokens {
                scale: 0,
                model: "whole".into(),
                usage_units: BTreeMap::from([("input".into(), 1)]),
            },
        ],
    };
    let rows = migration_usage(correction::ADJUST_UP_BUCKET, 42, &row).unwrap();
    assert!(rows.iter().all(|(at, _)| migration_authorizes(at)));
    let mut wrong_partition = rows[0].0.clone();
    wrong_partition.namespace[0] ^= 1;
    assert!(!migration_authorizes(&wrong_partition));
    assert!(!migration_authorizes(
        &receipt_address(OpId([7; 16])).unwrap()
    ));
    let decoded: UsageLedger = decode(&rows[0].1).unwrap();
    assert_eq!(decoded.requests, u64::MAX);
    assert_eq!(decoded.models[0].usage_units["maximum"], i128::MAX);
    assert_eq!(decoded.models[0].usage_units["zero"], 0);
    assert_eq!(decoded.models[1].usage_units["input"], 1_000_000);
    assert_eq!(index_time(&rows[1].0, &rows[1].1, USAGE).unwrap(), 42);
    let another = migration_usage("other", 42, &row).unwrap();
    assert_ne!(rows[0].0, another[0].0);
    assert_eq!(rows[1].0, another[1].0);
    let seal = crate::seal::lend();
    assert_eq!(rows[1].1.expose(&seal), another[1].1.expose(&seal));
}

#[test]
fn usage_import_refuses_duplicate_models_and_legacy_overflow() {
    let model = ModelTokens {
        scale: 6,
        model: "duplicate".into(),
        usage_units: BTreeMap::new(),
    };
    let mut row = UsageLedger {
        models: vec![model.clone(), model],
        ..Default::default()
    };
    assert!(migration_usage("bucket", 0, &row).is_err());
    row.models.truncate(1);
    row.models[0].scale = 0;
    row.models[0].usage_units.insert("input".into(), i128::MAX);
    assert!(migration_usage("bucket", 0, &row).is_err());
}
