// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/abi/sdk/store_migrate.rs`.

use super::*;
use crate::records::{UsageLedger, UNIT_INPUT};

/// Read a raw JSON row through the frozen 1.5.x shape and fold it: the per-row unit a store's
/// `migrate()` runs.
fn migrate_raw(raw: &str) -> UsageLedger {
    let v1: UsageLedgerV1 = serde_json::from_str(raw).expect("a 1.5.x row reads");
    fold_v1_ledger(v1)
}

/// The scalar tiers land on the reserved keys; open units ride through.
#[test]
fn folds_scalar_tiers_onto_reserved_keys() {
    let raw = r#"{"requests":3,"billable_requests":2,"models":[
        {"model":"gpt-4o","tokens":{"input":100,"output":50,"cache_read":10,"cache_write":8},
         "usage_units":{"audio":7}}]}"#;
    let l = migrate_raw(raw);
    assert_eq!(l.total_input(), 100);
    assert_eq!(l.total_output(), 50);
    assert_eq!(l.total_cache_read(), 10);
    assert_eq!(l.total_cache_write(), 8);
    let m = &l.models[0];
    assert_eq!(m.usage_units.get("audio"), Some(&7));
    assert_eq!(m.usage_units.get(UNIT_INPUT), Some(&100));
    assert_eq!(l.requests, 3);
    assert_eq!(l.billable_requests, 2);
}

/// A columnar 1.5.x row (`tokens_input` ... columns, no JSON) fills the frozen shape field by field
/// and folds to the same ledger its JSON twin does.
#[test]
fn a_columnar_row_folds_like_its_json_twin() {
    let columns = UsageLedgerV1 {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensV1 {
            model: "m".into(),
            tokens: TierTokensV1 {
                input: 11,
                output: 7,
                cache_read: 0,
                cache_write: 0,
            },
            usage_units: Default::default(),
        }],
    };
    let json = r#"{"requests":1,"billable_requests":1,"models":[
        {"model":"m","tokens":{"input":11,"output":7,"cache_read":0,"cache_write":0}}]}"#;
    assert_eq!(fold_v1_ledger(columns), migrate_raw(json));
}

/// The legacy `cache_creation` spelling folds onto `cache_write`, never a second key.
#[test]
fn canonicalizes_cache_creation_onto_cache_write() {
    let raw = r#"{"models":[{"model":"m","tokens":{"cache_write":5},
        "usage_units":{"cache_creation":4}}]}"#;
    let l = migrate_raw(raw);
    assert_eq!(l.total_cache_write(), 9);
    assert_eq!(l.models[0].usage_units.get("cache_creation"), None);
}

/// THE CRASH-SAFETY GATE. A crash mid-migration (rows 0 and 1 folded and written, the schema stamp
/// not yet applied) forces a full re-scan on the next open. Re-folding the folded rows must be the
/// identity, so the totals after crash plus rerun are byte-identical to one clean run.
#[test]
fn crash_partial_then_rerun_is_byte_identical_to_a_clean_run() {
    let raw_rows = [
        r#"{"requests":5,"billable_requests":5,"models":[{"model":"a","tokens":{"input":1000,"output":400,"cache_read":30,"cache_write":12}}]}"#,
        r#"{"requests":2,"billable_requests":1,"models":[{"model":"b","tokens":{"input":7,"output":0,"cache_read":0,"cache_write":0}},{"model":"c","tokens":{"input":0,"output":9,"cache_read":0,"cache_write":0},"usage_units":{"images":2}}]}"#,
        r#"{"requests":9,"billable_requests":9,"models":[{"model":"d","tokens":{"input":42,"output":42,"cache_read":42,"cache_write":42}}]}"#,
    ];
    let clean: Vec<UsageLedger> = raw_rows.iter().map(|r| migrate_raw(r)).collect();

    let folded_0 = serde_json::to_string(&clean[0]).unwrap();
    let folded_1 = serde_json::to_string(&clean[1]).unwrap();
    let on_disk_after_crash = [folded_0.as_str(), folded_1.as_str(), raw_rows[2]];
    let rerun: Vec<UsageLedger> = on_disk_after_crash.iter().map(|r| migrate_raw(r)).collect();

    for (c, r) in clean.iter().zip(rerun.iter()) {
        assert_eq!(
            serde_json::to_string(c).unwrap(),
            serde_json::to_string(r).unwrap(),
            "crash plus rerun must be byte-identical to a clean single run"
        );
    }
    assert_eq!(rerun[0].total_input(), 1000);
    assert_eq!(rerun[0].total_output(), 400);
    assert_eq!(rerun[2].total_cache_write(), 42);
}

/// Folding an already-folded row adds zero: the identity the crash proof rests on, isolated.
#[test]
fn refolding_a_v2_row_adds_zero() {
    let raw = r#"{"requests":1,"models":[{"model":"m","tokens":{"input":50}}]}"#;
    let once = migrate_raw(raw);
    let twice = migrate_raw(&serde_json::to_string(&once).unwrap());
    assert_eq!(
        serde_json::to_string(&once).unwrap(),
        serde_json::to_string(&twice).unwrap()
    );
}
