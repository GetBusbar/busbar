// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/api/src/usage_migration.rs`.

use super::*;

/// Deserialize a raw JSON row through the frozen V1 struct and fold it — the exact per-row unit a
/// byte-persisting backend runs during the schema-gated scan.
fn migrate_raw(raw: &str) -> UsageLedger {
    let v1: UsageLedgerV1 = serde_json::from_str(raw).expect("v1 deserializes");
    fold_v1_ledger(v1)
}

/// A pre-M1b row's scalar tiers land on the canonical reserved keys, opens carried through.
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

/// The legacy `cache_creation` open spelling canonicalizes onto `cache_write` (never two keys).
#[test]
fn canonicalizes_cache_creation_onto_cache_write() {
    let raw = r#"{"models":[{"model":"m","tokens":{"cache_write":5},
        "usage_units":{"cache_creation":4}}]}"#;
    let l = migrate_raw(raw);
    // 5 (reserved tier) + 4 (legacy open) fold onto ONE key.
    assert_eq!(l.total_cache_write(), 9);
    assert_eq!(l.models[0].usage_units.get("cache_creation"), None);
}

/// THE HARD CRASH-SAFETY GATE. A crash mid-migration (some rows already folded + written, the
/// schema stamp not yet applied) forces a full re-scan on reboot. Re-folding the already-folded
/// rows must be the IDENTITY, so the fleet budget totals after crash+rerun are BYTE-IDENTICAL to
/// a clean single run — the never-rolling `UsageLedger` totals can neither double-count nor be
/// lost. Proven by re-serializing a folded row and re-running the migration over it.
#[test]
fn crash_partial_then_rerun_is_byte_identical_to_a_clean_run() {
    // Three pre-M1b rows (raw v1 on disk).
    let raw_rows = [
        r#"{"requests":5,"billable_requests":5,"models":[{"model":"a","tokens":{"input":1000,"output":400,"cache_read":30,"cache_write":12}}]}"#,
        r#"{"requests":2,"billable_requests":1,"models":[{"model":"b","tokens":{"input":7,"output":0,"cache_read":0,"cache_write":0}},{"model":"c","tokens":{"input":0,"output":9,"cache_read":0,"cache_write":0},"usage_units":{"images":2}}]}"#,
        r#"{"requests":9,"billable_requests":9,"models":[{"model":"d","tokens":{"input":42,"output":42,"cache_read":42,"cache_write":42}}]}"#,
    ];

    // CLEAN RUN: migrate every raw row exactly once.
    let clean: Vec<UsageLedger> = raw_rows.iter().map(|r| migrate_raw(r)).collect();

    // CRASH RUN: the migrator folds row 0 and row 1 and WRITES them back (they are now v2 on
    // disk — no `tokens` field), then crashes BEFORE stamping the schema version. On reboot the
    // whole set is re-scanned: rows 0,1 are re-read from their FOLDED (v2) bytes; row 2 is still
    // raw v1. Every row is migrated again.
    let folded_0 = serde_json::to_string(&clean[0]).unwrap();
    let folded_1 = serde_json::to_string(&clean[1]).unwrap();
    let on_disk_after_crash = [
        folded_0.as_str(),
        folded_1.as_str(),
        raw_rows[2], // never got folded before the crash
    ];
    let rerun: Vec<UsageLedger> = on_disk_after_crash.iter().map(|r| migrate_raw(r)).collect();

    // BYTE-IDENTICAL: serialize both runs and compare. A double-count on the re-folded rows, or a
    // lost total, would diverge here.
    for (c, r) in clean.iter().zip(rerun.iter()) {
        assert_eq!(
            serde_json::to_string(c).unwrap(),
            serde_json::to_string(r).unwrap(),
            "crash+rerun budget totals must be byte-identical to a clean single run"
        );
    }
    // Spot-check the load-bearing never-rolling totals survived exactly.
    assert_eq!(rerun[0].total_input(), 1000);
    assert_eq!(rerun[0].total_output(), 400);
    assert_eq!(rerun[2].total_cache_write(), 42);
}

/// Folding an ALREADY-migrated (v2) ledger is a strict no-op on the counts — the identity the
/// crash-safety proof rests on, isolated.
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
