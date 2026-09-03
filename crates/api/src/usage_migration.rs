// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE-SHOT USAGE-LEDGER MIGRATION (1.6.0 M1b): fold the pre-M1b scalar `TierTokens` rows onto
//! the name-keyed [`crate::store::ModelTokens::usage_units`] ledger, gated by a BACKEND-INTERNAL
//! usage-ledger schema version ([`USAGE_SCHEMA_V2`]).
//!
//! WHERE THE GATE LIVES. The schema version is a durable-backend concern, exactly like the existing
//! `SCHEMA_VERSION 5→6` billable-requests backfill each backend runs in its own `migrate()` (see the
//! note in `governance::state::hydrate_budgets`). It is deliberately NOT a `Store` trait method: the
//! trait's completeness gate (`plugin-loader`) requires every method to cross the plugin ABI, and a
//! one-shot schema bump is not request-path traffic. A byte-persisting backend reads its own stored
//! schema meta, and if it is `< `[`USAGE_SCHEMA_V2`], applies [`fold_v1_ledger`] to each ledger row
//! (and folds its own metering rows likewise) before stamping the new version. The in-repo
//! `MemoryStore` is ephemeral and already holds new-shape values, so it has nothing to migrate.
//!
//! WHY A MIGRATION EXISTS. Before M1b, a persisted ledger row carried a scalar `tokens: TierTokens`
//! struct (`input`/`output`/`cache_read`/`cache_write`) BESIDE an optional open `usage_units` map.
//! M1b dissolves `TierTokens`: the reserved four are now PLAIN KEYS in the one `usage_units` map, so
//! the live [`crate::store::ModelTokens`] no longer has a `tokens` field. A byte-persisting backend
//! that deserialized an old row straight into the new type would SILENTLY DROP the `tokens` field
//! (serde ignores unknown fields) — losing the never-rolling budget totals. This module recovers
//! them: the frozen V1 deserialization structs below still carry `tokens`, and [`fold_v1_ledger`]
//! folds those fields into the canonical `usage_units` keys ONCE.
//!
//! IDEMPOTENT BY CONSTRUCTION — THE CRASH-SAFETY PROOF. A backend migrates row-by-row: read a raw
//! row through [`UsageLedgerV1`], [`fold_v1_ledger`] it, write the folded row back, and stamp
//! [`USAGE_SCHEMA_V2`] only after the whole scan. If it CRASHES mid-scan (some rows folded, the
//! stamp not yet written), the next boot re-runs the whole scan. An already-folded row has NO
//! `tokens` field on disk, so [`UsageLedgerV1`] deserializes it with `tokens` defaulted to all-zero
//! (`#[serde(default)]`), and folding a zero tier ADDS 0 — the re-fold is the identity. So a crash +
//! reboot can neither double-count nor lose a budget total: the folded ledger is byte-identical to a
//! clean single run. That equality is a HARD gate, proven by [`tests`].
//!
//! The V1 structs live ONLY here (never in the serving path); the pricer/ledger/flush all speak the
//! name-keyed map exclusively.

use std::collections::BTreeMap;

use crate::store::{
    ModelTokens, UsageLedger, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};

/// The name-keyed usage-ledger schema version stamped after the M1b fold completes.
pub const USAGE_SCHEMA_V2: u32 = 2;

/// FROZEN, deserialization-only. The pre-M1b `TierTokens` shape. Every field `#[serde(default)]` so
/// an already-migrated row (no `tokens` object on disk) deserializes to all-zero — the identity the
/// idempotent re-fold depends on.
#[derive(Debug, Clone, Copy, Default, serde::Deserialize)]
pub struct TierTokensV1 {
    #[serde(default)]
    pub input: u64,
    #[serde(default)]
    pub output: u64,
    #[serde(default)]
    pub cache_read: u64,
    #[serde(default)]
    pub cache_write: u64,
}

/// FROZEN, deserialization-only. The pre-M1b per-model row: the scalar `tokens` PLUS any open
/// `usage_units` that already rode beside it (M1 additive rows).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ModelTokensV1 {
    pub model: String,
    #[serde(default)]
    pub tokens: TierTokensV1,
    #[serde(default)]
    pub usage_units: BTreeMap<String, u64>,
}

/// FROZEN, deserialization-only. The pre-M1b bucket ledger.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct UsageLedgerV1 {
    #[serde(default)]
    pub requests: u64,
    #[serde(default)]
    pub billable_requests: u64,
    #[serde(default)]
    pub models: Vec<ModelTokensV1>,
}

/// Fold `add` into `out[unit]`, canonicalizing the legacy `cache_creation` spelling onto
/// [`UNIT_CACHE_WRITE`] so the two names never split one concept across two keys. A zero add is a
/// no-op (the idempotent-re-fold identity; also keeps the sparse map free of zero entries).
fn fold_unit(out: &mut BTreeMap<String, u64>, unit: &str, add: u64) {
    if add == 0 {
        return;
    }
    let canon = if unit == "cache_creation" {
        UNIT_CACHE_WRITE
    } else {
        unit
    };
    let slot = out.entry(canon.to_string()).or_insert(0);
    *slot = slot.saturating_add(add);
}

/// Fold one pre-M1b per-model row onto the name-keyed representation: the four `tokens` fields land
/// on the reserved keys, every open unit is carried through (canonicalized). Idempotent: a row whose
/// `tokens` are all zero (an already-migrated row re-read) folds to exactly its existing units.
pub fn fold_v1_model(v1: ModelTokensV1) -> ModelTokens {
    let mut units: BTreeMap<String, u64> = BTreeMap::new();
    fold_unit(&mut units, UNIT_INPUT, v1.tokens.input);
    fold_unit(&mut units, UNIT_OUTPUT, v1.tokens.output);
    fold_unit(&mut units, UNIT_CACHE_READ, v1.tokens.cache_read);
    fold_unit(&mut units, UNIT_CACHE_WRITE, v1.tokens.cache_write);
    for (k, v) in v1.usage_units {
        fold_unit(&mut units, &k, v);
    }
    ModelTokens {
        model: v1.model,
        usage_units: units,
    }
}

/// Fold one pre-M1b bucket ledger onto the name-keyed representation (see [`fold_v1_model`]). The
/// request counters pass through unchanged. This is the per-row unit a backend applies under the
/// [`USAGE_SCHEMA_V2`] gate.
pub fn fold_v1_ledger(v1: UsageLedgerV1) -> UsageLedger {
    UsageLedger {
        requests: v1.requests,
        billable_requests: v1.billable_requests,
        models: v1.models.into_iter().map(fold_v1_model).collect(),
    }
}

#[cfg(test)]
mod tests {
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
}
