// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE 1.5.x -> 1.6.0 USAGE-ROW FOLD a store plugin's own `migrate()` calls (#33, M5/parity).
//!
//! A 1.5.x usage-ledger row carried its per-model tokens as four named pricing tiers
//! (`input`/`output`/`cache_read`/`cache_write`) beside an optional open `usage_units` map. 1.6.0
//! keeps ONE name-keyed map ([`ModelTokens::usage_units`]): the four tiers are plain keys in it.
//! A backend that read an old row straight into the new type would drop the tiers and zero every
//! customer's counters. This module is the fold that carries them over.
//!
//! WHERE IT RUNS. Not in the engine: 1.5.5 had no data dir, so a 1.5.x row lives in the store
//! plugin's own database and only the plugin holds its bytes. Each store sibling's `migrate()`
//! reads its own 1.5.x rows into [`UsageLedgerV1`] (a JSON row through serde, a columnar row by
//! filling [`ModelTokensV1`]'s fields from its `tokens_*` columns), calls [`fold_v1_ledger`], writes
//! the result and stamps its own schema version. One fold, in the SDK every store plugin already
//! links, so no backend re-implements it. Pure: no engine or kernel dependency, integer counts only.
//!
//! The metering and audit rows need no fold: a 1.5.x `usage_metering` row's columns are
//! [`crate::records::MeteringRow`]'s, with `priced_from_ms` 0 (the opening card) and no open units,
//! and a 1.5.x audit row is [`crate::records::AuditRecord`] field for field.
//!
//! CRASH-IDEMPOTENT BY CONSTRUCTION. A backend folds row by row and stamps its schema only after
//! the whole scan. A crash mid-scan re-runs the scan on the next open: an already-folded row has no
//! `tokens` on disk, so it reads back with all four tiers zero, and folding a zero tier adds
//! nothing. The re-fold is the identity, so crash plus rerun is byte-identical to one clean run.
//! `tests/store_migrate_tests.rs` holds that property; the store-migration conformance harness
//! (`plugin-loader`'s `store_migration_conformance_tests`) holds each backend to it end to end.
//!
//! This is the deleted engine fold (`busbar-contract/src/records.rs` + `busbar-kernel-ledger`'s
//! `usage_migration`, removed by #33) in its correct home, logic unchanged.

use crate::records::{
    ModelTokens, UsageLedger, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
use std::collections::BTreeMap;

/// FROZEN, read-only. A 1.5.x row's four pricing tiers. Every field defaults to zero, so an
/// already-folded row (no `tokens` on disk) reads as all-zero: the identity the re-fold relies on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct TierTokensV1 {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

/// FROZEN, read-only. A 1.5.x per-model row: the scalar tiers plus any open units beside them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct ModelTokensV1 {
    pub model: String,
    #[serde(default)]
    pub tokens: TierTokensV1,
    #[serde(default)]
    pub usage_units: BTreeMap<String, u64>,
}

/// FROZEN, read-only. A 1.5.x bucket ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct UsageLedgerV1 {
    pub requests: u64,
    pub billable_requests: u64,
    pub models: Vec<ModelTokensV1>,
}

/// Add `add` to `out[unit]`, spelling the legacy `cache_creation` as [`UNIT_CACHE_WRITE`] so one
/// concept never splits across two keys. A zero add is a no-op, which keeps the map sparse and
/// makes the re-fold the identity.
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

/// Fold one 1.5.x per-model row: the four tiers land on the reserved keys and every open unit is
/// carried through, canonicalized.
pub fn fold_v1_model(v1: ModelTokensV1) -> ModelTokens {
    let mut units = BTreeMap::new();
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

/// Fold one 1.5.x bucket ledger (see [`fold_v1_model`]); the request counters pass through.
pub fn fold_v1_ledger(v1: UsageLedgerV1) -> UsageLedger {
    UsageLedger {
        requests: v1.requests,
        billable_requests: v1.billable_requests,
        models: v1.models.into_iter().map(fold_v1_model).collect(),
    }
}

#[cfg(test)]
#[path = "tests/store_migrate_tests.rs"]
mod tests;
