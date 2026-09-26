// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE-SHOT USAGE-LEDGER MIGRATION (1.6.0 M1b): fold the pre-M1b scalar `TierTokens` rows onto
//! the name-keyed [`ModelTokens::usage_units`] ledger, gated by a BACKEND-INTERNAL
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
//! the live [`ModelTokens`] no longer has a `tokens` field. A byte-persisting backend
//! that deserialized an old row straight into the new type would SILENTLY DROP the `tokens` field
//! (serde ignores unknown fields) — losing the never-rolling budget totals. This module recovers
//! them: the frozen V1 deserialization structs ([`UsageLedgerV1`]) still carry `tokens`, and
//! [`fold_v1_ledger`] folds those fields into the canonical `usage_units` keys ONCE.
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
//! The V1 structs are read ONLY here (never in the serving path); the pricer/ledger/flush all speak
//! the name-keyed map exclusively.

// The frozen pre-M1b row SHAPES and the fold that maps them onto the live shapes are the contract's:
// the V1-to-current mapping is fixed byte for byte by the frozen layouts, so two honest
// implementations could not differ (#83(d)), and a store backend that runs the fold names only the
// contract. Re-exported here so the schema gate, the fold and the rows it folds are named from one
// module.
pub use busbar_contract::records::{
    fold_v1_ledger, fold_v1_model, ModelTokensV1, TierTokensV1, UsageLedgerV1,
};

/// The name-keyed usage-ledger schema version stamped after the M1b fold completes.
pub const USAGE_SCHEMA_V2: u32 = 2;

#[cfg(test)]
#[path = "tests/usage_migration_tests.rs"]
mod tests;
