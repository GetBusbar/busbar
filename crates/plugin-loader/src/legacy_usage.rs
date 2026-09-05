// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5.5 USAGE-LEDGER wire, spoken to a store plugin that predates the name-keyed unit map.
//!
//! A published 1.5.x store plugin persists per-model tokens as four named pricing tiers:
//!
//! ```json
//! {"model":"m-openai-chat","tokens":{"input":6,"output":12,"cache_read":0,"cache_write":0}}
//! ```
//!
//! 1.6.0 replaced that struct with one open `usage_units` map (`{"input":6,"output":12}`), which
//! carries the same four tiers PLUS any unit a plane declares. The map is the right in-tree shape,
//! but it is NOT what an already-published plugin can decode: sent to a 1.5.5 store, the flush
//! comes back `malformed request JSON: missing field 'tokens'` and NOTHING is persisted — usage and
//! budget balances are silently lost across a restart.
//!
//! So the translation lives HERE, in the loader's adapter, not in the engine's ledger: the engine
//! keeps one internal row shape, and a store loaded at the older payload schema is spoken to in the
//! shape it was built against. A current-schema store keeps getting the unit map unchanged.
//!
//! The mapping is exact in both directions for the four reserved units (`input` / `output` /
//! `cache_read` / `cache_write`), which is everything a 1.5.x deployment can produce. A unit key
//! outside those four has no column in a 1.5.x store and is dropped on the way out — the caller
//! warns once when that actually happens, so the loss is never silent.

use busbar_api::{
    ModelTokens, ModelTokensDelta, UsageDelta, UsageLedger, RESERVED_UNITS, UNIT_CACHE_READ,
    UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
use serde::{Deserialize, Serialize};

/// The FIRST payload schema that speaks the name-keyed unit map. A store plugin below this version
/// was built against the four-tier struct and must be spoken to in that shape.
pub(crate) const UNIT_MAP_ABI: u32 = 4;

/// Does a store at this payload schema need the 1.5.5 four-tier usage shape?
pub(crate) fn needs_legacy_usage_wire(abi_version: u32) -> bool {
    abi_version < UNIT_MAP_ABI
}

/// Per-model token counts split by pricing tier — the 1.5.5 `TierTokens`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TierTokens {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

/// The signed twin of [`TierTokens`] — the 1.5.5 `TierTokensDelta`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TierTokensDelta {
    pub input: i64,
    pub output: i64,
    pub cache_read: i64,
    pub cache_write: i64,
}

/// One model's tier counts inside a 1.5.5 ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LegacyModelTokens {
    pub model: String,
    pub tokens: TierTokens,
}

/// One model's signed tier delta inside a 1.5.5 delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LegacyModelTokensDelta {
    pub model: String,
    pub tokens: TierTokensDelta,
}

/// The 1.5.5 `UsageLedger` — field-for-field, including the `serde(default)` on the request split
/// that a pre-1.5.3 row may not carry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LegacyUsageLedger {
    pub requests: u64,
    #[serde(default)]
    pub billable_requests: u64,
    pub models: Vec<LegacyModelTokens>,
}

/// The 1.5.5 `UsageDelta`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LegacyUsageDelta {
    pub requests: i64,
    #[serde(default)]
    pub billable_requests: i64,
    pub models: Vec<LegacyModelTokensDelta>,
}

/// The two store requests whose PAYLOAD changed shape in 1.6.0. Externally tagged exactly like the
/// current `StoreRequest`, so the variant names on the wire are byte-identical and only the ledger
/// object inside differs — a 1.5.5 plugin decodes these as its own.
#[derive(Debug, Serialize)]
pub(crate) enum LegacyStoreRequest {
    PutUsage {
        bucket_id: String,
        window_start: u64,
        ledger: LegacyUsageLedger,
    },
    AddUsage {
        bucket_id: String,
        window_start: u64,
        delta: LegacyUsageDelta,
    },
}

/// The store responses those requests can produce: `Unit` for the writes, `Usage` for the read.
/// Any other variant is a plugin answering the wrong shape and fails to decode, which surfaces as a
/// store error rather than a silently empty ledger.
#[derive(Debug, Deserialize)]
pub(crate) enum LegacyStoreResponse {
    Unit,
    Usage(LegacyUsageLedger),
}

/// Split a unit map into the four 1.5.5 tier fields plus the names that have no tier to go to.
fn split_units<T: Copy + Default>(
    units: &std::collections::BTreeMap<String, T>,
) -> ([T; 4], Vec<String>) {
    let mut tiers = [T::default(); 4];
    let mut dropped = Vec::new();
    for (name, value) in units {
        match RESERVED_UNITS.iter().position(|r| *r == name.as_str()) {
            Some(i) => tiers[i] = *value,
            None => dropped.push(name.clone()),
        }
    }
    (tiers, dropped)
}

/// Fold the four 1.5.5 tier fields back into a unit map. A zero tier contributes NO key, so a
/// round-trip of an all-zero row is the same empty map the current shape would have produced.
fn join_units(tokens: TierTokens) -> std::collections::BTreeMap<String, u64> {
    let mut units = std::collections::BTreeMap::new();
    for (name, value) in [
        (UNIT_INPUT, tokens.input),
        (UNIT_OUTPUT, tokens.output),
        (UNIT_CACHE_READ, tokens.cache_read),
        (UNIT_CACHE_WRITE, tokens.cache_write),
    ] {
        if value != 0 {
            units.insert(name.to_string(), value);
        }
    }
    units
}

/// Encode an engine ledger into the 1.5.5 shape. Also returns every unit name that had no 1.5.5
/// column, so the caller can say so once.
pub(crate) fn ledger_to_legacy(ledger: &UsageLedger) -> (LegacyUsageLedger, Vec<String>) {
    let mut dropped_all = Vec::new();
    let models = ledger
        .models
        .iter()
        .map(|m| {
            let (t, dropped) = split_units(&m.usage_units);
            dropped_all.extend(dropped);
            LegacyModelTokens {
                model: m.model.clone(),
                tokens: TierTokens {
                    input: t[0],
                    output: t[1],
                    cache_read: t[2],
                    cache_write: t[3],
                },
            }
        })
        .collect();
    (
        LegacyUsageLedger {
            requests: ledger.requests,
            billable_requests: ledger.billable_requests,
            models,
        },
        dropped_all,
    )
}

/// Encode an engine delta into the 1.5.5 shape (the flush direction that the money regression hit).
pub(crate) fn delta_to_legacy(delta: &UsageDelta) -> (LegacyUsageDelta, Vec<String>) {
    let mut dropped_all = Vec::new();
    let models = delta
        .models
        .iter()
        .map(|m: &ModelTokensDelta| {
            let (t, dropped) = split_units(&m.usage_units);
            dropped_all.extend(dropped);
            LegacyModelTokensDelta {
                model: m.model.clone(),
                tokens: TierTokensDelta {
                    input: t[0],
                    output: t[1],
                    cache_read: t[2],
                    cache_write: t[3],
                },
            }
        })
        .collect();
    (
        LegacyUsageDelta {
            requests: delta.requests,
            billable_requests: delta.billable_requests,
            models,
        },
        dropped_all,
    )
}

/// Decode a 1.5.5 ledger the plugin returned into the engine's unit-map shape. Without this a
/// 1.5.5 row deserializes into the current struct with an EMPTY unit map (the map has a serde
/// default), so a restart would hydrate zero tokens from a store that holds the real counts.
pub(crate) fn ledger_from_legacy(legacy: LegacyUsageLedger) -> UsageLedger {
    UsageLedger {
        requests: legacy.requests,
        billable_requests: legacy.billable_requests,
        models: legacy
            .models
            .into_iter()
            .map(|m| ModelTokens {
                model: m.model,
                usage_units: join_units(m.tokens),
            })
            .collect(),
    }
}
