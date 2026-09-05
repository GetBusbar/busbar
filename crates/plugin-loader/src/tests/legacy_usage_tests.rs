// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The USAGE-LEDGER adapter: a store plugin loaded at the older payload schema must be handed the
//! 1.5.5 four-tier row, and must be understood when it hands one back.
//!
//! The regression these pin is a MONEY one, found by the shadow oracle: 1.6.0 replaced the
//! per-model `tokens: {input, output, cache_read, cache_write}` struct with one open `usage_units`
//! map and sent that new shape to the PUBLISHED 1.5.5 sqlite store, which answered
//! `malformed request JSON: missing field 'tokens'` on every flush tick. Nothing was persisted, so
//! usage and budget balances silently reset across a restart. The read direction was just as bad
//! and quieter: a 1.5.5 row decoded into the current struct yields an EMPTY unit map (the map has a
//! serde default), i.e. zero tokens read back from a store that holds the real counts.
//!
//! The wire bytes are captured at the C-ABI seam, so these assert what a plugin ACTUALLY receives,
//! not what an in-tree type happens to serialize to.

use super::*;
use crate::legacy_usage::{
    delta_to_legacy, ledger_from_legacy, ledger_to_legacy, needs_legacy_usage_wire,
    LegacyModelTokens, LegacyUsageLedger, TierTokens, UNIT_MAP_ABI,
};
use busbar_api::{ModelTokens, ModelTokensDelta, UNIT_CACHE_READ, UNIT_INPUT, UNIT_OUTPUT};

/// The request bytes the last `capture_call` saw — the JSON a plugin would have to decode.
static LAST_REQUEST: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

/// A fake `busbar_call` that RECORDS the request, then answers `StoreResponse::Unit`.
unsafe extern "C-unwind" fn capture_call(
    _handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if !req.is_null() && req_len != 0 {
        *LAST_REQUEST.lock().unwrap_or_else(|p| p.into_inner()) =
            std::slice::from_raw_parts(req, req_len).to_vec();
    }
    fake_call(_handle, req, req_len, out, out_len)
}

/// A `DynStore` over the in-tree example plugin, bound to `abi` and with its call seam recording.
fn store_at_abi(abi: u32) -> Option<DynStore> {
    let path = store_example_plugin_path()?;
    let bytes = std::fs::read(&path).expect("read the in-tree store example plugin cdylib");
    let (lib, staged) = stage::load_library_from_bytes(&bytes, "usage-wire")
        .expect("stage the in-tree store example plugin for the usage-wire harness");
    let mut raw = wire_up_raw(
        lib,
        "{}",
        "usage-wire".to_string(),
        abi_kind::STORE,
        abi_kind::STORE,
        Some(staged),
    )
    .expect("wire up raw");
    raw.call = capture_call;
    raw.free = fake_free;
    Some(DynStore::new(raw, abi))
}

/// One flush's worth of tokens: 6 in, 12 out.
fn one_delta() -> UsageDelta {
    UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            model: "m-openai-chat".to_string(),
            usage_units: [
                (UNIT_INPUT.to_string(), 6i64),
                (UNIT_OUTPUT.to_string(), 12i64),
            ]
            .into_iter()
            .collect(),
        }],
    }
}

/// Run `op` against a store at `abi` and return the request JSON the plugin received.
fn request_json_for(abi: u32, op: impl FnOnce(&DynStore)) -> serde_json::Value {
    let store = store_at_abi(abi).expect("checked by the caller");
    FAKE_CALL_HANDLE.with(|c| c.set((STATUS_OK, br#""Unit""#)));
    LAST_REQUEST
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    op(&store);
    let bytes = LAST_REQUEST
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    serde_json::from_slice(&bytes).expect("the request the plugin received is JSON")
}

/// THE REGRESSION, at the wire: the flush a store loaded at the 1.5.5 payload schema receives
/// carries the four named tiers under `tokens`, which is the only shape that plugin can decode.
#[test]
fn add_usage_to_an_abi_2_store_sends_the_1_5_5_tier_row() {
    if store_example_plugin_path().is_none() {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    }
    let delta = one_delta();
    let sent = request_json_for(2, |s| {
        s.add_usage("bucket", 0, &delta).expect("flush accepted");
    });
    let model = &sent["AddUsage"]["delta"]["models"][0];
    assert_eq!(
        model["tokens"],
        serde_json::json!({"input": 6, "output": 12, "cache_read": 0, "cache_write": 0}),
        "a 1.5.5 store must receive the four named tiers under `tokens`; it answers \
         `missing field 'tokens'` to anything else and NOTHING is persisted. Sent: {sent}"
    );
    assert!(
        model.get("usage_units").is_none(),
        "the unit map must not ride along to a store that cannot decode it: {sent}"
    );
    assert_eq!(sent["AddUsage"]["delta"]["requests"], 1);
    assert_eq!(sent["AddUsage"]["delta"]["billable_requests"], 1);
    assert_eq!(sent["AddUsage"]["bucket_id"], "bucket");
}

/// The same flush to a CURRENT-schema store keeps the unit map — the adapter is scoped to the old
/// wire and does not downgrade a store that speaks the new one (open units would be lost).
#[test]
fn add_usage_to_a_current_store_still_sends_the_unit_map() {
    if store_example_plugin_path().is_none() {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    }
    let delta = one_delta();
    let sent = request_json_for(busbar_plugin::cold::ABI_VERSION, |s| {
        s.add_usage("bucket", 0, &delta).expect("flush accepted");
    });
    let model = &sent["AddUsage"]["delta"]["models"][0];
    assert_eq!(
        model["usage_units"],
        serde_json::json!({"input": 6, "output": 12}),
        "a current store keeps receiving the open unit map: {sent}"
    );
    assert!(model.get("tokens").is_none(), "no legacy row: {sent}");
}

/// `put_usage` (the absolute set) travels the same adapter as the additive flush.
#[test]
fn put_usage_to_an_abi_2_store_sends_the_1_5_5_tier_row() {
    if store_example_plugin_path().is_none() {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    }
    let ledger = UsageLedger {
        requests: 3,
        billable_requests: 2,
        models: vec![ModelTokens {
            model: "m".to_string(),
            usage_units: [(UNIT_CACHE_READ.to_string(), 9u64)].into_iter().collect(),
        }],
    };
    let sent = request_json_for(2, |s| {
        s.put_usage("bucket", 7, &ledger).expect("write accepted");
    });
    assert_eq!(
        sent["PutUsage"]["ledger"]["models"][0]["tokens"],
        serde_json::json!({"input": 0, "output": 0, "cache_read": 9, "cache_write": 0}),
        "sent: {sent}"
    );
    assert_eq!(sent["PutUsage"]["window_start"], 7);
}

/// The READ direction: a 1.5.5 ledger coming back is understood. Decoded as the current shape it
/// would be an empty unit map — a restart hydrating zero tokens from a store holding the counts.
#[test]
fn get_usage_from_an_abi_2_store_reads_the_1_5_5_tier_row() {
    if store_example_plugin_path().is_none() {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    }
    let store = store_at_abi(2).expect("checked above");
    FAKE_CALL_HANDLE.with(|c| {
        c.set((
            STATUS_OK,
            br#"{"Usage":{"requests":4,"billable_requests":3,"models":[{"model":"m","tokens":{"input":6,"output":12,"cache_read":0,"cache_write":0}}]}}"#,
        ))
    });
    let got = store.get_usage("bucket", 0).expect("ledger read back");
    assert_eq!(got.requests, 4);
    assert_eq!(got.billable_requests, 3);
    assert_eq!(
        got.total_input(),
        6,
        "input tokens survive the read: {got:?}"
    );
    assert_eq!(got.total_output(), 12, "output tokens survive: {got:?}");
    assert_eq!(got.total_tokens(), 18);
}

/// The schema boundary itself: everything below the unit-map schema takes the legacy wire, the
/// unit-map schema and above take the current one.
#[test]
fn the_legacy_wire_covers_exactly_the_schemas_below_the_unit_map() {
    assert_eq!(UNIT_MAP_ABI, 4, "the unit map landed at payload schema 4");
    assert!(needs_legacy_usage_wire(2), "every published 1.5.x store");
    assert!(needs_legacy_usage_wire(3));
    assert!(!needs_legacy_usage_wire(4));
    assert!(!needs_legacy_usage_wire(busbar_plugin::cold::ABI_VERSION));
}

/// A round trip through the 1.5.5 shape preserves the four priced tiers exactly.
#[test]
fn the_four_priced_tiers_round_trip_through_the_1_5_5_shape() {
    let ledger = UsageLedger {
        requests: 5,
        billable_requests: 4,
        models: vec![ModelTokens {
            model: "m".to_string(),
            usage_units: busbar_api::RESERVED_UNITS
                .iter()
                .enumerate()
                .map(|(i, u)| (u.to_string(), (i as u64 + 1) * 10))
                .collect(),
        }],
    };
    let (legacy, dropped) = ledger_to_legacy(&ledger);
    assert!(dropped.is_empty(), "the reserved four all have a column");
    assert_eq!(ledger_from_legacy(legacy), ledger);
}

/// A unit a 1.5.x store has no column for is REPORTED, not silently swallowed — the caller says so
/// once. The four priced tiers still make the trip.
#[test]
fn an_open_unit_with_no_1_5_5_column_is_reported() {
    let delta = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: [
                (UNIT_INPUT.to_string(), 6i64),
                ("voice_seconds".to_string(), 30i64),
            ]
            .into_iter()
            .collect(),
        }],
    };
    let (legacy, dropped) = delta_to_legacy(&delta);
    assert_eq!(dropped, vec!["voice_seconds".to_string()]);
    assert_eq!(legacy.models[0].tokens.input, 6);
}

/// An all-zero legacy row decodes to the same empty map the current shape would produce, so a
/// never-used bucket does not sprout four zero keys on every read.
#[test]
fn an_all_zero_legacy_row_decodes_to_an_empty_unit_map() {
    let decoded = ledger_from_legacy(LegacyUsageLedger {
        requests: 0,
        billable_requests: 0,
        models: vec![LegacyModelTokens {
            model: "m".to_string(),
            tokens: TierTokens::default(),
        }],
    });
    assert!(decoded.models[0].usage_units.is_empty());
    assert!(decoded.models[0].is_zero());
}
