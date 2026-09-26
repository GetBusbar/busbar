// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The METERING row's price instant against a store built before it existed (DECISION #79).
//!
//! The store below is a faithful model of every published 1.5.x store plugin's metering table: it
//! decodes the request with serde (so an unknown field is silently ignored, exactly as a plugin
//! compiled against the 1.5.5 `MeteringDelta` does), upserts on the FOUR columns it knows —
//! `(bucket, key_id, provider, model)`, the `ON CONFLICT` target of the published sqlite store — and
//! reads rows back with no `priced_from_ms` at all. It sits behind the real C-ABI call seam of a real
//! `DynStore`, so these assert what such a store ends up HOLDING, not what an in-tree type encodes.

use super::*;
use crate::{DynStore, RawPlugin};
use busbar_contract::records::RecordStore as _;
use std::collections::BTreeMap;
use std::os::raw::c_void;
use std::sync::Mutex;

/// One 1.5.x metering row: the four keyed columns plus the counters it sums.
#[derive(Default, Clone)]
struct LegacyCell {
    tokens_input: u64,
    tokens_output: u64,
    requests: u64,
    billable_requests: u64,
}

/// The fake store's table, keyed exactly as the published stores key it.
type Table = Mutex<BTreeMap<(u64, String, String, String), LegacyCell>>;

/// A `busbar_call` that behaves like a 1.5.x store's metering table.
unsafe extern "C-unwind" fn legacy_store_call(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: `handle` is the leaked `Table` `legacy_store` built; `req` is the engine's buffer.
    let table = unsafe { &*(handle as *const Table) };
    let req: serde_json::Value =
        serde_json::from_slice(unsafe { std::slice::from_raw_parts(req, req_len) })
            .expect("the engine sends JSON");
    let answer = if let Some(d) = req.get("AddMetering") {
        let s = |k: &str| d[k].as_str().expect("string column").to_string();
        let n = |k: &str| d[k].as_u64().expect("counter column");
        let mut t = table.lock().unwrap();
        let cell = t
            .entry((n("bucket"), s("key_id"), s("provider"), s("model")))
            .or_default();
        cell.tokens_input += n("tokens_input");
        cell.tokens_output += n("tokens_output");
        cell.requests += n("requests");
        cell.billable_requests += n("billable_requests");
        serde_json::json!("Unit")
    } else if let Some(bucket) = req.get("ListMetering") {
        let bucket = bucket.as_u64().expect("bucket");
        let rows: Vec<serde_json::Value> = table
            .lock()
            .unwrap()
            .iter()
            .filter(|((b, ..), _)| *b == bucket)
            .map(|((_, key_id, provider, model), c)| {
                // No `priced_from_ms`: the 1.5.x row has no such column.
                serde_json::json!({
                    "key_id": key_id, "model": model, "provider": provider,
                    "tokens_input": c.tokens_input, "tokens_output": c.tokens_output,
                    "tokens_cache_read": 0, "tokens_cache_write": 0,
                    "requests": c.requests, "billable_requests": c.billable_requests,
                })
            })
            .collect();
        serde_json::json!({ "Metering": rows })
    } else {
        panic!("the metering tests send only AddMetering/ListMetering, got {req}");
    };
    let boxed: Box<[u8]> = serde_json::to_vec(&answer).unwrap().into_boxed_slice();
    // SAFETY: the engine hands valid out-pointers.
    unsafe {
        *out_len = boxed.len();
        *out = Box::into_raw(boxed) as *mut u8;
    }
    busbar_plugin::cold::STATUS_OK
}

unsafe extern "C-unwind" fn legacy_store_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        // SAFETY: allocated by `legacy_store_call` as a boxed slice of exactly `len` bytes.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
    }
}

unsafe extern "C-unwind" fn legacy_store_close(handle: *mut c_void) {
    // SAFETY: `handle` is the `Box<Table>` leaked by `legacy_store`, closed exactly once.
    drop(unsafe { Box::from_raw(handle as *mut Table) });
}

/// A `DynStore` at payload schema `abi` over a fresh 1.5.x-shaped metering table.
fn legacy_store(abi: u32) -> DynStore {
    let table: Box<Table> = Box::default();
    DynStore::new(
        RawPlugin {
            handle: Box::into_raw(table) as *mut c_void,
            call: legacy_store_call,
            free: legacy_store_free,
            close: legacy_store_close,
            path: "legacy-metering".to_string(),
            kind: busbar_plugin::cold::kind::STORE,
            shape: std::sync::atomic::AtomicU8::new(0),
            _lib: None,
            _backing: None,
        },
        abi,
    )
}

const DAY: u64 = 1_758_672_000; // a UTC-midnight bucket, in seconds
const NOON_MS: u64 = (DAY + 12 * 3600) * 1000; // the corrected card's `effective_from`

fn delta(provider: &str, priced_from_ms: u64, tokens_input: u64) -> MeteringDelta {
    MeteringDelta {
        usage_units: Default::default(),
        key_id: "vk_a".to_string(),
        bucket: DAY,
        model: "m-chat".to_string(),
        provider: provider.to_string(),
        tokens_input,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms,
    }
}

/// THE MONEY CELL. A card edit at noon splits the day's metering cell in the engine; flushed to a
/// published (abi 2) store, the two halves must come back as two rows, each carrying the instant
/// its price started — otherwise the whole day reads back as one `priced_from_ms = 0` row and is
/// priced at the midnight card.
#[test]
fn a_rate_card_split_day_stays_split_on_an_abi_2_store() {
    let store = legacy_store(2);
    store.add_metering(&delta("prov-a", 0, 100)).unwrap();
    store.add_metering(&delta("prov-a", NOON_MS, 100)).unwrap();

    let mut rows = store.list_metering(DAY).unwrap();
    rows.sort_by_key(|r| r.priced_from_ms);
    let got: Vec<(&str, u64, u64)> = rows
        .iter()
        .map(|r| (r.provider.as_str(), r.priced_from_ms, r.tokens_input))
        .collect();
    assert_eq!(
        got,
        vec![("prov-a", 0, 100), ("prov-a", NOON_MS, 100)],
        "the morning and the afternoon must stay two cells, each with its own price instant"
    );
}

/// A deployment that never edited its card dates every cell `0`, and its rows must be exactly the
/// rows 1.5.5 wrote: nothing is folded into `provider`, so a rollback reads them unchanged.
#[test]
fn an_opening_card_row_is_written_to_an_abi_2_store_unchanged() {
    let d = delta("prov-a", 0, 7);
    assert_eq!(metering_delta_to_legacy(&d), d);
    let store = legacy_store(2);
    store.add_metering(&d).unwrap();
    store.add_metering(&d).unwrap();
    let rows = store.list_metering(DAY).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (
            rows[0].provider.as_str(),
            rows[0].priced_from_ms,
            rows[0].tokens_input
        ),
        ("prov-a", 0, 14)
    );
}

/// A provider whose own name contains the mark is always encoded, so decoding the LAST mark can
/// never misread part of a real provider name as a price instant.
#[test]
fn a_provider_name_containing_the_mark_round_trips() {
    for (provider, at) in [
        ("odd|priced_from_ms=5", 0),
        ("odd|priced_from_ms=5", NOON_MS),
    ] {
        let d = delta(provider, at, 1);
        let sent = metering_delta_to_legacy(&d);
        let row = metering_row_from_legacy(MeteringRow {
            usage_units: Default::default(),
            key_id: sent.key_id,
            model: sent.model,
            provider: sent.provider,
            tokens_input: 1,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
            priced_from_ms: 0,
        });
        assert_eq!((row.provider.as_str(), row.priced_from_ms), (provider, at));
    }
}

/// A current-schema store is sent the delta untouched — the instant rides in its own field.
#[test]
fn a_current_store_is_sent_the_delta_unchanged() {
    assert!(needs_legacy_metering_wire(2));
    assert!(needs_legacy_metering_wire(3));
    assert!(!needs_legacy_metering_wire(
        busbar_plugin::cold::ABI_VERSION
    ));
}

/// A 1.5.x store has no column for a ledgered class outside the token split (`usage_units`): the
/// counts are stripped on the way out (the loader says so, once), and a delta that carried nothing
/// else is not sent at all — no empty row appears in a published store.
#[test]
fn an_abi_2_store_is_never_sent_a_class_it_has_no_column_for() {
    let mut classes_only = delta("tp", 0, 0);
    classes_only.requests = 0;
    classes_only.billable_requests = 0;
    classes_only.usage_units = [("tool_calls".to_string(), 3)].into();
    let sent = metering_delta_to_legacy(&classes_only);
    assert!(sent.usage_units.is_empty());
    assert!(metering_delta_is_empty(&sent));
    let mut with_request = classes_only.clone();
    with_request.requests = 1;
    assert!(!metering_delta_is_empty(&metering_delta_to_legacy(
        &with_request
    )));

    let store = legacy_store(2);
    store.add_metering(&classes_only).unwrap();
    assert!(
        store.list_metering(DAY).unwrap().is_empty(),
        "a classes-only delta writes no row to a store that cannot hold it"
    );
    store.add_metering(&with_request).unwrap();
    let rows = store.list_metering(DAY).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].requests, rows[0].usage_units.len()), (1, 0));
}
